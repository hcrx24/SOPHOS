"""
tests/test_end_to_end.py
End-to-end test verifying upload, search, trapdoor chain step decryption, and document fetching.
"""
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "sophos_client"))

import pytest
import hashlib
import tempfile
import shutil
from core.crypto import (
    generate_master_key, generate_rsa_keypair,
    rsa_extract_private, rsa_extract_public,
    prf, random_st, apply_trapdoor, apply_public,
    make_ut, encrypt_doc_id, decrypt_doc_id,
    make_doc_id, doc_key, aes_gcm_encrypt, aes_gcm_decrypt,
    st_to_bytes, st_from_bytes,
)
from core.keywords import extract_keywords
from core.state_db import KeywordStateDB


class MockServerDB:
    def __init__(self):
        self.doc_store = {}
        self.index_store = {}

    def put_document(self, doc_id, iv, ciphertext, tag, filename):
        self.doc_store[doc_id] = {
            "iv": iv, "ciphertext": ciphertext, "tag": tag, "filename": filename
        }

    def put_index_batch(self, entries):
        for ut, enc_id in entries:
            self.index_store[ut] = enc_id

    def get_index_entry(self, ut):
        return self.index_store.get(ut)

    def get_document(self, doc_id):
        return self.doc_store.get(doc_id)


@pytest.fixture
def test_env():
    temp_dir = tempfile.mkdtemp()
    state_db_path = os.path.join(temp_dir, "client_test.db")
    
    server_db = MockServerDB()
    client_db = KeywordStateDB(state_db_path)
    
    priv, pub = generate_rsa_keypair()
    d, N = rsa_extract_private(priv)
    e, _ = rsa_extract_public(pub)
    master_key = generate_master_key()
    
    yield server_db, client_db, master_key, d, e, N
    
    client_db.close()
    shutil.rmtree(temp_dir)


def test_full_upload_search_fetch_flow(test_env):
    server_db, client_db, master_key, d, e, N = test_env
    filename = "test_doc.txt"
    content = "Sophos searchable encryption with forward privacy and gRPC mTLS."
    
    # 1. Upload simulation
    doc_id = make_doc_id(filename)
    k_doc = doc_key(master_key, doc_id)
    iv, ciphertext, tag = aes_gcm_encrypt(k_doc, content.encode("utf-8"))
    
    # Store document on server
    server_db.put_document(doc_id, iv, ciphertext, tag, filename.encode("utf-8"))
    
    # Extract keywords & build index entries
    keywords = sorted(extract_keywords(content))
    assert "sophos" in keywords
    assert "encryption" in keywords
    
    entries = []
    for word in keywords:
        kw_bytes = prf(master_key, word)
        state = client_db.get_state(word)
        if state is None:
            st_cur = random_st(N)
            counter = 0
        else:
            st_blob, counter = state
            st_cur = apply_trapdoor(st_from_bytes(st_blob), d, N)
            counter += 1
        
        ut = make_ut(kw_bytes, st_cur)
        enc_id = encrypt_doc_id(doc_id, kw_bytes, st_cur)
        entries.append((ut, enc_id))
        client_db.set_state(word, st_to_bytes(st_cur), counter)
    
    server_db.put_index_batch(entries)
    
    # 2. Search simulation for keyword "sophos"
    kw_search = "sophos"
    st_blob, counter = client_db.get_state(kw_search)
    st_latest = st_from_bytes(st_blob)
    kw_bytes = prf(master_key, kw_search)
    
    # Server walks chain from counter down to 0
    search_hits = []
    st_int = st_latest
    for step in range(counter, -1, -1):
        st_cur_bytes = st_int.to_bytes(256, "big")
        ut = hashlib.sha256(kw_bytes + st_cur_bytes).digest()
        enc_id = server_db.get_index_entry(ut)
        if enc_id is not None:
            search_hits.append((step, enc_id))
        if step > 0:
            st_int = pow(st_int, e, N)
            
    assert len(search_hits) == 1
    hit_step, hit_enc_id = search_hits[0]
    assert hit_step == 0
    
    # 3. Client decrypts doc_id using the step evolution logic
    current_step = counter
    st_cur = st_latest
    steps_to_evolve = current_step - hit_step
    for _ in range(steps_to_evolve):
        st_cur = apply_public(st_cur, e, N)
    
    recovered_doc_id = decrypt_doc_id(hit_enc_id, kw_bytes, st_cur)
    assert recovered_doc_id == doc_id
    
    # 4. Fetch document from server using recovered_doc_id
    fetched_doc = server_db.get_document(recovered_doc_id)
    assert fetched_doc is not None
    
    rec_k_doc = doc_key(master_key, recovered_doc_id)
    plaintext = aes_gcm_decrypt(rec_k_doc, fetched_doc["iv"], fetched_doc["ciphertext"], fetched_doc["tag"])
    assert plaintext.decode("utf-8") == content
