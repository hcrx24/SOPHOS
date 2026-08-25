"""
tests/test_crypto.py
Unit tests for the SOPHOS cryptographic primitives.
"""
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "sophos_client"))

import pytest
from core.crypto import (
    generate_master_key, generate_rsa_keypair,
    rsa_extract_private, rsa_extract_public,
    prf, random_st, apply_trapdoor, apply_public,
    st_to_bytes, st_from_bytes,
    make_ut, encrypt_doc_id, decrypt_doc_id,
    aes_gcm_encrypt, aes_gcm_decrypt,
    doc_key, make_doc_id,
)


@pytest.fixture(scope="module")
def rsa_keys():
    priv, pub = generate_rsa_keypair()
    d, N = rsa_extract_private(priv)
    e, _ = rsa_extract_public(pub)
    return d, e, N


def test_master_key_length():
    K = generate_master_key()
    assert len(K) == 32


def test_rsa_trapdoor_roundtrip(rsa_keys):
    """pow(pow(x, d, N), e, N) == x"""
    d, e, N = rsa_keys
    x = random_st(N)
    assert pow(pow(x, d, N), e, N) == x


def test_prf_deterministic():
    K = generate_master_key()
    assert prf(K, "vpn") == prf(K, "vpn")
    assert prf(K, "vpn") != prf(K, "rsa")


def test_prf_length():
    assert len(prf(b"\x00"*32, "test")) == 32


def test_update_token_deterministic(rsa_keys):
    d, e, N = rsa_keys
    K = generate_master_key()
    kw = prf(K, "openvpn")
    st = random_st(N)
    assert make_ut(kw, st) == make_ut(kw, st)


def test_encrypt_decrypt_doc_id(rsa_keys):
    d, e, N = rsa_keys
    K = generate_master_key()
    kw = prf(K, "openvpn")
    st = random_st(N)
    doc_id = make_doc_id("test.txt")
    enc  = encrypt_doc_id(doc_id, kw, st)
    dec  = decrypt_doc_id(enc, kw, st)
    assert dec == doc_id
    assert enc != doc_id   # must not be plaintext


def test_aes_gcm_roundtrip():
    key = os.urandom(32)
    plaintext = b"Hello SOPHOS SSE!"
    iv, ct, tag = aes_gcm_encrypt(key, plaintext)
    recovered = aes_gcm_decrypt(key, iv, ct, tag)
    assert recovered == plaintext


def test_aes_gcm_wrong_key():
    from cryptography.exceptions import InvalidTag
    key = os.urandom(32)
    iv, ct, tag = aes_gcm_encrypt(key, b"secret")
    with pytest.raises(InvalidTag):
        aes_gcm_decrypt(os.urandom(32), iv, ct, tag)


def test_doc_key_per_document():
    K = generate_master_key()
    id1 = make_doc_id("file1.txt")
    id2 = make_doc_id("file2.txt")
    assert doc_key(K, id1) != doc_key(K, id2)


def test_chain_consistency(rsa_keys):
    """ST values produced during upload must be correctly reversed during search."""
    d, e, N = rsa_keys
    K = generate_master_key()
    kw = prf(K, "authentication")
    doc_id = make_doc_id("doc.txt")

    # Simulate 3 uploads for keyword "authentication"
    st = random_st(N)
    chain = [st]
    for _ in range(3):
        st = apply_trapdoor(st, d, N)
        chain.append(st)

    # chain = [ST0, ST1, ST2, ST3] — server has entries for ST1, ST2, ST3
    # (ST0 was the initial random, first upload uses ST1 = apply_trapdoor(ST0, d, N))
    enc_ids = [encrypt_doc_id(doc_id, kw, chain[i]) for i in range(1, 4)]

    # Server-side: walk backward from ST3 to ST1 using public key
    st_cur = chain[3]
    for i in range(2, -1, -1):  # steps 2, 1, 0
        recovered = decrypt_doc_id(enc_ids[i], kw, st_cur)
        assert recovered == doc_id, f"Failed at chain step {i}"
        if i > 0:
            st_cur = apply_public(st_cur, e, N)
