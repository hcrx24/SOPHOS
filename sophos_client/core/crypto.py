"""
sophos_client/core/crypto.py
All cryptographic primitives for the SOPHOS SSE client.

Implements:
  - RSA-2048 keypair generation and PEM serialization
  - HMAC-SHA256 PRF  (keyword key derivation)
  - RSA trapdoor chain  (pow with private key d,N)
  - RSA public chain   (pow with public key e,N)
  - Update token  UT = SHA256(Kw ‖ ST)
  - Encrypted doc ID  enc_id = doc_id XOR SHA256(Kw ‖ ST ‖ b"id")
  - AES-256-GCM document encryption / decryption
  - Per-document key derivation  K_doc = HMAC(master_key, b"doc" ‖ doc_id)
  - doc_id generation  SHA256(filename_bytes + nonce)[:16]

Security note:
  RSA is used here ONLY as a one-way trapdoor permutation over Z_N*,
  NOT for public-key encryption. No PKCS/OAEP padding is applied.
  This is correct per the Sophos construction (Bost, CCS 2016).
"""

import hashlib
import hmac as _hmac
import os
import struct

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.serialization import (
    load_pem_private_key,
    load_pem_public_key,
)

# RSA-2048 → 256-byte big-endian integers
ST_BYTE_LEN = 256
DOC_ID_LEN  = 16


# ─────────────────────────────────────────────────────────────────────────────
#  Key Generation
# ─────────────────────────────────────────────────────────────────────────────

def generate_master_key() -> bytes:
    """Generate a 256-bit (32-byte) master key K."""
    return os.urandom(32)


def generate_rsa_keypair():
    """
    Generate an RSA-2048 keypair.
    Returns (private_key_obj, public_key_obj).
    """
    priv = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend(),
    )
    return priv, priv.public_key()


def rsa_extract_private(private_key) -> tuple[int, int]:
    """Extract (d, N) as Python integers from an RSA private key object."""
    nums = private_key.private_numbers()
    return nums.d, nums.public_numbers.n


def rsa_extract_public(public_key) -> tuple[int, int]:
    """Extract (e, N) as Python integers from an RSA public key object."""
    nums = public_key.public_numbers()
    return nums.e, nums.n


# ─────────────────────────────────────────────────────────────────────────────
#  Key Serialization / Deserialization
# ─────────────────────────────────────────────────────────────────────────────

def save_master_key(key: bytes, path: str) -> None:
    with open(path, "wb") as f:
        f.write(key)


def load_master_key(path: str) -> bytes:
    with open(path, "rb") as f:
        data = f.read()
    if len(data) != 32:
        raise ValueError(f"master.key must be 32 bytes, got {len(data)}")
    return data


def save_rsa_private(private_key, path: str) -> None:
    pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    )
    with open(path, "wb") as f:
        f.write(pem)


def save_rsa_public(public_key, path: str) -> None:
    pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    with open(path, "wb") as f:
        f.write(pem)


def load_rsa_private(path: str):
    with open(path, "rb") as f:
        return load_pem_private_key(f.read(), password=None, backend=default_backend())


def load_rsa_public(path: str):
    with open(path, "rb") as f:
        return load_pem_public_key(f.read(), backend=default_backend())


# ─────────────────────────────────────────────────────────────────────────────
#  HMAC PRF
# ─────────────────────────────────────────────────────────────────────────────

def prf(key: bytes, data: bytes | str) -> bytes:
    """
    HMAC-SHA256 pseudorandom function.
    Kw = prf(master_key, keyword_bytes)  →  32 bytes
    """
    if isinstance(data, str):
        data = data.encode("utf-8")
    return _hmac.new(key, data, hashlib.sha256).digest()


# ─────────────────────────────────────────────────────────────────────────────
#  RSA Trapdoor Chain
# ─────────────────────────────────────────────────────────────────────────────

def random_st(N: int) -> int:
    """
    Generate a random initial search token ST_0 ∈ Z_N*.
    ST_0 is a random element of the RSA group.
    """
    while True:
        candidate = int.from_bytes(os.urandom(ST_BYTE_LEN), "big") % N
        if candidate > 1:          # avoid degenerate elements 0 and 1
            return candidate


def apply_trapdoor(st: int, d: int, N: int) -> int:
    """
    Client-side update: ST_{i+1} = ST_i^d mod N  (private key, inverse permutation).
    Each new document upload for a keyword advances the chain by one step.
    """
    return pow(st, d, N)


def apply_public(st: int, e: int, N: int) -> int:
    """
    Server-side traversal: ST_{i-1} = ST_i^e mod N  (public key).
    Used by the server during Search to walk the chain backwards.
    Also used by the client to recompute intermediate ST values for decryption.
    """
    return pow(st, e, N)


def st_to_bytes(st: int) -> bytes:
    return st.to_bytes(ST_BYTE_LEN, "big")


def st_from_bytes(data: bytes) -> int:
    return int.from_bytes(data, "big")


# ─────────────────────────────────────────────────────────────────────────────
#  Update Token & Encrypted Doc ID
# ─────────────────────────────────────────────────────────────────────────────

def make_ut(kw_bytes: bytes, st: int) -> bytes:
    """
    UT = SHA256(Kw ‖ ST_bytes)  →  32 bytes
    This is the key stored in the server's encrypted index.
    """
    return hashlib.sha256(kw_bytes + st_to_bytes(st)).digest()


def _id_mask(kw_bytes: bytes, st: int, length: int) -> bytes:
    """Internal: derive a byte-mask for XOR-encrypting doc_id."""
    full = hashlib.sha256(kw_bytes + st_to_bytes(st) + b"id").digest()
    # Repeat/extend if somehow doc_id_len > 32 (shouldn't happen with 16-byte IDs)
    mask = b""
    i = 0
    while len(mask) < length:
        mask += hashlib.sha256(full + struct.pack(">I", i)).digest()
        i += 1
    return mask[:length]


def encrypt_doc_id(doc_id: bytes, kw_bytes: bytes, st: int) -> bytes:
    """enc_id = doc_id XOR mask(Kw, ST)  →  same length as doc_id (16 bytes)."""
    mask = _id_mask(kw_bytes, st, len(doc_id))
    return bytes(a ^ b for a, b in zip(doc_id, mask))


def decrypt_doc_id(enc_id: bytes, kw_bytes: bytes, st: int) -> bytes:
    """Inverse of encrypt_doc_id (XOR is self-inverse with same key)."""
    return encrypt_doc_id(enc_id, kw_bytes, st)  # XOR is symmetric


# ─────────────────────────────────────────────────────────────────────────────
#  AES-256-GCM Document Encryption
# ─────────────────────────────────────────────────────────────────────────────

def doc_key(master_key: bytes, doc_id: bytes) -> bytes:
    """
    Derive a per-document symmetric key.
    K_doc = SHA256(master_key ‖ b"doc" ‖ doc_id)  →  32 bytes
    """
    return hashlib.sha256(master_key + b"doc" + doc_id).digest()


def aes_gcm_encrypt(key: bytes, plaintext: bytes) -> tuple[bytes, bytes, bytes]:
    """
    AES-256-GCM encrypt.
    Returns (iv, ciphertext, tag)  —  iv is 12 bytes (96-bit nonce).
    The `cryptography` library returns ciphertext+tag concatenated; we split.
    """
    aesgcm = AESGCM(key)
    iv = os.urandom(12)
    ct_with_tag = aesgcm.encrypt(iv, plaintext, None)
    ciphertext = ct_with_tag[:-16]
    tag        = ct_with_tag[-16:]
    return iv, ciphertext, tag


def aes_gcm_decrypt(key: bytes, iv: bytes, ciphertext: bytes, tag: bytes) -> bytes:
    """
    AES-256-GCM decrypt.
    Raises cryptography.exceptions.InvalidTag on authentication failure.
    """
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(iv, ciphertext + tag, None)


# ─────────────────────────────────────────────────────────────────────────────
#  Document ID Generation
# ─────────────────────────────────────────────────────────────────────────────

def make_doc_id(filename: str) -> bytes:
    """
    doc_id = SHA256(filename_bytes ‖ 8-random-bytes)[:16]
    Unique 16-byte identifier for each uploaded file.
    """
    nonce = os.urandom(8)
    return hashlib.sha256(filename.encode("utf-8") + nonce).digest()[:DOC_ID_LEN]
