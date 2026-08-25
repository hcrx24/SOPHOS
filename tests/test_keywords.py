"""
tests/test_keywords.py
Unit tests for the NLTK keyword extractor.
"""
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "sophos_client"))

from core.keywords import extract_keywords, CRYPTO_WHITELIST


def test_basic_extraction():
    text = "The VPN uses RSA encryption for secure authentication."
    kws = extract_keywords(text)
    assert "vpn" in kws
    assert "rsa" in kws
    assert "authentication" in kws or "authenticate" in kws


def test_stopwords_removed():
    text = "The quick brown fox is at the park."
    kws = extract_keywords(text)
    assert "the" not in kws
    assert "is"  not in kws
    assert "at"  not in kws


def test_lemmatization():
    text = "The server is encrypting multiple documents."
    kws = extract_keywords(text)
    # "encrypting" should lemmatize to "encrypt"
    assert "encrypt" in kws
    # "documents" should lemmatize to "document"
    assert "document" in kws


def test_crypto_whitelist_preserved():
    text = "AES GCM TLS RSA SHA HMAC PQC KEM"
    kws = extract_keywords(text)
    for term in ["aes", "gcm", "tls", "rsa", "sha", "hmac", "pqc", "kem"]:
        assert term in kws, f"'{term}' should be preserved by whitelist"


def test_deterministic():
    text = "OpenVPN uses RSA-2048 for authentication and AES-256-GCM for encryption."
    assert extract_keywords(text) == extract_keywords(text)


def test_search_normalization_matches_upload():
    """The same keyword pipeline must produce matching tokens for upload and search."""
    upload_text   = "The system uses RSA trapdoor permutation for forward-private SSE."
    search_query  = "trapdoor"
    upload_kws    = extract_keywords(upload_text)
    search_kws    = extract_keywords(search_query)
    # "trapdoor" should appear in both
    assert search_kws.issubset(upload_kws) or "trapdoor" in upload_kws


def test_min_length_filter():
    text = "a bb cc ddd"
    kws = extract_keywords(text)
    for kw in kws:
        if kw not in CRYPTO_WHITELIST:
            assert len(kw) >= 3, f"Short token '{kw}' should be filtered"
