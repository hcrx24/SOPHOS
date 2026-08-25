"""
sophos_client/core/keywords.py
Keyword extraction for SOPHOS SSE document indexing.

Pipeline:
  raw text
    → nltk.word_tokenize()
    → nltk.pos_tag()          (POS tags improve lemmatization accuracy)
    → WordNetLemmatizer()     (e.g. "encrypting" → "encrypt")
    → NLTK English stopwords  (remove: the, is, at, ...)
    → CRYPTO_WHITELIST        (always preserve: rsa, aes, vpn, tls, ...)
    → length filter (≥ 3 chars)
    → lowercase set of tokens

Why NOT an ML model:
  SOPHOS is a keyword-matching scheme. The client must produce the EXACT same
  string token during search as during upload. Neural embeddings produce float
  vectors — incompatible with the XOR-based encrypted-ID construction.
  Deterministic rule-based lemmatization is the correct and sufficient approach.
"""

from __future__ import annotations

import re
import string
import logging

logger = logging.getLogger("sophos.keywords")

# ─────────────────────────────────────────────────────────────────────────────
#  NLTK lazy initialization (downloads corpora on first use)
# ─────────────────────────────────────────────────────────────────────────────

def _ensure_nltk_data() -> None:
    """Download required NLTK corpora if not already present. Silent if already cached."""
    import nltk
    resources = [
        ("tokenizers/punkt",                    "punkt"),
        ("tokenizers/punkt_tab",                "punkt_tab"),
        ("taggers/averaged_perceptron_tagger",  "averaged_perceptron_tagger"),
        ("taggers/averaged_perceptron_tagger_eng", "averaged_perceptron_tagger_eng"),
        ("corpora/wordnet",                     "wordnet"),
        ("corpora/stopwords",                   "stopwords"),
        ("corpora/omw-1.4",                     "omw-1.4"),
    ]
    for path, pkg in resources:
        try:
            nltk.data.find(path)
        except LookupError:
            logger.info("Downloading NLTK resource: %s", pkg)
            nltk.download(pkg, quiet=True)


# ─────────────────────────────────────────────────────────────────────────────
#  Cryptographic / Security Technical Whitelist
#  These tokens are NEVER filtered regardless of length or stopword status.
# ─────────────────────────────────────────────────────────────────────────────

CRYPTO_WHITELIST: frozenset[str] = frozenset({
    # Ciphers & modes
    "aes", "des", "rsa", "ecc", "dsa", "dh", "ecdh", "ecdsa",
    "gcm", "cbc", "ecb", "ctr", "ofb", "cfb", "ccm", "ocb",
    # Hashes
    "sha", "sha1", "sha2", "sha3", "sha256", "sha512", "md5",
    "hmac", "blake", "blake2", "pbkdf", "pbkdf2", "bcrypt", "argon",
    # Protocols & standards
    "tls", "ssl", "ssh", "vpn", "pki", "pqc", "mtls", "sse", "fhe",
    "mpc", "zkp", "zk",  "kem", "kdf", "prng", "prf", "prp",
    "oram", "abe", "ibe", "ore", "ope", "phe", "she",
    # Misc crypto terms
    "xor", "otp", "mac", "tag", "nonce", "iv", "ciphertext",
    "plaintext", "trapdoor", "permutation", "lattice", "kyber",
    "dilithium", "falcon", "ntru", "sphincs", "mlkem", "mldsa",
    # Common abbreviations that may be filtered as too short
    "key", "kdf", "pem", "der", "asn",
})

MIN_TOKEN_LEN = 3   # tokens shorter than this are dropped (unless whitelisted)


# ─────────────────────────────────────────────────────────────────────────────
#  POS tag → WordNet POS mapping
# ─────────────────────────────────────────────────────────────────────────────

def _wordnet_pos(treebank_tag: str) -> str | None:
    """Map Penn Treebank POS tag to WordNet POS constant."""
    from nltk.corpus import wordnet
    if treebank_tag.startswith("J"):
        return wordnet.ADJ
    if treebank_tag.startswith("V"):
        return wordnet.VERB
    if treebank_tag.startswith("N"):
        return wordnet.NOUN
    if treebank_tag.startswith("R"):
        return wordnet.ADV
    return None  # default to NOUN in lemmatizer call


# ─────────────────────────────────────────────────────────────────────────────
#  Main Extractor
# ─────────────────────────────────────────────────────────────────────────────

class KeywordExtractor:
    """
    Stateless keyword extractor.  Call extract(text) → frozenset[str].
    Thread-safe after construction.
    """

    def __init__(self) -> None:
        _ensure_nltk_data()
        import nltk
        from nltk.stem import WordNetLemmatizer
        from nltk.corpus import stopwords as _sw
        self._lemmatizer = WordNetLemmatizer()
        self._stopwords  = frozenset(_sw.words("english"))
        self._nltk       = nltk

    def extract(self, text: str) -> frozenset[str]:
        """
        Extract a canonical set of lowercase keywords from raw text.

        Returns frozenset[str] — every token is the result that a future
        search query will produce after running through the same pipeline.
        """
        # 1. Tokenize
        tokens = self._nltk.word_tokenize(text)

        # 2. Lowercase, strip punctuation-only tokens
        tokens = [t.lower() for t in tokens if not all(c in string.punctuation for c in t)]

        # 3. Remove numeric-only tokens
        tokens = [t for t in tokens if not t.isdigit()]

        # 4. POS-tag for accurate lemmatization
        tagged = self._nltk.pos_tag(tokens)

        result: set[str] = set()
        for token, pos_tag in tagged:
            # Always preserve whitelisted crypto terms as-is
            if token in CRYPTO_WHITELIST:
                result.add(token)
                continue

            # Filter stopwords
            if token in self._stopwords:
                continue

            # Filter short tokens (after stopword check to keep e.g. "key")
            if len(token) < MIN_TOKEN_LEN:
                continue

            # Lemmatize with correct POS
            wn_pos = _wordnet_pos(pos_tag)
            if wn_pos:
                lemma = self._lemmatizer.lemmatize(token, pos=wn_pos)
            else:
                lemma = self._lemmatizer.lemmatize(token)   # default: noun

            if len(lemma) >= MIN_TOKEN_LEN:
                result.add(lemma)

        return frozenset(result)


# ─────────────────────────────────────────────────────────────────────────────
#  Module-level singleton convenience function
# ─────────────────────────────────────────────────────────────────────────────

_extractor: KeywordExtractor | None = None

def extract_keywords(text: str) -> frozenset[str]:
    """
    Module-level convenience wrapper.
    Lazily initializes the singleton KeywordExtractor.
    """
    global _extractor
    if _extractor is None:
        _extractor = KeywordExtractor()
    return _extractor.extract(text)
