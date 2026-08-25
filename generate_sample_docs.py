import os

sample_dir = "/home/sohan/Documents/SOHAN/Reading_Materials/Searchable_Encryption/SOPHOS/sample_docs"
os.makedirs(sample_dir, exist_ok=True)

# 1. Small file (~1.2 KB)
small = """===================================================================
SOPHOS SSE - Small Network Security Note
===================================================================
Date: 2026-07-21
Category: Network Security & Encryption

Abstract:
This document summarizes core principles of Symmetric Searchable Encryption (SSE)
and mutual TLS (mTLS) applied to client-server network architectures.

Key Cryptographic Concepts:
- Forward Privacy: The server cannot link search tokens to previous search queries.
- RSA-2048 Trapdoor: Used in Sophos to generate deterministic update tokens.
- HMAC-SHA256: Derives pseudo-random keyword keys (Kw) from master secret key K.
- AES-256-GCM: Authenticated encryption algorithm used for document storage.
- gRPC & mTLS: Cross-machine encrypted channel using self-signed CA certificates.

Keywords: network, vpn, rsa, encryption, security, sophos, mtls, grpc, privacy, HMAC, AES

System Architecture Summary:
Client holds master key K and SQLite database tracking keyword counters (ST).
Server runs gRPC servicer backed by LMDB key-value store holding encrypted index UT -> EncID.
"""
with open(os.path.join(sample_dir, "small_network_security.txt"), "w", encoding="utf-8") as f:
    f.write(small)

# 2. Medium file (~6 KB)
medium_text = """===================================================================
SOPHOS SSE - Technical Specification & VPN Architecture
===================================================================
System Overview:
Virtual Private Networks (VPN) and Secure Searchable Encryption (SSE)
provide end-to-end data confidentiality for high-security enterprise environments.

1. Protocol Description
The Sophos SSE scheme (Bost CCS 2016) achieves forward privacy by constructing an
inverted index using RSA trapdoor permutations. When a client adds a new document containing
keywords w_1, w_2, ..., w_n, it updates its local state database ST[w] and computes a
fresh update token UT = SHA256(Kw || ST) and encrypted document pointer enc_id.

2. Transport Security (mTLS + gRPC)
All client-server communications operate over gRPC using mutual Transport Layer Security (mTLS).
- Server authenticates using server.crt / server.key.
- Client authenticates using client.crt / client.key.
- Root Certificate Authority (ca.crt) validates both endpoints.
- Subject Alternative Names (SAN) ensure hostname verification for cross-machine deployment.

3. Keyword Processing & Lemmatization Pipeline
To prevent exact-match retrieval limitations, the client tokenization module processes text using:
- NLTK WordNetLemmatizer with POS tagging.
- Automated stopword removal (filtering common English terms like the, and, is).
- Cryptographic Whitelist preservation (ensuring terms like AES256, RSA2048, SHA256 are indexed).

4. Database Layout
- Client-side: SQLite database storing ST counter state per keyword (ST_w, counter_w).
- Server-side: High-performance LMDB key-value database with dual column families:
    a) encrypted_index: UT -> enc_id
    b) doc_store: doc_id -> (iv || tag || ciphertext)

""" + ("Security Notes on Forward Privacy:\nForward privacy guarantees that when a client uploads a document containing keyword w, the server cannot learn if w was previously searched. In Sophos, this is achieved because update tokens ST_i are evolved using the RSA private key d (ST_i = ST_{i-1}^d mod N), while search trapdoors allow the server to step backward using the public exponent e (ST_{i-1} = ST_i^e mod N).\n\n" * 12)

with open(os.path.join(sample_dir, "medium_vpn_architecture.txt"), "w", encoding="utf-8") as f:
    f.write(medium_text)

# 3. Large file (~30 KB)
large_intro = """===================================================================
Comprehensive Survey on Searchable Encryption and Trapdoor Chains
===================================================================
Author: Cryptography Research Group
Topic: Symmetric Searchable Encryption (SSE), RSA Trapdoors, and Forward Privacy

1. Introduction to Symmetric Searchable Encryption
Searchable Symmetric Encryption (SSE) enables a client to outsource encrypted data to an untrusted
cloud server while retaining the capability to search over the encrypted files without decrypting them.

2. Threat Model & Security Definitions
We consider an honest-but-curious server that correctly executes protocol operations but attempts to
deduce information about underlying documents and keywords from search and access patterns.
- Search Pattern: Determines whether two search queries correspond to the same keyword.
- Access Pattern: Reveals which encrypted documents match a given search query.
- Forward Privacy: Ensures that newly added documents cannot be linked to past search queries.
- Backward Privacy: Ensures that deleted documents are no longer accessible to future queries.

3. Detailed Analysis of the Sophos Construction
The Sophos protocol by Raphael Bost (CCS 2016) introduced an efficient forward-private SSE scheme based
on trapdoor permutations, specifically utilizing RSA groups Z_N*.

"""
large_body = ("Section 4. Performance Evaluation and Benchmarks\n" + "-"*60 + "\n" +
"We evaluated the throughput and latency of RSA-2048 trapdoor evaluation versus symmetric PRF constructions.\n" +
"In Sophos, client upload cost requires one RSA exponentiation per keyword-document pair:\n" +
"    ST_{w, i} = (ST_{w, i-1})^d  mod N\n" +
"Server search cost requires i RSA public exponentiations:\n" +
"    ST_{w, j-1} = (ST_{w, j})^e  mod N\n" +
"Since e is small (typically e = 65537), server search is extremely fast, requiring only 17 modular multiplications per token traversal.\n\n" +
"Key findings from our experimental evaluation:\n" +
"1. Index insertion throughput: ~2,500 keyword-document pairs per second on standard hardware.\n" +
"2. Server search latency: < 0.5 ms per matching document for token chain length up to 10,000.\n" +
"3. Memory footprint: LMDB key-value store overhead is < 15% above raw ciphertext storage.\n\n" * 25)

with open(os.path.join(sample_dir, "large_crypto_survey.txt"), "w", encoding="utf-8") as f:
    f.write(large_intro + large_body)

# 4. Extra Large file (~120 KB)
xlarge_intro = """===================================================================
Enterprise Security Audit and Automated Threat Mitigation Log
===================================================================
System ID: SOPHOS-GW-01
Environment: Distributed Production Cluster
Security Domain: Post-Quantum Cryptography & Searchable Encryption

"""
xlarge_entry = """[AUDIT LOG ENTRY #{id:04d}] Timestamp: 2026-07-21T12:{minute:02d}:00Z
Target Component: Sophos gRPC Server / Servicer Module
Event Type: Cryptographic Verification & Audit Checkpoint
Details: Verified RSA-2048 trapdoor permutation integrity. State counter = {id}.
Security Check: mTLS handshake validated with client certificate SAN=sophosclient.
Storage Check: LMDB database transaction committed successfully to column family encrypted_index.
Keyword Tokens Extracted: [vpn, rsa, encryption, security, network, audit, sophos, mtls, grpc]
Status: PASS (Zero anomalies detected during verification scan)
-------------------------------------------------------------------
"""
xlarge_content = xlarge_intro + "".join(xlarge_entry.format(id=i, minute=i%60) for i in range(1, 400))

with open(os.path.join(sample_dir, "xlarge_security_audit_log.txt"), "w", encoding="utf-8") as f:
    f.write(xlarge_content)

print("Sample files created successfully:")
for fname in sorted(os.listdir(sample_dir)):
    fpath = os.path.join(sample_dir, fname)
    size_kb = os.path.getsize(fpath) / 1024
    print(f"  - {fname}: {size_kb:.2f} KB")
