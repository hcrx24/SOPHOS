# Understanding Σoφoς (Sophos) Searchable Symmetric Encryption

> This tutorial explains Σoφoς from first principles with intuition, mathematics, communication flows, client/server state, and worked examples.

## 1. Big Picture

Σoφoς is **not** a document encryption scheme. It is an **encrypted search index**.

There are two independent parts:

1. **Document Encryption**
   - Encrypt each document using AES-GCM.
   - Upload encrypted document to the server.

2. **Encrypted Search Index (Σoφoς)**
   - Extract keywords.
   - Build `(keyword, documentID)` pairs.
   - Encrypt these mappings so the server can search without learning keywords.

---

## 2. Architecture

```text
               CLIENT                                SERVER

 Plain Documents                         Encrypted Documents
 Keyword Extraction                      Key-Value Index

 Master Key K                            UT -> Enc(DocID)
 RSA Private Key d
 W : keyword -> (Latest ST, Counter)
```

---

## 3. Keyword Extraction

Document:

```
OpenVPN uses Schnorr NIZKP authentication.
```

Extracted keywords:

```
openvpn
schnorr
nizkp
authentication
```

Each keyword forms one `(keyword, documentID)` pair.

---

## 4. Mathematical Building Blocks

### Keyword Key

For keyword `w`

```
Kw = PRF(K, w)
```

### Initial Search Token

First occurrence:

```
ST0 <- Random
```

(or deterministically from a PRF in the optimized construction).

### RSA Trapdoor Chain

Private update:

```
ST(i+1) = ST(i)^d mod N
```

Public traversal:

```
ST(i) = ST(i+1)^e mod N
```

### Update Token

```
UT = H(Kw || ST)
```

### Encrypted Document Identifier

```
Enc(DocID) = DocID XOR H2(Kw || ST)
```

---

# 5. Example

Documents:

| ID | Contents |
|----|----------|
|D1|OpenVPN Schnorr|
|D2|OpenVPN PQC|
|D3|RSA Authentication|
|D4|OpenVPN RSA|

Keywords:

```
openvpn
rsa
schnorr
authentication
pqc
```

## Upload D1

Keywords:

```
openvpn
schnorr
```

For openvpn

```
ST0=random

UT0=H(Kw,ST0)
```

Client W

|Keyword|Latest ST|Counter|
|---|---|---|
|openvpn|ST0|0|
|schnorr|ST0|0|

Server Index

|UT|Value|
|---|---|
|UT(openvpn,0)|Enc(D1)|
|UT(schnorr,0)|Enc(D1)|

Document Store

|DocID|Ciphertext|
|---|---|
|D1|AES(D1)|

---

## Upload D2

Keyword openvpn already exists.

```
ST1 = ST0^d mod N

UT1 = H(Kw,ST1)
```

Client replaces state.

|Keyword|Latest ST|Counter|
|---|---|---|
|openvpn|ST1|1|
|schnorr|ST0|0|
|pqc|ST0|0|

Server appends

|UT|Value|
|---|---|
|UT(openvpn,1)|Enc(D2)|
|UT(pqc,0)|Enc(D2)|

Document Store

D1,D2 encrypted.

---

## Upload D3

Keywords

```
rsa
authentication
```

Client

|Keyword|Latest ST|Counter|
|---|---|---|
|openvpn|ST1|1|
|schnorr|ST0|0|
|pqc|ST0|0|
|rsa|ST0|0|
|authentication|ST0|0|

Server appends

```
UT(rsa,0)->Enc(D3)

UT(auth,0)->Enc(D3)
```

---

## Upload D4

Keywords

```
openvpn
rsa
```

Update chains

```
openvpn

ST0 <- ST1 <- ST2

rsa

ST0 <- ST1
```

Client W

|Keyword|Latest ST|Counter|
|---|---|---|
|openvpn|ST2|2|
|rsa|ST1|1|
|schnorr|ST0|0|
|authentication|ST0|0|
|pqc|ST0|0|

Server appends

```
UT(openvpn,2)->Enc(D4)

UT(rsa,1)->Enc(D4)
```

---

# Upload D5

Suppose D5 contains

```
OpenVPN RSA Schnorr
```

Updates

```
openvpn: ST3

rsa: ST2

schnorr: ST1
```

Only **new rows** are appended.

Nothing is modified.

---

# Upload D6

Suppose D6 contains

```
OpenVPN Authentication
```

Updates

```
openvpn -> ST4

authentication -> ST1
```

Again only new UT rows are appended.

---

# Final Client State

|Keyword|Latest ST|Counter|
|---|---|---|
|openvpn|ST4|4|
|rsa|ST2|2|
|schnorr|ST1|1|
|authentication|ST1|1|
|pqc|ST0|0|

---

# Corrected Server Index (Conceptual)

The server **never stores** `(Kw, ST, n)`.

Those values exist only on the client during upload/search.

The server stores only:

```
UT = H(Kw || ST)
            ↓
      Enc(DocID)
```

Below is the evolution according to the upload sequence.

---

## Upload D1

Keywords:
- openvpn
- schnorr

Client computes

```
Kw_openvpn = PRF(K,"openvpn")
ST0(openvpn) = random
UT0(openvpn) = H(Kw_openvpn || ST0)

Kw_schnorr = PRF(K,"schnorr")
ST0(schnorr) = random
UT0(schnorr) = H(Kw_schnorr || ST0)
```

Server

| Key | Value |
|-----|-------|
|UT0(openvpn)|Enc(D1)|
|UT0(schnorr)|Enc(D1)|

---

## Upload D2

Keywords:
- openvpn
- pqc

Client

```
ST1(openvpn)=π⁻¹(ST0)

UT1(openvpn)=H(Kw_openvpn||ST1)

ST0(pqc)=random

UT0(pqc)=H(Kw_pqc||ST0)
```

Server

| Key | Value |
|-----|-------|
|UT0(openvpn)|Enc(D1)|
|UT1(openvpn)|Enc(D2)|
|UT0(schnorr)|Enc(D1)|
|UT0(pqc)|Enc(D2)|

---

## Upload D3

Keywords:
- rsa
- authentication

Server

| Key | Value |
|-----|-------|
|UT0(openvpn)|Enc(D1)|
|UT1(openvpn)|Enc(D2)|
|UT0(schnorr)|Enc(D1)|
|UT0(pqc)|Enc(D2)|
|UT0(rsa)|Enc(D3)|
|UT0(authentication)|Enc(D3)|

---

## Upload D4

Keywords:
- openvpn
- rsa

Client

```
ST2(openvpn)=π⁻¹(ST1)
UT2(openvpn)=H(Kw_openvpn||ST2)

ST1(rsa)=π⁻¹(ST0)
UT1(rsa)=H(Kw_rsa||ST1)
```

Server

| Key | Value |
|-----|-------|
|UT0(openvpn)|Enc(D1)|
|UT1(openvpn)|Enc(D2)|
|UT2(openvpn)|Enc(D4)|
|UT0(schnorr)|Enc(D1)|
|UT0(pqc)|Enc(D2)|
|UT0(rsa)|Enc(D3)|
|UT1(rsa)|Enc(D4)|
|UT0(authentication)|Enc(D3)|

---

## Upload D5

Keywords:
- openvpn
- rsa
- schnorr

Client

```
ST3(openvpn)
UT3(openvpn)

ST2(rsa)
UT2(rsa)

ST1(schnorr)
UT1(schnorr)
```

Server appends

| Key | Value |
|-----|-------|
|UT3(openvpn)|Enc(D5)|
|UT2(rsa)|Enc(D5)|
|UT1(schnorr)|Enc(D5)|

---

## Upload D6

Keywords:
- openvpn
- authentication

Client

```
ST4(openvpn)
UT4(openvpn)

ST1(authentication)
UT1(authentication)
```

Server appends

| Key | Value |
|-----|-------|
|UT4(openvpn)|Enc(D6)|
|UT1(authentication)|Enc(D6)|

---

## Final Server Index

| Key | Value |
|-----|-------|
|UT0(openvpn)|Enc(D1)|
|UT1(openvpn)|Enc(D2)|
|UT2(openvpn)|Enc(D4)|
|UT3(openvpn)|Enc(D5)|
|UT4(openvpn)|Enc(D6)|
|UT0(schnorr)|Enc(D1)|
|UT1(schnorr)|Enc(D5)|
|UT0(pqc)|Enc(D2)|
|UT0(rsa)|Enc(D3)|
|UT1(rsa)|Enc(D4)|
|UT2(rsa)|Enc(D5)|
|UT0(authentication)|Enc(D3)|
|UT1(authentication)|Enc(D6)|

---

### Important Note

The notation `(Kw, STn, n)` is **client-side state used for computation**.

The server **never stores**:

- Kw
- ST
- Counter n

The client sends `(Kw, ST_latest, counter)` **only during a search**. The server then regenerates

```
UT4(openvpn)
↓
UT3(openvpn)
↓
UT2(openvpn)
↓
UT1(openvpn)
↓
UT0(openvpn)
```

by traversing the RSA chain using the public exponent.


# Search Workflow

User searches

```
openvpn
```

Client computes

```
Kw=PRF(K,"openvpn")
```

Looks into W

```
ST4
counter=4
```

Sends

```
(Kw,ST4,4)
```

Server performs

```
UT4

↓

Enc(D6)

ST3=e(ST4)

↓

UT3

↓

Enc(D5)

ST2=e(ST3)

↓

Enc(D4)

ST1=e(ST2)

↓

Enc(D2)

ST0=e(ST1)

↓

Enc(D1)
```

Returns encrypted IDs.

Client computes

```
DocID = Enc(DocID) XOR H2(Kw,ST)
```

Recovered

```
D1
D2
D4
D5
D6
```

Client requests encrypted documents

```
AES(D1)

AES(D2)

...
```

Decrypts locally.

---

# Why Enc(DocID)?

If server stored plaintext DocIDs:

```
UT1 -> D1
UT9 -> D1
```

Server learns both entries point to the same document.

Instead

```
UT1 -> RandomBits

UT9 -> DifferentRandomBits
```

The relationship is hidden.

---

# Why Forward Privacy?

Every update generates

```
Fresh ST

↓

Fresh UT
```

Server only sees insertion of a new random key.

It cannot know which previous keyword chain it belongs to until a search occurs.

---

# Practical Storage

Client:

```
Master Key

RSA private key

W table
```

Server:

```
Encrypted document store

Encrypted index
```

No plaintext keyword is ever stored on the server.
