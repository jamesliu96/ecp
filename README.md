# E2EE Clipboard Protocol (ECP)

A serverless, pure-frontend web implementation of the End-to-End Encrypted Clipboard Protocol (ECP). ECP enables secure, peer-to-peer encrypted messaging and rich media sharing across untrusted out-of-band transport channels (such as instant messengers, email, social media, or physical clipboards) without requiring a backend server or central authority.

## Core Architecture & Layering

ECP strictly decouples its **Cryptographic Engine** from the **Transport Channel**:

- **Cryptographic Engine (Application Layer):** Handles post-quantum hybrid key exchange, double-ratchet state progression, payload framing, and zero-trust local persistence strictly inside client-side `IndexedDB`.
- **Transport Channel (Out-of-Band Layer):** ECP treats external communication channels as completely untrusted, opaque byte carriers. Sealed ASCII-safe envelopes (`e2e1:<Base64URL>`) can be copied to the OS clipboard and pasted into any existing messaging application, email, shared document, or QR code.
- **Zero-Backend & Offline First:** Operates 100% on the client side without relying on API gateways, WebSocket servers, or signaling coordinators.
- **Post-Quantum Cryptography (PQC):** Combines classical primitives with NIST Level 5 PQC standards via `@noble` libraries (`@noble/ciphers`, `@noble/curves`, `@noble/hashes`, `@noble/post-quantum`).

## Threat Model & Security Boundaries

### In-Scope Security Guarantees

- **Transport Confidentiality & Integrity:** All wire ciphertexts remain secure even when transmitted over unencrypted, monitored, or compromised third-party channels.
- **Post-Quantum Forward Secrecy & Break-In Recovery:** Every Double Ratchet turn continuously encapsulates a fresh **ML-KEM-1024** shared secret alongside classical **X25519** ECDH. Future quantum adversaries capturing transport payloads cannot decrypt historical or future sessions even if ephemeral ECDH keys are compromised.
- **Authenticity & Non-Repudiation:** Initial handshake signatures using composite **Ed25519 + ML-DSA-87** prevent active person-in-the-middle (PITM) identity spoofing.

### Out-of-Scope Risks

- **Host Environment Integrity:** Malware, malicious browser extensions, or OS-level keyloggers/clipboard monitors running on the user's host machine.
- **Side-Channel Probing:** Execution timing or memory access side-channels native to the JavaScript engine runtime environment.

## Usage Lifecycle

1. **Identity Generation:** Automatically generates a persistent cryptographic identity upon initial application boot.
2. **Peer Registration:** Users exchange out-of-band public identity bundles to add contacts.
3. **Session Initialization:** The initiator generates an `INIT` payload packet and transmits it across any external channel to establish a Hybrid Double Ratchet session.
4. **Encrypted Exchange:** Payload strings are generated, pasted into third-party communication apps, and parsed by the recipient's local instance to decrypt.

## Development & Build Pipeline

The application is written in standard TypeScript and styled with Tailwind CSS v4. To maintain verifiable build outputs, the project intentionally omits complex bundlers in favor of explicit CLI toolchains (`tsc`, Tailwind CLI, and static serving).

### Commands

- **Installation:** Clone the repository and install locked dependencies:

```sh
npm install
```

- **Local Development:** Start the file watcher and static development server:

```sh
npm run dev
```

- **Production Build:** Compile static JavaScript assets directly to root distribution files:

```sh
npm run build
```

## ECP Protocol Specification (v1)

### Cryptographic Primitive Stack

| Role                         | Primitive     | Specification / Key Length        | Implementation Library                 |
| ---------------------------- | ------------- | --------------------------------- | -------------------------------------- |
| **Hybrid Key Exchange**      | ECDH + ML-KEM | X25519 + FIPS 203 ML-KEM-1024     | `@noble/curves`, `@noble/post-quantum` |
| **Composite Signature**      | Signature     | Ed25519 + FIPS 204 ML-DSA-87      | `@noble/curves`, `@noble/post-quantum` |
| **Symmetric Encryption**     | AES-256-GCM   | 256-bit Key, 96-bit Nonce         | `@noble/ciphers`                       |
| **Key Derivation & Hashing** | HKDF / HMAC   | HMAC-SHA256 / HKDF-SHA256         | `@noble/hashes`                        |
| **Wire Encoding & Envelope** | Base64URL     | Prefixed ASCII Envelope (`e2e1:`) | Native TS / Web APIs                   |

### Framing & Wire Envelope Architecture

All serialized wire payloads are converted to raw binary arrays, encoded as unpadded Base64URL strings, and prefixed with the ASCII literal string `e2e1:` (e.g., `e2e1:<Base64URL>`).

#### Binary Header Layout (12 Bytes Total)

Every binary packet begins with a mandatory 12-byte header.

| Offset (Bytes) | Field Name     | Type       | Value / Range | Description                                         |
| -------------- | -------------- | ---------- | ------------- | --------------------------------------------------- |
| `0` – `3`      | Magic Bytes    | `Bytes[4]` | `E2E1`        | ASCII `E2E1` (`0x45`, `0x32`, `0x45`, `0x31`)       |
| `4`            | Version        | `UInt8`    | `0x01`        | Wire Protocol Version                               |
| `5`            | Packet Type    | `UInt8`    | `0x01`–`0x03` | `0x01`: INIT, `0x02`: RESP, `0x03`: MSG             |
| `6` – `7`      | Reserved       | `Bytes[2]` | `0x0000`      | Zero-padded byte alignment                          |
| `8` – `11`     | Payload Length | `UInt32BE` | Integer       | Big-Endian size of subsequent payload body in bytes |

### Identity Bundle Layout (4,225 Bytes Total)

An Identity Bundle encapsulates a peer's public keys for identity verification and hybrid key agreement.

| Field Name                 | Offset (Bytes)  | Size (Bytes) | Primitive   | Description                                  |
| -------------------------- | --------------- | ------------ | ----------- | -------------------------------------------- |
| **Bundle Version**         | `0`             | 1            | `UInt8`     | Format identifier (`0x01`)                   |
| **Ed25519 Public Key**     | `1` – `32`      | 32           | Ed25519     | Classical signature verification key         |
| **ML-DSA-87 Public Key**   | `33` – `2624`   | 2,592        | ML-DSA-87   | Post-quantum signature verification key      |
| **X25519 Public Key**      | `2625` – `2656` | 32           | X25519      | Static ECDH key agreement target             |
| **ML-KEM-1024 Public Key** | `2657` – `4224` | 1,568        | ML-KEM-1024 | Static post-quantum key encapsulation target |

### Packet Types & Serialization Specs

#### 1. INIT Packet Layout (`0x01`)

Used by the initiator to initiate a session, perform initial hybrid key agreement, and transmit the first encrypted message.

| Relative Offset   | Field Name                                  | Type / Size   | Description                                                    |
| ----------------- | ------------------------------------------- | ------------- | -------------------------------------------------------------- |
| `0` – `11`        | **Binary Header**                           | `Bytes[12]`   | Standard 12-byte header (`Type = 0x01`)                        |
| `12` – `4236`     | **Sender Identity Bundle**                  | `Bytes[4225]` | Initiator's public Identity Bundle                             |
| `4237` – `8461`   | **Receiver Identity Bundle**                | `Bytes[4225]` | Target recipient's public Identity Bundle                      |
| `8462` – `8493`   | **Ephemeral X25519 PK ($EK\_{\text{pk}}$)** | `Bytes[32]`   | Ephemeral X25519 Public Key generated by initiator             |
| `8494` – `10061`  | **ML-KEM Ciphertext ($KEM\_{\text{ct}}$)**  | `Bytes[1568]` | Encapsulated shared secret against receiver's static ML-KEM PK |
| `10062` – `14752` | **Composite Signature ($Sig$)**             | `Bytes[4691]` | Ed25519 Sig (64B) + ML-DSA-87 Sig (4627B) over setup data      |
| `14753`+          | **Payload Ciphertext**                      | Variable      | AES-256-GCM ciphertext of initial message string + 16B Tag     |

#### 2. RESP Packet Layout (`0x02`)

Sent by the responder to complete initial key setup and establish receiving/sending ratchet chains.

| Relative Offset | Field Name            | Type / Size   | Description                                         |
| --------------- | --------------------- | ------------- | --------------------------------------------------- |
| `0` – `11`      | **Binary Header**     | `Bytes[12]`   | Standard 12-byte header (`Type = 0x02`)             |
| `12` – `3179`   | **Encrypted Payload** | `Bytes[3168]` | AES-256-GCM encrypted parameters (derived via $SK$) |
| `3180` – `3195` | **AES-256-GCM Tag**   | `Bytes[16]`   | AEAD authentication tag                             |

##### RESP Plaintext Decrypted Payload (3,168 Bytes Total)

| Decrypted Offset | Field Name                        | Type / Size   | Description                                                              |
| ---------------- | --------------------------------- | ------------- | ------------------------------------------------------------------------ |
| `0` – `31`       | **Responder Ephemeral DH PK**     | `Bytes[32]`   | Responder's ephemeral X25519 Public Key ($DH_{s,\text{pk}}$)             |
| `32` – `1599`    | **ML-KEM Encapsulation CT**       | `Bytes[1568]` | Encapsulated secret ($KEM_{\text{ct2}}$) to initiator's static ML-KEM PK |
| `1600` – `3167`  | **Responder Ephemeral ML-KEM PK** | `Bytes[1568]` | Fresh ML-KEM Public Key ($KEM_{s,\text{pk}}$) for next ratchet step      |

#### 3. MSG Packet Layout (`0x03`)

Carries active Hybrid Double Ratchet session messages.

| Relative Offset | Field Name                                     | Type / Size   | Description                                                      |
| --------------- | ---------------------------------------------- | ------------- | ---------------------------------------------------------------- |
| `0` – `11`      | **Binary Header**                              | `Bytes[12]`   | Standard 12-byte header (`Type = 0x03`)                          |
| `12` – `27`     | **Conversation ID**                            | `Bytes[16]`   | First 16 bytes of SHA-256 hash over initial handshake parameters |
| `28` – `59`     | **Ephemeral DH Key ($DH\_{s,\text{pk}}$)**     | `Bytes[32]`   | Current ratchet step X25519 Public Key                           |
| `60` – `1627`   | **ML-KEM Ciphertext ($KEM\_{\text{ct}}$)**     | `Bytes[1568]` | Encapsulated secret for current ratchet turn                     |
| `1628` – `3195` | **Ephemeral ML-KEM PK ($KEM\_{s,\text{pk}}$)** | `Bytes[1568]` | Fresh ML-KEM Public Key for peer's subsequent ratchet turn       |
| `3196` – `3199` | **Previous Chain Length ($PN$)**               | `UInt32BE`    | Number of messages sent in previous sending chain                |
| `3200` – `3203` | **Message Sequence ($N_s$)**                   | `UInt32BE`    | Zero-indexed message counter in current sending chain            |
| `3204`+         | **Payload Ciphertext**                         | Variable      | AES-256-GCM ciphertext of UTF-8 message body + 16B Tag           |

### Authenticated Additional Data (AAD) Construction

To bind ciphertexts to wire headers and identity structures, AEAD operations require exact AAD byte concatenations:

- **INIT Packet (`0x01`):**

$$\text{AAD}_{\text{INIT}} = \text{Header}_{12\text{B}} \parallel \text{SenderBundle}_{4225\text{B}} \parallel \text{ReceiverBundle}_{4225\text{B}} \parallel EK_{\text{pk}, 32\text{B}} \parallel KEM_{\text{ct}, 1568\text{B}} \parallel Sig_{4691\text{B}}$$

- **RESP Packet (`0x02`):**

$$\text{AAD}_{\text{RESP}} = \text{Header}_{12\text{B}}$$

- **MSG Packet (`0x03`):**

$$\text{AAD}_{\text{MSG}} = \mathtt{"ECP-MSG-v1"} \parallel \text{ConvID}_{16\text{B}} \parallel \text{SenderIdentity}_{4225\text{B}} \parallel \text{ReceiverIdentity}_{4225\text{B}} \parallel \text{msgHdr}_{3192\text{B}}$$

(Note: $\text{msgHdr}$ is the unencrypted 3,192-byte header payload spanning offsets `12` through `3203` of the MSG packet).

### Cryptographic Derivations & Key Schedules

#### Auxiliary Symmetric Derivation Helper $f_{\text{sym}}$

Symmetric encryption keys and nonces are derived from a master key ($MK$) using:

$$
\begin{aligned}
f_{\text{sym}}(MK, \text{keyLabel}, \text{nonceLabel}) = \big( & \text{key} = \text{HKDF-SHA256}(MK, \text{0x00}^{32}, \text{UTF8}(\text{keyLabel}), 32), \\
& \text{nonce} = \text{HMAC-SHA256}(MK, \text{UTF8}(\text{nonceLabel}))[0 \dots 11] \big)
\end{aligned}
$$

#### 1. INIT Handshake Key Schedule

1. **Shared Key ($SK$):** Initiator computes ECDH shared secret $dh_1 = \text{X25519}(EK_{\text{sk}}, PeerID_{\text{dhPk}})$ and decapsulates/encapsulates $KEM_{\text{SS}}$.

$$SK = \text{HKDF-SHA256}\left(\mathtt{"ECP-INIT-v1"} \parallel dh_1 \parallel KEM_{\text{SS}}, \text{salt}=\text{0x00}^{32}, \text{info}=\mathtt{""}, 32\right)$$

2. **INIT Payload Encryption Keys:**

$$MK_{\text{init}} = \text{HKDF-SHA256}(SK, \text{0x00}^{32}, \mathtt{"ECP-INIT-MESSAGE-v1"}, 32)$$

$$\text{Keys}_{\text{init}} = f_{\text{sym}}(MK_{\text{init}}, \mathtt{"ECP-AES256GCM-v1"}, \mathtt{"ECP-INIT-NONCE"})$$

3. **Composite Signature Generation:** Initiator signs the setup vector:

$$Sig = \text{Sign}_{\text{Composite}}\left(\mathtt{"ECP-INIT-v1"} \parallel SenderID \parallel ReceiverID \parallel EK_{\text{pk}} \parallel KEM_{\text{ct}}\right)$$

(Constructed by concatenating Ed25519 signature [64 bytes] and ML-DSA-87 signature [4,627 bytes]).

4. **Conversation Identifier ($\text{ConvID}$):**

$$\text{ConvID} = \text{SHA256}\left(\mathtt{"ECP-CONVERSATION-v1"} \parallel EK_{\text{pk}} \parallel KEM_{\text{ct}}\right)[0 \dots 15]$$

5. **Initial Root Key ($RK_0$):**

$$RK_0 = \text{HKDF-SHA256}(SK, \text{0x00}^{32}, \mathtt{"ECP-DR-ROOT-v1"}, 32)$$

#### 2. RESP Handshake Key Schedule

1. **RESP Payload Encryption Keys:** Derived directly from $SK$:

$$\text{Keys}_{\text{resp}} = f_{\text{sym}}(SK, \mathtt{"ECP-RESP-v1"}, \mathtt{"ECP-RESP-NONCE-v1"})$$

2. **First Ratchet Step Derivation:** Responder generates $DH_s$ and $KEM_{\text{Res2}}$, computing $dh_2 = \text{X25519}(DH_{s,\text{sk}}, EK_{\text{pk}})$.

$$RK_1 \parallel CK_s = \text{HKDF-SHA256}\left(dh_2 \parallel KEM_{\text{Res2SS}}, \text{salt}=RK_0, \text{info}=\mathtt{"ECP-DR-RK-v1"}, 64\right)$$

#### 3. Double Ratchet Step & Chain Progression

1. **DH / KEM Ratchet Step ($kdfRoot$):** Executed whenever a message is sent/received with a new ratchet key:

$$RK_{i+1} \parallel CK_{\text{new}} = \text{HKDF-SHA256}\left(dh_{\text{shared}} \parallel KEM_{\text{SS}}, \text{salt}=RK_i, \text{info}=\mathtt{"ECP-DR-RK-v1"}, 64\right)$$

2. **Symmetric Chain Key Progression:** Advance chain key $CK$ to produce message key $MK$:

$$
\begin{aligned}
MK &= \text{HMAC-SHA256}(CK, \text{0x01}) \\
CK_{\text{next}} &= \text{HMAC-SHA256}(CK, \text{0x02})
\end{aligned}
$$

3. **Per-Message Symmetric Key & Nonce Derivation:**

$$\text{Keys}_{\text{msg}} = f_{\text{sym}}(MK, \mathtt{"ECP-AES256GCM-v1"}, \mathtt{"ECP-NONCE-v1"})$$

### Session State Machine & Replay Protection

- **Replay Protection via Handshake Signature Tracking (`usedInitEks`):** Receivers store the SHA-256 hash of processed INIT packet signatures (`sigHash = Base64URL(SHA256(Sig))`). Re-sent or duplicated INIT packets matching any stored signature hash in `usedInitEks` (retaining up to 100 historical entries) are immediately discarded with `"INIT packet replay detected"`.
- **Out-of-Order Message Handling & Skipped Key Cache (`skippedKeys`):** If a message arrives with sequence index $N > N_r$, intermediate message keys are derived via symmetric chain steps and stored in `skippedKeys` using the lookup key `${encodeBase64URL(DH_r.pk)}_${seq}`. The skipped key cache retains a maximum of 100 keys; older keys are pruned.
- **Frame Validation Limits:**
  - **Sequence Progression:** Received index $N < N_r$ throws `"Message frame out of order or replayed"`.
  - **Maximum Gap Bound:** If $N - N_r > 2000$, decryption aborts with `"Excessive message gap"`.
  - **Destination Verification:** Receivers execute constant-time memory comparisons on identity bundles (`constantTimeCompare(rIdBytes, localPubBytes)`). Misrouted packets raise `"INIT packet destination misrouted"`.
