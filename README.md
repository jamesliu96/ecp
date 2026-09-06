# E2EE Clipboard Protocol (ECP)

A serverless, pure-frontend web implementation of the End-to-End Encrypted Clipboard Protocol (ECP). ECP enables secure, peer-to-peer encrypted messaging and clipboard content sharing across untrusted transport channels without requiring a backend server or central authority.

## Core Architecture

- **Zero-Backend Processing:** Operates strictly on the client side. Messages are exchanged out-of-band via user-selected transport channels, such as instant messengers, email, shared documents, social media, QR codes, or physical notes.
- **Local Persistence:** Encrypted session states, keys, and identity profiles reside entirely within client-side `IndexedDB` storage.
- **Post-Quantum Cryptography (PQC):** Combines classical cryptography with NIST PQC standards via `@noble` libraries (`@noble/ciphers`, `@noble/curves`, `@noble/hashes`, `@noble/post-quantum`).
- **Zeroization & Memory Hygiene:** Ephemeral key material undergoes explicit zeroization immediately following cryptographic operations.

## Threat Model & Security Boundaries

### In-Scope Security Guarantees

- **Transport Confidentiality & Integrity:** All ciphertexts copied to the clipboard remain secure even when transmitted over unencrypted or compromised communication channels.
- **Post-Quantum Forward Secrecy:** Future quantum adversaries capturing current transport payloads cannot decrypt historical sessions due to hybrid X25519/ML-KEM-1024 key encapsulation and Double Ratchet state advancement.
- **Authenticity & Non-Repudiation:** Initial handshake signatures using ML-DSA-87 prevent active person-in-the-middle (PITM) identity spoofing.

### Out-of-Scope Risks

- **Host Environment Integrity:** Malware, malicious browser extensions, or OS-level keyloggers/clipboard monitors running on the user's host machine.
- **Side-Channel Attacks:** Execution timing or memory access side-channels native to the JavaScript engine runtime environment.

## Usage Lifecycle

1. **Identity Generation:** Automatically generates a persistent cryptographic identity upon initial application boot.
2. **Peer Registration:** Users exchange out-of-band public identity bundles to add contacts.
3. **Session Initialization:** The initiator generates an `INIT` payload packet and transmits it to the peer to establish a Double Ratchet session.
4. **Encrypted Exchange:** Ciphertexts are copied directly to the clipboard, transmitted across any third-party app, and pasted by the recipient to decrypt.

## Development & Build Pipeline

The application is written in standard TypeScript and styled with Tailwind CSS v4. To maintain verifiable build outputs, the project intentionally omits complex bundlers in favor of explicit CLI toolchains (`tsc`, Tailwind CLI, and static serving).

### Commands

- **Installation:** Clone the repository and install locked dependencies.

  ```sh
  npm install
  ```

- **Local Development:** Starts the file watcher and static development server.

  ```sh
  npm run dev
  ```

- **Production Build:** Compiles static JavaScript assets directly to root distribution files.

  ```sh
  npm run build
  ```

## ECP Protocol Specification (v1)

### Cryptographic Primitive Stack

| Role                         | Primitive   | Specification / Key Length                            |
| ---------------------------- | ----------- | ----------------------------------------------------- |
| **Classical Key Exchange**   | X25519      | 256-bit ECDH Curve                                    |
| **Post-Quantum KEM**         | ML-KEM-1024 | FIPS 203 (1568-byte Public Key, 1568-byte Ciphertext) |
| **Post-Quantum Signature**   | ML-DSA-87   | FIPS 204 (2592-byte Public Key, 4627-byte Signature)  |
| **Symmetric Encryption**     | AES-256-GCM | 256-bit Key, 96-bit Initialization Vector (IV)        |
| **Key Derivation & Hashing** | HKDF / HMAC | HMAC-SHA256 / HKDF-SHA256                             |
| **Wire Encoding**            | Base64URL   | Prefixed by ASCII string `e2e1:`                      |

### Framing & Packet Architecture

All serialized wire payloads enforce a 5 MB limit and begin with a mandatory 12-byte binary header.

#### Header Layout (12 Bytes Total)

| Offset (Bytes)  | Field Name     | Type       | Description                                            |
| --------------- | -------------- | ---------- | ------------------------------------------------------ |
| `0x00` – `0x03` | Magic Bytes    | `Bytes[4]` | Constant ASCII `E2E1` (`0x45`, `0x32`, `0x45`, `0x31`) |
| `0x04`          | Version        | `UInt8`    | Wire Protocol Version (`0x01`)                         |
| `0x05`          | Packet Type    | `UInt8`    | `0x01`: INIT, `0x02`: RESP, `0x03`: MSG                |
| `0x06` – `0x07` | Reserved       | `Bytes[2]` | Padding bytes for 32-bit alignment (`0x0000`)          |
| `0x08` – `0x0B` | Payload Length | `UInt32BE` | Length of payload body in bytes (Big-Endian)           |

### Identity Bundle Layout (4,193 Bytes Total)

| Field Name                 | Offset (Bytes) | Size (Bytes) | Cryptographic Purpose               |
| -------------------------- | -------------- | ------------ | ----------------------------------- |
| **Bundle Version**         | `0`            | 1            | Format identifier (`0x01`)          |
| **ML-DSA-87 Public Key**   | `1`            | 2,592        | Identity signature verification     |
| **X25519 Public Key**      | `2593`         | 32           | Long-term classical static DH key   |
| **ML-KEM-1024 Public Key** | `2625`         | 1,568        | Static PQC KEM encapsulation target |

### Packet Types & Payload Specifications

#### 1. INIT Packet Payload (`0x01`)

Establishes the session, performs hybrid key agreement, and verifies mutual identity. To prevent parsing faults, the receiver enforces a strict minimum structural integrity size of 14,639 bytes.

| Size (Bytes) | Field                               | Description                                        |
| ------------ | ----------------------------------- | -------------------------------------------------- |
| 4,193        | **Sender Identity Bundle**          | Initiator's public Identity Bundle                 |
| 4,193        | **Receiver Identity Bundle**        | Target peer's public Identity Bundle               |
| 32           | **Ephemeral X25519 PK ($Ek_{pk}$)** | Ephemeral DH Public Key                            |
| 1,568        | **ML-KEM Ciphertext ($KEM_{CT}$)**  | Encapsulated key against Receiver's ML-KEM PK      |
| 4,627        | **ML-DSA Signature ($Sig$)**        | Signature over parameters verifying handshake      |
| Variable     | **Encrypted Payload**               | AES-256-GCM ciphertext containing setup parameters |

#### 2. RESP Packet Payload (`0x02`)

Acknowledges initialization. The protocol drops RESP payloads shorter than 60 bytes (12-byte header + 48-byte payload).

| Size (Bytes) | Field                 | Description                                                                                  |
| ------------ | --------------------- | -------------------------------------------------------------------------------------------- |
| 48           | **Encrypted Payload** | AES-256-GCM payload containing Responder Ephemeral X25519 PK (32 bytes) + GCM Tag (16 bytes) |

#### 3. MSG Packet Payload (`0x03`)

Carries active Double Ratchet session payloads. Any `MSG` packet shorter than 84 bytes is dropped as truncated.

| Absolute Offset | Field Name                   | Type / Size | Description                                             |
| --------------- | ---------------------------- | ----------- | ------------------------------------------------------- |
| `12` – `27`     | Conversation ID              | `Bytes[16]` | Pseudorandom session identifier                         |
| `28` – `59`     | Ephemeral DH Key             | `Bytes[32]` | Current ratchet step X25519 Public Key                  |
| `60` – `63`     | Previous Chain Length ($PN$) | `UInt32BE`  | Number of messages sent in previous chain               |
| `64` – `67`     | Message Sequence ($N_s$)     | `UInt32BE`  | Message count index in current chain                    |
| `68`+           | Payload Ciphertext           | Variable    | AES-256-GCM message body and 16-byte authentication tag |

## Ratchet State Machine & Error Handling

To maintain synchronization and prevent abuse, ECP dictates specific constraints on `MSG` frame validation.

- **Sequence Progression & Replay Drop:** The protocol demands strict forward progression. During `DecryptMessage`, the parsed sequence number ($N$) is compared against the expected receive sequence ($N_r$). If $N < N_r$, the message is dropped immediately, throwing a `"Message frame out of order or replayed"` error.

- **Gap Limitation & Skipped Keys:** ECP handles dropped packets by advancing the receiving chain up to the target sequence $N$. To prevent CPU exhaustion or memory starvation attacks via continuous HMAC chaining, ECP enforces a strict limit: if $N - N_r > 2000$, it throws an `"Excessive message gap"` exception.

- **Ephemeral Zeroization:** During skipped frame advancement ($N_r < N$), intermediate receiving chain keys ($CK_r$) are wiped from RAM using `.fill(0)` immediately after generating the next step.

### Cryptographic Derivations & Formulas

#### Hybrid Master Key Encapsulation (INIT Phase)

The initial Shared Key ($SK$) combines classical ECDH key agreement with post-quantum key encapsulation using HKDF-SHA256:

$$SK = \text{HKDF-SHA256}\left(\mathtt{"ECP-INIT-v1"} \parallel DH_1 \parallel KEM_{SS}\right)$$

#### Initialization Signature

Handshake integrity and authenticity are asserted by signing the concatenated parameter block using the sender's ML-DSA-87 private key:

$$Sig = \text{Sign}_{\text{ML-DSA}}\left(\mathtt{"ECP-INIT-v1"} \parallel SenderID \parallel ReceiverID \parallel Ek_{pk} \parallel KEM_{CT}\right)$$

#### Symmetric Double Ratchet Chains

Chain Keys ($CK$) and Message Keys ($MK$) advance via HMAC-SHA256 step derivation:

$$
\begin{aligned}
MK &= \text{HMAC-SHA256}(CK, \text{0x01}) \\
CK_{\text{next}} &= \text{HMAC-SHA256}(CK, \text{0x02})
\end{aligned}
$$
