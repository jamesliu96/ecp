# E2EE Clipboard Protocol (ECP)

A serverless, pure-frontend web implementation of the End-to-End Encrypted Clipboard Protocol (ECP). ECP enables secure, peer-to-peer encrypted messaging and rich media sharing across untrusted transport channels without requiring a backend server or central authority.

## Core Architecture

- **Zero-Backend Processing:** Operates strictly on the client side. Messages and media are exchanged out-of-band via user-selected transport channels, such as instant messengers, email, shared documents, social media, QR codes, or physical notes.
- **Local Persistence:** Encrypted session states, keys, and identity profiles reside entirely within client-side `IndexedDB` storage.
- **Post-Quantum Cryptography (PQC):** Combines classical cryptography with NIST Level 5 PQC standards via `@noble` libraries (`@noble/ciphers`, `@noble/curves`, `@noble/hashes`, `@noble/post-quantum`).

## Threat Model & Security Boundaries

### In-Scope Security Guarantees

- **Transport Confidentiality & Integrity:** All ciphertexts copied to the clipboard remain secure even when transmitted over unencrypted or compromised communication channels.
- **Post-Quantum Forward Secrecy & Break-In Recovery:** Every Double Ratchet turn continuously encapsulates a fresh **ML-KEM-1024** shared secret alongside classical **X25519** ECDH. Future quantum adversaries capturing transport payloads cannot decrypt historical or future sessions even if ephemeral ECDH keys are compromised.
- **Authenticity & Non-Repudiation:** Initial handshake signatures using composite **ECDSA + ML-DSA-87** prevent active person-in-the-middle (PITM) identity spoofing.

### Out-of-Scope Risks

- **Host Environment Integrity:** Malware, malicious browser extensions, or OS-level keyloggers/clipboard monitors running on the user's host machine.
- **Side-Channel Probing:** Execution timing or memory access side-channels native to the JavaScript engine runtime environment.

## Usage Lifecycle

1. **Identity Generation:** Automatically generates a persistent cryptographic identity upon initial application boot.
2. **Peer Registration:** Users exchange out-of-band public identity bundles to add contacts.
3. **Session Initialization:** The initiator generates an `INIT` payload packet and transmits it to the peer to establish a Hybrid Double Ratchet session.
4. **Encrypted Exchange:** Ciphertexts and media Data URIs are copied directly to the clipboard, transmitted across any third-party app, and pasted by the recipient to decrypt.

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

| Role                         | Primitive      | Specification / Key Length       |
| ---------------------------- | -------------- | -------------------------------- |
| **Hybrid Key Exchange**      | ECDH + ML-KEM  | X25519 + FIPS 203 ML-KEM-1024    |
| **Composite Signature**      | ECDSA + ML-DSA | Ed25519 + FIPS 204 ML-DSA-87     |
| **Symmetric Encryption**     | AES-256-GCM    | 256-bit Key, 96-bit IV           |
| **Key Derivation & Hashing** | HKDF / HMAC    | HMAC-SHA256 / HKDF-SHA256        |
| **Wire Encoding**            | Base64URL      | Prefixed by ASCII string `e2e1:` |

### Framing & Packet Architecture

All serialized wire payloads enforce a 50 MB limit and begin with a mandatory 12-byte binary header.

#### Header Layout (12 Bytes Total)

| Offset (Bytes) | Field Name     | Type       | Description                                            |
| -------------- | -------------- | ---------- | ------------------------------------------------------ |
| `0` – `3`      | Magic Bytes    | `Bytes[4]` | Constant ASCII `E2E1` (`0x45`, `0x32`, `0x45`, `0x31`) |
| `4`            | Version        | `UInt8`    | Wire Protocol Version (`0x01`)                         |
| `5`            | Packet Type    | `UInt8`    | `0x01`: INIT, `0x02`: RESP, `0x03`: MSG                |
| `6` – `7`      | Reserved       | `Bytes[2]` | Padding bytes for 32-bit alignment (`0x0000`)          |
| `8` – `11`     | Payload Length | `UInt32BE` | Length of payload body in bytes (Big-Endian)           |

### Identity Bundle Layout (4,225 Bytes Total)

| Field Name                                       | Offset (Bytes) | Size (Bytes) | Cryptographic Purpose                                    |
| ------------------------------------------------ | -------------- | ------------ | -------------------------------------------------------- |
| **Bundle Version**                               | `0`            | 1            | Format identifier (`0x01`)                               |
| **Composite Signature PK (Ed25519 + ML-DSA-87)** | `1`            | 2,624        | Ed25519 (32B) + ML-DSA-87 (2,592B) identity verification |
| **Hybrid KEM PK (X25519 + ML-KEM-1024)**         | `2625`         | 1,600        | X25519 (32B) + ML-KEM-1024 (1,568B) encapsulation target |

### Packet Types & Payload Specifications

#### 1. INIT Packet Payload (`0x01`)

Establishes the session, performs hybrid key agreement, and verifies mutual identity.

| Absolute Offset  | Field Name                          | Type / Size   | Description                                           |
| ---------------- | ----------------------------------- | ------------- | ----------------------------------------------------- |
| `12` – `4236`    | **Sender Identity Bundle**          | `Bytes[4225]` | Initiator's public Identity Bundle                    |
| `4237` – `8461`  | **Receiver Identity Bundle**        | `Bytes[4225]` | Target peer's public Identity Bundle                  |
| `8462` – `10061` | **Hybrid Ephemeral PK ($Ek_{pk}$)** | `Bytes[1600]` | Ephemeral X25519 PK (32B) + ML-KEM Ciphertext (1568B) |
| `10062`–`14752`  | **Composite Signature ($Sig$)**     | `Bytes[4691]` | Ed25519 Signature (64B) + ML-DSA-87 Signature (4627B) |
| `14753`+         | **Encrypted Payload**               | Variable      | AES-256-GCM ciphertext containing setup parameters    |

#### 2. RESP Packet Payload (`0x02`)

Acknowledges initialization and establishes the receiving ratchet chain.

##### Wire Payload Structure (3,184 Bytes Total, Offset 12+)

| Relative Offset | Field Name        | Type / Size   | Description                               |
| --------------- | ----------------- | ------------- | ----------------------------------------- |
| `0` – `3167`    | Encrypted Payload | `Bytes[3168]` | AES-256-GCM encrypted payload (see below) |
| `3168` – `3183` | AES-256-GCM Tag   | `Bytes[16]`   | AEAD authentication tag                   |

##### Decrypted Plaintext Payload (3,168 Bytes Total)

| Decrypted Offset | Field Name                    | Type / Size   | Description                                      |
| ---------------- | ----------------------------- | ------------- | ------------------------------------------------ |
| `0` – `31`       | Responder Ephemeral DH PK     | `Bytes[32]`   | Responder X25519 Ephemeral Public Key            |
| `32` – `1599`    | ML-KEM Encapsulation CT       | `Bytes[1568]` | Encapsulated secret to Initiator's static ML-KEM |
| `1600` – `3167`  | Responder Ephemeral ML-KEM PK | `Bytes[1568]` | New ML-KEM Public Key for future ratchet steps   |

#### 3. MSG Packet Payload (`0x03`)

Carries active Hybrid Double Ratchet session payloads.

##### Unencrypted Wire Header (3,192 Bytes Total, Offset 12+)

| Relative Offset | Field Name                   | Type / Size   | Description                                          |
| --------------- | ---------------------------- | ------------- | ---------------------------------------------------- |
| `0` – `15`      | Conversation ID              | `Bytes[16]`   | Pseudorandom session identifier                      |
| `16` – `47`     | Ephemeral DH Key             | `Bytes[32]`   | Current ratchet step X25519 Public Key               |
| `48` – `1615`   | ML-KEM Ciphertext            | `Bytes[1568]` | Encapsulated secret for current ratchet step         |
| `1616` – `3183` | Ephemeral ML-KEM PK          | `Bytes[1568]` | Fresh ML-KEM Public Key for peer's next ratchet turn |
| `3184` – `3187` | Previous Chain Length ($PN$) | `UInt32BE`    | Number of messages sent in previous chain            |
| `3188` – `3191` | Message Sequence ($N_s$)     | `UInt32BE`    | Message count index in current chain                 |

##### Payload Ciphertext (Offset 3204+)

| Relative Offset | Field Name             | Type / Size | Description             |
| --------------- | ---------------------- | ----------- | ----------------------- |
| `3192`+         | Encrypted Message Body | Variable    | AES-256-GCM ciphertext  |
| End $- 16$      | AES-256-GCM Tag        | `Bytes[16]` | AEAD authentication tag |

### Authenticated Additional Data (AAD) Construction

To bind ciphertexts to their exact wire headers and identities, AEAD operations require strict AAD constructions:

- **INIT Packet (`0x01`):** `Header (12B) || SenderBundle (4225B) || ReceiverBundle (4225B) || Ek_pk (32B) || KEM_ct (1568B) || Sig (4691B)`
- **RESP Packet (`0x02`):** `Header (12B)`
- **MSG Packet (`0x03`):** `"ECP-MSG-v1" || ConvID (16B) || SenderIdentity (4225B) || ReceiverIdentity (4225B) || msgHdr (3192B)`

### Ratchet State Machine & Error Handling

To maintain synchronization and assist offline user debugging, ECP dictates explicit frame validation and diagnostic exceptions:

- **Sequence Progression & Replay Drop:** The protocol demands strict forward progression. During `DecryptMessage`, the parsed sequence number ($N$) is compared against the expected receive sequence ($N_r$). If $N < N_r$, the message is dropped, throwing `"Message frame out of order or replayed"`.
- **Gap Limitation & Skipped Keys:** ECP handles dropped packets by advancing the receiving chain up to the target sequence $N$. To prevent infinite loops during HMAC chaining, ECP enforces a strict limit: if $N - N_r > 2000$, it throws an `"Excessive message gap"` exception.
- **Diagnostic Cryptographic Failures:** If AEAD tag authentication fails, or if required keys are missing, the protocol throws explicit, localized exceptions (such as `"Message decryption failed: AEAD tag mismatch"`) to optimize offline client troubleshooting.

### Cryptographic Derivations & Formulas

#### Hybrid Master Key Encapsulation (INIT Phase)

The initial Shared Key ($SK$) combines classical ECDH key agreement with post-quantum key encapsulation using HKDF-SHA256:

$$SK = \text{HKDF-SHA256}\left(\mathtt{"ECP-INIT-v1"} \parallel DH_1 \parallel KEM_{SS}\right)$$

#### Composite Initialization Signature

Handshake integrity and authenticity are asserted by signing the concatenated parameter block using the sender's composite Ed25519 + ML-DSA-87 private keys:

$$Sig = \text{Sign}_{\text{Ed25519+ML-DSA-87}}\left(\mathtt{"ECP-INIT-v1"} \parallel SenderID \parallel ReceiverID \parallel Ek_{pk} \parallel KEM_{CT}\right)$$

#### Hybrid Double Ratchet Steps

Each DH ratchet turn advances the Root Key ($RK$) and derives new Chain Keys ($CK$) by combining X25519 ECDH and ML-KEM-1024 shared secrets:

$$RK_{i+1} \parallel CK_{i+1} = \text{HKDF-SHA256}\left(DH_{\text{shared}} \parallel KEM_{\text{SS}}, RK_i, \mathtt{"ECP-DR-RK-v1"}, 64\right)$$

#### Symmetric Chain Progression

Chain Keys ($CK$) and Message Keys ($MK$) advance within a chain via HMAC-SHA256:

$$
\begin{aligned}
MK &= \text{HMAC-SHA256}(CK, \text{0x01}) \\
CK_{\text{next}} &= \text{HMAC-SHA256}(CK, \text{0x02})
\end{aligned}
$$
