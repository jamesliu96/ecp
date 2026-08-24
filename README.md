# E2EE Clipboard Protocol (ECP)

A decentralized, pure-frontend web application for secure, peer-to-peer encrypted clipboard sharing and message communication. ECP operates entirely without a backend server, ensuring that all data processing and cryptographic operations are handled exclusively on the client side.

## Core Architecture & Security

- **Decentralized Engine:** Functions completely without backend infrastructure, facilitating direct, secure message exchange between clients via out-of-band transport.

- **Local Persistence:** All application state and secure channel configurations are stored locally within the browser utilizing IndexedDB.

- **Post-Quantum E2EE:** All plaintext is encrypted locally before being copied to the clipboard or transmitted, powered by the `@noble` cryptography suite (`@noble/ciphers`, `@noble/curves`, `@noble/hashes`, `@noble/post-quantum`), AES-256-GCM, X25519, ML-KEM-1024, ML-DSA-87, and Double Ratchet handshakes.

- **In-Browser Execution:** All cryptographic key generation, signing, and encryption execute strictly within the local web browser environment, alongside secure in-memory zeroization.

- **Zero-Knowledge & Privacy:** No user-generated data, cryptographic keys, or metadata are ever uploaded to a remote server, and the application contains zero third-party tracking.

## Usage Lifecycle

1. **Identity Generation:** Upon first load, the application automatically generates a local cryptographic identity.

2. **Peer Registration:** Exchange public identity bundles out-of-band with a peer and add their bundle to establish a recognized contact.

3. **Channel Handshake:** Initiate a secure session by generating an initialization block and sharing it with the registered peer.

4. **Encrypted Exchange:** Copy the generated ciphertext blocks from the application and paste them into any external transport medium to communicate securely, and paste incoming ciphertext blocks back into the application to decrypt them.

## Development Pipeline

The application is built using TypeScript 7 and Tailwind CSS v4. No application bundler is used; the build pipeline consists purely of `tsc`, Tailwind CLI, and `serve`. Source files live under the `src/` directory, and build outputs are emitted directly to the project root to be served by any standard static-file web server.

- **Installation:** Clone the repository and run `npm install` to install project dependencies.

- **Local Development:** Run `npm run dev` to start the full local development environment, including a static server and file watch modes.

- **Production Build:** Run `npm run build` to compile static assets for production deployment.
