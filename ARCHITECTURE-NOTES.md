## Architecture

quantum-shield is a **post-quantum file encryption CLI** using NIST FIPS 203 (ML-KEM-768) key encapsulation + AES-256-GCM authenticated encryption. Chunked files, constant-time comparisons, single binary.

### Encryption Pipeline

```mermaid
graph TB
    A["Plaintext File"] --> B["Chunker<br/>configurable chunk size"]
    B --> C["HKDF-SHA256<br/>per-chunk key derivation"]
    C --> D["AES-256-GCM<br/>per-chunk encrypt"]
    D --> E["Output File"]

    F["ML-KEM-768<br/>Key Generation"] --> G["Shared Secret<br/>32 bytes"]
    G --> C

    H["Header Format"]
    H --> H1["magic: QSHIELD (4B)"]
    H --> H2["version: u8 (1B)"]
    H --> H3["kem_ciphertext: 1088B"]
    H --> H4["nonce: 12B"]
    H --> H5["chunk_size: u32 (4B)"]

    E --> I["[Header 1109B][Chunk 0][Chunk 1]...[Chunk N]"]

    style F fill:#F15A24,color:#000,stroke:none
    style D fill:#DA2C38,color:#fff,stroke:none
    style C fill:#1a1a2e,color:#F15A24,stroke:#F15A24
```

### Key Derivation Chain

```mermaid
flowchart LR
    A["ML-KEM-768 Shared Secret<br/>32 bytes"] --> B["HKDF-Extract<br/>salt = 0x00...00"]
    B --> C["HKDF-Expand<br/>info = 'chunk_key' || index"]
    C --> D["AES Key<br/>32 bytes per chunk"]
    C --> E["Nonce<br/>12 bytes per chunk"]
    D --> F["AES-256-GCM<br/>Encrypt chunk"]
    E --> F

    style A fill:#F15A24,color:#000,stroke:none
```

### Decryption Pipeline

```mermaid
flowchart TB
    A["Encrypted File"] --> B["Parse Header<br/>1109 bytes"]
    B --> C["ML-KEM-768<br/>Decapsulate"]
    C --> D["Shared Secret<br/>32 bytes"]
    D --> E["HKDF<br/>per-chunk keys"]
    E --> F["AES-256-GCM<br/>per-chunk decrypt"]
    F --> G["Plaintext File"]
    F --> H["Constant-Time Tag<br/>Verify (subtle crate)"]

    H -->|"match ✓"| G
    H -->|"mismatch ✗"| I["ABORT: tampered"]

    style C fill:#F15A24,color:#000,stroke:none
    style H fill:#DA2C38,color:#fff,stroke:none
```

## Quickstart

### One-liner — Encrypt a file

```bash
cargo install quantum-shield && echo "secret data" > secret.txt && quantum-shield encrypt secret.txt -o secret.txt.enc
```

### One-liner — Decrypt a file

```bash
quantum-shield decrypt secret.txt.enc -o secret.txt
```

### One-liner — Build from source + test

```bash
git clone https://github.com/BartoszOsiej/quantum-shield && cd quantum-shield && cargo build --release && cargo test
```

### One-liner — Benchmark crypto operations

```bash
git clone https://github.com/BartoszOsiej/quantum-shield && cd quantum-shield && cargo run --release -- --bench
```

### One-liner — Encrypt with custom chunk size

```bash
quantum-shield encrypt large-file.bin -o large-file.bin.enc --chunk-size 65536
```

### One-liner — Docker

```bash
docker run --rm -v "$(pwd)":/data -w /data \
  ghcr.io/bartoszosiej/quantum-shield:latest \
  quantum-shield encrypt secret.txt -o secret.txt.enc
```

### Verify

```bash
quantum-shield info secret.txt.enc     # show header metadata
quantum-shield verify secret.txt.enc   # verify integrity (decrypt + tag check)
quantum-shield --version               # show ML-KEM-768 + AES-256-GCM versions
```
