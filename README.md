<img src="https://capsule-render.vercel.app/api?type=waving&color=gradient&customColorList=6,11,20&height=130&section=header&text=QuantumShield&fontSize=32&animation=fadeIn" width="100%" />

<div align="center">

[![Typing SVG](https://readme-typing-svg.demolab.com/?font=JetBrains+Mono&weight=600&size=18&duration=3000&pause=1200&color=58A6FF&center=true&vCenter=true&width=600&height=45&lines=Post-quantum%20file%20encryption%20CLI%20%E2%80%94%20ML-KEM-768%20%2B%20AES-256-GCM)](https://github.com/BartoszOsiej/pqguard)

</div># 🔒 pqguard

![License](https://img.shields.io/badge/License-MIT-green?style=flat-square)
![Rust](https://img.shields.io/badge/Rust-2021-DEA584?style=flat-square&logo=rust)
![crates.io](https://img.shields.io/crates/v/pqguard?style=flat-square&label=crates.io&logo=rust)
![CI](https://img.shields.io/github/actions/workflow/status/BartoszOsiej/pqguard/ci.yml?style=flat-square&label=CI)
![OpenSSF](https://img.shields.io/ossf-scorecard/github.com/BartoszOsiej/pqguard?style=flat-square)
![Downloads](https://img.shields.io/crates/d/pqguard?style=flat-square)

**Post-quantum file encryption CLI** — ML-KEM-768 (FIPS 203) + AES-256-GCM

Encrypt files using NIST-standardized post-quantum algorithms that resist both classical and quantum computer attacks.

## ⚡ Quick Start

```bash
# Install
cargo install pqguard

# Generate keypair
pqguard keygen

# Encrypt a file
pqguard encrypt secret.txt --recipient public_key.pqg.pub

# Multi-recipient (any of the listed private keys can decrypt)
pqguard encrypt secret.txt -r alice.pqg.pub -r bob.pqg.pub

# Decrypt
pqguard decrypt secret.pqg --private-key private_key.pqg.key
```

## 🧠 How It Works

```
┌─────────────────────────────────────────────────────┐
│  ENCRYPTION                                         │
│                                                     │
│  1. Generate random salt + nonce                    │
│  2. ML-KEM-768 encapsulate → shared secret + ct     │
│  3. HKDF-SHA256(shared_secret, salt) → aes_key     │
│  4. AES-256-GCM(aes_key, nonce, plaintext) → ct    │
│  5. Write: PQGR ‖ version ‖ kem_ct ‖ nonce ‖      │
│            salt ‖ aes_ct                            │
└─────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────┐
│  DECRYPTION                                         │
│                                                     │
│  1. Parse PQGR envelope                             │
│  2. ML-KEM-768 decapsulate(ct, dk) → shared_secret  │
│  3. HKDF-SHA256(shared_secret, salt) → aes_key     │
│  4. AES-256-GCM decrypt(aes_key, nonce, aes_ct)     │
│  5. Output plaintext                                │
└─────────────────────────────────────────────────────┘
```

## 🔐 Algorithm Details

| Component | Algorithm | Standard |
|-----------|-----------|----------|
| Key Exchange | ML-KEM-768 (Kyber768) | NIST FIPS 203 |
| Key Derivation | HKDF-SHA256 | RFC 5869 |
| Symmetric Encryption | AES-256-GCM | NIST SP 800-38D |

### Security Levels

- **ML-KEM-512**: NIST Level 1 (128-bit classical, ~128-bit quantum)
- **ML-KEM-768**: NIST Level 3 (192-bit classical, ~192-bit quantum) ← **default**
- **ML-KEM-1024**: NIST Level 5 (256-bit classical, ~256-bit quantum)

## 📖 Usage

### Generate Keypair

```bash
pqguard keygen -o /path/to/keys -n alice
```

Creates:
- `alice.pqg.pub` — Public key (safe to share)
- `alice.pqg.key` — Private key (keep secret! mode 0600)

### Encrypt

```bash
# Basic encryption
pqguard encrypt document.pdf --recipient bob.pqg.pub

# Specify output file
pqguard encrypt document.pdf -r bob.pqg.pub -o document.pqg
```

### Decrypt

```bash
pqguard decrypt document.pqg --private-key bob.pqg.key

# Specify output
pqguard decrypt document.pqg -k bob.pqg.key -o document.pdf
```

### Verify

```bash
pqguard verify document.pqg
# ✅ Valid pqguard file
#    KEM ciphertext: 1088 bytes
#    Encrypted data: 1048623 bytes
```

### Show Key Info

```bash
pqguard info alice.pqg.pub
# 📋 Key Information
#    Type: PQGUARD-PUBLIC-KEY
#    Algorithm: ML-KEM-768
#    Size: 1184 bits
#    Name: alice
```

## 🏗️ Building from Source

```bash
git clone https://github.com/BartoszOsiej/pqguard
cd pqguard
cargo build --release
```

## 🧪 Why Post-Quantum?

Classical cryptography (RSA, ECDH) will be broken by quantum computers running Shor's algorithm. NIST finalized post-quantum standards in 2024:

- **ML-KEM** (FIPS 203) — Key encapsulation
- **ML-DSA** (FIPS 204) — Digital signatures
- **SLH-DSA** (FIPS 205) — Hash-based signatures

The "harvest now, decrypt later" threat means data encrypted today with classical algorithms can be decrypted by future quantum computers. **pqguard** protects against this.

## 📊 Benchmarks

| Operation | Time |
|-----------|------|
| Keygen | ~150μs |
| Encapsulate | ~25μs |
| Decapsulate | ~30μs |
| AES-256-GCM (1MB) | ~0.5ms |

## 📜 License

MIT
---

![License](https://img.shields.io/github/license/BartoszOsiej/pqguard?style=flat-square)
![Top Language](https://img.shields.io/github/languages/top/BartoszOsiej/pqguard?style=flat-square)
![Last Commit](https://img.shields.io/github/last-commit/BartoszOsiej/pqguard?style=flat-square)
![Repo Size](https://img.shields.io/github/repo-size/BartoszOsiej/pqguard?style=flat-square)
[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/BartoszOsiej/pqguard/badge)](https://scorecard.dev/viewer/?uri=github.com/BartoszOsiej/pqguard)
---

## 📺 Demo

![pqguard Demo](assets/pqguard-demo.gif)
## Deep Dives

Extended dossiers (architecture, verification, benchmarks, error codex) ship in this repo:
- [SECURITY.md](SECURITY.md)
- [ARCHITECTURE-NOTES.md](ARCHITECTURE-NOTES.md)
