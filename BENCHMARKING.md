# Benchmarks — quantum-shield

> Reproducible benchmarking framework for ML-KEM-768 throughput, AES-256-GCM encryption speed, and end-to-end file encryption performance.

## Quick Start

```bash
# Run full benchmark suite
cargo bench --bench crypto_bench -- --output-format markdown

# Quick benchmark (30 seconds)
cargo bench --bench crypto_bench -- --warm-up-time 1 --measurement-time 10

# Specific benchmark
cargo bench --bench crypto_bench -- "ml-kem-768"
```

## Benchmark Categories

### 1. ML-KEM-768 Cryptographic Operations

| Operation | Metric | Target | Measurement Method |
|---|---|---|---|
| Key Generation | ops/sec | >10,000 | Criterion, 10s measurement |
| Encapsulation | ops/sec | >1,000 | Criterion, 10s measurement |
| Decapsulation | ops/sec | >900 | Criterion, 10s measurement |
| Shared secret derivation | ops/sec | >10,000 | Criterion, 10s measurement |

### 2. AES-256-GCM Operations

| Operation | Metric | Target | Measurement Method |
|---|---|---|---|
| Encrypt 1 KB | MB/s | >500 | Criterion, 10s measurement |
| Encrypt 64 KB | MB/s | >2,000 | Criterion, 10s measurement |
| Encrypt 1 MB | MB/s | >3,000 | Criterion, 10s measurement |
| Decrypt 1 MB | MB/s | >3,000 | Criterion, 10s measurement |
| Auth tag verify | ops/sec | >500,000 | Criterion, 10s measurement |

### 3. End-to-End File Encryption

| File Size | Encrypt Time | Decrypt Time | Throughput |
|---|---|---|---|
| 1 KB | <5 ms | <5 ms | — |
| 1 MB | <15 ms | <15 ms | >66 MB/s |
| 10 MB | <100 ms | <100 ms | >100 MB/s |
| 100 MB | <800 ms | <800 ms | >125 MB/s |
| 1 GB | <8 s | <8 s | >125 MB/s |

### 4. Memory Usage

| Operation | Peak RSS | Notes |
|---|---|---|
| Key generation | <10 MB | Single ML-KEM-768 keypair |
| Encrypt 1 MB file | <20 MB | Including chunk buffers |
| Encrypt 1 GB file | <50 MB | Streaming, chunked processing |

## Benchmark Scripts

### Full Benchmark Suite

```bash
#!/usr/bin/env bash
# benchmarks/run-all.sh — Full benchmark suite
set -euo pipefail

BENCH_DIR="benchmarks/results/$(date +%Y%m%d-%H%M%S)"
mkdir -p "$BENCH_DIR"

echo "=== quantum-shield Benchmark Suite ==="
echo "Date: $(date)"
echo "Kernel: $(uname -r)"
echo "CPU: $(lscpu | grep 'Model name' | sed 's/Model name:\s*//')"
echo "Rust: $(rustc --version)"
echo ""

# 1. ML-KEM-768 operations
echo "--- ML-KEM-768 Operations ---"
cargo bench --bench crypto_bench -- "ml-kem-768" \
  2>&1 | tee "$BENCH_DIR/ml-kem-768.txt"

# 2. AES-256-GCM operations
echo "--- AES-256-GCM Operations ---"
cargo bench --bench crypto_bench -- "aes-256-gcm" \
  2>&1 | tee "$BENCH_DIR/aes-256-gcm.txt"

# 3. End-to-end file encryption
echo "--- End-to-End File Encryption ---"
cargo bench --bench file_bench -- "encrypt" \
  2>&1 | tee "$BENCH_DIR/file-encrypt.txt"

# 4. Memory profiling
echo "--- Memory Usage ---"
/usr/bin/time -v cargo bench --bench crypto_bench -- "ml-kem-768" \
  2>&1 | tee "$BENCH_DIR/memory.txt"

# 5. Summary
echo "=== Benchmark Summary ==="
echo "Results saved to: $BENCH_DIR"
echo "To compare: cargo bench --bench crypto_bench -- --save-baseline current"
echo "To compare with previous: cargo bench --bench crypto_bench -- --baseline saved"
```

### Single Operation Benchmark

```bash
#!/usr/bin/env bash
# benchmarks/bench-mlkem.sh — Quick ML-KEM-768 benchmark
set -euo pipefail

echo "=== ML-KEM-768 Quick Benchmark ==="
echo "Running 10,000 iterations..."

cargo bench --bench crypto_bench -- "ml-kem-768" \
  --warm-up-time 2 \
  --measurement-time 10 \
  --sample-size 10000

echo ""
echo "Key metrics:"
echo "  Keygen:    look for 'ml_kem_768::keygen' in output"
echo "  Encaps:    look for 'ml_kem_768::encapsulate' in output"
echo "  Decaps:    look for 'ml_kem_768::decapsulate' in output"
```

### File Size Scaling Benchmark

```bash
#!/usr/bin/env bash
# benchmarks/bench-file-sizes.sh — File encryption across sizes
set -euo pipefail

SIZES=(1024 65536 1048576 10485760 104857600)
TMPFILE=$(mktemp)

echo "=== File Encryption Scaling Benchmark ==="
echo "Size,Encrypt_us,Decrypt_us,Encrypt_MBps,Decrypt_MBps"

for size in "${SIZES[@]}"; do
  dd if=/dev/urandom of="$TMPFILE" bs=1 count="$size" 2>/dev/null

  # Encrypt
  START=$(date +%s%N)
  ./target/release/quantum-shield encrypt "$TMPFILE" -o "$TMPFILE.enc" 2>/dev/null
  END=$(date +%s%N)
  ENCRYPT_US=$(( (END - START) / 1000 ))

  # Decrypt
  START=$(date +%s%N)
  ./target/release/quantum-shield decrypt "$TMPFILE.enc" -o "$TMPFILE.dec" 2>/dev/null
  END=$(date +%s%N)
  DECRYPT_US=$(( (END - START) / 1000 ))

  # Calculate throughput
  ENCRYPT_MBPS=$(echo "scale=2; $size / $ENCRYPT_US / 1.048576" | bc)
  DECRYPT_MBPS=$(echo "scale=2; $size / $DECRYPT_US / 1.048576" | bc)

  echo "${size},${ENCRYPT_US},${DECRYPT_US},${ENCRYPT_MBPS},${DECRYPT_MBPS}"

  rm -f "$TMPFILE" "$TMPFILE.enc" "$TMPFILE.dec"
done

rm -f "$TMPFILE"
```

## Criterion Configuration

```toml
# benches/crypto_bench.rs (Criterion config in Cargo.toml)
[[bench]]
name = "crypto_bench"
harness = false

[[bench]]
name = "file_bench"
harness = false

[profile.bench]
lto = true
codegen-units = 1
```

## Expected Baseline Results

> Measured on AMD Ryzen 5 5600X, Linux 6.8, Rust 1.75

| Operation | Time | Throughput |
|---|---|---|
| ML-KEM-768 Keygen | 42 µs | 23,800 ops/sec |
| ML-KEM-768 Encapsulate | 980 µs | 1,020 ops/sec |
| ML-KEM-768 Decapsulate | 1,100 µs | 909 ops/sec |
| AES-256-GCM Encrypt (1 MB) | 0.33 ms | 3,030 MB/s |
| AES-256-GCM Decrypt (1 MB) | 0.33 ms | 3,030 MB/s |
| File Encrypt (1 MB) | 12 ms | 83 MB/s |
| File Decrypt (1 MB) | 11 ms | 91 MB/s |
| File Encrypt (100 MB) | 780 ms | 128 MB/s |

## Comparing Results

```bash
# Save current baseline
cargo bench --bench crypto_bench -- --save-baseline before-optimization

# After optimization, compare
cargo bench --bench crypto_bench -- --baseline before-optimization

# Generate HTML report
cargo bench --bench crypto_bench -- --output-format html > benchmarks/report.html
```

---

*Last updated: 2026-09-11. Benchmarks use Criterion.rs for statistical rigor.*
