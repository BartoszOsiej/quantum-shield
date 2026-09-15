use pqguard::crypto::*;

// ── Key Generation ──────────────────────────────────────────

#[test]
fn keygen_produces_valid_keypair() {
    let (ek, dk) = generate_kem_keypair().unwrap();
    assert_eq!(ek.len(), 1184, "encapsulation key should be 1184 bytes");
    assert!(!dk.is_empty(), "decapsulation key should not be empty");
}

#[test]
fn keygen_produces_different_keys_each_time() {
    let (ek1, dk1) = generate_kem_keypair().unwrap();
    let (ek2, dk2) = generate_kem_keypair().unwrap();
    assert_ne!(ek1, ek2, "encapsulation keys should differ");
    assert_ne!(dk1, dk2, "decapsulation keys should differ");
}

// ── KEM Encapsulate / Decapsulate ───────────────────────────

#[test]
fn kem_roundtrip_shared_secret_matches() {
    let (ek, dk) = generate_kem_keypair().unwrap();
    let (ss1, ct) = kem_encapsulate(&ek).unwrap();
    let ss2 = kem_decapsulate(&dk, &ct).unwrap();
    assert_eq!(ss1, ss2, "shared secrets must match");
}

#[test]
fn kem_encapsulate_produces_1088_byte_ciphertext() {
    let (ek, _dk) = generate_kem_keypair().unwrap();
    let (_ss, ct) = kem_encapsulate(&ek).unwrap();
    assert_eq!(ct.len(), 1088, "ML-KEM-768 ciphertext should be 1088 bytes");
}

#[test]
fn kem_shared_secret_is_32_bytes() {
    let (ek, _dk) = generate_kem_keypair().unwrap();
    let (ss, _ct) = kem_encapsulate(&ek).unwrap();
    assert_eq!(ss.len(), 32, "shared secret should be 32 bytes");
}

#[test]
fn kem_different_encapsulations_produce_different_ciphertexts() {
    let (ek, _dk) = generate_kem_keypair().unwrap();
    let (_ss1, ct1) = kem_encapsulate(&ek).unwrap();
    let (_ss2, ct2) = kem_encapsulate(&ek).unwrap();
    assert_ne!(ct1, ct2, "ciphertexts should differ (randomized)");
}

#[test]
fn kem_decapsulate_with_wrong_key_produces_wrong_secret() {
    let (ek1, _dk1) = generate_kem_keypair().unwrap();
    let (ek2, dk2) = generate_kem_keypair().unwrap();
    let (ss1, ct1) = kem_encapsulate(&ek1).unwrap();
    // wrong key → different shared secret (ML-KEM doesn't error, just wrong SS)
    let ss2 = kem_decapsulate(&dk2, &ct1).unwrap();
    assert_ne!(ss1, ss2, "wrong key should produce different shared secret");
}

#[test]
fn kem_invalid_key_length_fails() {
    let result = kem_encapsulate(&[0u8; 100]);
    assert!(result.is_err(), "invalid key length should fail");
}

#[test]
fn kem_invalid_ciphertext_length_fails() {
    let (ek, dk) = generate_kem_keypair().unwrap();
    let (_ss, _ct) = kem_encapsulate(&ek).unwrap();
    let result = kem_decapsulate(&dk, &[0u8; 100]);
    assert!(result.is_err(), "invalid ciphertext length should fail");
}

// ── Key Derivation ──────────────────────────────────────────

#[test]
fn derive_key_produces_32_bytes() {
    let key = derive_key(b"shared secret", b"salt").unwrap();
    assert_eq!(key.len(), 32);
}

#[test]
fn derive_key_deterministic() {
    let k1 = derive_key(b"secret", b"salt").unwrap();
    let k2 = derive_key(b"secret", b"salt").unwrap();
    assert_eq!(k1, k2, "same inputs should produce same key");
}

#[test]
fn derive_key_different_salts_differ() {
    let k1 = derive_key(b"secret", b"salt1").unwrap();
    let k2 = derive_key(b"secret", b"salt2").unwrap();
    assert_ne!(k1, k2, "different salts should produce different keys");
}

#[test]
fn derive_key_different_secrets_differ() {
    let k1 = derive_key(b"secret1", b"salt").unwrap();
    let k2 = derive_key(b"secret2", b"salt").unwrap();
    assert_ne!(k1, k2, "different secrets should produce different keys");
}

// ── Symmetric Encrypt / Decrypt ─────────────────────────────

#[test]
fn symmetric_roundtrip() {
    let key = derive_key(b"test secret", b"test salt").unwrap();
    let nonce = generate_nonce();
    let plaintext = b"hello pqguard!";
    let ct = symmetric_encrypt(&key, &nonce, plaintext).unwrap();
    let pt = symmetric_decrypt(&key, &nonce, &ct).unwrap();
    assert_eq!(pt, plaintext);
}

#[test]
fn symmetric_different_nonces_produce_different_ciphertexts() {
    let key = derive_key(b"test", b"salt").unwrap();
    let n1 = generate_nonce();
    let n2 = generate_nonce();
    let data = b"same plaintext";
    let ct1 = symmetric_encrypt(&key, &n1, data).unwrap();
    let ct2 = symmetric_encrypt(&key, &n2, data).unwrap();
    assert_ne!(ct1, ct2);
}

#[test]
fn symmetric_decrypt_with_wrong_key_fails() {
    let k1 = derive_key(b"secret1", b"salt").unwrap();
    let k2 = derive_key(b"secret2", b"salt").unwrap();
    let nonce = generate_nonce();
    let ct = symmetric_encrypt(&k1, &nonce, b"secret").unwrap();
    let result = symmetric_decrypt(&k2, &nonce, &ct);
    assert!(result.is_err(), "decryption with wrong key should fail");
}

#[test]
fn symmetric_decrypt_with_wrong_nonce_fails() {
    let key = derive_key(b"test", b"salt").unwrap();
    let n1 = generate_nonce();
    let n2 = generate_nonce();
    let ct = symmetric_encrypt(&key, &n1, b"secret").unwrap();
    let result = symmetric_decrypt(&key, &n2, &ct);
    assert!(result.is_err(), "decryption with wrong nonce should fail");
}

#[test]
fn symmetric_tampered_ciphertext_fails() {
    let key = derive_key(b"test", b"salt").unwrap();
    let nonce = generate_nonce();
    let mut ct = symmetric_encrypt(&key, &nonce, b"secret").unwrap();
    ct[0] ^= 0xff; // flip bits
    let result = symmetric_decrypt(&key, &nonce, &ct);
    assert!(result.is_err(), "decryption of tampered data should fail");
}

#[test]
fn symmetric_empty_plaintext() {
    let key = derive_key(b"test", b"salt").unwrap();
    let nonce = generate_nonce();
    let ct = symmetric_encrypt(&key, &nonce, b"").unwrap();
    let pt = symmetric_decrypt(&key, &nonce, &ct).unwrap();
    assert_eq!(pt, b"");
}

#[test]
fn symmetric_large_plaintext() {
    let key = derive_key(b"test", b"salt").unwrap();
    let nonce = generate_nonce();
    let plaintext = vec![0xABu8; 1024 * 1024]; // 1 MB
    let ct = symmetric_encrypt(&key, &nonce, &plaintext).unwrap();
    let pt = symmetric_decrypt(&key, &nonce, &ct).unwrap();
    assert_eq!(pt, plaintext);
}

// ── SealedEnvelope Serialization ────────────────────────────

#[test]
fn envelope_roundtrip() {
    let (ek, dk) = generate_kem_keypair().unwrap();
    let plaintext = b"test data for envelope";
    let envelope = encrypt_bytes(&ek, plaintext).unwrap();

    // serialize → deserialize
    let bytes = envelope.to_bytes();
    let recovered = SealedEnvelope::from_bytes(&bytes).unwrap();

    // decrypt with recovered envelope
    let decrypted = decrypt_bytes(&dk, &recovered).unwrap();
    assert_eq!(decrypted, plaintext);
}

#[test]
fn envelope_starts_with_magic() {
    let (ek, _dk) = generate_kem_keypair().unwrap();
    let envelope = encrypt_bytes(&ek, b"test").unwrap();
    let bytes = envelope.to_bytes();
    assert_eq!(&bytes[0..4], b"PQGR", "magic header should be PQGR");
}

#[test]
fn envelope_version_is_1() {
    let (ek, _dk) = generate_kem_keypair().unwrap();
    let envelope = encrypt_bytes(&ek, b"test").unwrap();
    let bytes = envelope.to_bytes();
    assert_eq!(bytes[4], 1, "version should be 1");
}

#[test]
fn envelope_from_bytes_too_small_fails() {
    let result = SealedEnvelope::from_bytes(&[0u8; 10]);
    assert!(result.is_err());
}

#[test]
fn envelope_from_bytes_wrong_magic_fails() {
    let mut data = vec![0u8; 200];
    data[0..4].copy_from_slice(b"NOPE");
    let result = SealedEnvelope::from_bytes(&data);
    assert!(result.is_err());
}

#[test]
fn envelope_from_bytes_truncated_kem_fails() {
    let mut data = vec![0u8; 200];
    data[0..4].copy_from_slice(b"PQGR");
    data[4] = 1;
    // set kem_len to something huge
    data[5..9].copy_from_slice(&999999u32.to_le_bytes());
    let result = SealedEnvelope::from_bytes(&data);
    assert!(result.is_err());
}

// ── High-level Encrypt / Decrypt ────────────────────────────

#[test]
fn encrypt_decrypt_roundtrip_short() {
    let (ek, dk) = generate_kem_keypair().unwrap();
    let plaintext = b"hello";
    let envelope = encrypt_bytes(&ek, plaintext).unwrap();
    let decrypted = decrypt_bytes(&dk, &envelope).unwrap();
    assert_eq!(decrypted, plaintext);
}

#[test]
fn encrypt_decrypt_roundtrip_long() {
    let (ek, dk) = generate_kem_keypair().unwrap();
    let plaintext = vec![42u8; 10_000];
    let envelope = encrypt_bytes(&ek, &plaintext).unwrap();
    let decrypted = decrypt_bytes(&dk, &envelope).unwrap();
    assert_eq!(decrypted, plaintext);
}

#[test]
fn encrypt_decrypt_binary_data() {
    let (ek, dk) = generate_kem_keypair().unwrap();
    let plaintext: Vec<u8> = (0..=255).cycle().take(1000).collect();
    let envelope = encrypt_bytes(&ek, &plaintext).unwrap();
    let decrypted = decrypt_bytes(&dk, &envelope).unwrap();
    assert_eq!(decrypted, plaintext);
}

#[test]
fn decrypt_with_wrong_key_fails() {
    let (ek1, _dk1) = generate_kem_keypair().unwrap();
    let (_ek2, dk2) = generate_kem_keypair().unwrap();
    let envelope = encrypt_bytes(&ek1, b"secret").unwrap();
    let result = decrypt_bytes(&dk2, &envelope);
    assert!(result.is_err());
}

// ── Salt and Nonce Generation ───────────────────────────────

#[test]
fn salt_is_32_bytes() {
    assert_eq!(generate_salt().len(), SALT_LEN);
}

#[test]
fn nonce_is_12_bytes() {
    assert_eq!(generate_nonce().len(), NONCE_LEN);
}

#[test]
fn salts_differ() {
    let s1 = generate_salt();
    let s2 = generate_salt();
    assert_ne!(s1, s2);
}

#[test]
fn nonces_differ() {
    let n1 = generate_nonce();
    let n2 = generate_nonce();
    assert_ne!(n1, n2);
}

// ── Constants ───────────────────────────────────────────────

#[test]
fn algorithm_names() {
    assert_eq!(KEM_ALG, "ML-KEM-768");
    assert_eq!(SYMMETRIC_ALG, "AES-256-GCM");
}

// ── Key File Format ─────────────────────────────────────────

#[test]
fn keyfile_roundtrip() {
    let dir = tempfile::tempdir().unwrap();
    let (pk_path, sk_path) =
        pqguard::keygen::generate_keypair(dir.path().to_str().unwrap(), "test-key").unwrap();

    let pk = pqguard::keygen::load_public_key(pk_path.to_str().unwrap()).unwrap();
    let sk = pqguard::keygen::load_secret_key(sk_path.to_str().unwrap()).unwrap();

    // keys should be non-empty
    assert!(!pk.is_empty());
    assert!(!sk.is_empty());

    // encrypt with pk, decrypt with sk
    let envelope = encrypt_bytes(&pk, b"keyfile test").unwrap();
    let decrypted = decrypt_bytes(&sk, &envelope).unwrap();
    assert_eq!(decrypted, b"keyfile test");
}

#[test]
fn keyfile_wrong_type_fails() {
    let dir = tempfile::tempdir().unwrap();
    let (_pk_path, sk_path) =
        pqguard::keygen::generate_keypair(dir.path().to_str().unwrap(), "test").unwrap();

    // try to load secret key as public
    let result = pqguard::keygen::load_public_key(sk_path.to_str().unwrap());
    assert!(result.is_err(), "loading secret key as public should fail");
}

// ── Bench-like stress test ──────────────────────────────────

#[test]
fn multiple_encryptions_with_same_key() {
    let (ek, dk) = generate_kem_keypair().unwrap();

    for i in 0..10 {
        let msg = format!("message {}", i);
        let envelope = encrypt_bytes(&ek, msg.as_bytes()).unwrap();
        let decrypted = decrypt_bytes(&dk, &envelope).unwrap();
        assert_eq!(decrypted, msg.as_bytes());
    }
}

// ── Multi-recipient (v2 envelope) ───────────────────────────

#[test]
fn multi_envelope_roundtrip_all_recipients() {
    let keys: Vec<(Vec<u8>, Vec<u8>)> = (0..3).map(|_| generate_kem_keypair().unwrap()).collect();
    let eks: Vec<Vec<u8>> = keys.iter().map(|(ek, _)| ek.clone()).collect();

    let envelope = MultiEnvelope::seal(&eks, b"shared secret message").unwrap();
    assert_eq!(envelope.recipients.len(), 3);

    for (_, dk) in &keys {
        let pt = envelope.open(dk).unwrap();
        assert_eq!(pt, b"shared secret message");
    }
}

#[test]
fn multi_envelope_rejects_wrong_key() {
    let (ek1, _) = generate_kem_keypair().unwrap();
    let (_, dk_other) = generate_kem_keypair().unwrap();

    let envelope = MultiEnvelope::seal(&[ek1], b"for your eyes only").unwrap();
    assert!(envelope.open(&dk_other).is_err());
}

#[test]
fn multi_envelope_serialization_roundtrip() {
    let (ek, dk) = generate_kem_keypair().unwrap();
    let envelope = MultiEnvelope::seal(&[ek], b"bytes test").unwrap();

    let bytes = envelope.to_bytes();
    assert_eq!(&bytes[0..4], b"PQGR");
    assert_eq!(bytes[4], 2);

    let parsed = MultiEnvelope::from_bytes(&bytes).unwrap();
    assert_eq!(parsed.open(&dk).unwrap(), b"bytes test");
}

#[test]
fn multi_envelope_rejects_truncated_and_extended() {
    let (ek, _) = generate_kem_keypair().unwrap();
    let bytes = MultiEnvelope::seal(&[ek], b"x").unwrap().to_bytes();

    assert!(MultiEnvelope::from_bytes(&bytes[..bytes.len() - 1]).is_err());
    let mut extended = bytes.clone();
    extended.push(0);
    assert!(MultiEnvelope::from_bytes(&extended).is_err());
    assert!(MultiEnvelope::from_bytes(&bytes[..10]).is_err());
}

#[test]
fn multi_envelope_empty_recipients_fails() {
    assert!(MultiEnvelope::seal(&[], b"nobody").is_err());
}

#[test]
fn v1_and_v2_envelopes_are_distinguishable() {
    let (ek, dk) = generate_kem_keypair().unwrap();

    let v1 = encrypt_bytes(&ek, b"v1").unwrap().to_bytes();
    assert_eq!(v1[4], 1);

    let v2 = MultiEnvelope::seal(&[ek.clone()], b"v2").unwrap().to_bytes();
    assert_eq!(v2[4], 2);

    // v1 parser must reject v2 and vice versa
    assert!(SealedEnvelope::from_bytes(&v2).is_err());
    let v2_parsed = MultiEnvelope::from_bytes(&v2).unwrap();
    assert_eq!(v2_parsed.open(&dk).unwrap(), b"v2");
}
