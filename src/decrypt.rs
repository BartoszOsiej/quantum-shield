use anyhow::Result;
use colored::*;
use std::fs;
use std::path::{Path, PathBuf};

use crate::crypto;
use crate::keyfile;

/// Default output path: strip the .pqg extension from the input.
fn default_output_path(input_path: &str) -> Result<PathBuf> {
    let p = Path::new(input_path);
    let stem = p
        .file_stem()
        .unwrap_or_default()
        .to_string_lossy()
        .to_string();
    let parent = p.parent().unwrap_or(Path::new("."));
    Ok(parent.join(stem))
}

/// Decrypt a file using your private key
pub fn decrypt_file(
    input_path: &str,
    private_key_path: &str,
    output_path: Option<&str>,
) -> Result<PathBuf> {
    let data = fs::read(input_path)?;

    let secret_key = keyfile::load_secret_key(private_key_path)?;

    // v2 multi-recipient: try our key against each recipient block
    if data.len() >= 5 && &data[0..4] == b"PQGR" && data[4] == 2 {
        let envelope = crypto::MultiEnvelope::from_bytes(&data)?;
        let plaintext = envelope.open(&secret_key)?;
        let out_path = match output_path {
            Some(p) => PathBuf::from(p),
            None => default_output_path(input_path)?,
        };
        fs::write(&out_path, &plaintext)?;
        println!("   {} {} bytes", "Decrypted:".dimmed(), plaintext.len());
        println!(
            "   {} {} (multi-recipient, {} blocks)",
            "Algorithm:".dimmed(),
            crypto::KEM_ALG,
            envelope.recipients.len()
        );
        return Ok(out_path);
    }

    // v1 single-recipient
    let envelope = crypto::SealedEnvelope::from_bytes(&data)?;

    // ML-KEM-768 decapsulate
    let shared_secret = crypto::kem_decapsulate(&secret_key, &envelope.kem_ciphertext)?;

    // Derive the same symmetric key
    let symmetric_key = crypto::derive_key(&shared_secret, &envelope.salt)?;

    // AES-256-GCM decrypt
    let plaintext = crypto::symmetric_decrypt(
        &symmetric_key,
        &envelope.symmetric_nonce,
        &envelope.encrypted_data,
    )?;

    let out_path = match output_path {
        Some(p) => PathBuf::from(p),
        None => default_output_path(input_path)?,
    };

    fs::write(&out_path, &plaintext)?;

    println!("   {} {} bytes", "Decrypted:".dimmed(), plaintext.len());
    println!("   {} {}", "Algorithm:".dimmed(), crypto::KEM_ALG);

    Ok(out_path)
}
