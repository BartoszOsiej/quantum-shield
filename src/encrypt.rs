use anyhow::{bail, Result};
use colored::*;
use std::fs;
use std::path::PathBuf;

use crate::crypto;
use crate::keyfile;

pub fn encrypt_file(
    input_path: &str,
    recipient_pubkey_paths: &[String],
    output_path: Option<&str>,
    _sender_key_path: Option<&str>,
) -> Result<PathBuf> {
    let plaintext = fs::read(input_path)?;
    if plaintext.is_empty() {
        bail!("Input file is empty");
    }
    if recipient_pubkey_paths.is_empty() {
        bail!("At least one recipient is required");
    }

    let recipient_pks: Vec<Vec<u8>> = recipient_pubkey_paths
        .iter()
        .map(|p| keyfile::load_public_key(p))
        .collect::<Result<Vec<_>>>()?;

    let data_len;
    let envelope_bytes = if recipient_pks.len() == 1 {
        // Single recipient → classic v1 envelope (unchanged format)
        let salt = crypto::generate_salt();
        let nonce = crypto::generate_nonce();
        let (shared_secret, kem_ciphertext) = crypto::kem_encapsulate(&recipient_pks[0])?;
        let symmetric_key = crypto::derive_key(&shared_secret, &salt)?;
        let encrypted_data = crypto::symmetric_encrypt(&symmetric_key, &nonce, &plaintext)?;
        data_len = encrypted_data.len();
        crypto::SealedEnvelope {
            kem_ciphertext,
            symmetric_nonce: nonce,
            salt,
            encrypted_data,
        }
        .to_bytes()
    } else {
        // Multiple recipients → v2 envelope, one independent block each
        let envelope = crypto::MultiEnvelope::seal(&recipient_pks, &plaintext)?;
        data_len = plaintext.len() * envelope.recipients.len();
        envelope.to_bytes()
    };

    let out_path = match output_path {
        Some(p) => PathBuf::from(p),
        None => {
            let mut p = PathBuf::from(input_path);
            p.set_extension("pqg");
            p
        }
    };

    fs::write(&out_path, &envelope_bytes)?;

    println!(
        "   {} {} recipient(s)",
        "Recipients:".dimmed(),
        recipient_pks.len()
    );
    println!(
        "   {} {} bytes → {} bytes",
        "Size:".dimmed(),
        plaintext.len(),
        envelope_bytes.len()
    );
    println!("   {} {}", "KEM:".dimmed(), crypto::KEM_ALG);
    println!("   {} {}", "Cipher:".dimmed(), crypto::SYMMETRIC_ALG);

    Ok(out_path)
}

pub fn verify_file(input_path: &str) -> Result<()> {
    let data = fs::read(input_path)?;
    match crypto::SealedEnvelope::from_bytes(&data) {
        Ok(envelope) => {
            println!("{}", "✅ Valid pqguard file".green().bold());
            println!(
                "   {} {} bytes",
                "KEM ciphertext:".dimmed(),
                envelope.kem_ciphertext.len()
            );
            println!(
                "   {} {} bytes",
                "Encrypted data:".dimmed(),
                envelope.encrypted_data.len()
            );
            Ok(())
        }
        Err(e) => {
            println!("{}", format!("❌ Invalid: {}", e).red().bold());
            bail!("Verification failed");
        }
    }
}
