use std::fs;
use tempfile::tempdir;

// Test the full encrypt/decrypt cycle
#[test]
fn test_full_cycle() {
    let dir = tempdir().unwrap();
    let dir_path = dir.path();

    // Generate keypair
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_pqguard"))
        .args(["keygen", "-o", &dir_path.to_string_lossy(), "-n", "test"])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "keygen failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let pub_key = dir_path.join("test.pqg.pub");
    let priv_key = dir_path.join("test.pqg.key");
    assert!(pub_key.exists());
    assert!(priv_key.exists());

    // Create test file
    let test_file = dir_path.join("test_input.txt");
    let test_content = b"Hello from the post-quantum future!";
    fs::write(&test_file, test_content).unwrap();

    // Encrypt
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_pqguard"))
        .args([
            "encrypt",
            &test_file.to_string_lossy(),
            "-r",
            &pub_key.to_string_lossy(),
        ])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "encrypt failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let encrypted_file = dir_path.join("test_input.pqg");
    assert!(encrypted_file.exists());

    // Decrypt
    let decrypted_file = dir_path.join("test_output.txt");
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_pqguard"))
        .args([
            "decrypt",
            &encrypted_file.to_string_lossy(),
            "--private-key",
            &priv_key.to_string_lossy(),
            "-o",
            &decrypted_file.to_string_lossy(),
        ])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "decrypt failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    // Verify content matches
    let decrypted_content = fs::read(&decrypted_file).unwrap();
    assert_eq!(decrypted_content, test_content);
}

// Test wrong key fails
#[test]
fn test_wrong_key_fails() {
    let dir = tempdir().unwrap();
    let dir_path = dir.path();

    // Generate two keypairs
    for name in ["alice", "bob"] {
        let output = std::process::Command::new(env!("CARGO_BIN_EXE_pqguard"))
            .args(["keygen", "-o", &dir_path.to_string_lossy(), "-n", name])
            .output()
            .unwrap();
        assert!(output.status.success());
    }

    // Create test file
    let test_file = dir_path.join("secret.txt");
    fs::write(&test_file, b"top secret").unwrap();

    // Encrypt with Alice's public key
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_pqguard"))
        .args([
            "encrypt",
            &test_file.to_string_lossy(),
            "-r",
            &dir_path.join("alice.pqg.pub").to_string_lossy(),
        ])
        .output()
        .unwrap();
    assert!(output.status.success());

    // Try to decrypt with Bob's private key — should fail
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_pqguard"))
        .args([
            "decrypt",
            &dir_path.join("secret.pqg").to_string_lossy(),
            "--private-key",
            &dir_path.join("bob.pqg.key").to_string_lossy(),
            "-o",
            &dir_path.join("wrong.txt").to_string_lossy(),
        ])
        .output()
        .unwrap();
    assert!(
        !output.status.success(),
        "Decrypt with wrong key should fail"
    );
}

// Test verify command
#[test]
fn test_verify_valid_file() {
    let dir = tempdir().unwrap();
    let dir_path = dir.path();

    // Generate keypair and encrypt
    std::process::Command::new(env!("CARGO_BIN_EXE_pqguard"))
        .args(["keygen", "-o", &dir_path.to_string_lossy(), "-n", "test"])
        .output()
        .unwrap();

    let test_file = dir_path.join("input.txt");
    fs::write(&test_file, b"test data").unwrap();

    std::process::Command::new(env!("CARGO_BIN_EXE_pqguard"))
        .args([
            "encrypt",
            &test_file.to_string_lossy(),
            "-r",
            &dir_path.join("test.pqg.pub").to_string_lossy(),
        ])
        .output()
        .unwrap();

    // Verify
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_pqguard"))
        .args(["verify", &dir_path.join("input.pqg").to_string_lossy()])
        .output()
        .unwrap();
    assert!(output.status.success());
    assert!(String::from_utf8_lossy(&output.stdout).contains("Valid pqguard file"));
}

// Test verify rejects invalid file
#[test]
fn test_verify_rejects_invalid() {
    let dir = tempdir().unwrap();
    let test_file = dir.path().join("garbage.bin");
    fs::write(&test_file, b"this is not a pqguard file").unwrap();

    let output = std::process::Command::new(env!("CARGO_BIN_EXE_pqguard"))
        .args(["verify", &test_file.to_string_lossy()])
        .output()
        .unwrap();
    assert!(!output.status.success());
}

// Test key info
#[test]
fn test_key_info() {
    let dir = tempdir().unwrap();

    std::process::Command::new(env!("CARGO_BIN_EXE_pqguard"))
        .args(["keygen", "-o", &dir.path().to_string_lossy(), "-n", "test"])
        .output()
        .unwrap();

    let output = std::process::Command::new(env!("CARGO_BIN_EXE_pqguard"))
        .args(["info", &dir.path().join("test.pqg.pub").to_string_lossy()])
        .output()
        .unwrap();
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("ML-KEM-768"));
    assert!(stdout.contains("PQGUARD-PUBLIC-KEY"));
}

// Test binary file encryption
#[test]
fn test_binary_file() {
    let dir = tempdir().unwrap();
    let dir_path = dir.path();

    std::process::Command::new(env!("CARGO_BIN_EXE_pqguard"))
        .args(["keygen", "-o", &dir_path.to_string_lossy(), "-n", "test"])
        .output()
        .unwrap();

    // Create binary file with random data
    let binary_data: Vec<u8> = (0..10000).map(|i| (i % 256) as u8).collect();
    let bin_file = dir_path.join("binary.dat");
    fs::write(&bin_file, &binary_data).unwrap();

    // Encrypt
    std::process::Command::new(env!("CARGO_BIN_EXE_pqguard"))
        .args([
            "encrypt",
            &bin_file.to_string_lossy(),
            "-r",
            &dir_path.join("test.pqg.pub").to_string_lossy(),
        ])
        .output()
        .unwrap();

    // Decrypt
    let output_file = dir_path.join("binary_dec.dat");
    std::process::Command::new(env!("CARGO_BIN_EXE_pqguard"))
        .args([
            "decrypt",
            &dir_path.join("binary.pqg").to_string_lossy(),
            "--private-key",
            &dir_path.join("test.pqg.key").to_string_lossy(),
            "-o",
            &output_file.to_string_lossy(),
        ])
        .output()
        .unwrap();

    let decrypted = fs::read(&output_file).unwrap();
    assert_eq!(decrypted, binary_data);
}

// Multi-recipient end-to-end: two recipients, both can decrypt
#[test]
fn test_multi_recipient_cycle() {
    let dir = tempdir().unwrap();
    let dir_path = dir.path();
    let bin = env!("CARGO_BIN_EXE_pqguard");

    for name in ["alice", "bob"] {
        let output = std::process::Command::new(bin)
            .args(["keygen", "-o", &dir_path.to_string_lossy(), "-n", name])
            .output()
            .unwrap();
        assert!(output.status.success());
    }

    let test_file = dir_path.join("shared.txt");
    fs::write(&test_file, b"readable by both").unwrap();

    let output = std::process::Command::new(bin)
        .args([
            "encrypt",
            &test_file.to_string_lossy(),
            "-r",
            &dir_path.join("alice.pqg.pub").to_string_lossy(),
            "-r",
            &dir_path.join("bob.pqg.pub").to_string_lossy(),
            "-o",
            &dir_path.join("shared.pqg").to_string_lossy(),
        ])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "multi-encrypt failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    for (name, out) in [("alice", "from_alice.txt"), ("bob", "from_bob.txt")] {
        let output = std::process::Command::new(bin)
            .args([
                "decrypt",
                &dir_path.join("shared.pqg").to_string_lossy(),
                "-p",
                &dir_path.join(format!("{name}.pqg.key")).to_string_lossy(),
                "-o",
                &dir_path.join(out).to_string_lossy(),
            ])
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "decrypt as {name} failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert_eq!(fs::read(dir_path.join(out)).unwrap(), b"readable by both");
    }
}
