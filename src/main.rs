use pqguard::{decrypt, encrypt, keygen};

use anyhow::Result;
use clap::{Parser, Subcommand};
use colored::*;

#[derive(Parser)]
#[command(
    name = "pqguard",
    about = "🔒 Post-quantum file encryption using ML-KEM-768 + AES-256-GCM",
    version,
    long_about = "pqguard encrypts files using NIST-standardized post-quantum algorithms.\n\n\
        Algorithm: ML-KEM-768 (FIPS 203) for key exchange + AES-256-GCM for symmetric encryption.\n\
        This provides protection against both classical and quantum computer attacks."
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Generate a new keypair
    Keygen {
        /// Output directory for key files
        #[arg(short, long, default_value = ".")]
        output: String,

        /// Key alias/name
        #[arg(short, long, default_value = "default")]
        name: String,
    },

    /// Encrypt a file
    Encrypt {
        /// Input file to encrypt
        input: String,

        /// Recipient's public key file (repeat for multi-recipient encryption)
        #[arg(short, long = "recipient", value_name = "KEYFILE")]
        recipient: Vec<String>,

        /// Output file (default: input.pqg)
        #[arg(short, long)]
        output: Option<String>,

        /// Your private key for sender authentication
        #[arg(short, long)]
        sender_key: Option<String>,
    },

    /// Decrypt a file
    Decrypt {
        /// Input encrypted file (.pqg)
        input: String,

        /// Your private key file
        #[arg(short, long)]
        private_key: String,

        /// Output file (default: input without .pqg)
        #[arg(short, long)]
        output: Option<String>,
    },

    /// Show information about a key file
    Info {
        /// Key file to inspect
        key_file: String,
    },

    /// Verify a file's integrity
    Verify {
        /// Encrypted file
        input: String,
    },
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Keygen { output, name } => {
            println!("{}", "🔐 Generating post-quantum keypair...".cyan().bold());
            let paths = keygen::generate_keypair(&output, &name)?;
            println!("{} {}", "✅".green(), "Keypair generated:".green().bold(),);
            println!("   {} {}", "Public key:".dimmed(), paths.0.display());
            println!("   {} {}", "Private key:".dimmed(), paths.1.display());
            println!();
            println!(
                "{}",
                "⚠️  Keep your private key secret! Anyone with it can decrypt your files.".yellow()
            );
        }

        Commands::Encrypt {
            input,
            recipient,
            output,
            sender_key,
        } => {
            println!(
                "{}",
                format!("🔒 Encrypting '{}' with ML-KEM-768...", input)
                    .cyan()
                    .bold()
            );
            let out_path = encrypt::encrypt_file(
                &input,
                &recipient,
                output.as_deref(),
                sender_key.as_deref(),
            )?;
            println!(
                "{} {}",
                "✅".green(),
                format!("Encrypted → {}", out_path.display()).green().bold()
            );
        }

        Commands::Decrypt {
            input,
            private_key,
            output,
        } => {
            println!("{}", format!("🔓 Decrypting '{}'...", input).cyan().bold());
            let out_path = decrypt::decrypt_file(&input, &private_key, output.as_deref())?;
            println!(
                "{} {}",
                "✅".green(),
                format!("Decrypted → {}", out_path.display()).green().bold()
            );
        }

        Commands::Info { key_file } => {
            keygen::show_key_info(&key_file)?;
        }

        Commands::Verify { input } => {
            encrypt::verify_file(&input)?;
        }
    }

    Ok(())
}
