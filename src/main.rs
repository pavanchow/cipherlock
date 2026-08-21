use clap::{Parser, Subcommand};
use std::fs;
use std::path::PathBuf;
use std::process::ExitCode;

use cipherlock::format;

#[derive(Parser)]
#[command(name = "cipherlock", version, about = "A from scratch ChaCha20-Poly1305 authenticated encryption toolkit")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Encrypt a file with a passphrase
    Encrypt {
        input: PathBuf,
        output: PathBuf,
        #[arg(long = "pass")]
        pass: String,
    },
    /// Decrypt a file with a passphrase
    Decrypt {
        input: PathBuf,
        output: PathBuf,
        #[arg(long = "pass")]
        pass: String,
    },
}

fn main() -> ExitCode {
    let cli = Cli::parse();

    let result = match cli.command {
        Command::Encrypt { input, output, pass } => run_encrypt(&input, &output, &pass),
        Command::Decrypt { input, output, pass } => run_decrypt(&input, &output, &pass),
    };

    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("cipherlock: {e}");
            ExitCode::FAILURE
        }
    }
}

fn run_encrypt(input: &PathBuf, output: &PathBuf, pass: &str) -> Result<(), String> {
    let plaintext = fs::read(input).map_err(|e| format!("could not read {}: {e}", input.display()))?;
    let file = format::encrypt(pass, &plaintext);
    fs::write(output, file).map_err(|e| format!("could not write {}: {e}", output.display()))?;
    println!("encrypted {} -> {}", input.display(), output.display());
    Ok(())
}

fn run_decrypt(input: &PathBuf, output: &PathBuf, pass: &str) -> Result<(), String> {
    let file = fs::read(input).map_err(|e| format!("could not read {}: {e}", input.display()))?;
    let plaintext = format::decrypt(pass, &file).map_err(|e| e.to_string())?;
    fs::write(output, plaintext).map_err(|e| format!("could not write {}: {e}", output.display()))?;
    println!("decrypted {} -> {}", input.display(), output.display());
    Ok(())
}
