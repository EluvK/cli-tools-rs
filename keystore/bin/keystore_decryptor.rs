use std::path::Path;

use keystore_tools_rs::{decrypt_key, KeystoreError};

use clap::Parser;

#[derive(Parser)]
#[clap(about = "decrypt keystore file")]
struct Args {
    /// password to encrypt keystore file
    password: String,

    /// Path to save keystore file
    file: String,
}

fn main() -> Result<(), KeystoreError> {
    let args = Args::parse();
    let file_path_str = args.file;
    let file_path = Path::new(&file_path_str);
    let result = decrypt_key(file_path, args.password)?;
    println!("private key: {}", hex::encode(result));
    Ok(())
}
