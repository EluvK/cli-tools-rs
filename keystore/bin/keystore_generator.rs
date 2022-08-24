use std::path::Path;

use clap::Parser;
use keystore_tools_rs::{
    address_from_pk, encrypt_key_with_args, pubkey_from_pk, KeystoreError, DEFAULT_IV_SIZE,
    DEFAULT_KEY_SIZE, DEFAULT_SALT_SIZE,
};
use rand::RngCore;

#[derive(Parser)]
#[clap(about = "generate keystore file")]
struct Args {
    /// specify private key in hex str
    #[clap(short = 'p', long = "--private_key")]
    private_key: Option<String>,

    /// specify iv in hex str
    #[clap(short = 'i', long = "--iv")]
    iv: Option<String>,

    /// specify salt in hex str
    #[clap(short = 's', long = "--salt")]
    salt: Option<String>,

    /// password to encrypt keystore file
    password: String,

    /// Path to save keystore file
    path: Option<String>,

    /// show keystore info
    #[clap(short = 'd', long = "--debug")]
    debug: bool,
}

fn main() -> Result<(), KeystoreError> {
    let args = Args::parse();

    let file_path_str = args.path.unwrap_or(String::from("./keystore/"));

    let file_path = Path::new(&file_path_str);

    let mut rng = rand::thread_rng();

    let mut pk = vec![0u8; DEFAULT_KEY_SIZE];
    let mut iv = vec![0u8; DEFAULT_IV_SIZE];
    let mut salt = vec![0u8; DEFAULT_SALT_SIZE];

    if let Some(pk_str) = args.private_key {
        pk = hex::decode(pk_str)?;
    } else {
        rng.fill_bytes(pk.as_mut_slice());
    }

    if let Some(iv_str) = args.iv {
        iv = hex::decode(iv_str)?;
    } else {
        rng.fill_bytes(iv.as_mut_slice());
    }

    if let Some(salt_str) = args.salt {
        salt = hex::decode(salt_str)?;
    } else {
        rng.fill_bytes(salt.as_mut_slice());
    }

    let uuid = encrypt_key_with_args(file_path, &pk, &args.password, &salt, &iv)?;

    println!("keystore file generate: {}", uuid);

    if args.debug {
        println!("private key: {}", hex::encode(&pk).as_str());
        println!("public  key: {}", pubkey_from_pk(&pk)?);
        println!("eth address: {:?}", address_from_pk(&pk)?);
    }

    Ok(())
}
