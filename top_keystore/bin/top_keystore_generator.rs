use clap::Parser;
use rand::RngCore;
use top_keystore_tools_rs::{generate_T0_keystore, generate_T8_keystore, KeystoreError};

#[derive(Parser)]
#[clap(about = "generate keystore file")]
struct Args {
    /// password to encrypt keystore file
    password: String,

    /// specify private key in hex str (without `0x`)
    #[clap(short = 'p', long = "private_key")]
    private_key: Option<String>,

    /// create T0 keystore, or T8 by default
    #[clap(short = '0', long = "t0")]
    t0_account: bool,

    /// create minerkey, or owner key by default
    #[clap(short = 'm', long = "owner_address")]
    owner_address: Option<String>,
}

fn main() -> Result<(), KeystoreError> {
    let args = Args::parse();

    let mut rng = rand::thread_rng();

    const DEFAULT_KEY_SIZE: usize = 32usize;
    let mut pk = vec![0u8; DEFAULT_KEY_SIZE];

    if let Some(pk_str) = args.private_key {
        pk = hex::decode(pk_str)?;
    } else {
        rng.fill_bytes(pk.as_mut_slice());
    }

    if args.t0_account {
        let result = generate_T0_keystore(pk, args.password, args.owner_address)?;
        println!("{}", result);
    } else {
        let result = generate_T8_keystore(pk, args.password, args.owner_address)?;
        println!("{}", result);
    }

    Ok(())
}
