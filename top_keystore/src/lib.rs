mod error;
mod t0_algorithm;
mod t0_type;
mod t8_algorithm;
mod t8_type;
mod top_utils;

pub use error::KeystoreError;
use rand::RngCore;

use crate::{t0_algorithm::generate_T0_key_with_args, t8_algorithm::generate_T8_key_with_args};

#[allow(non_snake_case)]
pub fn generate_T0_keystore<PriKBase, S>(
    pk: PriKBase,
    password: S,
    is_miner: Option<String>,
) -> Result<String, KeystoreError>
where
    PriKBase: AsRef<[u8]>,
    S: AsRef<[u8]>,
{
    let mut rng = rand::thread_rng();

    const DEFAULT_SALT_SIZE: usize = 32usize;
    const DEFAULT_IV_SIZE: usize = 16usize;
    const DEFAULT_INFO_SIZE: usize = 8usize;

    let mut salt = vec![0u8; DEFAULT_SALT_SIZE];
    let mut iv = vec![0u8; DEFAULT_IV_SIZE];
    let mut info = vec![0u8; DEFAULT_INFO_SIZE];

    rng.fill_bytes(iv.as_mut_slice());
    rng.fill_bytes(salt.as_mut_slice());
    rng.fill_bytes(info.as_mut_slice());

    let prikey_base = base64::encode(&pk);

    // println!("base prikey {}", prikey_base);

    let keystore = generate_T0_key_with_args(prikey_base, password, info, salt, iv, is_miner)?;

    let result = serde_json::to_string(&keystore)?;

    Ok(result)
}

#[allow(non_snake_case)]
pub fn generate_T8_keystore<PriK, S>(
    pk: PriK,
    password: S,
    is_miner: Option<String>,
) -> Result<String, KeystoreError>
where
    PriK: AsRef<[u8]>,
    S: AsRef<[u8]>,
{
    let mut rng = rand::thread_rng();

    const DEFAULT_SALT_SIZE: usize = 32usize;
    const DEFAULT_IV_SIZE: usize = 16usize;

    let mut salt = vec![0u8; DEFAULT_SALT_SIZE];
    let mut iv = vec![0u8; DEFAULT_IV_SIZE];

    rng.fill_bytes(iv.as_mut_slice());
    rng.fill_bytes(salt.as_mut_slice());

    let prikey_hex = hex::encode(&pk);

    // println!("hex prikey {}", prikey_hex);

    let keystore = generate_T8_key_with_args(prikey_hex, password, salt, iv, is_miner)?;

    let result = serde_json::to_string(&keystore)?;

    Ok(result)
}
