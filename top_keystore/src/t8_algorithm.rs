use crate::{
    error::KeystoreError,
    t8_type::{T8CipherparamsJson, T8Crypto, T8KdfType, T8KdfparamsType, T8Keystore},
    top_utils::{BasePubKey, KeyType, TopAddress},
};

use aes::cipher::{KeyIvInit, StreamCipher};
use digest::Update;
use k256::{ecdsa::SigningKey, elliptic_curve::sec1::ToEncodedPoint, PublicKey};
use scrypt::{scrypt, Params as ScryptParams};
use sha3::{Digest, Keccak256};
use uuid::Uuid;

fn hex_prikey_to_top_base_pubkey<S>(pk: S) -> Result<BasePubKey, KeystoreError>
where
    S: AsRef<[u8]>,
{
    let prikey = hex::decode(&pk)?;

    let secret_key = SigningKey::from_bytes(prikey.as_ref())?;
    let public_key = PublicKey::from(&secret_key.verifying_key());
    let public_key = public_key.to_encoded_point(/* compress = */ false);
    let public_key = public_key.as_bytes();

    Ok(BasePubKey::from(base64::encode(public_key)))
}

fn hex_prikey_to_eth_account<S>(pk: S) -> Result<String, KeystoreError>
where
    S: AsRef<[u8]>,
{
    let prikey = hex::decode(&pk)?;

    let secret_key = SigningKey::from_bytes(prikey.as_ref())?;
    let public_key = PublicKey::from(&secret_key.verifying_key());
    let public_key = public_key.to_encoded_point(/* compress = */ false);
    let public_key = public_key.as_bytes();
    // println!("public_key is : {:?}", hex::encode(public_key));
    debug_assert_eq!(public_key[0], 0x04);
    let hash = keccak256(&public_key[1..]);
    Ok(hex::encode(&hash[12..]))
}

fn hex_prikey_to_top_t8_account<S>(pk: S) -> Result<TopAddress, KeystoreError>
where
    S: AsRef<[u8]>,
{
    let eth_address = hex_prikey_to_eth_account(pk)?;
    Ok(TopAddress::T8Address(String::from("T80000") + &eth_address))
}

/// Compute the Keccak-256 hash of input bytes.
fn keccak256<S>(bytes: S) -> [u8; 32]
where
    S: AsRef<[u8]>,
{
    let mut hasher = Keccak256::new();
    Digest::update(&mut hasher, bytes.as_ref());
    hasher.finalize().into()
}

const DEFAULT_CIPHER: &str = "aes-128-ctr";
const DEFAULT_KDF_PARAMS_DKLEN: u8 = 32u8;
const DEFAULT_KDF_PARAMS_LOG_N: u8 = 18u8; // The iteration count is used to slow down the computation
const DEFAULT_KDF_PARAMS_R: u32 = 8u32;
const DEFAULT_KDF_PARAMS_P: u32 = 1u32;

#[allow(non_snake_case)]
pub fn generate_T8_key_with_args<PriKHex, S, SALT, IV>(
    pk: PriKHex,
    password: S,
    salt: SALT,
    iv: IV,
    is_miner: Option<String>,
) -> Result<T8Keystore, KeystoreError>
where
    PriKHex: AsRef<[u8]>,
    S: AsRef<[u8]>,
    SALT: AsRef<[u8]>,
    IV: AsRef<[u8]>,
{
    let salt = salt.as_ref().to_vec();
    let iv = iv.as_ref().to_vec();

    let mut key = vec![0u8; DEFAULT_KDF_PARAMS_DKLEN as usize];
    let scrypt_params = ScryptParams::new(
        DEFAULT_KDF_PARAMS_LOG_N,
        DEFAULT_KDF_PARAMS_R,
        DEFAULT_KDF_PARAMS_P,
    )?;
    scrypt(password.as_ref(), &salt, &scrypt_params, key.as_mut_slice())?;

    let mut encryptor = ctr::Ctr128BE::<aes::Aes128>::new((&key[..16]).into(), (&iv[..16]).into());

    let mut ciphertext = hex::decode(&pk)?;
    encryptor.apply_keystream(&mut ciphertext);

    let mac = Keccak256::new()
        .chain(&key[16..32])
        .chain(&ciphertext)
        .finalize();

    let id = Uuid::new_v4();

    let mut top_keystore = T8Keystore {
        account_address: hex_prikey_to_top_t8_account(&pk)?,
        address: hex_prikey_to_eth_account(&pk)?,
        crypto: T8Crypto {
            cipher: String::from(DEFAULT_CIPHER),
            ciphertext,
            cipherparams: T8CipherparamsJson { iv },
            kdf: T8KdfType::Scrypt,
            kdfparams: T8KdfparamsType::Scrypt {
                dklen: DEFAULT_KDF_PARAMS_DKLEN,
                n: 2u32.pow(DEFAULT_KDF_PARAMS_LOG_N as u32),
                p: DEFAULT_KDF_PARAMS_P,
                r: DEFAULT_KDF_PARAMS_R,
                salt,
            },
            mac: mac.to_vec(),
        },
        id,
        version: 3,
        hint: String::from(""),
        key_type: KeyType::Owner,
        public_key: hex_prikey_to_top_base_pubkey(&pk)?,
    };
    if is_miner.is_some() {
        println!("miner address is {}", top_keystore.address);
        top_keystore.key_type = KeyType::Worker;
        top_keystore.account_address = TopAddress::T8Address(is_miner.clone().unwrap());
        top_keystore.address = is_miner.unwrap().chars().skip(6).collect();
    }

    Ok(top_keystore)
}

#[allow(non_snake_case)]
pub fn decrypt_T8_keystore<S>(keystore: T8Keystore, password: S) -> Result<String, KeystoreError>
where
    S: AsRef<[u8]>,
{
    let key = match keystore.crypto.kdfparams {
        T8KdfparamsType::Scrypt {
            dklen,
            n,
            p,
            r,
            salt,
        } => {
            let mut key = vec![0u8; dklen as usize];
            let log_n = (n as f32).log2() as u8;
            let scrypt_params = ScryptParams::new(log_n, r, p)?;
            scrypt(password.as_ref(), &salt, &scrypt_params, key.as_mut_slice())?;
            key
        }
    };
    let derive_mac = Keccak256::new()
        .chain(&key[16..32])
        .chain(&keystore.crypto.ciphertext)
        .finalize();
    if derive_mac.as_slice() != keystore.crypto.mac.as_slice() {
        return Err(KeystoreError::MacMismatch);
    }
    let mut decryptor = ctr::Ctr128BE::<aes::Aes128>::new(
        (&key[..16]).into(),
        (&keystore.crypto.cipherparams.iv[..16]).into(),
    );

    let mut pk = keystore.crypto.ciphertext.clone();
    decryptor.apply_keystream(&mut pk);

    Ok(String::from(hex::encode(pk)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::RngCore;
    #[test]
    fn test_t0_generate() {
        let mut rng = rand::thread_rng();

        const DEFAULT_KEY_SIZE: usize = 32usize;
        const DEFAULT_SALT_SIZE: usize = 32usize;
        const DEFAULT_IV_SIZE: usize = 16usize;

        let mut pk = vec![0u8; DEFAULT_KEY_SIZE];
        let mut salt = vec![0u8; DEFAULT_SALT_SIZE];
        let mut iv = vec![0u8; DEFAULT_IV_SIZE];

        rng.fill_bytes(pk.as_mut_slice());
        rng.fill_bytes(iv.as_mut_slice());
        rng.fill_bytes(salt.as_mut_slice());

        let prikey_hex = hex::encode(&pk);
        println!("prikey_hex: {}", prikey_hex);

        let keystore = generate_T8_key_with_args(&prikey_hex, "1234", salt, iv, None);
        println!("keystore: {:?}", keystore);
    }
}
