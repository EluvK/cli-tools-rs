mod error;
mod keystore;

pub use error::KeystoreError;
use keystore::{CipherparamsJson, CryptoJson, KdfType, KdfparamsType, Keystore};

use aes::cipher::{KeyIvInit, StreamCipher};
use digest::Update;
use scrypt::{scrypt, Params as ScryptParams};
use sha3::{Digest, Keccak256};
use std::{
    fs::File,
    io::{Read, Write},
    path::Path,
};
use uuid::Uuid;

use ethereum_types::H160 as Address;
use k256::{ecdsa::SigningKey, elliptic_curve::sec1::ToEncodedPoint, PublicKey};

/// Converts a K256 SigningKey to an Ethereum Address
pub fn address_from_pk<S>(pk: S) -> Result<Address, KeystoreError>
where
    S: AsRef<[u8]>,
{
    let secret_key = SigningKey::from_bytes(pk.as_ref())?;
    let public_key = PublicKey::from(&secret_key.verifying_key());
    let public_key = public_key.to_encoded_point(/* compress = */ false);
    let public_key = public_key.as_bytes();
    // println!("public_key is : {:?}", hex::encode(public_key));
    debug_assert_eq!(public_key[0], 0x04);
    let hash = keccak256(&public_key[1..]);
    Ok(Address::from_slice(&hash[12..]))
}

/// Convert a K256 SigningKey to public key
pub fn pubkey_from_pk<S>(pk: S) -> Result<String, KeystoreError>
where
    S: AsRef<[u8]>,
{
    let secret_key = SigningKey::from_bytes(pk.as_ref())?;
    let public_key = PublicKey::from(&secret_key.verifying_key());
    let public_key = public_key.to_encoded_point(/* compress = */ false);
    let public_key = public_key.as_bytes();
    Ok(hex::encode(public_key))
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

pub const DEFAULT_KEY_SIZE: usize = 32usize;
pub const DEFAULT_SALT_SIZE: usize = 32usize;
pub const DEFAULT_IV_SIZE: usize = 16usize;

const DEFAULT_CIPHER: &str = "aes-128-ctr";
const DEFAULT_KDF_PARAMS_DKLEN: u8 = 32u8;
const DEFAULT_KDF_PARAMS_LOG_N: u8 = 18u8; // The iteration count is used to slow down the computation
const DEFAULT_KDF_PARAMS_R: u32 = 8u32;
const DEFAULT_KDF_PARAMS_P: u32 = 1u32;

pub fn decrypt_key<P, S>(path: P, password: S) -> Result<Vec<u8>, KeystoreError>
where
    P: AsRef<Path>,
    S: AsRef<[u8]>,
{
    let mut file = File::open(path)?;
    let mut contents = String::new();
    file.read_to_string(&mut contents)?;
    let keystore: Keystore = serde_json::from_str(&contents)?;

    let key = match keystore.crypto.kdfparams {
        KdfparamsType::Scrypt {
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

    Ok(pk)
}

pub fn encrypt_key_with_args<P, PriK, S, SALT, IV>(
    dir: P,
    pk: PriK,
    password: S,
    salt: SALT,
    iv: IV,
) -> Result<String, KeystoreError>
where
    P: AsRef<Path>,
    PriK: AsRef<[u8]>,
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

    let mut ciphertext = pk.as_ref().to_vec();
    encryptor.apply_keystream(&mut ciphertext);

    let mac = Keccak256::new()
        .chain(&key[16..32])
        .chain(&ciphertext)
        .finalize();

    let id = Uuid::new_v4();
    let name = id.to_string();

    let keystore = Keystore {
        address: address_from_pk(&pk)?,
        crypto: CryptoJson {
            cipher: String::from(DEFAULT_CIPHER),
            ciphertext,
            cipherparams: CipherparamsJson { iv },
            kdf: KdfType::Scrypt,
            kdfparams: KdfparamsType::Scrypt {
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
    };

    let contents = serde_json::to_string(&keystore)?;

    let mut file = File::create(dir.as_ref().join(&name))?;
    file.write_all(contents.as_bytes())?;

    Ok(name)
}
