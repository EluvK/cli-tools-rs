use crate::{
    error::KeystoreError,
    t0_type::{T0CipherparamsJson, T0Crypto, T0KdfType, T0KdfparamsType, T0Keystore},
    top_utils::{BasePubKey, KeyType, TopAddress},
};
use base58::ToBase58;
use hkdf::Hkdf;
use ripemd::Ripemd160;
use sha2::Sha256;
use sha3::{Digest, Sha3_256, Sha3_512};

use aes::cipher::{block_padding::Pkcs7, BlockEncryptMut, KeyIvInit};

use k256::{ecdsa::SigningKey, elliptic_curve::sec1::ToEncodedPoint, PublicKey};

fn base_prikey_to_top_base_pubkey<S>(pk: S) -> Result<BasePubKey, KeystoreError>
where
    S: AsRef<[u8]>,
{
    let prikey = base64::decode(&pk)?;

    let secret_key = SigningKey::from_bytes(prikey.as_ref())?;
    let public_key = PublicKey::from(&secret_key.verifying_key());
    let public_key = public_key.to_encoded_point(/* compress = */ false);
    let public_key = public_key.as_bytes();

    Ok(BasePubKey::from(base64::encode(public_key)))
}

fn base_prikey_to_base_account<S>(pk: S) -> Result<String, KeystoreError>
where
    S: AsRef<[u8]>,
{
    let prikey = base64::decode(&pk)?;

    let secret_key = SigningKey::from_bytes(prikey.as_ref())?;
    let public_key = PublicKey::from(&secret_key.verifying_key());
    let public_key = public_key.to_encoded_point(/* compress = */ false);
    let public_key = public_key.as_bytes();

    let mut hash = rip160(sha2_256(&public_key)).to_vec();

    hash.insert(0, 48); // top version use char '0', not BTC's hex 0x0

    let checksum_hash = sha2_256(sha2_256(&hash));

    let account_bytes = [&hash, &checksum_hash[..4]].concat();

    Ok(account_bytes.to_base58())
}

fn base_prikey_to_top_t0_account<S>(pk: S) -> Result<TopAddress, KeystoreError>
where
    S: AsRef<[u8]>,
{
    Ok(TopAddress::T0Address(
        String::from("T00000") + &base_prikey_to_base_account(&pk)?,
    ))
}

fn sha2_256<S>(bytes: S) -> [u8; 32]
where
    S: AsRef<[u8]>,
{
    let mut hasher = Sha256::new();
    hasher.update(&bytes);
    hasher.finalize().into()
}

fn sha3_256<S>(bytes: S) -> [u8; 32]
where
    S: AsRef<[u8]>,
{
    let mut hasher = Sha3_256::new();
    hasher.update(&bytes);
    hasher.finalize().into()
}

fn rip160<S>(bytes: S) -> [u8; 20]
where
    S: AsRef<[u8]>,
{
    let mut hasher = Ripemd160::new();
    hasher.update(&bytes);
    hasher.finalize().into()
}

const DEFAULT_CIPHER: &str = "aes-256-cbc";
const DEFAULT_KDF_TYPE: T0KdfType = T0KdfType::Hkdf;
const DEFAULT_KDF_HKDF_DKLEN: u8 = 64;
const DEFAULT_KDF_PRF: &str = "sha3-256"; // actually is "sha3-512"

#[allow(non_snake_case)]
pub fn generate_T0_key_with_args<PriKBase, S, INFO, SALT, IV>(
    pk: PriKBase,
    password: S,
    info: INFO,
    salt: SALT,
    iv: IV,
    is_miner: Option<String>,
) -> Result<T0Keystore, KeystoreError>
where
    PriKBase: AsRef<[u8]>,
    S: AsRef<[u8]>,
    INFO: AsRef<[u8]>,
    SALT: AsRef<[u8]>,
    IV: AsRef<[u8]>,
{
    let salt = salt.as_ref().to_vec();
    // println!("salt: {}", hex::encode(&salt));

    let info = info.as_ref().to_vec();
    // println!("info: {}", hex::encode(&info));

    let hk = Hkdf::<Sha3_512>::new(Some(&salt[..]), password.as_ref());
    let mut key = [0u8; 64];
    hk.expand(&info, &mut key)
        .expect("64 is a valid length for Sha512 to output");

    // println!("key: {}", hex::encode(&key));

    let iv = iv.as_ref().to_vec();
    // println!("iv: {}", hex::encode(&iv));

    type Aes256CbcEnc = cbc::Encryptor<aes::Aes256>;
    if iv.len() > 16 {
        println!("warning: iv length exceed. rest of it will not be used.");
    }
    if key.len() > 32 {
        // println!("warning: key length exceed. rest of it will not be used."); // always.
    }
    let key_fixed: [u8; 32] = key[0..32].try_into().unwrap();
    let iv_fixed: [u8; 16] = iv[0..16].try_into().unwrap();

    let mut buf = [0u8; 48];
    let ciphertext = Aes256CbcEnc::new(&key_fixed.into(), &iv_fixed.into())
        .encrypt_padded_b2b_mut::<Pkcs7>(pk.as_ref(), &mut buf)
        .unwrap()
        .to_vec();
    // println!("ciphertext: {}", hex::encode(&ciphertext));

    let hash_slice = [&key[32..], &ciphertext].concat();
    // println!("{}", hex::encode(&hash_slice));

    let mac = sha3_256(&hash_slice).to_vec();
    // println!("mac: {}", hex::encode(&mac));

    let mut top_keystore = T0Keystore {
        account_address: base_prikey_to_top_t0_account(&pk)?,
        crypto: T0Crypto {
            cipher: String::from(DEFAULT_CIPHER),
            cipherparams: T0CipherparamsJson { iv },
            ciphertext,
            kdf: DEFAULT_KDF_TYPE,
            kdfparams: T0KdfparamsType::Hkdf {
                dklen: DEFAULT_KDF_HKDF_DKLEN,
                info,
                prf: String::from(DEFAULT_KDF_PRF),
                salt,
            },
            mac: mac,
        },
        hint: String::from(""),
        key_type: KeyType::Owner,
        public_key: base_prikey_to_top_base_pubkey(&pk)?,
    };
    if is_miner.is_some() {
        println!("miner address is {}", base_prikey_to_base_account(&pk)?);
        top_keystore.key_type = KeyType::Worker;
        top_keystore.account_address = TopAddress::T0Address(is_miner.unwrap());
    }

    Ok(top_keystore)
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
        const DEFAULT_INFO_SIZE: usize = 8usize;

        let mut pk = vec![0u8; DEFAULT_KEY_SIZE];
        let mut salt = vec![0u8; DEFAULT_SALT_SIZE];
        let mut iv = vec![0u8; DEFAULT_IV_SIZE];
        let mut info = vec![0u8; DEFAULT_INFO_SIZE];

        rng.fill_bytes(pk.as_mut_slice());
        rng.fill_bytes(iv.as_mut_slice());
        rng.fill_bytes(salt.as_mut_slice());
        rng.fill_bytes(info.as_mut_slice());

        let prikey_base = base64::encode(&pk);
        println!("pk_base: {}", prikey_base);

        let keystore = generate_T0_key_with_args(prikey_base, "1234", info, salt, iv, None);
        println!("keystore: {:?}", keystore);
    }
}
