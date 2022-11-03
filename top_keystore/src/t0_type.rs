use hex::{FromHex, ToHex};
use serde::{de::Deserializer, ser::Serializer, Deserialize, Serialize};

use crate::top_utils::{BasePubKey, KeyType, TopAddress};

fn buffer_to_hex_with_prefix<T, S>(buffer: &T, serializer: S) -> Result<S::Ok, S::Error>
where
    T: AsRef<[u8]>,
    S: Serializer,
{
    serializer.serialize_str(&(String::from("0x") + &buffer.encode_hex::<String>()))
}

fn hex_prefixed_to_buffer<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
where
    D: Deserializer<'de>,
{
    use serde::de::Error;
    String::deserialize(deserializer).and_then(|string| {
        if !string.starts_with("0x") {
            return Err(Error::custom("hex string not start with 0x"));
        }
        Vec::from_hex(&string[2..]).map_err(|err| Error::custom(err.to_string()))
    })
}

#[derive(Debug, Deserialize, Serialize)]
pub struct T0Keystore {
    pub account_address: TopAddress,
    pub crypto: T0Crypto,
    pub hint: String,
    pub key_type: KeyType,
    pub public_key: BasePubKey,
}

/// "crypto" part of keystore json
#[derive(Debug, Deserialize, Serialize)]
pub struct T0Crypto {
    pub cipher: String,

    pub cipherparams: T0CipherparamsJson,

    #[serde(
        serialize_with = "buffer_to_hex_with_prefix",
        deserialize_with = "hex_prefixed_to_buffer"
    )]
    pub ciphertext: Vec<u8>,

    pub kdf: T0KdfType,

    pub kdfparams: T0KdfparamsType,

    #[serde(
        serialize_with = "buffer_to_hex_with_prefix",
        deserialize_with = "hex_prefixed_to_buffer"
    )]
    pub mac: Vec<u8>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct T0CipherparamsJson {
    #[serde(
        serialize_with = "buffer_to_hex_with_prefix",
        deserialize_with = "hex_prefixed_to_buffer"
    )]
    pub iv: Vec<u8>,
}

#[derive(Debug, Deserialize, Serialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum T0KdfType {
    Hkdf,
}

#[derive(Debug, Deserialize, Serialize, PartialEq)]
#[serde(untagged)]
/// Defines the various parameters used in the supported KDFs.
pub enum T0KdfparamsType {
    Hkdf {
        dklen: u8,
        #[serde(
            serialize_with = "buffer_to_hex_with_prefix",
            deserialize_with = "hex_prefixed_to_buffer"
        )]
        info: Vec<u8>,
        prf: String,
        #[serde(
            serialize_with = "buffer_to_hex_with_prefix",
            deserialize_with = "hex_prefixed_to_buffer"
        )]
        salt: Vec<u8>,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_keystore_ds_from_json_data() {
        let json_data = r#"
        {
            "account_address": "T00000La9XMpaTxFaVoC3TNG1nhh1dZhnmAVWts2",
            "crypto": {
                "cipher": "aes-256-cbc",
                "cipherparams": {
                    "iv": "0x3c2a2396e1068904246020d5f6502690"
                },
                "ciphertext": "0xf134f927bfc2ce9b937628ca23c304a67e602d04f70052110f9e41686cc585ed4b32d4ddc4f638066383bddee4745d8c",
                "kdf": "hkdf",
                "kdfparams": {
                    "dklen": 64,
                    "info": "0x4a86857a6ae2469f",
                    "prf": "sha3-256",
                    "salt": "0x48a16e6fae69f01dec9e2db9ffdf7cbcaf986876813b0a5ebf15ebbf3f6b6e54"
                },
                "mac": "0x2a2a805f10e556ddc5f2e1eb5d591bb6981f7e335b84dedc5c1fbfc545e06905"
            },
            "hint": "hint",
            "key_type": "owner",
            "public_key": "BIkTJTUj5rm2Ft4+irSt4PrZXkEuaRs8TTNV/LBKRDzXz2oUOtzVw/8sw0s/XuD5QOYgqC4fE69m1PWVexInjR4="
        }
        "#;
        let keystore: T0Keystore = serde_json::from_str(json_data).unwrap();
        assert_eq!(
            keystore.account_address,
            TopAddress::T0Address(String::from("T00000La9XMpaTxFaVoC3TNG1nhh1dZhnmAVWts2"))
        );

        assert_eq!(
            keystore.crypto.cipherparams.iv.as_slice(),
            hex::decode("3c2a2396e1068904246020d5f6502690")
                .unwrap()
                .as_slice()
        );

        assert_eq!(
            keystore.crypto.kdfparams,
            T0KdfparamsType::Hkdf {
                dklen: 64,
                info: hex::decode("4a86857a6ae2469f").unwrap(),
                prf: String::from("sha3-256"),
                salt: hex::decode(
                    "48a16e6fae69f01dec9e2db9ffdf7cbcaf986876813b0a5ebf15ebbf3f6b6e54"
                )
                .unwrap()
            }
        )
    }
}
