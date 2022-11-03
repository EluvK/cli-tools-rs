use hex::{FromHex, ToHex};
use serde::{de::Deserializer, ser::Serializer, Deserialize, Serialize};
use uuid::Uuid;

use crate::top_utils::{BasePubKey, KeyType, TopAddress};

fn buffer_to_hex<T, S>(buffer: &T, serializer: S) -> Result<S::Ok, S::Error>
where
    T: AsRef<[u8]>,
    S: Serializer,
{
    serializer.serialize_str(&buffer.encode_hex::<String>())
}

fn hex_to_buffer<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
where
    D: Deserializer<'de>,
{
    use serde::de::Error;
    String::deserialize(deserializer)
        .and_then(|string| Vec::from_hex(&string).map_err(|err| Error::custom(err.to_string())))
}

#[derive(Debug, Deserialize, Serialize)]
pub struct T8Keystore {
    pub account_address: TopAddress,
    pub address: String,
    pub crypto: T8Crypto,
    pub hint: String,
    pub id: Uuid,
    pub key_type: KeyType,
    pub public_key: BasePubKey,
    pub version: u8,
}

/// "crypto" part of keystore json
#[derive(Debug, Deserialize, Serialize)]
pub struct T8Crypto {
    pub cipher: String,

    pub cipherparams: T8CipherparamsJson,

    #[serde(serialize_with = "buffer_to_hex", deserialize_with = "hex_to_buffer")]
    pub ciphertext: Vec<u8>,

    pub kdf: T8KdfType,

    pub kdfparams: T8KdfparamsType,

    #[serde(serialize_with = "buffer_to_hex", deserialize_with = "hex_to_buffer")]
    pub mac: Vec<u8>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct T8CipherparamsJson {
    #[serde(serialize_with = "buffer_to_hex", deserialize_with = "hex_to_buffer")]
    pub iv: Vec<u8>,
}

#[derive(Debug, Deserialize, Serialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum T8KdfType {
    Scrypt,
}

#[derive(Debug, Deserialize, Serialize, PartialEq)]
#[serde(untagged)]
/// Defines the various parameters used in the supported KDFs.
pub enum T8KdfparamsType {
    Scrypt {
        dklen: u8,
        n: u32,
        p: u32,
        r: u32,
        #[serde(serialize_with = "buffer_to_hex", deserialize_with = "hex_to_buffer")]
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
            "account_address" : "T800001eea1208209ee21012929fe4ea68fb7278fb7873",
            "address" : "1eea1208209ee21012929fe4ea68fb7278fb7873",
            "crypto" : {
                "cipher" : "aes-128-ctr",
                "cipherparams" : {
                    "iv" : "ef889e9219b4a14f193101a80e8e5fbf"
                },
                "ciphertext" : "46aea55a71ac280055bf7ac91d4dafef4f332970012f089ea4f8f2ecbfde1200",
                "kdf" : "scrypt",
                "kdfparams" : {
                    "dklen" : 32,
                    "n" : 262144,
                    "p" : 1,
                    "r" : 8,
                    "salt" : "1693e62e812f300fad43f689bfc74b171ad0624e8f9d7133a1c7267992c49164"
                },
                "mac" : "55ebd5ceb56ab72527c967a45df6c720facdf92a146ba5d469040e1525e11c22"
            },
            "hint" : "1234",
            "id" : "7e43faf7-f316-9eb0-c2b2-a53f420cc032",
            "key_type" : "owner",
            "public_key" : "BJQ1OL1V808dljOw8svItc74uuJO21FqniB1QT2xIAidUzfKNVU0rkKSzo++D5q+jnbyEYXD+Wv6C7p9wTSfPN8=",
            "version" : 3
        }
        "#;
        let keystore: T8Keystore = serde_json::from_str(json_data).unwrap();
        assert_eq!(
            keystore.address.as_bytes(),
            hex::decode("1eea1208209ee21012929fe4ea68fb7278fb7873")
                .unwrap()
                .as_slice()
        );

        assert_eq!(
            keystore.crypto.cipherparams.iv.as_slice(),
            hex::decode("ef889e9219b4a14f193101a80e8e5fbf")
                .unwrap()
                .as_slice()
        );

        assert_eq!(
            keystore.crypto.kdfparams,
            T8KdfparamsType::Scrypt {
                dklen: 32,
                n: 262144,
                p: 1,
                r: 8,
                salt: hex::decode(
                    "1693e62e812f300fad43f689bfc74b171ad0624e8f9d7133a1c7267992c49164"
                )
                .unwrap()
                .to_vec()
            }
        )
    }
}
