use serde::{de::Deserializer, ser::Serializer, Deserialize, Serialize};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum TopUtilsError {
    #[error("KeyTypeError")]
    KeyTypeError,
}

#[derive(Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(untagged)]
pub enum TopAddress {
    T0Address(String),
    T8Address(String),
}

pub type BasePubKey = String;

// pub type T0Address = String;

fn owner_keytype_to_str<S>(serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    serializer.serialize_str(KeyType::Owner.as_str())
}

fn miner_keytype_to_str<S>(serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    serializer.serialize_str(KeyType::Miner.as_str())
}

fn str_to_keytype_owner<'de, D>(deserializer: D) -> Result<(), D::Error>
where
    D: Deserializer<'de>,
{
    use serde::de::Error;

    String::deserialize(deserializer).and_then(|string| {
        if KeyType::str_equal(&string, KeyType::Owner) {
            Ok(())
        } else {
            Err(Error::custom(TopUtilsError::KeyTypeError.to_string()))
        }
    })
}

fn str_to_keytype_miner<'de, D>(deserializer: D) -> Result<(), D::Error>
where
    D: Deserializer<'de>,
{
    use serde::de::Error;

    String::deserialize(deserializer).and_then(|string| {
        if KeyType::str_equal(&string, KeyType::Miner) {
            Ok(())
        } else {
            Err(Error::custom(TopUtilsError::KeyTypeError.to_string()))
        }
    })
}

#[derive(Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(untagged)]
pub enum KeyType {
    #[serde(
        serialize_with = "owner_keytype_to_str",
        deserialize_with = "str_to_keytype_owner"
    )]
    Owner,
    #[serde(
        serialize_with = "miner_keytype_to_str",
        deserialize_with = "str_to_keytype_miner"
    )]
    Miner,
}

impl KeyType {
    fn as_str(&self) -> &'static str {
        match self {
            KeyType::Owner => "owner",
            KeyType::Miner => "miner",
        }
    }
    fn from_str(data: &str) -> Result<KeyType, TopUtilsError> {
        match data {
            "owner" => Ok(KeyType::Owner),
            "miner" => Ok(KeyType::Miner),
            _ => Err(TopUtilsError::KeyTypeError),
        }
    }
    fn str_equal(data: &str, expect_type: KeyType) -> bool {
        match KeyType::from_str(data) {
            Ok(result_type) => {
                if result_type == expect_type {
                    return true;
                }
                return false;
            }
            Err(_) => false,
        }
    }
}
