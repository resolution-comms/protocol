use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Error, Debug, Serialize, Deserialize, Clone)]
#[serde(tag = "code", rename_all = "snake_case")]
pub enum UserError {
    #[error("Specified profile name is too long (expected <= 64 characters, got {length}).")]
    ProfileNameLength {
        length: usize
    },

    #[error("Profile names may contain only the characters Aa-Zz, 0-9, -, and _. Provided username: {provided}")]
    ProfileNameCharacters {
        provided: String
    }
}

impl UserError {
    pub fn prof_name_length(length: usize) -> Self {
        Self::ProfileNameLength { length }
    }

    pub fn prof_name_chars(value: impl AsRef<str>) -> Self {
        Self::ProfileNameCharacters { provided: value.as_ref().to_string() }
    }
}

#[derive(Error, Debug)]
pub enum Error {
    #[error("Cryptography error (AES): {0:?}")]
    AES(#[from] aes_gcm::Error),

    #[error("Base64 decoding error: {0:?}")]
    Base64Decoding(#[from] base64::DecodeError),

    #[error("MSGPACK decoding error: {0:?}")]
    MsgpackDecoding(#[from] rmp_serde::decode::Error),

    #[error("MSGPACK encoding error: {0:?}")]
    MsgpackEncoding(#[from] rmp_serde::encode::Error),

    #[error("Encountered internal OQS cryptography error: {0:?}")]
    OQS(#[from] oqs::Error),

    #[error("Invalid bytestring length: expected {0}, got {1}")]
    BadLength(usize, usize),

    #[error("Encountered a user error: {0:?}")]
    UserError(#[from] UserError),

    #[error("Uninitialized field: {0:?}")]
    UninitializedField(#[from] derive_builder::UninitializedFieldError),

    #[error(transparent)]
    Other(#[from] anyhow::Error),
}

pub type Result<T> = std::result::Result<T, Error>;
