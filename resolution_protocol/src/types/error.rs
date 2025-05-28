use thiserror::Error;

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

    #[error(transparent)]
    Other(#[from] anyhow::Error),
}

pub type Result<T> = std::result::Result<T, Error>;
