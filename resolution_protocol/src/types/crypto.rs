use std::{
    convert::Infallible,
    ops::{Deref, DerefMut},
    str::FromStr,
};

use aes_gcm::{
    Aes256Gcm,
    Key, // Or `Aes128Gcm`
    Nonce,
    aead::{Aead, AeadCore, KeyInit, OsRng},
};
use base64::prelude::*;
use serde::{Deserialize, Serialize};
use serde_with::serde_as;

type B64 = serde_with::base64::Base64<serde_with::base64::UrlSafe, serde_with::formats::Unpadded>;

#[derive(Clone)]
struct AesKey(Key<Aes256Gcm>);

impl From<Key<Aes256Gcm>> for AesKey {
    fn from(value: Key<Aes256Gcm>) -> Self {
        Self(value)
    }
}

impl TryFrom<Vec<u8>> for AesKey {
    type Error = Infallible;
    fn try_from(value: Vec<u8>) -> Result<Self, Self::Error> {
        Ok(Self(*Key::<Aes256Gcm>::from_slice(value.as_slice())))
    }
}

impl AsRef<[u8]> for AesKey {
    fn as_ref(&self) -> &[u8] {
        self.0.as_slice()
    }
}

impl Deref for AesKey {
    type Target = Key<Aes256Gcm>;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for AesKey {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Base64(String);

impl<T: IntoIterator<Item = u8>> From<T> for Base64 {
    fn from(value: T) -> Self {
        Self(BASE64_URL_SAFE_NO_PAD.encode(value.into_iter().collect::<Vec<u8>>()))
    }
}

impl AsRef<str> for Base64 {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl Into<String> for Base64 {
    fn into(self) -> String {
        self.0.clone()
    }
}

impl FromStr for Base64 {
    type Err = Infallible;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(Self(s.to_string()))
    }
}

impl TryInto<Vec<u8>> for Base64 {
    type Error = crate::Error;
    fn try_into(self) -> Result<Vec<u8>, Self::Error> {
        BASE64_URL_SAFE_NO_PAD
            .decode(self.0)
            .or_else(|e| Err(crate::Error::from(e)))
    }
}

impl Base64 {
    pub fn new(value: impl IntoIterator<Item = u8>) -> Self {
        Self::from(value)
    }

    pub fn value(&self) -> Vec<u8> {
        self.clone()
            .try_into()
            .expect("Contained value is non-parseable/wrong format.")
    }

    pub fn try_value(&self) -> crate::Result<Vec<u8>> {
        self.clone().try_into()
    }
}

#[serde_as]
#[derive(Clone, Serialize, Deserialize)]
pub struct SymmetricKey(#[serde_as(as = "B64")] AesKey);

impl SymmetricKey {
    pub fn new() -> Self {
        Self(Aes256Gcm::generate_key(OsRng).into())
    }

    fn cipher(&self) -> Aes256Gcm {
        Aes256Gcm::new(&self.0.0)
    }

    pub fn encrypt(&self, data: impl AsRef<[u8]>) -> crate::Result<String> {
        let nonce = Aes256Gcm::generate_nonce(OsRng);
        let ciphertext = self
            .cipher()
            .encrypt(&nonce, data.as_ref())
            .or_else(|e| Err(crate::Error::from(e)))?;

        Ok(String::new())
    }
}
