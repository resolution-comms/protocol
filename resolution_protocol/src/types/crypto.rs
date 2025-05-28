use std::{
    convert::Infallible,
    ops::{Deref, DerefMut}
};

use aes_gcm::{
    aead::{Aead, AeadCore, KeyInit, OsRng}, Aes256Gcm, Key, Nonce
};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use serde_with::serde_as;

use super::encodings::{Msgpack, B64};

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

pub type SymmetricCipher = Msgpack<(Vec<u8>, Vec<u8>)>;

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

    pub fn encrypt(&self, data: impl AsRef<[u8]>) -> crate::Result<SymmetricCipher> {
        let nonce = Aes256Gcm::generate_nonce(OsRng);
        let ciphertext = self
            .cipher()
            .encrypt(&nonce, data.as_ref())
            .or_else(|e| Err(crate::Error::from(e)))?;

        Msgpack::encode(&(nonce.to_vec(), ciphertext))
    }

    pub fn decrypt(&self, cipher: impl Into<SymmetricCipher>) -> crate::Result<Vec<u8>> {
        let msgpack = cipher.into();
        let (nonce, ciphertext) = msgpack.decode()?;
        self.cipher().decrypt(&Nonce::from_slice(&nonce), ciphertext.as_slice()).or_else(|e| Err(crate::Error::from(e)))
    }

    pub fn encrypt_data(&self, data: impl Serialize) -> crate::Result<SymmetricCipher> {
        let serialized = rmp_serde::to_vec(&data)?;
        self.encrypt(serialized)
    }

    pub fn decrypt_data<T: DeserializeOwned>(&self, cipher: impl Into<SymmetricCipher>) -> crate::Result<T> {
        let decrypted = self.decrypt(cipher)?;
        Ok(rmp_serde::from_slice::<T>(decrypted.as_slice())?)
    }
}
