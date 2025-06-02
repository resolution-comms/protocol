use std::{fmt::Debug, ops::{Deref, DerefMut}, sync::Arc};

use aes_gcm::{aead::{Aead, OsRng}, aes::Aes256, AeadCore, Aes256Gcm, Key, KeyInit, Nonce};
use generic_array::{GenericArray, typenum};
use oqs::{self, kem::{self, Ciphertext}, sig};
use serde::{Deserialize, Serialize};
use serde_with::serde_as;
use uuid::Uuid;

use super::encodings::{Msgpack, B64};

#[serde_as]
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct SharedSecret(#[serde_as(as = "B64")] Vec<u8>);

impl From<GenericArray<u8, typenum::U32>> for SharedSecret {
    fn from(value: GenericArray<u8, typenum::U32>) -> Self {
        Self(value.to_vec())
    }
}

impl From<[u8; 32]> for SharedSecret {
    fn from(value: [u8; 32]) -> Self {
        Self(value.to_vec())
    }
}

impl TryFrom<Vec<u8>> for SharedSecret {
    type Error = crate::Error;
    fn try_from(value: Vec<u8>) -> Result<Self, Self::Error> {
        if value.len() != 32 {
            Err(crate::Error::BadLength(value.len(), 32))
        } else {
            Ok(Self(value))
        }
    }
}

impl Deref for SharedSecret {
    type Target = Vec<u8>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for SharedSecret {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl AsRef<Vec<u8>> for SharedSecret {
    fn as_ref(&self) -> &Vec<u8> {
        &self.0
    }
}

impl Into<Key<Aes256>> for SharedSecret {
    fn into(self) -> Key<Aes256> {
        Key::<Aes256>::from_slice(&self.0).clone()
    }
}

impl SharedSecret {
    pub fn generate() -> Self {
        Self(Aes256::generate_key(OsRng).to_vec())
    }
}

pub type SingleEncryption = (
    Msgpack<(
        Ciphertext, // Encrypted shared secret
        Vec<u8>, // Nonce
        Vec<u8> // Encrypted content
    )>, 
    sig::Signature
);

pub type GroupEncryption = (
    Msgpack<(
        Uuid, // Key ID
        Vec<u8>, // Nonce
        Vec<u8> //Encrypted content
    )>, 
    sig::Signature
);

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct GroupKey(Uuid, SharedSecret);

impl GroupKey {
    pub fn new() -> Self {
        Self(Uuid::new_v4(), SharedSecret::generate())
    }

    pub fn id(&self) -> Uuid {
        self.0.clone()
    }

    pub fn key(&self) -> SharedSecret {
        self.1.clone()
    }
}

#[derive(Serialize, Deserialize, Clone)]
pub struct EncryptionContext {
    encryption: (kem::PublicKey, kem::SecretKey),
    signing: (sig::PublicKey, sig::SecretKey),

    #[serde(skip, default = "EncryptionContext::default_kem_instance")]
    kem: Arc<kem::Kem>,

    #[serde(skip, default = "EncryptionContext::default_sig_instance")]
    sig: Arc<sig::Sig>
}

impl EncryptionContext {
    pub fn generate() -> crate::Result<Self> {
        let kem_instance = kem::Kem::new(kem::Algorithm::MlKem768)?;
        let sig_instance = sig::Sig::new(sig::Algorithm::Falcon512)?;
        let (epk, esk) = kem_instance.keypair()?;
        let (spk, ssk) = sig_instance.keypair()?;

        Ok(Self {
            encryption: (epk, esk),
            signing: (spk, ssk),
            kem: Arc::new(kem_instance),
            sig: Arc::new(sig_instance)
        })
    }

    fn default_kem_instance() -> Arc<kem::Kem> {
        Arc::new(kem::Kem::new(kem::Algorithm::MlKem768).expect("Should be able to create a KEM instance."))
    }

    fn default_sig_instance() -> Arc<sig::Sig> {
        Arc::new(sig::Sig::new(sig::Algorithm::Falcon512).expect("Should be able to create a SIG instance."))
    }

    pub fn public_keys(&self) -> (kem::PublicKey, sig::PublicKey) {
        (self.encryption.0.clone(), self.signing.0.clone())
    }

    pub fn secret_keys(&self) -> (kem::SecretKey, sig::SecretKey) {
        (self.encryption.1.clone(), self.signing.1.clone())
    }

    pub fn encrypt_direct(&self, target: impl AsRef<kem::PublicKey>, data: impl AsRef<Vec<u8>>) -> crate::Result<SingleEncryption> {
        let nonce = Aes256Gcm::generate_nonce(OsRng);
        let (opaque_key, ss) = self.kem.encapsulate(target.as_ref())?;
        let aes = Aes256Gcm::new_from_slice(ss.into_vec().as_slice())?;
        let encrypted_block = aes.encrypt(&nonce, data.as_ref().as_slice())?;
        let record = Msgpack::encode(&(opaque_key, nonce.clone().to_vec(), encrypted_block))?;
        let signature = self.sig.sign(record.as_slice(), &self.secret_keys().1)?;

        Ok((record, signature))
    }

    pub fn decrypt_direct(&self, data: SingleEncryption, signer: impl AsRef<sig::PublicKey>) -> crate::Result<Vec<u8>> {
        let (record, signature) = data;
        let _ = self.sig.verify(record.as_slice(), &signature, signer.as_ref())?;
        let (ciphertext, nonce, encrypted_block) = record.decode()?;
        let shared_secret = self.kem.decapsulate(&self.secret_keys().0, &ciphertext)?;
        let aes = Aes256Gcm::new_from_slice(shared_secret.into_vec().as_slice())?;
        let decrypted_block = aes.decrypt(Nonce::from_slice(nonce.as_slice()), encrypted_block.as_slice())?;

        Ok(decrypted_block)
    }

    pub fn encrypt_group(&self, key: GroupKey, targets: impl IntoIterator<Item = impl AsRef<kem::PublicKey>>, data: impl AsRef<Vec<u8>>) -> crate::Result<Vec<(kem::PublicKey, SingleEncryption)>> {
        let nonce = Aes256Gcm::generate_nonce(OsRng);
        let aes = Aes256Gcm::new_from_slice(key.key().as_slice())?;
        let encrypted_block = aes.encrypt(&nonce, data.as_ref().as_slice())?;
        let record = Msgpack::encode(&(key.id(), nonce.clone().to_vec(), encrypted_block))?;
        let signature = self.sig.sign(record.as_slice(), &self.secret_keys().1)?;
        let wrapped_data = Msgpack::encode(&(record, signature))?;

        let mut results = Vec::<(kem::PublicKey, SingleEncryption)>::new();
        for t in targets {
            let target = t.as_ref();
            results.push((target.clone(), self.encrypt_direct(t, wrapped_data.as_slice().to_vec())?));
        }

        Ok(results)
    }

    pub fn decrypt_group(&self, key: GroupKey, data: SingleEncryption, signer: impl AsRef<sig::PublicKey>) -> crate::Result<Vec<u8>> {
        let sign = signer.as_ref();
        let (group_data, signature) = Msgpack::<GroupEncryption>::from_binary(self.decrypt_direct(data, &signer)?)?.decode()?;
        let _ = self.sig.verify(group_data.as_slice(), &signature, &sign.clone())?;
        let (key_id, nonce, encrypted_block) = group_data.decode()?;
        if key_id != key.id() {
            return Err(crate::Error::from(crate::UserError::invalid_key_id(key.id(), key_id)));
        }
        let aes = Aes256Gcm::new_from_slice(key.key().as_slice())?;
        let decrypted_block = aes.decrypt(Nonce::from_slice(nonce.as_slice()), encrypted_block.as_slice())?;

        Ok(decrypted_block)
    }
}
