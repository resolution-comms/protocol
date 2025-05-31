use std::{ops::{Deref, DerefMut}, sync::Arc};

use aes_gcm::{aead::{Aead, OsRng}, aes::Aes256, AeadCore, Aes256Gcm, Key, KeyInit};
use generic_array::{GenericArray, typenum};
use oqs::{self, kem::{self, Ciphertext}, sig::{self, Signature}};
use serde::{Deserialize, Serialize};
use serde_with::serde_as;

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

#[serde_as]
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct SingleEncryptionCipherBody {
    pub origin: (kem::PublicKey, sig::PublicKey),

    #[serde_as(as = "B64")]
    pub nonce: Vec<u8>,
    pub shared: Ciphertext,

    #[serde_as(as = "B64")]
    pub cipher: Vec<u8>
}

pub type SingleCipher = Msgpack<SingleEncryptionCipherBody>;

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

    fn secret_keys(&self) -> (kem::SecretKey, sig::SecretKey) {
        (self.encryption.1.clone(), self.signing.1.clone())
    }

    pub fn encrypt(&self, target: &kem::PublicKey, data: impl AsRef<Vec<u8>>) -> crate::Result<(SingleCipher, Signature)> {
        let nonce = Aes256Gcm::generate_nonce(OsRng);
        let (encrypted_secret, ss) = self.kem.encapsulate(target)?;
        let encryption_key: Key<Aes256> = SharedSecret::try_from(ss.into_vec())?.into();
        let encrypted_data = Aes256Gcm::new(&encryption_key).encrypt(&nonce, data.as_ref().as_slice())?;
        let packed: SingleCipher = Msgpack::encode(&SingleEncryptionCipherBody {
            origin: self.public_keys(),
            nonce: nonce.to_vec(),
            shared: encrypted_secret,
            cipher: encrypted_data
        })?;
        let signature = self.sig.sign(packed.as_slice(), &self.secret_keys().1)?;
        Ok((packed, signature))
    }

    pub fn decrypt(&self, data: SingleCipher, signature: Signature, known_signer: Option<sig::PublicKey>) -> crate::Result<Vec<u8>> {
        let unpacked = data.decode()?;
        let signer = known_signer.unwrap_or(unpacked.origin.1);
        self.sig.verify(data.as_slice(),&signature,&signer)?;
        let shared_secret = self.kem.decapsulate(&self.secret_keys().0, &unpacked.shared)?;
        let aes_key: Key<Aes256> = SharedSecret::try_from(shared_secret.into_vec())?.into();
        let decrypted_data = Aes256Gcm::new(&aes_key).decrypt(unpacked.nonce.as_slice().into(), unpacked.cipher.as_slice())?;
        Ok(decrypted_data)
    }
}
