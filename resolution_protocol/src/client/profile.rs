use crate::types::crypto::EncryptionContext;
use aes_gcm::aead::OsRng;
use derive_builder::Builder;
use iroh::{RelayUrl, node_info::UserData};
use oqs::{kem, sig};
use regex::Regex;
use serde::{Deserialize, Serialize};

#[derive(Clone, Serialize, Deserialize)]
pub struct PublicProfileData {
    pub profile_id: String,

    #[serde(default)]
    pub display_name: Option<String>,

    #[serde(default)]
    pub pronouns: Option<String>,
    pub signing_key: sig::PublicKey,
    pub encryption_key: kem::PublicKey,
}

impl PublicProfileData {
    pub fn profile_name(&self) -> String {
        self.profile_id.split_once("#").unwrap().0.to_string()
    }

    pub fn discriminant(&self) -> String {
        self.profile_id.split_once("#").unwrap().1.to_string()
    }
}

#[derive(Clone, Serialize, Deserialize, Builder)]
#[builder(build_fn(error = "crate::Error", validate = "Self::validate"))]
pub struct Profile {
    profile_name: String,

    #[builder(setter(custom), default = "self.default_iroh_keys()")]
    iroh_keys: (iroh::PublicKey, iroh::SecretKey),

    #[builder(setter(custom), default = "self.default_encryption_context()?")]
    encryption_context: EncryptionContext,

    #[builder(setter(into, strip_option), default)]
    display_name: Option<String>,

    #[builder(setter(into, strip_option), default)]
    pronouns: Option<String>,

    #[builder(setter(custom), default = "self.default_preferred_relay()")]
    preferred_relay: Option<RelayUrl>,
}

impl ProfileBuilder {
    fn default_iroh_keys(&self) -> (iroh::PublicKey, iroh::SecretKey) {
        let secret = iroh::SecretKey::generate(&mut OsRng);
        let public = secret.public();
        (public, secret)
    }

    fn default_encryption_context(&self) -> crate::Result<EncryptionContext> {
        EncryptionContext::generate()
    }

    fn default_preferred_relay(&self) -> Option<RelayUrl> {
        Some(iroh::defaults::prod::default_na_relay_node().url)
    }

    pub fn iroh_keys(&mut self, public: iroh::PublicKey, private: iroh::SecretKey) {
        self.iroh_keys = Some((public, private));
    }

    pub fn encryption_context(&mut self, context: EncryptionContext) {
        self.encryption_context = Some(context);
    }

    pub fn with_relay(&mut self, url: RelayUrl) {
        self.preferred_relay = Some(Some(url));
    }

    pub fn without_relay(&mut self) {
        self.preferred_relay = Some(None);
    }

    fn validate(&self) -> crate::Result<()> {
        let valid_chars = Regex::new(r"^[a-zA-Z0-9\-_]*$").expect("Invalid static regex");
        if let Some(profile_name) = &self.profile_name {
            if profile_name.len() > 64 {
                Err(crate::UserError::prof_name_length(profile_name.len()).into())
            } else {
                if valid_chars.is_match(&profile_name) {
                    Ok(())
                } else {
                    Err(crate::UserError::prof_name_chars(profile_name.clone()).into())
                }
            }
        } else {
            Ok(())
        }
    }
}

impl Profile {
    pub fn builder() -> ProfileBuilder {
        ProfileBuilder::default()
    }

    pub fn profile_name(&self) -> String {
        self.profile_name.clone()
    }

    pub fn profile_id(&self) -> String {
        format!("{0}#{1}", self.profile_name(), self.discriminant())
    }

    pub fn discriminant(&self) -> String {
        let (encr, sign) = self.encryption_context.public_keys();
        let mut keycomb = Vec::<u8>::new();
        keycomb.extend(encr.into_vec());
        keycomb.extend(sign.into_vec());
        format!(
            "{:X}",
            crc::Crc::<u16>::new(&crc::CRC_16_IBM_SDLC).checksum(&keycomb)
        )
    }

    pub fn public_profile(&self) -> PublicProfileData {
        let (encryption, signing) = self.encryption_context.public_keys();
        PublicProfileData {
            profile_id: self.profile_id(),
            display_name: self.display_name.clone(),
            pronouns: self.pronouns.clone(),
            signing_key: signing,
            encryption_key: encryption,
        }
    }

    pub fn address(&self) -> iroh::NodeAddr {
        let mut addr = iroh::NodeAddr::new(self.iroh_keys.0);
        if let Some(relay) = &self.preferred_relay {
            addr = addr.with_relay_url(relay.clone());
        }

        addr
    }

    pub fn user_data(&self) -> UserData {
        UserData::try_from(String::from("role=client")).unwrap()
    }

    pub async fn make_endpoint(&self) -> crate::Result<iroh::Endpoint> {
        iroh::Endpoint::builder()
            .discovery_n0()
            .discovery_dht()
            .discovery_local_network()
            .user_data_for_discovery(self.user_data())
            .alpns(vec![crate::constants::PROTOCOL_ALPN.to_vec()])
            .secret_key(self.iroh_keys.1.clone())
            .bind()
            .await
            .or_else(|e| Err(crate::Error::Other(e)))
    }
}
