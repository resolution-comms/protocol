use std::{convert::Infallible, marker::PhantomData, str::FromStr};

use base64::prelude::*;
use rmpv::Value;
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use serde_with::serde_as;

pub type B64 =
    serde_with::base64::Base64<serde_with::base64::UrlSafe, serde_with::formats::Unpadded>;

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
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Msgpack<T: Serialize + DeserializeOwned = Value>(
    #[serde_as(as = "B64")] Vec<u8>,
    PhantomData<T>,
);

impl<T: Serialize + DeserializeOwned> Msgpack<T> {
    pub fn as_slice(&self) -> &[u8] {
        &self.0
    }

    pub fn encode(data: &T) -> crate::Result<Self> {
        Ok(Self(rmp_serde::to_vec(data)?, PhantomData))
    }

    pub fn decode(&self) -> crate::Result<T> {
        Ok(rmp_serde::from_slice(&self.0)?)
    }

    pub fn replace(&mut self, value: &T) -> crate::Result<Option<T>> {
        let old = if let Ok(decoded) = self.decode() {
            Some(decoded)
        } else {
            None
        };

        self.0 = rmp_serde::to_vec(value)?;
        Ok(old)
    }

    pub fn valid(&self) -> bool {
        self.decode().is_ok()
    }

    pub fn from_binary(data: impl IntoIterator<Item = u8>) -> crate::Result<Self> {
        let bytes: Vec<u8> = data.into_iter().collect();
        let _ = rmp_serde::from_slice::<T>(&bytes)?;
        Ok(Self(bytes, PhantomData))
    }
}
