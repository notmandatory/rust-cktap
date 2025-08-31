// Copyright (c) 2025 rust-cktap contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

mod error;
mod sats_card;
mod sats_chip;
mod tap_signer;

uniffi::setup_scaffolding!();

use crate::error::{
    CertsError, ChainCodeError, CkTapError, KeyError, PsbtError, ReadError, StatusError,
};
use crate::sats_card::SatsCard;
use crate::sats_chip::SatsChip;
use crate::tap_signer::TapSigner;
use futures::lock::Mutex;
use rust_cktap::Network;
use rust_cktap::shared::FactoryRootKey;
use rust_cktap::shared::{Certificate, Read};
use std::fmt::{Debug, Display, Formatter};
use std::str::FromStr;
use std::sync::Arc;

#[uniffi::export(callback_interface)]
#[async_trait::async_trait]
pub trait CkTransport: Send + Sync {
    async fn transmit_apdu(&self, command_apdu: Vec<u8>) -> Result<Vec<u8>, CkTapError>;
}

pub struct CkTransportWrapper(Box<dyn CkTransport>);

#[async_trait::async_trait]
impl rust_cktap::CkTransport for CkTransportWrapper {
    async fn transmit_apdu(
        &self,
        command_apdu: Vec<u8>,
    ) -> Result<Vec<u8>, rust_cktap::CkTapError> {
        self.0
            .transmit_apdu(command_apdu)
            .await
            .map_err(|e| rust_cktap::CkTapError::Transport(e.to_string()))
    }
}

#[derive(uniffi::Object, Clone, Eq, PartialEq)]
pub struct PrivateKey {
    inner: rust_cktap::PrivateKey,
}

#[uniffi::export]
impl PrivateKey {
    #[uniffi::constructor]
    pub fn from(data: Vec<u8>) -> Result<Self, KeyError> {
        Ok(Self {
            inner: rust_cktap::PrivateKey::from_slice(data.as_slice(), Network::Bitcoin)
                .map_err(|e| KeyError::Secp256k1 { msg: e.to_string() })?,
        })
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        self.inner.to_bytes()
    }
}

#[derive(uniffi::Object, Clone, Eq, PartialEq)]
pub struct PublicKey {
    inner: rust_cktap::PublicKey,
}

#[uniffi::export]
impl PublicKey {
    #[uniffi::constructor]
    pub fn from(data: Vec<u8>) -> Result<Self, KeyError> {
        Ok(Self {
            inner: rust_cktap::PublicKey::from_slice(data.as_slice())
                .map_err(|e| KeyError::Secp256k1 { msg: e.to_string() })?,
        })
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        self.inner.to_bytes()
    }
}

#[derive(uniffi::Object, Clone, Eq, PartialEq)]
pub struct ChainCode {
    inner: rust_cktap::ChainCode,
}

#[uniffi::export]
impl ChainCode {
    #[uniffi::constructor]
    pub fn from_bytes(data: Vec<u8>) -> Result<Self, ChainCodeError> {
        let data: [u8; 32] = data.try_into()?;
        Ok(Self {
            inner: rust_cktap::ChainCode::from(data),
        })
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        self.inner.to_bytes().to_vec()
    }
}

#[derive(uniffi::Object, Clone, Eq, PartialEq)]
pub struct Psbt {
    inner: rust_cktap::Psbt,
}

#[uniffi::export]
impl Psbt {
    #[uniffi::constructor]
    pub fn from_base64(data: String) -> Result<Self, PsbtError> {
        Ok(Self {
            inner: rust_cktap::Psbt::from_str(&data)?,
        })
    }

    pub fn to_base64(&self) -> String {
        self.inner.to_string()
    }
}

#[derive(uniffi::Object, Clone, Eq, PartialEq)]
pub struct Xpub {
    inner: rust_cktap::Xpub,
}

#[uniffi::export]
impl Xpub {
    pub fn encode(&self) -> Vec<u8> {
        self.inner.encode().to_vec()
    }
}

impl Display for Xpub {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.inner)
    }
}

#[derive(uniffi::Enum)]
pub enum CkTapCard {
    SatsCard(Arc<SatsCard>),
    TapSigner(Arc<TapSigner>),
    SatsChip(Arc<SatsChip>),
}

#[uniffi::export]
pub async fn to_cktap(transport: Box<dyn CkTransport>) -> Result<CkTapCard, StatusError> {
    let wrapper = CkTransportWrapper(transport);
    let cktap: rust_cktap::CkTapCard = rust_cktap::shared::to_cktap(Arc::new(wrapper)).await?;

    match cktap {
        rust_cktap::CkTapCard::SatsCard(sc) => {
            Ok(CkTapCard::SatsCard(Arc::new(SatsCard(Mutex::new(sc)))))
        }
        rust_cktap::CkTapCard::TapSigner(ts) => {
            Ok(CkTapCard::TapSigner(Arc::new(TapSigner(Mutex::new(ts)))))
        }
        rust_cktap::CkTapCard::SatsChip(sc) => {
            Ok(CkTapCard::SatsChip(Arc::new(SatsChip(Mutex::new(sc)))))
        }
    }
}

// command helpers

async fn read(
    card: &mut (impl Read + Send + Sync),
    cvc: Option<String>,
) -> Result<Vec<u8>, ReadError> {
    card.read(cvc)
        .await
        .map(|pk| pk.to_bytes())
        .map_err(ReadError::from)
}

async fn check_cert(card: &mut (impl Certificate + Send + Sync)) -> Result<(), CertsError> {
    match card.check_certificate().await? {
        FactoryRootKey::Pub(_) => Ok(()),
        FactoryRootKey::Dev(_) => Err(CertsError::InvalidRootCert {
            msg: "Developer Cert Found".to_string(),
        }),
    }
}
