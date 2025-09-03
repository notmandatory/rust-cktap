// Copyright (c) 2025 rust-cktap contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

mod error;
mod sats_card;
mod sats_chip;
mod tap_signer;

uniffi::setup_scaffolding!();

use crate::error::{CertsError, CkTapError, ReadError, StatusError};
use crate::sats_card::SatsCard;
use crate::sats_chip::SatsChip;
use crate::tap_signer::TapSigner;
use futures::lock::Mutex;
use rust_cktap::shared::FactoryRootKey;
use rust_cktap::shared::{Certificate, Read};
use std::fmt::Debug;
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
) -> Result<String, ReadError> {
    card.read(cvc)
        .await
        .map(|pk| pk.to_string())
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
