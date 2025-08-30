// Copyright (c) 2025 rust-cktap contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

use crate::error::{
    CertsError, CkTapError, DeriveError, DumpError, ReadError, SignPsbtError, UnsealError,
};
use crate::{ChainCode, PrivateKey, Psbt, PublicKey, check_cert, read};
use futures::lock::Mutex;
use rust_cktap::commands::{Authentication, Wait};
use std::sync::Arc;

#[derive(uniffi::Object)]
pub struct SatsCard(pub Mutex<rust_cktap::SatsCard>);

#[derive(uniffi::Record, Debug, Clone)]
pub struct SatsCardStatus {
    pub proto: u64,
    pub ver: String,
    pub birth: u64,
    pub active_slot: u8,
    pub num_slots: u8,
    pub addr: Option<String>,
    pub pubkey: Vec<u8>,
    pub auth_delay: Option<u8>,
}

#[derive(uniffi::Record, Clone)]
pub struct UnsealedSlot {
    slot: u8,
    privkey: Option<Arc<PrivateKey>>,
    pubkey: Arc<PublicKey>,
}

#[uniffi::export]
impl SatsCard {
    pub async fn status(&self) -> SatsCardStatus {
        let card = self.0.lock().await;
        SatsCardStatus {
            proto: card.proto as u64,
            ver: card.ver().to_string(),
            birth: card.birth as u64,
            active_slot: card.slots.0,
            num_slots: card.slots.1,
            addr: card.addr.clone(),
            pubkey: card.pubkey().to_bytes(),
            auth_delay: card.auth_delay().map(|d| d as u8),
        }
    }

    pub async fn address(&self) -> Result<String, ReadError> {
        let mut card = self.0.lock().await;
        card.address().await.map_err(ReadError::from)
    }

    pub async fn read(&self) -> Result<Vec<u8>, ReadError> {
        let mut card = self.0.lock().await;
        read(&mut *card, None).await
    }

    pub async fn wait(&self) -> Result<(), CkTapError> {
        let mut card = self.0.lock().await;
        // if auth delay call wait
        while card.auth_delay().is_some() {
            card.wait(None).await?;
        }
        Ok(())
    }

    pub async fn check_cert(&self) -> Result<(), CertsError> {
        let mut card = self.0.lock().await;
        check_cert(&mut *card).await
    }

    pub async fn new_slot(
        &self,
        slot: u8,
        chain_code: Option<Arc<ChainCode>>,
        cvc: String,
    ) -> Result<u8, CkTapError> {
        let mut card = self.0.lock().await;
        let chain_code = chain_code.map(|cc| cc.inner);
        card.new_slot(slot, chain_code, &cvc)
            .await
            .map_err(CkTapError::from)
    }

    pub async fn derive(&self) -> Result<ChainCode, DeriveError> {
        let mut card = self.0.lock().await;
        let chain_code = card.derive().await.map(|cc| ChainCode { inner: cc })?;
        Ok(chain_code)
    }

    pub async fn unseal(&self, slot: u8, cvc: String) -> Result<UnsealedSlot, UnsealError> {
        let mut card = self.0.lock().await;
        let (privkey, pubkey) = card.unseal(slot, &cvc).await?;
        let pubkey = Arc::new(PublicKey { inner: pubkey });
        let privkey = Some(Arc::new(PrivateKey { inner: privkey }));
        Ok(UnsealedSlot {
            slot,
            pubkey,
            privkey,
        })
    }

    pub async fn dump(&self, slot: u8, cvc: Option<String>) -> Result<UnsealedSlot, DumpError> {
        let mut card = self.0.lock().await;
        let (privkey, pubkey) = card.dump(slot, cvc).await?;
        let pubkey = Arc::new(PublicKey { inner: pubkey });
        let privkey = privkey.map(|sk| Arc::new(PrivateKey { inner: sk }));
        Ok(UnsealedSlot {
            slot,
            pubkey,
            privkey,
        })
    }

    pub async fn sign_psbt(
        &self,
        slot: u8,
        psbt: Arc<Psbt>,
        cvc: String,
    ) -> Result<Psbt, SignPsbtError> {
        let mut card = self.0.lock().await;
        let psbt = card
            .sign_psbt(slot, (*psbt).clone().inner, &cvc)
            .await
            .map(|psbt| Psbt { inner: psbt })?;
        Ok(psbt)
    }
}
