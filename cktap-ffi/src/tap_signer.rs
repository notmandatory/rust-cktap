// Copyright (c) 2025 rust-cktap contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

use crate::error::{
    CertsError, ChangeError, CkTapError, DeriveError, ReadError, SignPsbtError, XpubError,
};
use crate::{check_cert, read};
use futures::lock::Mutex;
use rust_cktap::shared::{Authentication, Nfc, Wait};
use rust_cktap::tap_signer::TapSignerShared;
use rust_cktap::{Psbt, rand_chaincode};
use std::str::FromStr;

#[derive(uniffi::Object)]
pub struct TapSigner(pub Mutex<rust_cktap::TapSigner>);

#[derive(uniffi::Record, Debug, Clone)]
pub struct TapSignerStatus {
    pub proto: u64,
    pub ver: String,
    pub birth: u64,
    pub path: Option<Vec<u64>>,
    pub num_backups: u64,
    pub pubkey: String,
    pub card_ident: String,
    pub auth_delay: Option<u8>,
}

#[uniffi::export]
impl TapSigner {
    pub async fn status(&self) -> TapSignerStatus {
        let card = self.0.lock().await;
        TapSignerStatus {
            proto: card.proto as u64,
            ver: card.ver().to_string(),
            birth: card.birth as u64,
            path: card
                .path
                .clone()
                .map(|p| p.iter().map(|&p| p as u64).collect()),
            num_backups: card.num_backups.unwrap_or_default() as u64,
            pubkey: card.pubkey().to_string(),
            card_ident: card.card_ident(),
            auth_delay: card.auth_delay().map(|d| d as u8),
        }
    }

    pub async fn read(&self, cvc: String) -> Result<String, ReadError> {
        let mut card = self.0.lock().await;
        read(&mut *card, Some(cvc)).await
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

    pub async fn init(&self, cvc: String) -> Result<(), CkTapError> {
        let mut card = self.0.lock().await;
        init(&mut *card, cvc).await
    }

    pub async fn sign_psbt(&self, psbt: String, cvc: String) -> Result<String, SignPsbtError> {
        let mut card = self.0.lock().await;
        let psbt = sign_psbt(&mut *card, psbt, cvc).await?;
        Ok(psbt)
    }

    pub async fn derive(&self, path: Vec<u32>, cvc: String) -> Result<String, DeriveError> {
        let mut card = self.0.lock().await;
        let pubkey = derive(&mut *card, path, cvc).await?;
        Ok(pubkey)
    }

    pub async fn change(&self, new_cvc: String, cvc: String) -> Result<(), ChangeError> {
        let mut card = self.0.lock().await;
        change(&mut *card, new_cvc, cvc).await?;
        Ok(())
    }

    pub async fn nfc(&self) -> Result<String, CkTapError> {
        let mut card = self.0.lock().await;
        let url = card.nfc().await?;
        Ok(url)
    }

    pub async fn xpub(&self, master: bool, cvc: String) -> Result<String, XpubError> {
        let mut card = self.0.lock().await;
        let xpub = card.xpub(master, &cvc).await?;
        Ok(xpub.to_string())
    }
}

/// Initialize a new TAPSIGNER card.
pub async fn init(
    card: &mut (impl TapSignerShared + Send + Sync),
    cvc: String,
) -> Result<(), CkTapError> {
    let chain_code = rand_chaincode();
    card.init(chain_code, &cvc).await.map_err(CkTapError::from)
}

/// Sign (but not finalize) the psbt
///
/// PSBT argument and return are encoded as base64 strings.
pub async fn sign_psbt(
    card: &mut (impl TapSignerShared + Send + Sync),
    psbt: String,
    cvc: String,
) -> Result<String, SignPsbtError> {
    let unsigned_psbt = Psbt::from_str(&psbt)?;
    let psbt = card.sign_psbt(unsigned_psbt, &cvc).await?;
    Ok(psbt.to_string())
}

/// Derive the pubkey at the given derivation path, return as hex serialized string
pub async fn derive(
    card: &mut (impl TapSignerShared + Send + Sync),
    path: Vec<u32>,
    cvc: String,
) -> Result<String, DeriveError> {
    let pubkey = card.derive(path, &cvc).await.map(|pk| pk.to_string())?;
    Ok(pubkey)
}

pub async fn change(
    card: &mut (impl TapSignerShared + Send + Sync),
    new_cvc: String,
    cvc: String,
) -> Result<(), ChangeError> {
    card.change(&new_cvc, &cvc).await?;
    Ok(())
}
