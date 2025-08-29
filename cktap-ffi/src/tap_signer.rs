use crate::error::{CertsError, ChangeError, CkTapError, DeriveError, ReadError, SignPsbtError};
use crate::{ChainCode, Psbt, PublicKey, check_cert, read};
use futures::lock::Mutex;
use rust_cktap::commands::{Authentication, Wait};
use rust_cktap::tap_signer::TapSignerShared;
use std::sync::Arc;

#[derive(uniffi::Object)]
pub struct TapSigner(pub Mutex<rust_cktap::TapSigner>);

#[derive(uniffi::Record, Debug, Clone)]
pub struct TapSignerStatus {
    pub proto: u64,
    pub ver: String,
    pub birth: u64,
    pub path: Option<Vec<u64>>,
    pub num_backups: u64,
    pub pubkey: Vec<u8>,
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
            pubkey: card.pubkey().to_bytes(),
            auth_delay: card.auth_delay().map(|d| d as u8),
        }
    }

    pub async fn read(&self, cvc: String) -> Result<Vec<u8>, ReadError> {
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

    pub async fn init(&self, chain_code: Arc<ChainCode>, cvc: String) -> Result<(), CkTapError> {
        let mut card = self.0.lock().await;
        init(&mut *card, chain_code, cvc).await
    }

    pub async fn sign_psbt(&self, psbt: Arc<Psbt>, cvc: String) -> Result<Psbt, SignPsbtError> {
        let mut card = self.0.lock().await;
        let psbt = sign_psbt(&mut *card, psbt, cvc).await?;
        Ok(psbt)
    }

    pub async fn derive(&self, path: Vec<u32>, cvc: String) -> Result<PublicKey, DeriveError> {
        let mut card = self.0.lock().await;
        let pubkey = derive(&mut *card, path, cvc).await?;
        Ok(pubkey)
    }

    pub async fn change(&self, new_cvc: String, cvc: String) -> Result<(), ChangeError> {
        let mut card = self.0.lock().await;
        change(&mut *card, new_cvc, cvc).await?;
        Ok(())
    }
}

pub async fn init(
    card: &mut (impl TapSignerShared + Send + Sync),
    chain_code: Arc<ChainCode>,
    cvc: String,
) -> Result<(), CkTapError> {
    card.init(chain_code.inner, &cvc)
        .await
        .map_err(CkTapError::from)
}

pub async fn sign_psbt(
    card: &mut (impl TapSignerShared + Send + Sync),
    psbt: Arc<Psbt>,
    cvc: String,
) -> Result<Psbt, SignPsbtError> {
    let psbt = card
        .sign_psbt((*psbt).clone().inner, &cvc)
        .await
        .map(|psbt| Psbt { inner: psbt })?;
    Ok(psbt)
}

pub async fn derive(
    card: &mut (impl TapSignerShared + Send + Sync),
    path: Vec<u32>,
    cvc: String,
) -> Result<PublicKey, DeriveError> {
    let pubkey = card
        .derive(path, &cvc)
        .await
        .map(|pk| PublicKey { inner: pk })?;
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
