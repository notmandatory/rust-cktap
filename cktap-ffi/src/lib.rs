uniffi::setup_scaffolding!();

use futures::lock::Mutex;
use rust_cktap::commands::{Authentication, Read};
use std::fmt::Debug;
use std::sync::Arc;

#[derive(Debug, thiserror::Error, uniffi::Error)]
pub enum CkTapError {
    #[error("Core Error: {msg}")]
    Core { msg: String },
    #[error("Transport Error: {msg}")]
    Transport { msg: String },
}

impl From<rust_cktap::Error> for CkTapError {
    fn from(e: rust_cktap::Error) -> Self {
        CkTapError::Core { msg: e.to_string() }
    }
}

#[uniffi::export(callback_interface)]
#[async_trait::async_trait]
pub trait CkTransport: Send + Sync {
    async fn transmit_apdu(&self, command_apdu: Vec<u8>) -> Result<Vec<u8>, CkTapError>;
}

pub struct CkTransportWrapper(Box<dyn CkTransport>);

#[async_trait::async_trait]
impl rust_cktap::CkTransport for CkTransportWrapper {
    async fn transmit_apdu(&self, command_apdu: Vec<u8>) -> Result<Vec<u8>, rust_cktap::Error> {
        self.0
            .transmit_apdu(command_apdu)
            .await
            .map_err(|e| rust_cktap::Error::Transport(e.to_string()))
    }
}

// TODO de-duplicate code between SatsCard, TapSigner and SatsChip

#[derive(uniffi::Object)]
pub struct SatsCard(Mutex<rust_cktap::SatsCard>);

#[uniffi::export]
impl SatsCard {
    pub async fn ver(&self) -> String {
        self.0.lock().await.ver().to_string()
    }

    pub async fn address(&self) -> Result<String, CkTapError> {
        self.0
            .lock()
            .await
            .address()
            .await
            .map_err(|e| CkTapError::Core { msg: e.to_string() })
    }

    pub async fn read(&self) -> Result<Vec<u8>, CkTapError> {
        self.0
            .lock()
            .await
            .read(None)
            .await
            .map(|pk| pk.serialize().to_vec())
            .map_err(|e| CkTapError::Core { msg: e.to_string() })
    }
    // TODO implement the rest of the commands
}

#[derive(uniffi::Object)]
pub struct TapSigner(Mutex<rust_cktap::TapSigner>);

#[uniffi::export]
impl TapSigner {
    pub async fn ver(&self) -> String {
        self.0.lock().await.ver().to_string()
    }

    pub async fn read(&self, cvc: String) -> Result<Vec<u8>, CkTapError> {
        self.0
            .lock()
            .await
            .read(Some(cvc))
            .await
            .map(|pk| pk.serialize().to_vec())
            .map_err(|e| CkTapError::Core { msg: e.to_string() })
    }
    // TODO implement the rest of the commands
}

#[derive(uniffi::Object)]
pub struct SatsChip(Mutex<rust_cktap::SatsChip>);

#[uniffi::export]
impl SatsChip {
    pub async fn ver(&self) -> String {
        self.0.lock().await.ver().to_string()
    }

    pub async fn read(&self) -> Result<Vec<u8>, CkTapError> {
        self.0
            .lock()
            .await
            .read(None)
            .await
            .map(|pk| pk.serialize().to_vec())
            .map_err(|e| CkTapError::Core { msg: e.to_string() })
    }
    // TODO implement the rest of the commands
}

#[derive(uniffi::Enum)]
pub enum CkTapCard {
    SatsCard(Arc<SatsCard>),
    TapSigner(Arc<TapSigner>),
    SatsChip(Arc<SatsChip>),
}

#[uniffi::export]
pub async fn to_cktap(transport: Box<dyn CkTransport>) -> Result<CkTapCard, CkTapError> {
    let wrapper = CkTransportWrapper(transport);
    let cktap: rust_cktap::CkTapCard = rust_cktap::commands::to_cktap(Arc::new(wrapper))
        .await
        .map_err(Into::<CkTapError>::into)?;

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

#[uniffi::export]
pub fn rand_nonce() -> Vec<u8> {
    rust_cktap::rand_nonce().to_vec()
}
