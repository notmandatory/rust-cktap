uniffi::setup_scaffolding!();

use rust_cktap::apdu::{AppletSelect, CommandApdu, ResponseApdu, StatusResponse};
use rust_cktap::{rand_nonce as core_rand_nonce, Error as CoreError};
use std::fmt::Debug;

#[derive(Debug, thiserror::Error, uniffi::Error)]
pub enum Error {
    #[error("Core Error: {msg}")]
    Core { msg: String },
    #[error("Transport Error: {msg}")]
    Transport { msg: String },
}

impl From<CoreError> for Error {
    fn from(e: CoreError) -> Self {
        Error::Core { msg: e.to_string() }
    }
}

#[derive(uniffi::Record)]
pub struct FfiStatusResponse {
    pub proto: u64,
    pub ver: String,
    pub birth: u64,
    // Flatten Option<(u8, u8)> to slot_0 and slot_1
    pub slot_0: Option<u8>,
    pub slot_1: Option<u8>,
    pub addr: Option<String>,
    pub tapsigner: Option<bool>,
    pub satschip: Option<bool>,
    pub path: Option<Vec<u64>>,
    pub num_backups: Option<u64>,
    pub pubkey: Vec<u8>,
    pub card_nonce: Vec<u8>, // Use Vec<u8> for [u8; 16]
    pub testnet: Option<bool>,
    pub auth_delay: Option<u64>,
}

impl From<StatusResponse> for FfiStatusResponse {
    fn from(sr: StatusResponse) -> Self {
        Self {
            proto: sr.proto as u64,
            ver: sr.ver,
            birth: sr.birth as u64,
            slot_0: sr.slots.map(|s| s.0),
            slot_1: sr.slots.map(|s| s.1),
            addr: sr.addr,
            tapsigner: sr.tapsigner,
            satschip: sr.satschip,
            path: sr.path.map(|p| p.into_iter().map(|u| u as u64).collect()),
            num_backups: sr.num_backups.map(|n| n as u64),
            pubkey: sr.pubkey,
            card_nonce: sr.card_nonce.to_vec(),
            testnet: sr.testnet,
            auth_delay: sr.auth_delay.map(|d| d as u64),
        }
    }
}

#[uniffi::export(callback_interface)]
pub trait CkTransportFfi: Send + Sync + Debug + 'static {
    fn transmit_apdu(&self, command_apdu: Vec<u8>) -> Result<Vec<u8>, Error>;
}

#[uniffi::export]
pub async fn get_status(transport: Box<dyn CkTransportFfi>) -> Result<FfiStatusResponse, Error> {
    let cmd = AppletSelect::default();
    let command_apdu = cmd.apdu_bytes();
    let rapdu = transport
        .transmit_apdu(command_apdu)
        .map_err(|e| Error::Transport { msg: e.to_string() })?;
    let response = StatusResponse::from_cbor(rapdu)?;
    Ok(response.into())
}

#[derive(uniffi::Record)]
pub struct TestRecord {
    pub message: String,
    pub count: u32,
}

// this is actually a class per Object not Record
#[derive(uniffi::Object)]
pub struct TestStruct {
    pub value: u32,
}

#[uniffi::export]
pub fn rand_nonce() -> Vec<u8> {
    core_rand_nonce().to_vec()
}
