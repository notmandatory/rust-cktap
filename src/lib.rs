use ciborium::de::from_reader;
use ciborium::ser::into_writer;
use ciborium::value::Value;
use serde::{Deserialize, Serialize};
use std::fmt::Debug;

pub const APP_ID: [u8; 15] = *b"\xf0CoinkiteCARDv1";

pub const SELECT_CLA_INS_P1P2: [u8; 4] = [0x00, 0xA4, 0x04, 0x00];
pub const CBOR_CLA_INS_P1P2: [u8; 4] = [0x00, 0xCB, 0x00, 0x00];

// require nonce sizes (bytes)
pub const CARD_NONCE_SIZE: usize = 16;
pub const USER_NONCE_SIZE: usize = 16;

// Errors

#[derive(Debug)]
pub enum Error {
    CiborDe(String),
    CiborValue(String),
    CkTap {
        error: String,
        code: usize,
    },
    #[cfg(feature = "pcsc")]
    PcSc(String),
}

impl<T> From<ciborium::de::Error<T>> for Error
where
    T: core::fmt::Debug,
{
    fn from(e: ciborium::de::Error<T>) -> Self {
        Error::CiborDe(e.to_string())
    }
}

impl From<ciborium::value::Error> for Error {
    fn from(e: ciborium::value::Error) -> Self {
        Error::CiborDe(e.to_string())
    }
}

#[cfg(feature = "pcsc")]
impl From<pcsc::Error> for Error {
    fn from(e: pcsc::Error) -> Self {
        Error::PcSc(e.to_string())
    }
}

// Apdu Traits

pub trait CommandApdu {
    fn apdu_bytes(&self) -> Vec<u8>
    where
        Self: serde::Serialize,
    {
        let mut command = Vec::new();
        into_writer(&self, &mut command).unwrap();
        build_apdu(&CBOR_CLA_INS_P1P2, command.as_slice())
    }
}

pub trait ResponseApdu {
    fn from_cbor<'a>(cbor: Vec<u8>) -> Result<Self, Error>
    where
        Self: Deserialize<'a> + Debug,
    {
        let cbor_value: Value = from_reader(&cbor[..])?;
        let cbor_struct: Result<ErrorResponse, _> = cbor_value.deserialized();
        if let Ok(error_resp) = cbor_struct {
            Err(Error::CkTap {
                error: error_resp.error,
                code: error_resp.code,
            })?;
        }
        let cbor_struct: Self = cbor_value.deserialized()?;
        Ok(cbor_struct)
    }
}

fn build_apdu(header: &[u8], command: &[u8]) -> Vec<u8> {
    let command_len = command.len();
    assert!(command_len <= 255, "apdu command too long"); // TODO use Err
    [header, &[command_len as u8], command].concat()
}

// Commands

/// Applet Select
///
#[derive(Default, Serialize, Clone, Debug, PartialEq, Eq)]
pub struct AppletSelect {}

impl CommandApdu for AppletSelect {
    fn apdu_bytes(&self) -> Vec<u8> {
        build_apdu(&SELECT_CLA_INS_P1P2, &APP_ID)
    }
}

/// Status Command
///
#[derive(Serialize, Clone, Debug, PartialEq, Eq)]
pub struct StatusCommand {
    /// 'status' command
    cmd: String,
}

impl Default for StatusCommand {
    fn default() -> Self {
        StatusCommand {
            cmd: "status".to_string(),
        }
    }
}

impl CommandApdu for StatusCommand {}

/// Read Command
///
/// Apps need to write a CBOR message to read a SATSCARD's current payment address, or a
/// TAPSIGNER's derived public key.
#[derive(Serialize, Clone, Debug, PartialEq, Eq)]
pub struct ReadCommand {
    /// 'read' command
    cmd: String,
    /// provided by app, cannot be all same byte (& should be random), 16 bytes
    #[serde(with = "serde_bytes")]
    nonce: Vec<u8>,
    /// (TAPSIGNER only) auth is required, 33 bytes
    #[serde(with = "serde_bytes")]
    epubkey: Option<Vec<u8>>,
    /// (TAPSIGNER only) auth is required encrypted CVC value, 6 to 32 bytes
    xcvc: Option<String>,
}

impl ReadCommand {
    pub fn new(nonce: Vec<u8>, epubkey: Option<Vec<u8>>, xcvc: Option<String>) -> Self {
        ReadCommand {
            cmd: "read".to_string(),
            nonce,
            epubkey,
            xcvc,
        }
    }
}

impl CommandApdu for ReadCommand {}

/// Wait Command
///
/// Invalid CVC codes return error 401 (bad auth), through the third incorrect attempt. After the
/// third incorrect attempt, a 15-second delay is required. Any further attempts to authenticate
/// will return error 429 (rate limited) until the delay has passed.
///
/// In rate-limiting mode, the status command returns the auth_delay field with a positive value.
///
/// The wait command takes one second to execute and reduces the auth_delay by one unit. Typically,
/// 15 wait commands need to be executed before retrying a CVC.
#[derive(Serialize, Clone, Debug, PartialEq, Eq)]
pub struct WaitCommand {
    /// 'wait' command
    cmd: String,
    /// app's ephemeral public key (optional)
    #[serde(with = "serde_bytes")]
    epubkey: Option<Vec<u8>>,
    /// encrypted CVC value (optional), 6 to 32 bytes
    xcvc: Option<String>,
}

impl WaitCommand {
    pub fn new(epubkey: Option<Vec<u8>>, xcvc: Option<String>) -> Self {
        WaitCommand {
            cmd: "wait".to_string(),
            epubkey,
            xcvc,
        }
    }
}

impl CommandApdu for WaitCommand {}

/// This command is used to verify the card was made by Coinkite and is not counterfeit. Two
/// requests are needed: first, fetch the certificates, and then provide a nonce to be signed.
#[derive(Serialize, Clone, Debug, PartialEq, Eq)]
pub struct CertsCommand {
    /// 'certs' command
    cmd: String,
}

impl Default for CertsCommand {
    fn default() -> Self {
        CertsCommand {
            cmd: "certs".to_string(),
        }
    }
}

impl CommandApdu for CertsCommand {}

// Responses

#[derive(Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct ErrorResponse {
    pub error: String,
    pub code: usize,
}

#[derive(Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct StatusResponse {
    pub proto: usize,
    pub ver: String,
    pub birth: usize,
    pub slots: Option<Vec<usize>>,
    pub addr: Option<String>,
    pub tapsigner: Option<bool>,
    pub satschip: Option<bool>,
    pub path: Option<Vec<usize>>,
    pub num_backups: Option<usize>,
    #[serde(with = "serde_bytes")]
    pub pubkey: Vec<u8>,
    #[serde(with = "serde_bytes")]
    pub card_nonce: Vec<u8>,
    pub testnet: Option<bool>,
    pub auth_delay: Option<usize>,
}

impl ResponseApdu for StatusResponse {}

/// Read Response
///
/// The signature is created from the digest (SHA-256) of these bytes:
///
/// b'OPENDIME' (8 bytes)
/// (card_nonce - 16 bytes)
/// (nonce from read command - 16 bytes)
/// (slot - 1 byte)
#[derive(Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct ReadResponse {
    /// signature over a bunch of fields using private key of slot, 64 bytes
    #[serde(with = "serde_bytes")]
    pub sig: Vec<u8>,
    /// public key for this slot/derivation, 33 bytes
    #[serde(with = "serde_bytes")]
    pub pubkey: Vec<u8>,
    /// new nonce value, for NEXT command (not this one), 16 bytes
    #[serde(with = "serde_bytes")]
    pub card_nonce: Vec<u8>,
}

impl ResponseApdu for ReadResponse {}

/// Wait Response
///
/// When auth_delay is zero, the CVC can be retried and tested without side effects.
#[derive(Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct WaitResponse {
    /// command result
    success: bool,
    /// how much more delay is now required
    auth_delay: usize,
}

impl ResponseApdu for WaitResponse {}

/// The response is static for any particular card. The values are captured during factory setup.
/// Each entry in the list is a 65-byte signature. The first signature signs the card's public key,
/// and each following signature signs the public key used in the previous signature. Although two
/// levels of signatures are planned, more are possible.
#[derive(Deserialize, Clone, Debug)]
pub struct CertsResponse {
    /// list of certificates, from 'batch' to 'root'
    cert_chain: Vec<Value>,
}
impl ResponseApdu for CertsResponse {}

impl CertsResponse {
    pub fn cert_chain(&self) -> Vec<Vec<u8>> {
        self.clone()
            .cert_chain
            .into_iter()
            .filter_map(|v| match v {
                Value::Bytes(bv) => Some(bv),
                _ => None,
            })
            .collect()
    }
}
