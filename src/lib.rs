use ciborium::de::from_reader;
use ciborium::ser::into_writer;
use ciborium::value::Value;
use serde::{Deserialize, Serialize};
use std::fmt::Debug;

pub const APP_ID: [u8; 15] = *b"\xf0CoinkiteCARDv1";

pub const SELECT_CLA_INS_P1P2: [u8; 4] = [0x00, 0xA4, 0x04, 0x00];
pub const CBOR_CLA_INS_P1P2: [u8; 4] = [0x00, 0xCB, 0x00, 0x00];

// require nonce sizes (bytes)
pub const CARD_NONCE_SIZE:usize = 16;
pub const USER_NONCE_SIZE:usize = 16;

// Apdu Traits

pub trait CommandApdu {
    fn apdu_bytes(&self) -> Vec<u8>;
}

pub trait ResponseApdu {
    fn from_cbor<'a>(cbor: Vec<u8>) -> Self where Self: Deserialize<'a> + Debug {
        let cbor_value: Value = from_reader(&cbor[..]).unwrap(); // TODO use Err
        let cbor_struct: Self = cbor_value.deserialized().unwrap(); // TODO use Err
        cbor_struct
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
pub struct AppletSelect {}

impl Default for AppletSelect {
    fn default() -> Self {
        AppletSelect {}
    }
}

impl CommandApdu for AppletSelect {
    fn apdu_bytes(&self) -> Vec<u8> {
        build_apdu(&SELECT_CLA_INS_P1P2, &APP_ID)
    }
}

/// Status Command
///
#[derive(Serialize, Clone, Debug, PartialEq, Eq)]
pub struct StatusCommand {
    /// command
    cmd: String,
}

impl Default for StatusCommand {
    fn default() -> Self {
        StatusCommand {
            cmd: "status".to_string()
        }
    }
}

impl CommandApdu for StatusCommand {
    fn apdu_bytes(&self) -> Vec<u8> {
        let mut command = Vec::new();
        into_writer(&self, &mut command).unwrap();
        build_apdu(&CBOR_CLA_INS_P1P2, command.as_slice())
    }
}

// Read Command
//
// Apps need to write a CBOR message to read a SATSCARD's current payment address, or a
// TAPSIGNER's derived public key.
// #[derive(Serialize, Clone, Debug, PartialEq, Eq)]
// pub struct ReadRequest {
//     /// command
//     cmd: String,
//     /// provided by app, cannot be all same byte (& should be random)
//     nonce: [u8;16],
//     /// (TAPSIGNER only) auth is required
//     epubkey: Option<[u8;33]>,
//     /// (TAPSIGNER only) auth is required encrypted CVC value
//     xcvc: Option<[u8;32]>,
// }

// Responses

#[derive(Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct StatusResponse {
    proto: usize,
    ver: String,
    birth: usize,
    slots: Option<Vec<usize>>,
    addr: Option<String>,
    tapsigner: Option<bool>,
    satschip: Option<bool>,
    path: Option<Vec<usize>>,
    num_backups: Option<usize>,
    #[serde(with = "serde_bytes")]
    pubkey: Vec<u8>,
    #[serde(with = "serde_bytes")]
    card_nonce: Vec<u8>,
    testnet: Option<bool>,
}

impl ResponseApdu for StatusResponse {}

// Read Response
//
// The signature is created from the digest (SHA-256) of these bytes:
//
// b'OPENDIME' (8 bytes)
// (card_nonce - 16 bytes)
// (nonce from read command - 16 bytes)
// (slot - 1 byte)
// #[derive(Deserialize, Clone, Debug, PartialEq, Eq)]
// pub struct ReadResponse {
//     /// signature over a bunch of fields using private key of slot
//     sig: [u8;64],
//     /// public key for this slot/derivation
//     pubkey: [u8;32],
//     /// new nonce value, for NEXT command (not this one)
//     card_nonce: [u8;16],
// }
