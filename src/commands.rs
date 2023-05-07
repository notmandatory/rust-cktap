use ciborium::de::from_reader;
use ciborium::ser::into_writer;
use ciborium::value::Value;
use secp256k1::PublicKey;
use serde::{Deserialize, Serialize};
use serde;
use std::fmt;
use std::fmt::Debug;

use hex::encode;

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
    #[serde(with = "serde_bytes")]
    xcvc: Option<Vec<u8>>,
}

impl ReadCommand {
    pub fn for_tapsigner(nonce: Vec<u8>, epubkey: PublicKey, xcvc: Vec<u8>) -> Self {
        ReadCommand {
            cmd: "read".to_string(),
            nonce,
            epubkey: Some(epubkey.serialize().to_vec()),
            xcvc: Some(xcvc),
        }
    }

    pub fn for_satscard(nonce: Vec<u8>) -> Self {
        ReadCommand {
            cmd: "read".to_string(),
            nonce,
            epubkey: None,
            xcvc: None,
        }
    } 
}

impl CommandApdu for ReadCommand {}

#[derive(Serialize, Clone, Debug, PartialEq, Eq)]
pub struct DeriveCommand {
    cmd: String,
    /// provided by app, cannot be all same byte (& should be random), 16 bytes
    #[serde(with = "serde_bytes")]
    nonce: Vec<u8>,
}

/// nfc command to return dynamic url for NFC-enabled smart phone
#[derive(Serialize, Clone, Debug, PartialEq, Eq)]
pub struct NfcCommand {
    cmd: String,
}

impl Default for NfcCommand {
    fn default() -> Self {
        Self {
            cmd: "nfc".to_string(),
        }
    }
}

impl CommandApdu for NfcCommand {}

/// Sign Command
/// {
//     'cmd': 'sign',              # command
//     'slot': 0,                  # (optional) which slot's to key to use, must be unsealed.
//     'subpath': [0, 0],          # (TAPSIGNER only) additional derivation keypath to be used
//     'digest': (32 bytes),        # message digest to be signed
//     'epubkey': (33 bytes),       # app's ephemeral public key
//     'xcvc': (6 bytes)          # encrypted CVC value
// }
#[derive(Serialize, Clone, Debug, PartialEq, Eq)]
pub struct SignCommand {
    cmd: String,
    slot: Option<u8>,
    subpath: Option<[u32; 2]>, // additional keypath for TapSigner only
    #[serde(with = "serde_bytes")]
    digest: Vec<u8>, // message digest to be signed
    #[serde(with = "serde_bytes")]
    epubkey: Vec<u8>,
    #[serde(with = "serde_bytes")]
    xcvc: Vec<u8>,
}

impl SignCommand {
    // pub fn for_satscard(slot: Option<u8>, digest: Vec<u8>, epubkey: Vec<u8>, xcvc: Vec<u8>) -> Self {
    //     Self {
    //         cmd: "sign".to_string(),
    //         slot,
    //         digest,
    //         subpath: None,
    //         epubkey,
    //         xcvc,
    //     }
    // }

    pub fn for_tapsigner(subpath: Option<[u32; 2]>, digest: Vec<u8>, epubkey: PublicKey, xcvc: Vec<u8>) -> Self {
        SignCommand {
            cmd: "sign".to_string(),
            slot: Some(0),
            subpath,
            digest,
            epubkey: epubkey.serialize().to_vec(),
            xcvc,
        }
    }
}

impl CommandApdu for SignCommand {}

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
    #[serde(with = "serde_bytes")]
    xcvc: Option<Vec<u8>>,
}

impl WaitCommand {
    pub fn new(epubkey: Option<Vec<u8>>, xcvc: Option<Vec<u8>>) -> Self {
        WaitCommand {
            cmd: "wait".to_string(),
            epubkey,
            xcvc,
        }
    }
}

impl CommandApdu for WaitCommand {}

/// Certs Command
///
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

/// Check Command
///
/// This command is used to verify the card was made by Coinkite and is not counterfeit. Two
/// requests are needed: first, fetch the certificates, and then provide a nonce to be signed.
#[derive(Serialize, Clone, Debug, PartialEq, Eq)]
pub struct CheckCommand {
    /// 'check' command
    cmd: String,
    /// random value from app, 16 bytes
    #[serde(with = "serde_bytes")]
    nonce: Vec<u8>,
}

impl CheckCommand {
    pub fn new(nonce: Vec<u8>) -> Self {
        CheckCommand {
            cmd: "check".to_string(),
            nonce,
        }
    }
}

impl CommandApdu for CheckCommand {}

/// New Command
///
/// SATSCARD: Use this command to pick a new private key and start a fresh slot. The operation cannot be performed if the current slot is sealed.
///
/// TAPSIGNER: This command is only used once.
///
/// The slot number is included in the request to prevent command replay.
///
/// At this point:
///
///     No new slots available? Abort and fail command.
///     A new key pair is picked and stored into the new slot.
///         The chain_code must be used in that process and stored.
///         The card uses TRNG to pick a new master_pubkey (pair).
///
/// The new values take effect immediately, so some fields of the next status response will have
/// new values.
#[derive(Serialize, Clone, Debug, PartialEq, Eq)]
pub struct NewCommand {
    /// 'new' command
    cmd: String,
    /// (optional: default zero) slot to be affected, must equal currently-active slot number
    slot: usize,
    /// app's entropy share to be applied to new slot (optional on SATSCARD), 32 bytes
    #[serde(with = "serde_bytes")]
    chain_code: Option<Vec<u8>>,
    /// app's ephemeral public key, 33 bytes
    #[serde(with = "serde_bytes")]
    epubkey: Vec<u8>,
    /// encrypted CVC value, 6 bytes
    #[serde(with = "serde_bytes")]
    xcvc: Vec<u8>,
}

impl NewCommand {
    pub fn new(slot: usize, chain_code: Option<Vec<u8>>, epubkey: Vec<u8>, xcvc: Vec<u8>) -> Self {
        NewCommand {
            cmd: "new".to_string(),
            slot,
            chain_code,
            epubkey,
            xcvc,
        }
    }
}

impl CommandApdu for NewCommand {}

/// Dump Command
///
/// This reveals the details for any slot. The current slot is not affected. This is a no-op in
/// terms of response content, if slots aren't available yet, or if a slot hasn't been unsealed.
/// The factory uses this to verify the CVC is printed correctly without side effects.
///
/// If the epubkey or xcvc is absent, the command still works, but the no sensitive information is
/// shared.
///
/// Incorrect auth values for xcvc will fail as normal. Omit the xcvc and epubkey value to proceed
/// without authentication if CVC is unknown.
#[derive(Serialize, Clone, Debug, PartialEq, Eq)]
pub struct DumpCommand {
    /// 'dump' command
    cmd: String,
    /// which slot to dump, must be unsealed.
    slot: usize,
    /// app's ephemeral public key (optional), 33 bytes
    #[serde(with = "serde_bytes")]
    #[serde(skip_serializing_if = "Option::is_none")]
    epubkey: Option<Vec<u8>>,
    /// encrypted CVC value (optional), 6 bytes
    #[serde(with = "serde_bytes")]
    #[serde(skip_serializing_if = "Option::is_none")]
    xcvc: Option<Vec<u8>>,
}

impl DumpCommand {
    pub fn new(slot: usize, epubkey: Option<Vec<u8>>, xcvc: Option<Vec<u8>>) -> Self {
        DumpCommand {
            cmd: "dump".to_string(),
            slot,
            epubkey,
            xcvc,
        }
    }
}

impl CommandApdu for DumpCommand {}


// TAPSIGNER only - Provides the current XPUB (BIP-32 serialized), either at the top level (master) or the derived key in use (see 'path' value in status response)
// {
//     'cmd': 'xpub',              # command
//     'master': (boolean),        # give master (`m`) XPUB, otherwise derived XPUB
//     'epubkey': (33 bytes),       # app's ephemeral public key (required)
//     'xcvc': (6 bytes)          # encrypted CVC value (required)
// }
#[derive(Serialize, Clone, Debug, PartialEq, Eq)]
pub struct XpubCommand {
    cmd: String,
    master: bool,
    #[serde(with = "serde_bytes")]
    epubkey: Vec<u8>,
    #[serde(with = "serde_bytes")]
    xcvc: Vec<u8>
}

impl CommandApdu for XpubCommand {}

impl XpubCommand {
    pub fn new(master: bool, epubkey: PublicKey, xcvc: Vec<u8>) -> Self {
        Self {
            cmd: "xpub".to_string(),
            master,
            epubkey: epubkey.serialize().to_vec(),
            xcvc
        }
    }
}


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
    #[serde(default)]
    pub auth_delay: Option<usize>,
}

impl ResponseApdu for StatusResponse {}

// impl std::fmt::Display for StatusResponse {
//     fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
//         write!(f, "Name: {}, Age: {}", self.name, self.age)
//     }
// }

/// Read Response
///
/// The signature is created from the digest (SHA-256) of these bytes:
///
/// b'OPENDIME' (8 bytes)
/// (card_nonce - 16 bytes)
/// (nonce from read command - 16 bytes)
/// (slot - 1 byte)
#[derive(Serialize, Deserialize, Clone, PartialEq, Eq)]
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

// fn serialize_hex_vec<S>(value: &Vec<u8>, serializer: S) -> Result<S::Ok, S::Error>
// where
//     S: serde::Serializer,
// {
//     let hex_str = value.iter().map(|b| format!("{:02X}", b)).collect::<String>();
//     serializer.serialize_str(&hex_str)
// }

impl ResponseApdu for ReadResponse {}

impl fmt::Debug for ReadResponse {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("ReadResponse")
            .field("sig", &encode(&self.sig))
            .field("pubkey", &encode(&self.pubkey))
            .field("card_nonce", &encode(&self.card_nonce))
            .finish()
    }
}

/// nfc Response
///
/// URL for smart phone to navigate to
#[derive(Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct NfcResponse {
    /// command result
    pub url: String
}

impl ResponseApdu for NfcResponse {}

/// Sign Response
///
// SATSCARD: Arbitrary signatures can be created for unsealed slots. The app could perform this, since the private key is known, but it's best if the app isn't contaminated with private key information. This could be used for both spending and multisig wallet operations.
//
// TAPSIGNER: This is its core feature — signing an arbitrary message digest with a tap. Once the card is set up (the key is picked), the command will always be valid.
#[derive(Deserialize, Clone, PartialEq, Eq)]
pub struct SignResponse {
    /// command result
    pub slot: u8,
    #[serde(with = "serde_bytes")]
    pub sig: Vec<u8>,
    #[serde(with = "serde_bytes")]
    pub pubkey: Vec<u8>,
    #[serde(with = "serde_bytes")]
    pub card_nonce: Vec<u8>, 
}

impl ResponseApdu for SignResponse {}

impl fmt::Debug for SignResponse {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("SignResponse")
            .field("slot", &self.slot)
            .field("sig", &encode(&self.sig))
            .field("pubkey", &encode(&self.pubkey))
            .field("card_nonce", &encode(&self.card_nonce))
            .finish()
    }
}


/// Wait Response
///
/// When auth_delay is zero, the CVC can be retried and tested without side effects.
#[derive(Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct WaitResponse {
    /// command result
    pub success: bool,
    /// how much more delay is now required
    #[serde(default)]
    pub auth_delay: usize,
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

/// Check Certs Response
///
/// The auth_sig value is a signature made using the card's public key (card_pubkey).
///
/// The signature is created from the digest (SHA-256) of these bytes:
///
/// b'OPENDIME' (8 bytes)
/// (card_nonce - 16 bytes)
/// (nonce from check command - 16 bytes)
///
/// Starting in version 1.0.0 of the SATSCARD, the public key (33 bytes) for the current slot is appended to the above message. (If the current slot is unsealed or not yet used, this does not happen.) With the pubkey in place, the message being signed will be:
///
/// b'OPENDIME' (8 bytes)
/// (card_nonce - 16 bytes)
/// (nonce from check command - 16 bytes)
/// (pubkey of current sealed slot - 33 bytes)
///
/// The app verifies this signature and checks that the public key in use is the card_pubkey to prove it is talking to a genuine Coinkite card. The signatures of each certificate chain element are then verified by recovering the pubkey at each step. This checks that the batch certificate is signing the card's pubkey, that the root certificate is signing the batch certificate's key and so on. The root certificate's expected pubkey must be shared out-of-band and already known to the app.
///
/// At this time, the only valid factory root pubkey is:
///
/// 03028a0e89e70d0ec0d932053a89ab1da7d9182bdc6d2f03e706ee99517d05d9e1
#[derive(Deserialize, Clone, Debug)]
pub struct CheckResponse {
    /// signature using card_pubkey, 64 bytes
    #[serde(with = "serde_bytes")]
    auth_sig: Vec<u8>,
    /// new nonce value, for NEXT command (not this one), 16 bytes
    #[serde(with = "serde_bytes")]
    card_nonce: Vec<u8>,
}

impl ResponseApdu for CheckResponse {}

/// New Response
///
/// There is a very, very small — 1 in 2128 — chance of arriving at an invalid private key. This
/// returns error 205 (unlucky number). Retries are allowed with no delay. Also, buy a lottery
/// ticket immediately.
///
/// SATSCARD: derived address is generated based on m/0.
///
/// TAPSIGNER: uses the default derivation path of m/84h/0h/0h.
///
/// In either case, the status and read commands are required to learn the details of the new
/// address/key.
#[derive(Deserialize, Clone, Debug)]
pub struct NewResponse {
    /// slot just made
    slot: usize,
    /// new nonce value, for NEXT command (not this one), 16 bytes
    #[serde(with = "serde_bytes")]
    card_nonce: Vec<u8>,
}

impl ResponseApdu for NewResponse {}

/// Dump Response
///
/// Without the CVC, the dump command returns just the sealed/unsealed/unused status for each slot,
/// with the exception of unsealed slots where the address in full is also provided.
#[derive(Deserialize, Clone, Debug)]
pub struct DumpResponse {
    /// slot just made
    slot: usize,
    /// private key for spending (for addr), 32 bytes
    /// The private keys are encrypted, XORed with the session key
    #[serde(with = "serde_bytes")]
    #[serde(default)]
    privkey: Option<Vec<u8>>,
    /// public key, 33 bytes
    #[serde(with = "serde_bytes")]
    #[serde(default)]
    pubkey: Vec<u8>,
    /// nonce provided by customer originally
    #[serde(with = "serde_bytes")]
    #[serde(default)]
    chain_code: Option<Vec<u8>>,
    /// master private key for this slot (was picked by card), 32 bytes
    #[serde(with = "serde_bytes")]
    #[serde(default)]
    master_pk: Option<Vec<u8>>,
    /// flag that slots unsealed for unusual reasons (absent if false)
    #[serde(default)]
    tampered: Option<bool>,
    /// if no xcvc provided, slot used status
    #[serde(default)]
    used: Option<bool>,
    /// if no xcvc provided, slot sealed status
    sealed: Option<bool>,
    /// if no xcvc provided, full payment address (not censored)
    #[serde(default)]
    addr: Option<String>,
    /// new nonce value, for NEXT command (not this one), 16 bytes
    #[serde(with = "serde_bytes")]
    card_nonce: Vec<u8>,
}

impl ResponseApdu for DumpResponse {}


#[derive(Deserialize, Clone)]
pub struct XpubResponse {
    #[serde(with = "serde_bytes")]
    pub xpub: Vec<u8>,
    #[serde(with = "serde_bytes")]
    pub card_nonce: Vec<u8>,
}

impl ResponseApdu for XpubResponse {}

impl fmt::Debug for XpubResponse {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("XpubResponse")
            .field("xpub", &encode(&self.xpub))
            .field("card_nonce", &encode(&self.card_nonce))
            .finish()
    }
}

// Response for a used slot with XCVC provided:
//
// {
//     'slot': 0,                     # which slot is being dumped
//     'privkey': (32 bytes),         # private key for spending (for addr)
//     'pubkey': (33 bytes),          # public key
//     'chain_code': (32 bytes),      # nonce provided by customer originally
//     'master_pk': (32 bytes),       # master private key for this slot (was picked by card)
//     'tampered': (bool),            # flag that slots unsealed for unusual reasons (absent if false)
//     'card_nonce': (16 bytes)       # new nonce value, for NEXT command (not this one)
// }
//
// The private keys are encrypted, XORed with the session key, but the other values are shared unencrypted.
//
// The tampered field is only present (and True) if the slot was unsealed due to confusion or uncertainty about its status. In other words, if the card unsealed itself rather than via a successful unseal command.
//
// If the XCVC (and/or epubkey) is not provided, then the response contains the full payment address and indicates it is unsealed. In version 1.0.3 and later, the full compressed pubkey for the payment address is also provided.
//
// {
//     'slot': 0,                     # which slot is being dumped
//     'sealed': False,
//     'addr': 'bc1qsqkhv..qf735wvl3lh8',   # full payment address (not censored)
//     'pubkey': (33 bytes),          # public key corresponding to payment address (since v1.0.3)
//     'card_nonce': (16 bytes)       # new nonce value, for NEXT command (not this one)
// }
//
// The response for an unused slot (no CVC provided):
//
// {
//     'slot': 2,                     # which slot is being dumped
//     'used': False,
//     'card_nonce': (16 bytes)       # new nonce value, for NEXT command (not this one)
// }
//
// For the currently active slot, the response is (no CVC provided):
//
// {
//     'slot': 3,                     # which slot is being dumped
//     'sealed': True,
//     'card_nonce': (16 bytes)       # new nonce value, for NEXT command (not this one)
// }
