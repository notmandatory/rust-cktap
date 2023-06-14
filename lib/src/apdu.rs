/// An Application Protocol Data Unit (APDU) is the unit of communication between a smart card
/// reader and a smart card. This file defines the Coinkite APDU and set of command/responses.
use ciborium::de::from_reader;
use ciborium::ser::into_writer;
use ciborium::value::Value;
use secp256k1::ecdh::SharedSecret;
use secp256k1::hashes::hex::ToHex;
use secp256k1::PublicKey;
use serde;
use serde::{Deserialize, Serialize};
use std::fmt;
use std::fmt::{Debug, Formatter};

use secp256k1::ecdsa::Signature;

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
    IncorrectSignature(String),
    UnknownCardType(String),
    #[cfg(feature = "pcsc")]
    PcSc(String),
    #[cfg(feature = "emulator")]
    Emulator(String),
}

impl<T> From<ciborium::de::Error<T>> for Error
where
    T: Debug,
{
    fn from(e: ciborium::de::Error<T>) -> Self {
        Error::CiborDe(e.to_string())
    }
}

impl From<ciborium::value::Error> for Error {
    fn from(e: ciborium::value::Error) -> Self {
        Error::CiborValue(e.to_string())
    }
}

impl From<secp256k1::Error> for Error {
    fn from(e: secp256k1::Error) -> Self {
        Error::IncorrectSignature(e.to_string())
    }
}

#[cfg(feature = "pcsc")]
impl From<pcsc::Error> for Error {
    fn from(e: pcsc::Error) -> Self {
        Error::PcSc(e.to_string())
    }
}

#[derive(Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct ErrorResponse {
    pub error: String,
    pub code: usize,
}

// Apdu Traits
pub trait CommandApdu {
    fn name() -> String;
    fn apdu_bytes(&self) -> Vec<u8>
    where
        Self: serde::Serialize + Debug,
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
            return Err(Error::CkTap {
                error: error_resp.error,
                code: error_resp.code,
            });
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
#[derive(Default, Serialize, Clone, Debug, PartialEq, Eq)]
pub struct AppletSelect {}

impl CommandApdu for AppletSelect {
    fn name() -> String {
        String::default()
    }
    fn apdu_bytes(&self) -> Vec<u8> {
        build_apdu(&SELECT_CLA_INS_P1P2, &APP_ID)
    }
}

/// Status Command
#[derive(Serialize, Clone, Debug, PartialEq, Eq)]
pub struct StatusCommand {
    /// 'status' command
    cmd: String,
}

impl Default for StatusCommand {
    fn default() -> Self {
        StatusCommand { cmd: Self::name() }
    }
}

impl CommandApdu for StatusCommand {
    fn name() -> String {
        "status".to_string()
    }
}

#[derive(Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct StatusResponse {
    pub proto: usize,
    pub ver: String,
    pub birth: usize,
    pub slots: Option<(u8, u8)>,
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
    pub fn authenticated(nonce: Vec<u8>, epubkey: PublicKey, xcvc: Vec<u8>) -> Self {
        ReadCommand {
            cmd: Self::name(),
            nonce,
            epubkey: Some(epubkey.serialize().to_vec()),
            xcvc: Some(xcvc),
        }
    }

    pub fn unauthenticated(nonce: Vec<u8>) -> Self {
        ReadCommand {
            cmd: Self::name(),
            nonce,
            epubkey: None,
            xcvc: None,
        }
    }
}

impl CommandApdu for ReadCommand {
    fn name() -> String {
        "read".to_string()
    }
}

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

impl ResponseApdu for ReadResponse {}

impl ReadResponse {
    pub fn signature(&self) -> Result<Signature, Error> {
        Signature::from_compact(self.sig.as_slice()).map_err(|e| Error::CiborValue(e.to_string()))
        // .expect("Failed to construct ECDSA signature from ReadResponse")
    }

    pub fn pubkey(&self, session_key: Option<SharedSecret>) -> PublicKey {
        let pubkey = if let Some(sk) = session_key {
            unzip(&self.pubkey, sk)
        } else {
            self.pubkey.clone()
        };
        PublicKey::from_slice(pubkey.as_slice())
            .expect("Failed to construct a PublicKey from ReadResponse")
    }
}

fn unzip(encoded: &[u8], session_key: SharedSecret) -> Vec<u8> {
    let zipped_bytes = encoded.to_owned().split_off(1);
    let unzipped_bytes = zipped_bytes
        .iter()
        .zip(session_key.as_ref())
        .map(|(x, y)| x ^ y);

    let mut pubkey = encoded.to_owned();
    pubkey.splice(1..33, unzipped_bytes);
    pubkey
}

impl fmt::Display for ReadResponse {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "pubkey: {}", self.pubkey.to_hex())
    }
}

impl Debug for ReadResponse {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        f.debug_struct("ReadResponse")
            .field("sig", &self.sig.to_hex())
            .field("pubkey", &self.pubkey.to_hex())
            .field("card_nonce", &self.card_nonce.to_hex())
            .finish()
    }
}

// Checks payment address derivation: https://github.com/coinkite/coinkite-tap-proto/blob/master/docs/protocol.md#satscard-checks-payment-address-derivation
#[derive(Serialize, Clone, Debug, PartialEq, Eq)]
pub struct DeriveCommand {
    cmd: String,
    /// provided by app, cannot be all same byte (& should be random), 16 bytes
    #[serde(with = "serde_bytes")]
    nonce: Vec<u8>,
    path: Vec<u32>, // tapsigner: empty list for `m` case (a no-op)
    /// app's ephemeral public key
    #[serde(with = "serde_bytes")]
    epubkey: Option<Vec<u8>>,
    /// encrypted CVC value
    #[serde(with = "serde_bytes")]
    xcvc: Option<Vec<u8>>,
}

impl CommandApdu for DeriveCommand {
    fn name() -> String {
        "derive".to_string()
    }
}

impl DeriveCommand {
    pub fn for_satscard(nonce: Vec<u8>) -> Self {
        DeriveCommand {
            cmd: Self::name(),
            nonce,
            path: vec![],
            epubkey: None,
            xcvc: None,
        }
    }

    pub fn for_tapsigner(
        nonce: Vec<u8>,
        path: Vec<u32>,
        epubkey: PublicKey,
        xcvc: Vec<u8>,
    ) -> Self {
        DeriveCommand {
            cmd: Self::name(),
            nonce,
            path,
            epubkey: Some(epubkey.serialize().to_vec()),
            xcvc: Some(xcvc),
        }
    }
}

#[derive(Deserialize, Clone)]
pub struct DeriveResponse {
    #[serde(with = "serde_bytes")]
    pub sig: Vec<u8>, // 64 bytes
    /// chain code of derived subkey
    #[serde(with = "serde_bytes")]
    pub chain_code: Vec<u8>, // 32 bytes
    /// master public key in effect (`m`)
    #[serde(with = "serde_bytes")]
    pub master_pubkey: Vec<u8>, // 33 bytes
    /// derived public key for indicated path
    #[serde(with = "serde_bytes")]
    #[serde(default = "Option::default")]
    pub pubkey: Option<Vec<u8>>, // 33 bytes
    /// new nonce value, for NEXT command (not this one)
    #[serde(with = "serde_bytes")]
    pub card_nonce: Vec<u8>, // 16 bytes
}

impl ResponseApdu for DeriveResponse {}

impl Debug for DeriveResponse {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        f.debug_struct("DeriveResponse")
            .field("sig", &self.sig.to_hex())
            .field("chain_code", &self.chain_code.to_hex())
            .field("master_pubkey", &self.master_pubkey.to_hex())
            .field("pubkey", &self.pubkey.clone().map(|pk| pk.to_hex()))
            .field("card_nonce", &self.card_nonce.to_hex())
            .finish()
    }
}

/// Certs Command
///
/// This command is used to verify the card was made by Coinkite and is not counterfeit. Two
/// requests are needed: first, fetch the certificates, and then provide a nonce to be signed.
#[derive(Serialize, Clone, Debug, PartialEq, Eq)]
pub struct CertsCommand {
    /// 'certs' command
    cmd: String,
}

impl CommandApdu for CertsCommand {
    fn name() -> String {
        "certs".to_string()
    }
}

impl Default for CertsCommand {
    fn default() -> Self {
        CertsCommand { cmd: Self::name() }
    }
}

/// The response is static for any particular card. The values are captured during factory setup.
/// Each entry in the list is a 65-byte signature. The first signature signs the card's public key,
/// and each following signature signs the public key used in the previous signature. Although two
/// levels of signatures are planned, more are possible.
#[derive(Deserialize, Clone)]
pub struct CertsResponse {
    /// list of certificates, from 'batch' to 'root'
    // TODO create custom deserializer like "serde_bytes" but for Vec<Vec<u8>>
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

impl Debug for CertsResponse {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        let cert_hexes: Vec<String> = self.cert_chain().iter().map(|key| key.to_hex()).collect();
        f.debug_struct("CertsResponse")
            .field("cert_chain", &cert_hexes)
            .finish()
    }
}

/// Check Command
///
/// This command is used to verify the card was made by Coinkite and is not counterfeit. Two
/// requests are needed: first, fetch the certificates (i.e CertsCommand), and then provide a nonce to be signed.
#[derive(Serialize, Clone, Debug, PartialEq, Eq)]
pub struct CheckCommand {
    /// 'check' command
    cmd: String,
    /// random value from app, 16 bytes
    #[serde(with = "serde_bytes")]
    nonce: Vec<u8>,
}

impl CommandApdu for CheckCommand {
    fn name() -> String {
        "check".to_string()
    }
}

impl CheckCommand {
    pub fn new(nonce: Vec<u8>) -> Self {
        CheckCommand {
            cmd: Self::name(),
            nonce,
        }
    }
}

/// Check Certs Response
/// ref: https://github.com/coinkite/coinkite-tap-proto/blob/master/docs/protocol.md#certs
#[derive(Deserialize, Clone)]
pub struct CheckResponse {
    /// signature using card_pubkey, 64 bytes
    #[serde(with = "serde_bytes")]
    pub auth_sig: Vec<u8>,
    /// new nonce value, for NEXT command (not this one), 16 bytes
    #[serde(with = "serde_bytes")]
    pub card_nonce: Vec<u8>,
}

impl ResponseApdu for CheckResponse {}

impl Debug for CheckResponse {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        f.debug_struct("CheckResponse")
            .field("auth_sig", &self.auth_sig.to_hex())
            .field("card_nonce", &self.card_nonce.to_hex())
            .finish()
    }
}

/// nfc command to return dynamic url for NFC-enabled smart phone
#[derive(Serialize, Clone, Debug, PartialEq, Eq)]
pub struct NfcCommand {
    cmd: String,
}

impl Default for NfcCommand {
    fn default() -> Self {
        Self { cmd: Self::name() }
    }
}

impl CommandApdu for NfcCommand {
    fn name() -> String {
        "nfc".to_string()
    }
}

/// nfc Response
///
/// URL for smart phone to navigate to
#[derive(Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct NfcResponse {
    /// command result
    pub url: String,
}

impl ResponseApdu for NfcResponse {}

/// Sign Command
// {
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
    subpath: Option<[u32; 2]>,
    // additional keypath for TapSigner only
    #[serde(with = "serde_bytes")]
    digest: Vec<u8>,
    // message digest to be signed
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

    pub fn for_tapsigner(
        subpath: Option<[u32; 2]>,
        digest: Vec<u8>,
        epubkey: PublicKey,
        xcvc: Vec<u8>,
    ) -> Self {
        let cmd = Self::name();

        SignCommand {
            cmd,
            slot: Some(0),
            subpath,
            digest,
            epubkey: epubkey.serialize().to_vec(),
            xcvc,
        }
    }
}

impl CommandApdu for SignCommand {
    fn name() -> String {
        "sign".to_string()
    }
}

/// Sign Response
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

impl Debug for SignResponse {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        f.debug_struct("SignResponse")
            .field("slot", &self.slot)
            .field("sig", &self.sig.to_hex())
            .field("pubkey", &self.pubkey.to_hex())
            .field("card_nonce", &self.card_nonce.to_hex())
            .finish()
    }
}

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
            cmd: Self::name(),
            epubkey,
            xcvc,
        }
    }
}

impl CommandApdu for WaitCommand {
    fn name() -> String {
        "wait".to_string()
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

/// New Command
///
/// SATSCARD: Use this command to pick a new private key and start a fresh slot. The operation cannot be performed if the current slot is sealed.
///
/// TAPSIGNER: This command is only used once.
///
/// The slot number is included in the request to prevent command replay.
#[derive(Serialize, Clone, Debug, PartialEq, Eq)]
pub struct NewCommand {
    /// 'new' command
    cmd: String,
    /// (use 0 for TapSigner) slot to be affected, must equal currently-active slot number
    slot: u8,
    /// app's entropy share to be applied to new slot (optional on SATSCARD)
    #[serde(with = "serde_bytes")]
    chain_code: Option<Vec<u8>>, // 32 bytes
    /// app's ephemeral public key
    #[serde(with = "serde_bytes")]
    epubkey: Vec<u8>, // 33 bytes
    /// encrypted CVC value
    #[serde(with = "serde_bytes")]
    xcvc: Vec<u8>, // 6 bytes
}

impl NewCommand {
    pub fn new(
        slot: Option<u8>,
        chain_code: Option<Vec<u8>>,
        epubkey: Vec<u8>,
        xcvc: Vec<u8>,
    ) -> Self {
        let slot = slot.unwrap_or_default();
        NewCommand {
            cmd: Self::name(),
            slot,
            chain_code,
            epubkey,
            xcvc,
        }
    }
}

impl CommandApdu for NewCommand {
    fn name() -> String {
        "new".to_string()
    }
}

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
    pub slot: u8,
    /// new nonce value, for NEXT command (not this one)
    #[serde(with = "serde_bytes")]
    pub card_nonce: Vec<u8>, // 16 bytes
}

impl ResponseApdu for NewResponse {}

/// Unseal Command
///
/// Unseal the current slot.
/// NOTE: The slot number is included in the request to prevent command replay. Only the current slot can be unsealed.
#[derive(Serialize, Clone, Debug, PartialEq, Eq)]
pub struct UnsealCommand {
    /// 'unseal' command
    cmd: String,
    /// slot to be unsealed, must equal currently-active slot number
    slot: u8,
    /// app's ephemeral public key, 33 bytes
    #[serde(with = "serde_bytes")]
    epubkey: Vec<u8>,
    /// encrypted CVC value, 6 bytes
    #[serde(with = "serde_bytes")]
    xcvc: Vec<u8>,
}

impl UnsealCommand {
    pub fn new(slot: u8, epubkey: Vec<u8>, xcvc: Vec<u8>) -> Self {
        UnsealCommand {
            cmd: Self::name(),
            slot,
            epubkey,
            xcvc,
        }
    }
}

impl CommandApdu for UnsealCommand {
    fn name() -> String {
        "unseal".to_string()
    }
}

/// Unseal Response
#[derive(Deserialize, Clone, Debug)]
pub struct UnsealResponse {
    /// slot just unsealed
    pub slot: u8,
    /// private key for spending (for addr), 32 bytes
    /// The private keys are encrypted, XORed with the session key
    #[serde(with = "serde_bytes")]
    pub privkey: Vec<u8>,
    /// slot's pubkey (convenience, since could be calc'd from privkey), 33 bytes
    #[serde(with = "serde_bytes")]
    pub pubkey: Vec<u8>,
    /// card's master private key, 32 bytes
    #[serde(with = "serde_bytes")]
    pub master_pk: Vec<u8>,
    /// nonce provided by customer
    #[serde(with = "serde_bytes")]
    pub chain_code: Vec<u8>,
    /// new nonce value, for NEXT command (not this one), 16 bytes
    #[serde(with = "serde_bytes")]
    pub card_nonce: Vec<u8>,
}

impl ResponseApdu for UnsealResponse {}

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
            cmd: Self::name(),
            slot,
            epubkey,
            xcvc,
        }
    }
}

impl CommandApdu for DumpCommand {
    fn name() -> String {
        "dump".to_string()
    }
}

/// Dump Response
///
/// Without the CVC, the dump command returns just the sealed/unsealed/unused status for each slot,
/// with the exception of unsealed slots where the address in full is also provided.
#[derive(Deserialize, Clone, Debug)]
pub struct DumpResponse {
    /// slot just made
    pub slot: usize,
    /// private key for spending (for addr), 32 bytes
    /// The private keys are encrypted, XORed with the session key
    #[serde(with = "serde_bytes")]
    #[serde(default)]
    pub privkey: Option<Vec<u8>>,
    /// public key, 33 bytes
    #[serde(with = "serde_bytes")]
    #[serde(default)]
    pub pubkey: Vec<u8>,
    /// nonce provided by customer originally
    #[serde(with = "serde_bytes")]
    #[serde(default)]
    pub chain_code: Option<Vec<u8>>,
    /// master private key for this slot (was picked by card), 32 bytes
    #[serde(with = "serde_bytes")]
    #[serde(default)]
    pub master_pk: Option<Vec<u8>>,
    /// flag that slots unsealed for unusual reasons (absent if false)
    #[serde(default)]
    pub tampered: Option<bool>,
    /// if no xcvc provided, slot used status
    #[serde(default)]
    pub used: Option<bool>,
    /// if no xcvc provided, slot sealed status
    pub sealed: Option<bool>,
    /// if no xcvc provided, full payment address (not censored)
    #[serde(default)]
    pub addr: Option<String>,
    /// new nonce value, for NEXT command (not this one), 16 bytes
    #[serde(with = "serde_bytes")]
    pub card_nonce: Vec<u8>,
}

impl ResponseApdu for DumpResponse {}

/// TAPSIGNER only - Provides the current XPUB (BIP-32 serialized), either at the top level (master) or the derived key in use (see 'path' value in status response)
#[derive(Serialize, Clone, Debug, PartialEq, Eq)]
pub struct XpubCommand {
    cmd: String,  // always "xpub"
    master: bool, // give master (`m`) XPUB, otherwise derived XPUB
    #[serde(with = "serde_bytes")]
    epubkey: Vec<u8>, // app's ephemeral public key (required)
    #[serde(with = "serde_bytes")]
    xcvc: Vec<u8>, //encrypted CVC value (required)
}

impl CommandApdu for XpubCommand {
    fn name() -> String {
        "xpub".to_string()
    }
}

impl XpubCommand {
    pub fn new(master: bool, epubkey: PublicKey, xcvc: Vec<u8>) -> Self {
        Self {
            cmd: Self::name(),
            master,
            epubkey: epubkey.serialize().to_vec(),
            xcvc,
        }
    }
}

#[derive(Deserialize, Clone)]
pub struct XpubResponse {
    #[serde(with = "serde_bytes")]
    pub xpub: Vec<u8>,
    #[serde(with = "serde_bytes")]
    pub card_nonce: Vec<u8>,
}

impl ResponseApdu for XpubResponse {}

impl Debug for XpubResponse {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        f.debug_struct("XpubResponse")
            .field("xpub", &self.xpub.to_hex())
            .field("card_nonce", &self.card_nonce.to_hex())
            .finish()
    }
}
