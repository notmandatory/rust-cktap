use core::fmt::{self, Formatter};

use super::{CommandApdu, ResponseApdu};

use secp256k1::{hashes::hex::DisplayHex as _, PublicKey};
use serde::{Deserialize, Serialize};

// MARK: - XpubCommand
/// TAPSIGNER only - Provides the current XPUB (BIP-32 serialized), either at the top level (master) or the derived key in use (see 'path' value in status response)
#[derive(Serialize, Clone, Debug, PartialEq, Eq)]
pub struct XpubCommand {
    cmd: &'static str, // always "xpub"
    master: bool,      // give master (`m`) XPUB, otherwise derived XPUB
    #[serde(with = "serde_bytes")]
    epubkey: [u8; 33], // app's ephemeral public key (required)
    #[serde(with = "serde_bytes")]
    xcvc: Vec<u8>, //encrypted CVC value (required)
}

impl CommandApdu for XpubCommand {
    fn name() -> &'static str {
        "xpub"
    }
}

impl XpubCommand {
    pub fn new(master: bool, epubkey: PublicKey, xcvc: Vec<u8>) -> Self {
        Self {
            cmd: Self::name(),
            master,
            epubkey: epubkey.serialize(),
            xcvc,
        }
    }
}

#[derive(Deserialize, Clone)]
pub struct XpubResponse {
    #[serde(with = "serde_bytes")]
    pub xpub: Vec<u8>,
    #[serde(with = "serde_bytes")]
    pub card_nonce: [u8; 16],
}

impl ResponseApdu for XpubResponse {}

impl std::fmt::Debug for XpubResponse {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        f.debug_struct("XpubResponse")
            .field("xpub", &self.xpub.to_lower_hex_string())
            .field("card_nonce", &self.card_nonce.to_lower_hex_string())
            .finish()
    }
}

// MARK: - ChangeCommand
/// TAPSIGNER only - Change the PIN (CVC) used for card authentication to a new user provided one
#[derive(Serialize, Clone, Debug, PartialEq, Eq)]
pub struct ChangeCommand {
    // always "change"
    cmd: &'static str,

    // new cvc value (required) (6 - 32 bytes)
    #[serde(with = "serde_bytes")]
    data: Vec<u8>,

    // app's ephemeral public key (required)
    #[serde(with = "serde_bytes")]
    epubkey: [u8; 33],

    //encrypted CVC value (required) (6-32 bytes)
    #[serde(with = "serde_bytes")]
    xcvc: Vec<u8>,
}

impl CommandApdu for ChangeCommand {
    fn name() -> &'static str {
        "change"
    }
}

impl ChangeCommand {
    pub fn new(data: Vec<u8>, epubkey: PublicKey, xcvc: Vec<u8>) -> Self {
        Self {
            cmd: Self::name(),
            data,
            epubkey: epubkey.serialize(),
            xcvc,
        }
    }
}
