use crate::apdu::Error;
use secp256k1::hashes::hex::ToHex;
use secp256k1::PublicKey;
use std::convert::TryFrom;
use std::fmt;
use std::fmt::Debug;

/// Published Coinkite factory root keys.
const PUB_FACTORY_ROOT_KEY: &str =
    "03028a0e89e70d0ec0d932053a89ab1da7d9182bdc6d2f03e706ee99517d05d9e1";
/// Obsolete dev value, but keeping for a little while longer.
const DEV_FACTORY_ROOT_KEY: &str =
    "027722ef208e681bac05f1b4b3cc478d6bf353ac9a09ff0c843430138f65c27bab";

pub enum FactoryRootKey {
    Pub(PublicKey),
    Dev(PublicKey),
}

impl TryFrom<PublicKey> for FactoryRootKey {
    type Error = Error;

    fn try_from(pubkey: PublicKey) -> Result<Self, Error> {
        match pubkey.serialize().to_hex().as_str() {
            PUB_FACTORY_ROOT_KEY => Ok(FactoryRootKey::Pub(pubkey)),
            DEV_FACTORY_ROOT_KEY => Ok(FactoryRootKey::Dev(pubkey)),
            _ => Err(Error::IncorrectSignature(
                "Root cert is not from Coinkite. Card is counterfeit.".to_string(),
            )),
        }
    }
}

impl FactoryRootKey {
    pub fn name(&self) -> String {
        match &self {
            FactoryRootKey::Pub(_) => "Root Factory Certificate".to_string(),
            FactoryRootKey::Dev(_) => "Root Factory Certificate (TESTING ONLY)".to_string(),
        }
    }
}

impl Debug for FactoryRootKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self {
            FactoryRootKey::Pub(pk) => {
                write!(f, "FactoryRootKey::Pub({:?})", pk)
            }
            FactoryRootKey::Dev(pk) => {
                write!(f, "FactoryRootKey::Dev({:?})", pk)
            }
        }
    }
}
