extern crate core;

pub use bitcoin::psbt::Psbt;
pub use bitcoin::secp256k1::rand;
pub use bitcoin_hashes::sha256::Hash;

pub use commands::CkTransport;
pub use error::CkTapError;
pub use error::Error;

use bitcoin::key::rand::Rng as _;

pub(crate) mod apdu;
pub mod commands;
pub mod error;
pub(crate) mod factory_root_key;
pub mod sats_card;
pub mod sats_chip;
pub mod tap_signer;

#[cfg(feature = "emulator")]
pub mod emulator;

#[cfg(feature = "pcsc")]
pub mod pcsc;

pub type SatsCard = sats_card::SatsCard;
pub type TapSigner = tap_signer::TapSigner;
pub type SatsChip = sats_chip::SatsChip;

// BIP 32 hardened derivation bitmask, 1 << 31
const BIP32_HARDENED_MASK: u32 = 1 << 31;

pub enum CkTapCard {
    SatsCard(SatsCard),
    TapSigner(TapSigner),
    SatsChip(SatsChip),
}

impl core::fmt::Debug for CkTapCard {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match &self {
            CkTapCard::TapSigner(ts) => {
                write!(f, "CkTap::TapSigner({ts:?})")
            }
            CkTapCard::SatsChip(sc) => {
                write!(f, "CkTap::SatsChip({sc:?})")
            }
            CkTapCard::SatsCard(sc) => {
                write!(f, "CkTap::SatsCard({sc:?})")
            }
        }
    }
}

// utility functions

pub fn rand_chaincode(rng: &mut rand::rngs::ThreadRng) -> [u8; 32] {
    let mut chain_code = [0u8; 32];
    rng.fill(&mut chain_code);
    chain_code
}

pub fn rand_nonce() -> [u8; 16] {
    let rng = &mut rand::thread_rng();
    let mut nonce = [0u8; 16];
    rng.fill(&mut nonce);
    nonce
}
