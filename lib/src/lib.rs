extern crate core;

use bitcoin::key::rand::Rng as _;
use commands::CkTransport;

pub mod apdu;
pub mod commands;
pub mod factory_root_key;

pub use bitcoin::{
    Address, Network,
    key::CompressedPublicKey,
    key::UntweakedPublicKey,
    secp256k1::{self, rand},
};
pub use bitcoin_hashes;

#[cfg(feature = "emulator")]
pub mod emulator;

#[cfg(feature = "pcsc")]
pub mod pcsc;
pub mod sats_card;
pub mod sats_chip;
pub mod tap_signer;

pub type TapSigner<T> = tap_signer::TapSigner<T>;
pub type SatsCard<T> = sats_card::SatsCard<T>;

pub enum CkTapCard<T: CkTransport> {
    SatsCard(SatsCard<T>),
    TapSigner(TapSigner<T>),
    SatsChip(SatsChip<T>),
}

// re-export
use crate::sats_chip::SatsChip;
pub use apdu::Error;

impl<T: CkTransport> core::fmt::Debug for CkTapCard<T> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match &self {
            CkTapCard::TapSigner(t) => {
                write!(f, "CkTap::TapSigner({t:?})")
            }
            CkTapCard::SatsChip(t) => {
                write!(f, "CkTap::SatsChip({t:?})")
            }
            CkTapCard::SatsCard(s) => {
                write!(f, "CkTap::SatsCard({s:?})")
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

// Errors
// #[derive(Debug)]
// pub enum Error {

//     // #[cfg(feature = "pcsc")]
//     // PcSc(String),
// }

// impl<T> From<ciborium::de::Error<T>> for Error
// where
//     T: Debug,
// {
//     fn from(e: ciborium::de::Error<T>) -> Self {
//         Error::CiborDe(e.to_string())
//     }
// }
