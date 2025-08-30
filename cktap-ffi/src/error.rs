// Copyright (c) 2025 rust-cktap contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

use std::fmt::Debug;

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error, uniffi::Error)]
pub enum KeyError {
    #[error("Secp256k1 error: {msg}")]
    Secp256k1 { msg: String },
    #[error("Key from slice error: {msg}")]
    KeyFromSlice { msg: String },
}

impl From<rust_cktap::SecpError> for KeyError {
    fn from(value: rust_cktap::SecpError) -> Self {
        KeyError::Secp256k1 {
            msg: value.to_string(),
        }
    }
}

impl From<rust_cktap::FromSliceError> for KeyError {
    fn from(value: rust_cktap::FromSliceError) -> Self {
        KeyError::KeyFromSlice {
            msg: value.to_string(),
        }
    }
}

#[derive(Debug, thiserror::Error, uniffi::Error)]
pub enum ChainCodeError {
    #[error("Invalid length {len}, must be 32 bytes")]
    InvalidLength { len: u64 },
}

impl From<Vec<u8>> for ChainCodeError {
    fn from(value: Vec<u8>) -> Self {
        ChainCodeError::InvalidLength {
            len: value.len() as u64,
        }
    }
}

#[derive(Debug, thiserror::Error, uniffi::Error)]
pub enum PsbtError {
    #[error("Could not parse psbt: {msg}")]
    Parse { msg: String },
}

impl From<rust_cktap::PsbtParseError> for PsbtError {
    fn from(value: rust_cktap::PsbtParseError) -> Self {
        PsbtError::Parse {
            msg: value.to_string(),
        }
    }
}

/// Errors returned by the CkTap card.
#[derive(Debug, Copy, Clone, PartialEq, Eq, thiserror::Error, uniffi::Error)]
pub enum CardError {
    #[error("Rare or unlucky value used/occurred. Start again")]
    UnluckyNumber,
    #[error("Invalid/incorrect/incomplete arguments provided to command")]
    BadArguments,
    #[error("Authentication details (CVC/epubkey) are wrong")]
    BadAuth,
    #[error("Command requires auth, and none was provided")]
    NeedsAuth,
    #[error("The 'cmd' field is an unsupported command")]
    UnknownCommand,
    #[error("Command is not valid at this time, no point retrying")]
    InvalidCommand,
    #[error("You can't do that right now when card is in this state")]
    InvalidState,
    #[error("Nonce is not unique-looking enough")]
    WeakNonce,
    #[error("Unable to decode CBOR data stream")]
    BadCBOR,
    #[error("Can't change CVC without doing a backup first")]
    BackupFirst,
    #[error("Due to auth failures, delay required")]
    RateLimited,
}

impl From<rust_cktap::CardError> for CardError {
    fn from(value: rust_cktap::CardError) -> Self {
        match value {
            rust_cktap::CardError::UnluckyNumber => CardError::UnluckyNumber,
            rust_cktap::CardError::BadArguments => CardError::BadArguments,
            rust_cktap::CardError::BadAuth => CardError::BadAuth,
            rust_cktap::CardError::NeedsAuth => CardError::NeedsAuth,
            rust_cktap::CardError::UnknownCommand => CardError::UnknownCommand,
            rust_cktap::CardError::InvalidCommand => CardError::InvalidCommand,
            rust_cktap::CardError::InvalidState => CardError::InvalidState,
            rust_cktap::CardError::WeakNonce => CardError::WeakNonce,
            rust_cktap::CardError::BadCBOR => CardError::BadCBOR,
            rust_cktap::CardError::BackupFirst => CardError::BackupFirst,
            rust_cktap::CardError::RateLimited => CardError::RateLimited,
        }
    }
}

/// Errors returned by the card, CBOR deserialization or value encoding, or the APDU transport.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error, uniffi::Error)]
pub enum CkTapError {
    #[error(transparent)]
    Card { err: CardError },
    #[error("CBOR deserialization error: {msg}")]
    CborDe { msg: String },
    #[error("CBOR value error: {msg}")]
    CborValue { msg: String },
    #[error("APDU transport error: {msg}")]
    Transport { msg: String },
    #[error("Unknown card type")]
    UnknownCardType,
}

impl From<rust_cktap::CkTapError> for CkTapError {
    fn from(value: rust_cktap::CkTapError) -> Self {
        match value {
            rust_cktap::CkTapError::Card(err) => CkTapError::Card { err: err.into() },
            rust_cktap::CkTapError::CborDe(msg) => CkTapError::CborDe { msg },
            rust_cktap::CkTapError::CborValue(msg) => CkTapError::CborValue { msg },
            rust_cktap::CkTapError::Transport(msg) => CkTapError::Transport { msg },
            rust_cktap::CkTapError::UnknownCardType => CkTapError::UnknownCardType,
        }
    }
}

/// Errors returned by the `status` command.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error, uniffi::Error)]
pub enum StatusError {
    #[error(transparent)]
    CkTap {
        #[from]
        err: CkTapError,
    },
    #[error(transparent)]
    Key {
        #[from]
        err: KeyError,
    },
}

impl From<rust_cktap::StatusError> for StatusError {
    fn from(value: rust_cktap::StatusError) -> Self {
        match value {
            rust_cktap::StatusError::CkTap(err) => StatusError::CkTap { err: err.into() },
            rust_cktap::StatusError::KeyFromSlice(err) => StatusError::Key { err: err.into() },
        }
    }
}

/// Errors returned by the `read` command.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error, uniffi::Error)]
pub enum ReadError {
    #[error(transparent)]
    CkTap {
        #[from]
        err: CkTapError,
    },
    #[error(transparent)]
    Key {
        #[from]
        err: KeyError,
    },
}

impl From<rust_cktap::ReadError> for ReadError {
    fn from(value: rust_cktap::ReadError) -> Self {
        match value {
            rust_cktap::ReadError::CkTap(err) => ReadError::CkTap { err: err.into() },
            rust_cktap::ReadError::Secp256k1(err) => ReadError::Key { err: err.into() },
            rust_cktap::ReadError::KeyFromSlice(err) => ReadError::Key { err: err.into() },
        }
    }
}

/// Errors returned by the `certs` command.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error, uniffi::Error)]
pub enum CertsError {
    #[error(transparent)]
    CkTap {
        #[from]
        err: CkTapError,
    },
    #[error(transparent)]
    Key {
        #[from]
        err: KeyError,
    },
    #[error("Root cert is not from Coinkite. Card is counterfeit: {msg}")]
    InvalidRootCert { msg: String },
}

impl From<rust_cktap::CertsError> for CertsError {
    fn from(value: rust_cktap::CertsError) -> Self {
        match value {
            rust_cktap::CertsError::CkTap(err) => CertsError::CkTap { err: err.into() },
            rust_cktap::CertsError::Secp256k1(err) => CertsError::Key { err: err.into() },
            rust_cktap::CertsError::KeyFromSlice(err) => CertsError::Key { err: err.into() },
            rust_cktap::CertsError::InvalidRootCert(msg) => CertsError::InvalidRootCert { msg },
        }
    }
}

/// Errors returned by the `derive` command.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error, uniffi::Error)]
pub enum DeriveError {
    #[error(transparent)]
    CkTap {
        #[from]
        err: CkTapError,
    },
    #[error(transparent)]
    Key {
        #[from]
        err: KeyError,
    },
    #[error("Invalid chain code: {msg}")]
    InvalidChainCode { msg: String },
}

impl From<rust_cktap::DeriveError> for DeriveError {
    fn from(value: rust_cktap::DeriveError) -> Self {
        match value {
            rust_cktap::DeriveError::CkTap(err) => DeriveError::CkTap { err: err.into() },
            rust_cktap::DeriveError::Secp256k1(err) => DeriveError::Key { err: err.into() },
            rust_cktap::DeriveError::KeyFromSlice(err) => DeriveError::Key { err: err.into() },
            rust_cktap::DeriveError::InvalidChainCode(msg) => DeriveError::InvalidChainCode { msg },
        }
    }
}

/// Errors returned by the `unseal` command.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error, uniffi::Error)]
pub enum UnsealError {
    #[error(transparent)]
    CkTap {
        #[from]
        err: CkTapError,
    },
    #[error(transparent)]
    Key {
        #[from]
        err: KeyError,
    },
}

impl From<rust_cktap::UnsealError> for UnsealError {
    fn from(value: rust_cktap::UnsealError) -> Self {
        match value {
            rust_cktap::UnsealError::CkTap(err) => UnsealError::CkTap { err: err.into() },
            rust_cktap::UnsealError::Secp256k1(err) => UnsealError::Key { err: err.into() },
            rust_cktap::UnsealError::KeyFromSlice(err) => UnsealError::Key { err: err.into() },
        }
    }
}

/// Errors returned by the `dump` command.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error, uniffi::Error)]
pub enum DumpError {
    #[error(transparent)]
    CkTap {
        #[from]
        err: CkTapError,
    },
    #[error(transparent)]
    Key {
        #[from]
        err: KeyError,
    },
    #[error("Slot is sealed: {slot}")]
    SlotSealed { slot: u8 },
    #[error("Slot is unused: {slot}")]
    SlotUnused { slot: u8 },
    /// If the slot was unsealed due to confusion or uncertainty about its status.
    /// In other words, if the card unsealed itself rather than via a
    /// successful `unseal` command.
    #[error("Slot was unsealed improperly: {slot}")]
    SlotTampered { slot: u8 },
}

impl From<rust_cktap::DumpError> for DumpError {
    fn from(value: rust_cktap::DumpError) -> Self {
        match value {
            rust_cktap::DumpError::CkTap(err) => DumpError::CkTap { err: err.into() },
            rust_cktap::DumpError::Secp256k1(err) => DumpError::Key { err: err.into() },
            rust_cktap::DumpError::KeyFromSlice(err) => DumpError::Key { err: err.into() },
            rust_cktap::DumpError::SlotSealed(slot) => DumpError::SlotSealed { slot },
            rust_cktap::DumpError::SlotUnused(slot) => DumpError::SlotUnused { slot },
            rust_cktap::DumpError::SlotTampered(slot) => DumpError::SlotTampered { slot },
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error, uniffi::Error)]
pub enum SignPsbtError {
    #[error("Invalid path at index: {index}")]
    InvalidPath { index: u64 },
    #[error("Invalid script at index: {index}")]
    InvalidScript { index: u64 },
    #[error("Missing pubkey at index: {index}")]
    MissingPubkey { index: u64 },
    #[error("Missing UTXO at index: {index}")]
    MissingUtxo { index: u64 },
    #[error("Pubkey mismatch at index: {index}")]
    PubkeyMismatch { index: u64 },
    #[error("Sighash error: {msg}")]
    SighashError { msg: String },
    #[error("Signature error: {msg}")]
    SignatureError { msg: String },
    #[error("Signing slot is not unsealed: {slot}")]
    SlotNotUnsealed { slot: u8 },
    #[error(transparent)]
    CkTap {
        #[from]
        err: CkTapError,
    },
    #[error("Witness program error: {msg}")]
    WitnessProgram { msg: String },
}

impl From<rust_cktap::SignPsbtError> for SignPsbtError {
    fn from(value: rust_cktap::SignPsbtError) -> SignPsbtError {
        match value {
            rust_cktap::SignPsbtError::InvalidPath(index) => SignPsbtError::InvalidPath {
                index: index as u64,
            },
            rust_cktap::SignPsbtError::InvalidScript(index) => SignPsbtError::InvalidScript {
                index: index as u64,
            },
            rust_cktap::SignPsbtError::MissingPubkey(index) => SignPsbtError::MissingPubkey {
                index: index as u64,
            },
            rust_cktap::SignPsbtError::MissingUtxo(index) => SignPsbtError::MissingUtxo {
                index: index as u64,
            },
            rust_cktap::SignPsbtError::PubkeyMismatch(index) => SignPsbtError::PubkeyMismatch {
                index: index as u64,
            },
            rust_cktap::SignPsbtError::SighashError(msg) => SignPsbtError::SighashError { msg },
            rust_cktap::SignPsbtError::SignatureError(msg) => SignPsbtError::SignatureError { msg },
            rust_cktap::SignPsbtError::SlotNotUnsealed(slot) => {
                SignPsbtError::SlotNotUnsealed { slot }
            }
            rust_cktap::SignPsbtError::CkTap(err) => SignPsbtError::CkTap { err: err.into() },
            rust_cktap::SignPsbtError::WitnessProgram(msg) => SignPsbtError::WitnessProgram { msg },
        }
    }
}

/// Errors returned by the `change` command.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error, uniffi::Error)]
pub enum ChangeError {
    #[error(transparent)]
    CkTap {
        #[from]
        err: CkTapError,
    },
    #[error("new cvc is too short, must be at least 6 bytes, was only {len} bytes")]
    TooShort { len: u64 },
    #[error("new cvc is too long, must be at most 32 bytes, was {len} bytes")]
    TooLong { len: u64 },
    #[error("new cvc is the same as the old one")]
    SameAsOld,
}

impl From<rust_cktap::ChangeError> for ChangeError {
    fn from(value: rust_cktap::ChangeError) -> Self {
        match value {
            rust_cktap::ChangeError::CkTap(err) => ChangeError::CkTap { err: err.into() },
            rust_cktap::ChangeError::TooShort(len) => ChangeError::TooShort { len: len as u64 },
            rust_cktap::ChangeError::TooLong(len) => ChangeError::TooLong { len: len as u64 },
            rust_cktap::ChangeError::SameAsOld => ChangeError::SameAsOld,
        }
    }
}
