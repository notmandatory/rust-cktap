use bitcoin::secp256k1;
use serde::Deserialize;
use std::fmt::Debug;

// Errors
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum Error {
    #[error("CiborDe: {0}")]
    CiborDe(String),
    #[error("CiborValue: {0}")]
    CiborValue(String),
    #[error("CkTap: {0:?}")]
    CkTap(CkTapError),
    #[error("IncorrectSignature: {0}")]
    IncorrectSignature(String),
    #[error("Root cert is not from Coinkite. Card is counterfeit: {0}")]
    InvalidRootCert(String),
    #[error("Card chain code doesn't match user provided chain code")]
    InvalidChaincode,
    #[error("UnknownCardType: {0}")]
    UnknownCardType(String),
    #[error("Transport: {0}")]
    Transport(String),
    #[error("PSBT: {0}")]
    Psbt(String),
    #[error("Sign PSBT: {0}")]
    SignPsbt(String),
    #[error("Slot is sealed: {0}")]
    SlotSealed(u8),
    #[error("Slot is unused: {0}")]
    SlotUnused(u8),
    /// If the slot was unsealed due to confusion or uncertainty about its status.
    /// In other words, if the card unsealed itself rather than via a
    /// successful `unseal` command.
    #[error("Slot was unsealed improperly: {0}")]
    SlotTampered(u8),
}

#[derive(Debug, Copy, Clone, PartialEq, Eq, thiserror::Error)]
pub enum CkTapError {
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

impl CkTapError {
    pub fn error_from_code(code: u16) -> Option<CkTapError> {
        match code {
            205 => Some(CkTapError::UnluckyNumber),
            400 => Some(CkTapError::BadArguments),
            401 => Some(CkTapError::BadAuth),
            403 => Some(CkTapError::NeedsAuth),
            404 => Some(CkTapError::UnknownCommand),
            405 => Some(CkTapError::InvalidCommand),
            406 => Some(CkTapError::InvalidState),
            417 => Some(CkTapError::WeakNonce),
            422 => Some(CkTapError::BadCBOR),
            425 => Some(CkTapError::BackupFirst),
            429 => Some(CkTapError::RateLimited),
            _ => None,
        }
    }

    pub fn error_code(&self) -> u16 {
        match self {
            CkTapError::UnluckyNumber => 205,
            CkTapError::BadArguments => 400,
            CkTapError::BadAuth => 401,
            CkTapError::NeedsAuth => 403,
            CkTapError::UnknownCommand => 404,
            CkTapError::InvalidCommand => 405,
            CkTapError::InvalidState => 406,
            CkTapError::WeakNonce => 417,
            CkTapError::BadCBOR => 422,
            CkTapError::BackupFirst => 425,
            CkTapError::RateLimited => 429,
        }
    }
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

impl From<bitcoin::key::FromSliceError> for Error {
    fn from(e: bitcoin::key::FromSliceError) -> Self {
        Error::CiborValue(e.to_string())
    }
}

#[cfg(feature = "pcsc")]
impl From<pcsc::Error> for Error {
    fn from(e: pcsc::Error) -> Self {
        Error::Transport(e.to_string())
    }
}

#[derive(Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct ErrorResponse {
    pub error: String,
    pub code: u16,
}
