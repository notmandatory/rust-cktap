use serde::Deserialize;

pub const ISO_APPLET_SELECT_APDU: [u8; 20] = *b"\x00\xa4\x04\x00\x0f\xf0CoinkiteCARDv1";

#[derive(Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct StatusResponse {
    proto: usize,
    ver: String,
    birth: usize,
    slots: Option<Vec<usize>>,
    addr: Option<String>,
    tapsigner: Option<bool>,
    path: Option<Vec<usize>>,
    num_backups: Option<usize>,
    #[serde(with = "serde_bytes")]
    pubkey: Vec<u8>,
    #[serde(with = "serde_bytes")]
    card_nonce: Vec<u8>,
}