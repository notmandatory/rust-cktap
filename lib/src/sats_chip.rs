use bitcoin::secp256k1::{
    hashes::{sha256, Hash as _},
    All, Message, PublicKey, Secp256k1,
};

use crate::apdu::{Error, StatusResponse};
use crate::commands::{Authentication, Certificate, CkTransport, Read, Wait};
use crate::tap_signer::TapSignerShared;

/// - SATSCHIP model: this product variant is a TAPSIGNER in all respects,
///   except, as of v1.0.0: `num_backups` in status field is omitted, and
///   a flag `satschip=True` will be present instead. The "backup" command
///   is not supported and will fail with 404 error.
pub struct SatsChip<T: CkTransport> {
    pub transport: T,
    pub secp: Secp256k1<All>,
    pub proto: usize,
    pub ver: String,
    pub birth: usize,
    pub path: Option<Vec<usize>>,
    // [(1<<31)+84, (1<<31), (1<<31)], user-defined, will be omitted if not yet setup
    pub num_backups: Option<usize>,
    pub pubkey: PublicKey,
    pub card_nonce: [u8; 16],
    pub auth_delay: Option<usize>,
}

impl<T: CkTransport> Authentication<T> for SatsChip<T> {
    fn secp(&self) -> &Secp256k1<All> {
        &self.secp
    }

    fn pubkey(&self) -> &PublicKey {
        &self.pubkey
    }

    fn card_nonce(&self) -> &[u8; 16] {
        &self.card_nonce
    }

    fn set_card_nonce(&mut self, new_nonce: [u8; 16]) {
        self.card_nonce = new_nonce;
    }

    fn auth_delay(&self) -> &Option<usize> {
        &self.auth_delay
    }

    fn set_auth_delay(&mut self, auth_delay: Option<usize>) {
        self.auth_delay = auth_delay;
    }

    fn transport(&self) -> &T {
        &self.transport
    }
}

impl<T: CkTransport> TapSignerShared<T> for SatsChip<T> {}

impl<T: CkTransport> SatsChip<T> {
    pub fn try_from_status(transport: T, status_response: StatusResponse) -> Result<Self, Error> {
        let pubkey = status_response.pubkey.as_slice();
        let pubkey = PublicKey::from_slice(pubkey).map_err(|e| Error::CiborValue(e.to_string()))?;

        Ok(Self {
            transport,
            secp: Secp256k1::new(),
            proto: status_response.proto,
            ver: status_response.ver,
            birth: status_response.birth,
            path: status_response.path,
            num_backups: status_response.num_backups,
            pubkey,
            card_nonce: status_response.card_nonce,
            auth_delay: status_response.auth_delay,
        })
    }
}

impl<T: CkTransport> Wait<T> for SatsChip<T> {}

impl<T: CkTransport> Read<T> for SatsChip<T> {
    fn requires_auth(&self) -> bool {
        true
    }

    fn slot(&self) -> Option<u8> {
        None
    }
}

impl<T: CkTransport> Certificate<T> for SatsChip<T> {
    fn message_digest(&mut self, card_nonce: [u8; 16], app_nonce: [u8; 16]) -> Message {
        let mut message_bytes: Vec<u8> = Vec::new();
        message_bytes.extend("OPENDIME".as_bytes());
        message_bytes.extend(card_nonce);
        message_bytes.extend(app_nonce);

        let message_bytes_hash = sha256::Hash::hash(message_bytes.as_slice());
        Message::from_digest(message_bytes_hash.to_byte_array())
    }
}

impl<T: CkTransport> core::fmt::Debug for SatsChip<T> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("SatsChip")
            .field("proto", &self.proto)
            .field("ver", &self.ver)
            .field("birth", &self.birth)
            .field("path", &self.path)
            .field("num_backups", &self.num_backups)
            .field("pubkey", &self.pubkey)
            .field("card_nonce", &self.card_nonce)
            .field("auth_delay", &self.auth_delay)
            .finish()
    }
}
