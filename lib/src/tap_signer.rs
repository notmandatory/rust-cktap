use secp256k1::{
    ecdsa::Signature,
    hashes::{sha256, Hash as _},
    All, Message, PublicKey, Secp256k1,
};

use crate::apdu::{
    tap_signer::{BackupCommand, BackupResponse, ChangeCommand, ChangeResponse},
    CommandApdu as _, DeriveCommand, DeriveResponse, Error, NewCommand, NewResponse,
    StatusResponse,
};
use crate::commands::{Authentication, Certificate, CkTransport, Read, Wait};

pub struct TapSigner<T: CkTransport> {
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

#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum TapSignerError {
    #[error(transparent)]
    ApduError(#[from] Error),

    #[error("new cvc is too short, must be at least 6 bytes, was only {0} bytes")]
    NewCvcTooShort(usize),

    #[error("new cvc is too long, must be at most 32 bytes, was {0} bytes")]
    NewCvcTooLong(usize),

    #[error("new cvc is the same as the old one")]
    NewCvcSameAsOld,
}

impl<T: CkTransport> Authentication<T> for TapSigner<T> {
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

impl<T: CkTransport> TapSigner<T> {
    pub fn from_status(transport: T, status_response: StatusResponse) -> Self {
        let pubkey = status_response.pubkey.as_slice(); // TODO verify is 33 bytes?
        let pubkey = PublicKey::from_slice(pubkey)
            .map_err(|e| Error::CiborValue(e.to_string()))
            .unwrap();
        Self {
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
        }
    }

    pub async fn init(
        &mut self,
        chain_code: Vec<u8>,
        cvc: String,
    ) -> Result<NewResponse, TapSignerError> {
        let (_, epubkey, xcvc) = self.calc_ekeys_xcvc(&cvc, NewCommand::name());

        let new_command = NewCommand::new(Some(0), Some(chain_code), epubkey, xcvc);
        let new_response: NewResponse = self.transport.transmit(new_command).await?;

        self.card_nonce = new_response.card_nonce;
        Ok(new_response)
    }

    pub async fn derive(
        &mut self,
        path: Vec<u32>,
        cvc: String,
    ) -> Result<DeriveResponse, TapSignerError> {
        // set most significant bit to 1 to represent hardened path steps
        let path = path.iter().map(|p| p ^ (1 << 31)).collect();
        let app_nonce = crate::rand_nonce();
        let (_, epubkey, xcvc) = self.calc_ekeys_xcvc(&cvc, DeriveCommand::name());
        let cmd = DeriveCommand::for_tapsigner(app_nonce, path, epubkey, xcvc);
        let derive_response: DeriveResponse = self.transport.transmit(cmd).await?;

        let card_nonce = self.card_nonce();
        let sig = &derive_response.sig;
        let mut message_bytes: Vec<u8> = Vec::new();
        message_bytes.extend("OPENDIME".as_bytes());
        message_bytes.extend(card_nonce);
        message_bytes.extend(app_nonce);
        message_bytes.extend(&derive_response.chain_code);

        let message_bytes_hash = sha256::Hash::hash(message_bytes.as_slice());
        let message = Message::from_digest(message_bytes_hash.to_byte_array());

        let signature = Signature::from_compact(sig.as_slice()).map_err(Error::from)?;
        let pubkey =
            PublicKey::from_slice(derive_response.master_pubkey.as_slice()).map_err(Error::from)?;

        // TODO fix verify when a derivation path is used, currently only works if no path given
        self.secp()
            .verify_ecdsa(&message, &signature, &pubkey)
            .map_err(Error::from)?;

        self.card_nonce = derive_response.card_nonce;
        Ok(derive_response)
    }

    pub async fn change(
        &mut self,
        new_cvc: &str,
        cvc: &str,
    ) -> Result<ChangeResponse, TapSignerError> {
        if new_cvc.len() < 6 {
            return Err(TapSignerError::NewCvcTooShort(new_cvc.len()));
        }

        if new_cvc.len() > 32 {
            return Err(TapSignerError::NewCvcTooLong(new_cvc.len()));
        }

        if new_cvc == cvc {
            return Err(TapSignerError::NewCvcSameAsOld);
        }

        let (_, epubkey, xcvc) = self.calc_ekeys_xcvc(cvc, ChangeCommand::name());

        let change_command = ChangeCommand::new(new_cvc.as_bytes().to_vec(), epubkey, xcvc);
        let change_response: ChangeResponse = self.transport.transmit(change_command).await?;

        self.card_nonce = change_response.card_nonce;
        Ok(change_response)
    }

    pub async fn backup(&mut self, cvc: &str) -> Result<BackupResponse, TapSignerError> {
        let (_, epubkey, xcvc) = self.calc_ekeys_xcvc(cvc, "backup");

        let backup_command = BackupCommand::new(epubkey, xcvc);
        let backup_response: BackupResponse = self.transport.transmit(backup_command).await?;

        self.card_nonce = backup_response.card_nonce;
        Ok(backup_response)
    }
}

impl<T: CkTransport> Wait<T> for TapSigner<T> {}

impl<T: CkTransport> Read<T> for TapSigner<T> {
    fn requires_auth(&self) -> bool {
        true
    }

    fn slot(&self) -> Option<u8> {
        None
    }
}

impl<T: CkTransport> Certificate<T> for TapSigner<T> {
    fn message_digest(&mut self, card_nonce: [u8; 16], app_nonce: [u8; 16]) -> Message {
        let mut message_bytes: Vec<u8> = Vec::new();
        message_bytes.extend("OPENDIME".as_bytes());
        message_bytes.extend(card_nonce);
        message_bytes.extend(app_nonce);

        let message_bytes_hash = sha256::Hash::hash(message_bytes.as_slice());
        Message::from_digest(message_bytes_hash.to_byte_array())
    }
}

impl<T: CkTransport> core::fmt::Debug for TapSigner<T> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("TapSigner")
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
