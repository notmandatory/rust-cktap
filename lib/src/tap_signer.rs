use secp256k1::{
    ecdsa::Signature,
    hashes::{sha256, Hash as _},
    All, Message, PublicKey, Secp256k1,
};

use crate::apdu::{
    tap_signer::ChangeCommand, CommandApdu as _, DeriveCommand, DeriveResponse, Error, NewCommand,
    NewResponse, StatusResponse,
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
    pub card_nonce: Vec<u8>, // 16 bytes
    pub auth_delay: Option<usize>,
}

impl<T: CkTransport> Authentication<T> for TapSigner<T> {
    fn secp(&self) -> &Secp256k1<All> {
        &self.secp
    }

    fn pubkey(&self) -> &PublicKey {
        &self.pubkey
    }

    fn card_nonce(&self) -> &Vec<u8> {
        &self.card_nonce
    }

    fn set_card_nonce(&mut self, new_nonce: Vec<u8>) {
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

    pub async fn init(&mut self, chain_code: Vec<u8>, cvc: String) -> Result<NewResponse, Error> {
        let (_, epubkey, xcvc) = self.calc_ekeys_xcvc(&cvc, NewCommand::name());
        let epubkey = epubkey.serialize().to_vec();
        let new_command = NewCommand::new(Some(0), Some(chain_code), epubkey, xcvc);
        let new_response: Result<NewResponse, Error> = self.transport.transmit(new_command).await;
        if let Ok(response) = &new_response {
            self.card_nonce = response.card_nonce.clone();
        }
        new_response
    }

    pub async fn derive(&mut self, path: Vec<u32>, cvc: String) -> Result<DeriveResponse, Error> {
        // set most significant bit to 1 to represent hardened path steps
        let path = path.iter().map(|p| p ^ (1 << 31)).collect();
        let app_nonce = crate::rand_nonce();
        let (_, epubkey, xcvc) = self.calc_ekeys_xcvc(&cvc, DeriveCommand::name());
        let cmd = DeriveCommand::for_tapsigner(app_nonce.clone(), path, epubkey, xcvc);
        let derive_response: Result<DeriveResponse, Error> = self.transport.transmit(cmd).await;
        if let Ok(response) = &derive_response {
            let card_nonce = self.card_nonce();
            let sig = &response.sig;
            let mut message_bytes: Vec<u8> = Vec::new();
            message_bytes.extend("OPENDIME".as_bytes());
            message_bytes.extend(card_nonce);
            message_bytes.extend(app_nonce);
            message_bytes.extend(&response.chain_code);

            let message_bytes_hash = sha256::Hash::hash(message_bytes.as_slice());
            let message = Message::from_digest(message_bytes_hash.to_byte_array());

            let signature = Signature::from_compact(sig.as_slice())?;
            let pubkey = PublicKey::from_slice(response.master_pubkey.as_slice())?;
            // TODO fix verify when a derivation path is used, currently only works if no path given
            self.secp().verify_ecdsa(&message, &signature, &pubkey)?;
            self.set_card_nonce(response.card_nonce.clone());
        }
        derive_response
    }

    pub async fn change(&mut self, new_cvc: &str, cvc: &str) -> Result<(), Error> {
        let (_, _epubkey, _xcvc) = self.calc_ekeys_xcvc(cvc, ChangeCommand::name());
        todo!()
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
    fn message_digest(&mut self, card_nonce: Vec<u8>, app_nonce: Vec<u8>) -> Message {
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
