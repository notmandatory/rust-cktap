use secp256k1::{
    ecdsa::Signature,
    hashes::{sha256, Hash as _},
    All, Message, PublicKey, Secp256k1,
};

use crate::apdu::{
    CommandApdu as _, DeriveCommand, DeriveResponse, DumpCommand, DumpResponse, Error, NewCommand,
    NewResponse, StatusResponse, UnsealCommand, UnsealResponse,
};
use crate::commands::{Authentication, Certificate, CkTransport, Read, Wait};

pub struct SatsCard<T: CkTransport> {
    pub transport: T,
    pub secp: Secp256k1<All>,
    pub proto: usize,
    pub ver: String,
    pub birth: usize,
    pub slots: (u8, u8),
    pub addr: Option<String>,
    pub pubkey: PublicKey,
    pub card_nonce: Vec<u8>, // 16 bytes
    pub auth_delay: Option<usize>,
}

impl<T: CkTransport> Authentication<T> for SatsCard<T> {
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

impl<T: CkTransport> SatsCard<T> {
    pub fn from_status(transport: T, status_response: StatusResponse) -> Result<Self, Error> {
        let pubkey = status_response.pubkey.as_slice(); // TODO verify is 33 bytes?
        let pubkey = PublicKey::from_slice(pubkey)
            .map_err(|e| Error::CiborValue(e.to_string()))
            .unwrap();
        let slots = status_response
            .slots
            .ok_or_else(|| Error::CiborValue("Missing slots".to_string()))?;
        Ok(Self {
            transport,
            secp: Secp256k1::new(),
            proto: status_response.proto,
            ver: status_response.ver,
            birth: status_response.birth,
            pubkey,
            card_nonce: status_response.card_nonce,
            auth_delay: status_response.auth_delay,
            slots,
            addr: status_response.addr,
        })
    }

    pub async fn new_slot(
        &mut self,
        slot: u8,
        chain_code: Option<Vec<u8>>,
        cvc: String,
    ) -> Result<NewResponse, Error> {
        let (_, epubkey, xcvc) = self.calc_ekeys_xcvc(cvc, &NewCommand::name());
        let epubkey = epubkey.serialize().to_vec();
        let new_command = NewCommand::new(Some(slot), chain_code, epubkey, xcvc);
        let new_response: Result<NewResponse, Error> = self.transport.transmit(new_command).await;
        if let Ok(response) = &new_response {
            self.card_nonce = response.card_nonce.clone();
            self.slots.0 = response.slot;
        }
        new_response
    }

    pub async fn derive(&mut self) -> Result<DeriveResponse, Error> {
        let nonce = crate::rand_nonce();
        let card_nonce = self.card_nonce().clone();

        let cmd = DeriveCommand::for_satscard(nonce.clone());
        let resp: Result<DeriveResponse, Error> = self.transport().transmit(cmd).await;

        if let Ok(r) = &resp {
            self.set_card_nonce(r.card_nonce.clone());

            // Verify signature
            let mut message_bytes: Vec<u8> = Vec::new();
            message_bytes.extend("OPENDIME".as_bytes());
            message_bytes.extend(card_nonce);
            message_bytes.extend(nonce);
            message_bytes.extend(r.chain_code.clone());

            let message_bytes_hash = sha256::Hash::hash(message_bytes.as_slice());
            let message = Message::from_digest(message_bytes_hash.to_byte_array());
            let signature = Signature::from_compact(r.sig.as_slice())
                .expect("Failed to construct ECDSA signature from check response");
            let pubkey = PublicKey::from_slice(r.master_pubkey.as_slice())?;
            self.secp().verify_ecdsa(&message, &signature, &pubkey)?;
        }
        resp
    }

    pub async fn unseal(&mut self, slot: u8, cvc: String) -> Result<UnsealResponse, Error> {
        let (_, epubkey, xcvc) = self.calc_ekeys_xcvc(cvc, &UnsealCommand::name());
        let epubkey = epubkey.serialize().to_vec();
        let unseal_command = UnsealCommand::new(slot, epubkey, xcvc);
        let unseal_response: Result<UnsealResponse, Error> =
            self.transport.transmit(unseal_command).await;
        if let Ok(response) = &unseal_response {
            self.set_card_nonce(response.card_nonce.clone())
        }
        unseal_response
    }

    pub async fn dump(&self, slot: usize, cvc: Option<String>) -> Result<DumpResponse, Error> {
        let epubkey_xcvc = cvc.map(|cvc| {
            let (_, epubkey, xcvc) = self.calc_ekeys_xcvc(cvc, &DumpCommand::name());
            (epubkey, xcvc)
        });

        let (epubkey, xcvc) = epubkey_xcvc
            .map(|(epubkey, xcvc)| (Some(epubkey.serialize().to_vec()), Some(xcvc)))
            .unwrap_or((None, None));

        let dump_command = DumpCommand::new(slot, epubkey, xcvc);
        self.transport.transmit(dump_command).await
    }

    pub fn address(&mut self) -> Result<String, Error> {
        // let pubkey = self.read(None).unwrap().pubkey;
        // // let hrp = match self.testnet() { }
        // let encoded = bech32::encode("bc", pubkey.to_base32(), Variant::Bech32);
        // match encoded {
        //     Ok(e) => Ok(e),
        //     Err(_) => panic!("Failed to encoded pubkey")
        // }
        todo!()
    }
}

impl<T: CkTransport> Wait<T> for SatsCard<T> {}

impl<T: CkTransport> Read<T> for SatsCard<T> {
    fn requires_auth(&self) -> bool {
        false
    }
    fn slot(&self) -> Option<u8> {
        Some(self.slots.0)
    }
}

impl<T: CkTransport> Certificate<T> for SatsCard<T> {
    fn message_digest(&mut self, card_nonce: Vec<u8>, app_nonce: Vec<u8>) -> Message {
        let mut message_bytes: Vec<u8> = Vec::new();
        message_bytes.extend("OPENDIME".as_bytes());
        message_bytes.extend(card_nonce);
        message_bytes.extend(app_nonce);
        if self.ver != "0.9.0" {
            // Since this calls an async method, for now we don't include the pubkey
            // A better solution would be to store the pubkey
            // let pubkey = self.read(None).await.unwrap().pubkey;
            // message_bytes.extend(pubkey);
        }

        let message_bytes_hash = sha256::Hash::hash(message_bytes.as_slice());
        Message::from_digest(message_bytes_hash.to_byte_array())
    }
}

impl<T: CkTransport> core::fmt::Debug for SatsCard<T> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("SatsCard")
            .field("proto", &self.proto)
            .field("ver", &self.ver)
            .field("birth", &self.birth)
            .field("slots", &self.slots)
            .field("addr", &self.addr)
            .field("pubkey", &self.pubkey)
            .field("card_nonce", &self.card_nonce)
            .field("auth_delay", &self.auth_delay)
            .finish()
    }
}
