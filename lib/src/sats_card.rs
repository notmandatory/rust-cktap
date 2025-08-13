use bitcoin::hashes::{Hash as _, sha256};
use bitcoin::key::CompressedPublicKey as BitcoinPublicKey;
use bitcoin::secp256k1::{All, Message, PublicKey, Secp256k1, ecdsa::Signature};
use bitcoin::{Address, Network};

use crate::apdu::{
    CommandApdu as _, DeriveCommand, DeriveResponse, DumpCommand, DumpResponse, Error, NewCommand,
    NewResponse, StatusResponse, UnsealCommand, UnsealResponse,
};
use crate::commands::{Authentication, Certificate, CkTransport, Read, Wait};
use crate::secp256k1::hashes::hex::DisplayHex;

pub struct SatsCard<T: CkTransport> {
    pub transport: T,
    pub secp: Secp256k1<All>,
    pub proto: usize,
    pub ver: String,
    pub birth: usize,
    pub slots: (u8, u8),
    pub addr: Option<String>,
    pub pubkey: PublicKey,
    pub card_nonce: [u8; 16],
    pub auth_delay: Option<usize>,
}

impl<T: CkTransport> Authentication<T> for SatsCard<T> {
    fn secp(&self) -> &Secp256k1<All> {
        &self.secp
    }

    fn ver(&self) -> &str {
        &self.ver
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

impl<T: CkTransport> SatsCard<T> {
    pub fn from_status(transport: T, status_response: StatusResponse) -> Result<Self, Error> {
        let pubkey = status_response.pubkey.as_slice();
        let pubkey = PublicKey::from_slice(pubkey).map_err(|e| Error::CiborValue(e.to_string()))?;

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
        chain_code: Option<[u8; 32]>,
        cvc: &str,
    ) -> Result<NewResponse, Error> {
        let (_, epubkey, xcvc) = self.calc_ekeys_xcvc(cvc, NewCommand::name());
        let new_command = NewCommand::new(Some(slot), chain_code, epubkey, xcvc);
        let new_response: NewResponse = self.transport.transmit(&new_command).await?;
        self.card_nonce = new_response.card_nonce;
        self.slots.0 = new_response.slot;

        Ok(new_response)
    }

    pub async fn derive(&mut self) -> Result<DeriveResponse, Error> {
        let nonce = crate::rand_nonce();
        let card_nonce = *self.card_nonce();

        let cmd = DeriveCommand::for_satscard(nonce);
        let resp: DeriveResponse = self.transport().transmit(&cmd).await?;
        self.set_card_nonce(resp.card_nonce);

        // Verify signature
        let mut message_bytes: Vec<u8> = Vec::new();
        message_bytes.extend("OPENDIME".as_bytes());
        message_bytes.extend(card_nonce);
        message_bytes.extend(nonce);
        message_bytes.extend(resp.chain_code);

        let message_bytes_hash = sha256::Hash::hash(message_bytes.as_slice());
        let message = Message::from_digest(message_bytes_hash.to_byte_array());

        let signature = Signature::from_compact(&resp.sig)?;

        let pubkey = PublicKey::from_slice(&resp.master_pubkey)?;
        self.secp().verify_ecdsa(&message, &signature, &pubkey)?;

        Ok(resp)
    }

    pub async fn unseal(&mut self, slot: u8, cvc: &str) -> Result<UnsealResponse, Error> {
        let (_, epubkey, xcvc) = self.calc_ekeys_xcvc(cvc, UnsealCommand::name());
        let unseal_command = UnsealCommand::new(slot, epubkey, xcvc);
        let unseal_response: UnsealResponse = self.transport.transmit(&unseal_command).await?;
        self.set_card_nonce(unseal_response.card_nonce);

        Ok(unseal_response)
    }

    pub async fn dump(&self, slot: usize, cvc: Option<String>) -> Result<DumpResponse, Error> {
        let epubkey_xcvc = cvc.map(|cvc| {
            let (_, epubkey, xcvc) = self.calc_ekeys_xcvc(&cvc, DumpCommand::name());
            (epubkey, xcvc)
        });

        let (epubkey, xcvc) = epubkey_xcvc
            .map(|(epubkey, xcvc)| (Some(epubkey), Some(xcvc)))
            .unwrap_or((None, None));

        let dump_command = DumpCommand::new(slot, epubkey, xcvc);
        self.transport.transmit(&dump_command).await
    }

    pub async fn address(&mut self) -> Result<String, Error> {
        // TODO: support testnet
        let network = Network::Bitcoin;
        let slot_pubkey = self.read(None).await?.pubkey;
        let pk = BitcoinPublicKey::from_slice(&slot_pubkey)?;
        let address = Address::p2wpkh(&pk, network);
        Ok(address.to_string())
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
    async fn slot_pubkey(&mut self) -> Result<Option<PublicKey>, Error> {
        let pubkey = self.read(None).await?.pubkey(None)?;
        Ok(Some(pubkey))
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
            .field("card_nonce", &self.card_nonce.to_lower_hex_string())
            .field("auth_delay", &self.auth_delay)
            .finish()
    }
}
