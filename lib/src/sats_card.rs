use async_trait::async_trait;
use bitcoin::key::CompressedPublicKey as BitcoinPublicKey;
use bitcoin::secp256k1::{All, Message, PublicKey, Secp256k1, SecretKey, ecdsa::Signature};
use bitcoin::{Address, Network};
use bitcoin_hashes::sha256;
use std::sync::Arc;

use crate::apdu::{
    CommandApdu as _, DeriveCommand, DeriveResponse, DumpCommand, DumpResponse, Error, NewCommand,
    NewResponse, StatusResponse, UnsealCommand, UnsealResponse,
};
use crate::commands::{Authentication, Certificate, CkTransport, Read, Wait, transmit};
use crate::secp256k1;
use bitcoin_hashes::hex::DisplayHex;

pub struct SatsCard {
    pub transport: Arc<dyn CkTransport>,
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

impl Authentication for SatsCard {
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

    fn transport(&self) -> Arc<dyn CkTransport> {
        self.transport.clone()
    }
}

impl SatsCard {
    pub fn from_status(
        transport: Arc<dyn CkTransport>,
        status_response: StatusResponse,
    ) -> Result<Self, Error> {
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
    ) -> Result<u8, Error> {
        let (_, epubkey, xcvc) = self.calc_ekeys_xcvc(cvc, NewCommand::name());
        let new_command = NewCommand::new(Some(slot), chain_code, epubkey, xcvc);
        let new_response: NewResponse = transmit(self.transport(), &new_command).await?;
        self.card_nonce = new_response.card_nonce;
        self.slots.0 = new_response.slot;

        Ok(new_response.slot)
    }

    /// Verify the master public key and chain code used to derive the payment public key.
    ///
    /// The derivation is fixed as m/0, meaning the first non-hardened derived key. SATSCARD
    /// always uses that derived key as the payment address.
    ///
    /// The user should verify the returned card chain code matches the chain code they provided
    /// when they created the current slot, see: [`Self::new_slot`].
    ///
    /// Ref: https://github.com/coinkite/coinkite-tap-proto/blob/master/docs/protocol.md#derive
    pub async fn derive(&mut self) -> Result<[u8; 32], Error> {
        let nonce = crate::rand_nonce();
        let card_nonce = *self.card_nonce();

        let cmd = DeriveCommand::for_satscard(nonce);
        let resp: DeriveResponse = transmit(self.transport(), &cmd).await?;
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

        let master_pubkey = PublicKey::from_slice(&resp.master_pubkey)?;
        self.secp()
            .verify_ecdsa(&message, &signature, &master_pubkey)?;

        // return card chain code so user can verify it matches user provided chain code
        let card_chaincode = &resp.chain_code;

        // TODO verify a user's chain code (entropy) was used in picking the private key
        // SATSCARD returns the card's chain code and master public key
        // With the master pubkey and the chain code, reconstructs a BIP-32 XPUB (extended public key)
        // and verify it matches the payment address the card shares (i.e., the slot's pubkey)
        // it must equal the BIP-32 derived key (m/0) constructed from that XPUB.

        Ok(*card_chaincode)
    }

    /// Unseal a slot.
    ///
    /// Returns the private and corresponding public keys for that slot.
    pub async fn unseal(&mut self, slot: u8, cvc: &str) -> Result<(SecretKey, PublicKey), Error> {
        let (eprivkey, epubkey, xcvc) = self.calc_ekeys_xcvc(cvc, UnsealCommand::name());
        let unseal_command = UnsealCommand::new(slot, epubkey, xcvc);
        let unseal_response: UnsealResponse = transmit(self.transport(), &unseal_command).await?;
        self.set_card_nonce(unseal_response.card_nonce);

        // private key for spending (for addr), 32 bytes
        // the private key is encrypted, XORed with the session key, need to decrypt
        let session_key = secp256k1::ecdh::SharedSecret::new(self.pubkey(), &eprivkey);
        // decrypt the private key by XORing with the session key
        let privkey: Vec<u8> = session_key
            .as_ref()
            .iter()
            .zip(&unseal_response.privkey)
            .map(|(session_key_byte, privkey_byte)| session_key_byte ^ privkey_byte)
            .collect();
        let privkey = SecretKey::from_slice(&privkey)?;
        let pubkey = PublicKey::from_slice(&unseal_response.pubkey)?;
        // TODO should verify user provided chain code was used similar to above `derive`.
        Ok((privkey, pubkey))
    }

    pub async fn dump<T: CkTransport>(
        &self,
        slot: usize,
        cvc: Option<String>,
    ) -> Result<DumpResponse, Error> {
        let epubkey_xcvc = cvc.map(|cvc| {
            let (_, epubkey, xcvc) = self.calc_ekeys_xcvc(&cvc, DumpCommand::name());
            (epubkey, xcvc)
        });

        let (epubkey, xcvc) = epubkey_xcvc
            .map(|(epubkey, xcvc)| (Some(epubkey), Some(xcvc)))
            .unwrap_or((None, None));

        let dump_command = DumpCommand::new(slot, epubkey, xcvc);
        let dump_response: DumpResponse = transmit(self.transport(), &dump_command).await?;
        // TODO use chaincode and master public key to verify pubkey
        // TODO only return the verified slot keys
        // TODO return error if `tampered` is true
        Ok(dump_response)
    }

    pub async fn address(&mut self) -> Result<String, Error> {
        let network = Network::Bitcoin;
        let slot_pubkey = self.read(None).await?;
        let pk = BitcoinPublicKey::from_slice(&slot_pubkey.serialize())?;
        let address = Address::p2wpkh(&pk, network);
        Ok(address.to_string())
    }
}

#[async_trait]
impl Wait for SatsCard {}

#[async_trait]
impl Read for SatsCard {
    fn requires_auth(&self) -> bool {
        false
    }
    fn slot(&self) -> Option<u8> {
        Some(self.slots.0)
    }
}

#[async_trait]
impl Certificate for SatsCard {
    async fn slot_pubkey(&mut self) -> Result<Option<PublicKey>, Error> {
        let pubkey = self.read(None).await?;
        Ok(Some(pubkey))
    }
}

impl core::fmt::Debug for SatsCard {
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
