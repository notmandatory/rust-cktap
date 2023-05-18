use secp256k1::ecdh::SharedSecret;
use secp256k1::ecdsa::Signature;
use secp256k1::hashes::hex::ToHex;
use secp256k1::hashes::{sha256, Hash};
use secp256k1::rand::rngs::ThreadRng;
use secp256k1::rand::Rng;
use secp256k1::{rand, All, PublicKey, Secp256k1, SecretKey, Message};
use std::fmt;
use std::fmt::Debug;

pub mod commands;

#[cfg(feature = "pcsc")]
pub mod pcsc;

use commands::*;

pub trait Transport {
    fn find_first() -> Result<CkTapCard<Self>, Error>
    where
        Self: Sized;
    //fn find_cards() -> Vec<CkTapCard<Self>>;
    fn transmit<'a, C, R>(&self, command: C) -> Result<R, Error>
    where
        C: CommandApdu + serde::Serialize + Debug,
        R: ResponseApdu + serde::Deserialize<'a> + Debug,
    {
        let command_apdu = command.apdu_bytes();
        let rapdu = self.transmit_apdu(command_apdu)?;
        let response = R::from_cbor(rapdu.to_vec())?;
        Ok(response)
    }
    fn transmit_apdu(&self, command_apdu: Vec<u8>) -> Result<Vec<u8>, Error>;
}

pub enum CkTapCard<T: Transport + Sized> {
    TapSigner(TapSigner<T>),
    SatsChip(TapSigner<T>),
    SatsCard(SatsCard<T>),
}

impl<T: Transport + Sized> fmt::Debug for CkTapCard<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self {
            CkTapCard::TapSigner(t) => {
                write!(f, "CkTap::TapSigner({:?})", t)
            }
            CkTapCard::SatsChip(t) => {
                write!(f, "CkTap::SatsChip({:?})", t)
            }
            CkTapCard::SatsCard(s) => {
                write!(f, "CkTap::SatsCard({:?})", s)
            }
        }
    }
}

pub struct TapSigner<T: Transport + Sized> {
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

impl<T: Transport> Authentication for TapSigner<T> {
    fn secp(&self) -> &Secp256k1<All> {
        &self.secp
    }

    fn pubkey(&self) -> &PublicKey {
        &self.pubkey
    }

    fn card_nonce(&self) -> &Vec<u8> {
        &self.card_nonce
    }

    fn auth_delay(&self) -> &Option<usize> {
        &self.auth_delay
    }

    fn set_auth_delay(&mut self, auth_delay: Option<usize>) {
        self.auth_delay = auth_delay;
    }
}

impl<T: Transport> SharedCommands<T> for TapSigner<T> {
    fn transport(&self) -> &T {
        &self.transport
    }
}

impl<T: Transport + Sized> Debug for TapSigner<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
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

impl<T: Transport + Sized> TapSigner<T> {
    pub fn init(&mut self, chain_code: Vec<u8>, cvc: String) -> Result<NewResponse, Error> {
        let chain_code = Some(chain_code);
        let (_, epubkey, xcvc) = self.calc_ekeys_xcvc(cvc, &NewCommand::name());
        let epubkey = epubkey.serialize().to_vec();
        let new_command = NewCommand::new(0, chain_code, epubkey, xcvc);
        let new_response: Result<NewResponse, Error> = self.transport.transmit(new_command);
        if let Ok(response) = &new_response {
            self.card_nonce = response.card_nonce.clone();
        }
        new_response
    }

    pub fn read(&mut self, cvc: String) -> Result<ReadResponse, Error> {
        let (_, epubkey, xcvc) = self.calc_ekeys_xcvc(cvc, &ReadCommand::name());
        let read_command = ReadCommand::for_tapsigner(self.card_nonce.clone(), epubkey, xcvc);
        let read_response: Result<ReadResponse, Error> = self.transport.transmit(read_command);
        if let Ok(response) = &read_response {
            self.card_nonce = response.card_nonce.clone();
        }
        read_response
    }

    pub fn certs_check(&mut self, cvc: String, nonce: Vec<u8>) -> Result<(), Error> {
        let certs_cmd = CertsCommand::default();
        let certs_response: CertsResponse = self.transport.transmit(certs_cmd)?;
        dbg!(&certs_response);

        // let nonce = rand_nonce().to_vec();
        let check_cmd = CheckCommand::new(nonce.clone());
        let check_response: Result<CheckResponse, Error> = self.transport.transmit(check_cmd);
        dbg!(&check_response);

        if let Ok(response) = &check_response {
            self.card_nonce = response.card_nonce.clone();
        }

        // let slot_pubkey = match self.ver == "0.9.0".to_string() {
        //     true => None,
        //     false => Some("adsjhfklajdh")
        // };
        // digest:
        // b'OPENDIME' (8 bytes)
        // (card_nonce - 16 bytes)
        // (nonce from check command - 16 bytes)
        // SatsCard 1.0.0+: (pubkey of current sealed slot - 33 bytes)

        // Tapsigners current pubkey
        // Todo: verify signature return by read command
        let current_pubkey = &self.read(cvc).unwrap().pubkey;

        let card_pubkey = &self.pubkey;
        let card_nonce = &self.card_nonce;
        let app_nonce = &nonce;

        let mut message_bytes: Vec<u8> = Vec::new();
        message_bytes.extend("OPENDIME".as_bytes());
        message_bytes.extend(card_nonce);
        message_bytes.extend(app_nonce);
        //     assert len(msg) == 8 + CARD_NONCE_SIZE + USER_NONCE_SIZE
        message_bytes.extend(current_pubkey);

        let message = Message::from_hashed_data::<sha256::Hash>(message_bytes.as_slice());
        let signature = Signature::from_str(&check_response.unwrap().auth_sig.to_hex()).unwrap();
        // todo: get from card 
        use std::str::FromStr;
        assert!(self.secp.verify_ecdsa(&message, &signature, card_pubkey).is_ok()); 
        
        Ok(())
    }

    pub fn derive(&mut self, path: Vec<usize>, cvc: String) -> Result<DeriveResponse, Error> {
        let (_, epubkey, xcvc) = self.calc_ekeys_xcvc(cvc, &DeriveCommand::name());
        let cmd = DeriveCommand::for_tapsigner(
            self.card_nonce.clone(),
            path, 
            epubkey, 
            xcvc
        );
        let resp: Result<DeriveResponse, Error> = self.transport.transmit(cmd);
        if let Ok(derive_resp) = &resp {
            self.card_nonce = derive_resp.card_nonce.clone();

            // TODO: verify reponse
            // The digest:
                // b'OPENDIME' (8 bytes)    
                // (card_nonce - 16 bytes)
                // (nonce from command - 16 bytes)
                // (chain_code - 32 bytes)
            // must be signed by the master_pubkey
        }
        resp
    }
}

pub struct SatsCard<T: Transport + Sized> {
    pub transport: T,
    pub secp: Secp256k1<All>,
    pub proto: usize,
    pub ver: String,
    pub birth: usize,
    pub slots: (usize, usize),
    pub addr: Option<String>,
    pub pubkey: PublicKey,
    pub card_nonce: Vec<u8>, // 16 bytes
    pub auth_delay: Option<usize>,
}

impl<T: Transport> Authentication for SatsCard<T> {
    fn secp(&self) -> &Secp256k1<All> {
        &self.secp
    }

    fn pubkey(&self) -> &PublicKey {
        &self.pubkey
    }

    fn card_nonce(&self) -> &Vec<u8> {
        &self.card_nonce
    }

    fn auth_delay(&self) -> &Option<usize> {
        &self.auth_delay
    }

    fn set_auth_delay(&mut self, auth_delay: Option<usize>) {
        self.auth_delay = auth_delay;
    }
}

impl<T: Transport> SharedCommands<T> for SatsCard<T> {
    fn transport(&self) -> &T {
        &self.transport
    }
}

impl<T: Transport + Sized> SatsCard<T> {
    pub fn new_slot(
        &mut self,
        slot: usize,
        chain_code: Vec<u8>,
        cvc: String,
    ) -> Result<NewResponse, Error> {
        let chain_code = Some(chain_code);
        let (_, epubkey, xcvc) = self.calc_ekeys_xcvc(cvc, &NewCommand::name());
        let epubkey = epubkey.serialize().to_vec();
        let new_command = NewCommand::new(slot, chain_code, epubkey, xcvc);
        let new_response: Result<NewResponse, Error> = self.transport.transmit(new_command);
        if let Ok(response) = &new_response {
            self.card_nonce = response.card_nonce.clone();
        }
        new_response
    }

    pub fn read(&mut self) -> Result<ReadResponse, Error> {
        let command = ReadCommand::for_satscard(self.card_nonce.clone());
        let response: Result<ReadResponse, Error> = self.transport.transmit(command);
        if let Ok(read_response) = &response {
            self.card_nonce = read_response.card_nonce.clone();
        }
        response
    }

    pub fn derive(&mut self) -> Result<DeriveResponse, Error> {
        let cmd = DeriveCommand::for_satscard(self.card_nonce.clone());
        let resp: Result<DeriveResponse, Error> = self.transport.transmit(cmd);
        if let Ok(derive_resp) = &resp {
            self.card_nonce = derive_resp.card_nonce.clone();

            // TODO: verify reponse
            // The digest:
                // b'OPENDIME' (8 bytes)    
                // (card_nonce - 16 bytes)
                // (nonce from command - 16 bytes)
                // (chain_code - 32 bytes)
            // must be signed by the master_pubkey
        }
        resp
    }

    pub fn unseal(&self, slot: usize, cvc: String) -> Result<UnsealResponse, Error> {
        let (_, epubkey, xcvc) = self.calc_ekeys_xcvc(cvc, &UnsealCommand::name());
        let epubkey = epubkey.serialize().to_vec();
        let unseal_command = UnsealCommand::new(slot, epubkey, xcvc);
        self.transport.transmit(unseal_command)
    }

    pub fn dump(&self, slot: usize, cvc: Option<String>) -> Result<DumpResponse, Error> {
        let epubkey_xcvc = cvc.map(|cvc| {
            let (_, epubkey, xcvc) = self.calc_ekeys_xcvc(cvc, &DumpCommand::name());
            (epubkey, xcvc)
        });

        let (epubkey, xcvc) = epubkey_xcvc
            .map(|(epubkey, xcvc)| (Some(epubkey.serialize().to_vec()), Some(xcvc)))
            .unwrap_or((None, None));

        let dump_command = DumpCommand::new(slot, epubkey, xcvc);
        self.transport.transmit(dump_command)
    }
}

impl<T: Transport + Sized> Debug for SatsCard<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
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

// card traits

/// Shared commands that are called the same way for all card types.
pub trait SharedCommands<T>: Authentication
where
    T: Transport,
{
    fn transport(&self) -> &T;

    fn wait(&mut self, cvc: Option<String>) -> Result<WaitResponse, Error> {
        let epubkey_xcvc = cvc.map(|cvc| {
            let (_, epubkey, xcvc) = self.calc_ekeys_xcvc(cvc, &WaitCommand::name());
            (epubkey, xcvc)
        });

        let (epubkey, xcvc) = epubkey_xcvc
            .map(|(epubkey, xcvc)| (Some(epubkey.serialize().to_vec()), Some(xcvc)))
            .unwrap_or((None, None));

        let wait_command = WaitCommand::new(epubkey, xcvc);
        let wait_response: Result<WaitResponse, Error> = self.transport().transmit(wait_command);
        if let Ok(response) = &wait_response {
            if response.auth_delay > 0 {
                self.set_auth_delay(Some(response.auth_delay));
            } else {
                self.set_auth_delay(None);
            }
        }
        wait_response
    }

    fn certs(&self) -> Result<CertsResponse, Error> {
        let certs_command = CertsCommand::default();
        self.transport().transmit(certs_command)
    }

    fn nfc(&self) -> Result<NfcResponse, Error> {
        let nfc_command = NfcCommand::default();
        self.transport().transmit(nfc_command)
    }
}

// Helper functions for authenticated commands.
pub trait Authentication {
    fn secp(&self) -> &Secp256k1<All>;
    fn pubkey(&self) -> &PublicKey;
    fn card_nonce(&self) -> &Vec<u8>;
    fn auth_delay(&self) -> &Option<usize>;
    fn set_auth_delay(&mut self, auth_delay: Option<usize>);

    fn calc_ekeys_xcvc(&self, cvc: String, command: &String) -> (SecretKey, PublicKey, Vec<u8>) {
        let secp = Self::secp(self);
        let pubkey = Self::pubkey(self);
        let nonce = Self::card_nonce(self);
        let cvc_bytes = cvc.as_bytes();
        let card_nonce_bytes = nonce.as_slice();
        let card_nonce_command = [card_nonce_bytes, command.as_bytes()].concat();
        let (eprivkey, epubkey) = secp.generate_keypair(&mut rand::thread_rng());
        let session_key = SharedSecret::new(pubkey, &eprivkey);

        let md = sha256::Hash::hash(card_nonce_command.as_slice());

        let mask: Vec<u8> = session_key
            .as_ref()
            .iter()
            .zip(md.as_ref())
            .map(|(x, y)| x ^ y)
            .take(cvc_bytes.len())
            .collect();
        let xcvc = cvc_bytes.iter().zip(mask).map(|(x, y)| x ^ y).collect();
        (eprivkey, epubkey, xcvc)
    }
}

// utility functions

pub fn rand_chaincode(rng: &mut ThreadRng) -> [u8; 32] {
    let mut chain_code = [0u8; 32];
    rng.fill(&mut chain_code);
    chain_code
}

pub fn rand_nonce(rng: &mut ThreadRng) -> [u8; 16] {
    let mut nonce = [0u8; 16];
    rng.fill(&mut nonce);
    nonce
}
