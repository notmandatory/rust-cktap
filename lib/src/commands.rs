use crate::factory_root_key::FactoryRootKey;
use crate::{apdu::*, rand_nonce};
use crate::{CkTapCard, SatsCard, TapSigner};

use secp256k1::ecdh::SharedSecret;
use secp256k1::ecdsa::{RecoverableSignature, RecoveryId, Signature};
use secp256k1::hashes::{sha256, Hash};
use secp256k1::{rand, All, Message, PublicKey, Secp256k1, SecretKey};

use std::convert::TryFrom;

use std::fmt::Debug;

// Helper functions for authenticated commands.
pub trait Authentication<T: CkTransport> {
    fn secp(&self) -> &Secp256k1<All>;
    fn pubkey(&self) -> &PublicKey;
    fn slot(&self) -> Option<u8>;
    fn card_nonce(&self) -> &Vec<u8>;
    fn set_card_nonce(&mut self, new_nonce: Vec<u8>);
    fn auth_delay(&self) -> &Option<usize>;
    fn set_auth_delay(&mut self, auth_delay: Option<usize>);

    fn transport(&self) -> &T;

    fn calc_ekeys_xcvc(&self, cvc: String, command: &str) -> (SecretKey, PublicKey, Vec<u8>) {
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

    fn verify_sig(
        &self,
        app_nonce: Vec<u8>,
        sig: &Vec<u8>,
        eprivkey: Option<&SecretKey>,
        pubkey: &Vec<u8>,
        data: &[u8],
    ) -> Result<(), Error> {
        let message = self.message_digest(app_nonce, data.to_owned());
        let signature = Signature::from_compact(sig.as_slice())?;
        let pubkey = if let Some(epk) = eprivkey {
            let session_key = SharedSecret::new(self.pubkey(), epk);
            unzip(&mut pubkey.clone(), session_key).unwrap()
        } else {
            PublicKey::from_slice(pubkey.as_slice()).unwrap()
        };
        self.secp()
            .verify_ecdsa(&message, &signature, &pubkey)
            .map_err(|e| e.into())
    }

    fn message_digest(&self, app_nonce: Vec<u8>, data: Vec<u8>) -> Message {
        let card_nonce = self.card_nonce().clone();
        let mut message_bytes: Vec<u8> = Vec::new();
        message_bytes.extend("OPENDIME".as_bytes());
        message_bytes.extend(card_nonce);
        message_bytes.extend(app_nonce);
        message_bytes.extend(&data);
        Message::from_hashed_data::<sha256::Hash>(message_bytes.as_slice())
    }
}

pub trait CkTransport: Sized {
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

    fn to_cktap(self) -> Result<CkTapCard<Self>, Error> {
        // Get status from card
        let cmd = AppletSelect::default();
        let status_response: StatusResponse = self.transmit(cmd)?;

        // Return correct card variant using status
        match (status_response.tapsigner, status_response.satschip) {
            (Some(true), None) => Ok(CkTapCard::TapSigner(TapSigner::from_status(
                self,
                status_response,
            ))),
            (Some(true), Some(true)) => Ok(CkTapCard::TapSigner(TapSigner::from_status(
                self,
                status_response,
            ))),
            (None, None) => Ok(CkTapCard::SatsCard(
                SatsCard::from_status(self, status_response).unwrap(),
            )),
            (_, _) => Err(Error::UnknownCardType("Card not recognized.".to_string())),
        }
    }
}

// card traits
pub trait Read<T>: Authentication<T>
where
    T: CkTransport,
{
    fn requires_auth(&self) -> bool;

    fn read(&mut self, cvc: Option<String>) -> Result<ReadResponse, Error> {
        let app_nonce = rand_nonce().to_vec();
        if self.requires_auth() {
            let (eprivkey, epubkey, xcvc) =
                self.calc_ekeys_xcvc(cvc.unwrap(), &ReadCommand::name());
            let cmd = ReadCommand::authenticated(app_nonce.clone(), epubkey, xcvc);
            let read_response: Result<ReadResponse, Error> = self.transport().transmit(cmd);
            if let Ok(response) = &read_response {
                let slot = self.slot().unwrap_or_default();
                self.verify_sig(
                    app_nonce,
                    &response.sig,
                    Some(&eprivkey),
                    &response.pubkey,
                    &[slot],
                )?;
                self.set_card_nonce(response.card_nonce.clone());
            }
            read_response
        } else {
            let cmd = ReadCommand::unauthenticated(app_nonce.clone());
            let read_response: Result<ReadResponse, Error> = self.transport().transmit(cmd);
            if let Ok(response) = &read_response {
                let slot = self.slot().unwrap_or_default();
                self.verify_sig(app_nonce, &response.sig, None, &response.pubkey, &[slot])?;
                self.set_card_nonce(response.card_nonce.clone());
            }
            read_response
        }
    }
}

pub trait Wait<T>: Authentication<T>
where
    T: CkTransport,
{
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
}

pub trait Certificate<T>: Authentication<T>
where
    T: CkTransport,
{
    fn message_digest(&mut self, card_nonce: Vec<u8>, app_nonce: Vec<u8>) -> Message;

    fn check_certificate(&mut self) -> Result<FactoryRootKey, Error> {
        let nonce = rand_nonce().to_vec();
        let card_nonce = self.card_nonce().clone();

        let certs_cmd = CertsCommand::default();
        let certs_response: CertsResponse = self.transport().transmit(certs_cmd)?;

        let check_cmd = CheckCommand::new(nonce.clone());
        let check_response: Result<CheckResponse, Error> = self.transport().transmit(check_cmd);
        if let Ok(response) = &check_response {
            self.set_card_nonce(response.card_nonce.clone());
        }

        self.verify_card_signature(check_response.unwrap().auth_sig, card_nonce, nonce)?;

        let mut pubkey = *self.pubkey();
        for sig in &certs_response.cert_chain() {
            // BIP-137: https://github.com/bitcoin/bips/blob/master/bip-0137.mediawiki
            let subtract_by = match sig[0] {
                27..=30 => 27, // P2PKH uncompressed
                31..=34 => 31, // P2PKH compressed
                35..=38 => 35, // Segwit P2SH
                39..=42 => 39, // Segwit Bech32
                _ => panic!("Unrecognized BIP-137 address"),
            };
            let rec_id = RecoveryId::from_i32((sig[0] as i32) - subtract_by).unwrap();
            let (_, sig) = sig.split_at(1);
            let rec_sig = RecoverableSignature::from_compact(sig, rec_id).unwrap();
            let md = Message::from_hashed_data::<sha256::Hash>(&pubkey.serialize());
            pubkey = self.secp().recover_ecdsa(&md, &rec_sig).unwrap();
        }

        FactoryRootKey::try_from(pubkey)
    }

    fn verify_card_signature(
        &mut self,
        signature: Vec<u8>,
        card_nonce: Vec<u8>,
        app_nonce: Vec<u8>,
    ) -> Result<(), secp256k1::Error> {
        let message = self.message_digest(card_nonce, app_nonce);
        let signature = Signature::from_compact(signature.as_slice())
            .expect("Failed to construct ECDSA signature from check response");
        self.secp()
            .verify_ecdsa(&message, &signature, self.pubkey())
    }
}

fn unzip(encoded: &mut Vec<u8>, session_key: SharedSecret) -> Result<PublicKey, secp256k1::Error> {
    let session_key = session_key.as_ref(); // 32 bytes
    let mut pubkey = encoded.clone();
    let xor_bytes = encoded.split_off(1);
    let xor_bytes = xor_bytes
        .iter()
        .zip(session_key.as_ref())
        .map(|(x, y)| x ^ y);
    pubkey.splice(1..33, xor_bytes);
    PublicKey::from_slice(pubkey.as_slice())
}

// #[cfg(test)]
// mod tests {
//     use super::*;

//     #[test]
//     fn test_tapsigner_signature() {
//         let card_pubkey = PublicKey::from_slice(
//             &from_hex("0335170d9b853440080b0e5d6129f985ebeb919e7a90f28a5fa15c7987ec986a6b")
//                 .as_slice(),
//         )
//         .map_err(|e| Error::CiborValue(e.to_string()))
//         .unwrap();
//         let signature: Vec<u8> = from_hex("44721225a42eb3496cc38858adf8fafde9a752776d36c719aaa4f255ab121a0864be7d21eb47a5db88e3879b53ea74794d3e9503cc9b56b8bf9f948324198c30");
//         let card_nonce: Vec<u8> = from_hex("fd4c5d2c9d9c5a647cbc0b2b79ffef91");
//         let app_nonce: Vec<u8> = from_hex("273faf8a0b270f697bcb6c90dc8cd4ba");
//         let secp = Secp256k1::new();

//         assert!(
//             verify_tapsigner_signature(&card_pubkey, signature, card_nonce, app_nonce, &secp)
//                 .is_ok()
//         );
//     }
// }
