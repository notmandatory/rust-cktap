use crate::factory_root_key::FactoryRootKey;
use crate::{CardError, CkTapCard, CkTapError, SatsCard, TapSigner};
use crate::{apdu::*, rand_nonce};

use bitcoin::key::{PublicKey, rand};
use bitcoin::secp256k1;
use bitcoin::secp256k1::ecdh::SharedSecret;
use bitcoin::secp256k1::ecdsa::{RecoverableSignature, RecoveryId, Signature};
use bitcoin::secp256k1::{All, Message, Secp256k1};
use bitcoin_hashes::sha256;

use std::convert::TryFrom;

use crate::error::{CertsError, ReadError, StatusError};
use crate::sats_chip::SatsChip;
use async_trait::async_trait;
use std::fmt::Debug;
use std::sync::Arc;

/// Helper functions for authenticated commands.
pub trait Authentication {
    fn secp(&self) -> &Secp256k1<All>;
    fn ver(&self) -> &str;
    fn pubkey(&self) -> &PublicKey;
    fn card_nonce(&self) -> &[u8; 16];
    fn set_card_nonce(&mut self, new_nonce: [u8; 16]);
    fn auth_delay(&self) -> &Option<usize>;
    fn set_auth_delay(&mut self, auth_delay: Option<usize>);
    fn transport(&self) -> Arc<dyn CkTransport>;

    /// Calculate ephemeral key pair and XOR'd CVC.
    /// ref: ["Authenticating Commands with CVC"](https://github.com/coinkite/coinkite-tap-proto/blob/master/docs/protocol.md#authenticating-commands-with-cvc)
    fn calc_ekeys_xcvc(
        &self,
        cvc: &str,
        command: &str,
    ) -> (secp256k1::SecretKey, secp256k1::PublicKey, Vec<u8>) {
        let secp = Self::secp(self);
        let pubkey = Self::pubkey(self);
        let nonce = Self::card_nonce(self);
        let cvc_bytes = cvc.as_bytes();
        let card_nonce_command = [nonce, command.as_bytes()].concat();
        let (ephemeral_private_key, ephemeral_public_key) =
            secp.generate_keypair(&mut rand::thread_rng());

        let session_key = SharedSecret::new(&pubkey.inner, &ephemeral_private_key);
        let md = sha256::Hash::hash(card_nonce_command.as_slice());
        let md: &[u8; 32] = md.as_ref();

        let mask: Vec<u8> = session_key
            .as_ref()
            .iter()
            .zip(md)
            .map(|(x, y)| x ^ y)
            .take(cvc_bytes.len())
            .collect();

        let xcvc = cvc_bytes.iter().zip(mask).map(|(x, y)| x ^ y).collect();
        (ephemeral_private_key, ephemeral_public_key, xcvc)
    }
}

/// Trait for exchanging APDU data with cktap cards.
#[async_trait]
pub trait CkTransport: Sync + Send {
    async fn transmit_apdu(&self, command_apdu: Vec<u8>) -> Result<Vec<u8>, CkTapError>;
}

/// Helper function for serialize APDU commands, transmit them and deserialize responses.
pub(crate) async fn transmit<C, R>(
    transport: Arc<dyn CkTransport>,
    command: &C,
) -> Result<R, CkTapError>
where
    C: CommandApdu + serde::Serialize + Debug + Send + Sync,
    R: ResponseApdu + serde::de::DeserializeOwned + Debug + Send,
{
    let command_apdu = command.apdu_bytes();
    let rapdu = transport.transmit_apdu(command_apdu).await?;
    let response = R::from_cbor(rapdu.to_vec())?;
    Ok(response)
}

pub async fn to_cktap(transport: Arc<dyn CkTransport>) -> Result<CkTapCard, StatusError> {
    // Get status from card
    let cmd = AppletSelect::default();
    let status_response: StatusResponse = transmit(transport.clone(), &cmd).await?;

    // Return correct card variant using status
    match (status_response.tapsigner, status_response.satschip) {
        (Some(true), None) => {
            let tap_signer = TapSigner::try_from_status(transport, status_response)?;
            Ok(CkTapCard::TapSigner(tap_signer))
        }
        (Some(true), Some(true)) => {
            let sats_chip = SatsChip::try_from_status(transport, status_response)?;
            Ok(CkTapCard::SatsChip(sats_chip))
        }
        (None, None) => {
            let sats_card = SatsCard::from_status(transport, status_response)?;
            Ok(CkTapCard::SatsCard(sats_card))
        }
        (_, _) => Err(StatusError::CkTap(CkTapError::UnknownCardType)),
    }
}

/// Command to read and authenticate the cktap card's public key.
/// SatsCard does not require a CVC but TapSigner and SatsChip do.
/// ref: [read](https://github.com/coinkite/coinkite-tap-proto/blob/master/docs/protocol.md#read)
#[async_trait]
pub trait Read: Authentication {
    fn requires_auth(&self) -> bool;

    fn slot(&self) -> Option<u8>;

    async fn read(&mut self, cvc: Option<String>) -> Result<PublicKey, ReadError> {
        let card_nonce = *self.card_nonce();
        let app_nonce = rand_nonce();

        // create the message digest
        let mut message_bytes: Vec<u8> = Vec::new();
        message_bytes.extend("OPENDIME".as_bytes());
        message_bytes.extend(card_nonce);
        message_bytes.extend(app_nonce);
        if let Some(slot) = self.slot() {
            message_bytes.push(slot);
        } else {
            message_bytes.push(0);
        }
        let hash = sha256::Hash::hash(message_bytes.as_slice());
        let message_digest = Message::from_digest(hash.to_byte_array());

        // create the read command
        let (cmd, session_key) = if self.requires_auth() {
            let cvc = cvc.ok_or(CkTapError::Card(CardError::NeedsAuth))?;
            let (eprivkey, epubkey, xcvc) = self.calc_ekeys_xcvc(&cvc, ReadCommand::name());
            (
                ReadCommand::authenticated(app_nonce, epubkey, xcvc),
                Some(SharedSecret::new(&self.pubkey().inner, &eprivkey)),
            )
        } else {
            (ReadCommand::unauthenticated(app_nonce), None)
        };

        // send the read command to the card
        let read_response: ReadResponse = transmit(self.transport(), &cmd).await?;

        // convert the response to a PublicKey
        let pubkey = read_response.pubkey(session_key)?;
        self.secp().verify_ecdsa(
            &message_digest,
            &read_response.signature()?, // or add 'from' trait: Signature::from(response.sig: )
            &pubkey.inner,
        )?;

        // update the card nonce
        self.set_card_nonce(read_response.card_nonce);

        Ok(pubkey)
    }
}

#[async_trait]
pub trait Wait: Authentication {
    async fn wait(&mut self, cvc: Option<String>) -> Result<Option<usize>, CkTapError> {
        let epubkey_xcvc = cvc.map(|cvc| {
            let (_, epubkey, xcvc) = self.calc_ekeys_xcvc(&cvc, WaitCommand::name());
            (epubkey, xcvc)
        });

        let (epubkey, xcvc) = epubkey_xcvc
            .map(|(epubkey, xcvc)| (Some(epubkey), Some(xcvc)))
            .unwrap_or((None, None));

        let wait_command = WaitCommand::new(epubkey, xcvc);

        let wait_response: WaitResponse = transmit(self.transport(), &wait_command).await?;
        // TODO throw error if success == false
        if wait_response.auth_delay > 0 {
            let auth_delay = Some(wait_response.auth_delay);
            self.set_auth_delay(auth_delay);
            Ok(auth_delay)
        } else {
            self.set_auth_delay(None);
            Ok(None)
        }
    }
}

#[async_trait]
pub trait Certificate: Read {
    async fn check_certificate(&mut self) -> Result<FactoryRootKey, CertsError> {
        let app_nonce = rand_nonce();
        let card_nonce = *self.card_nonce();

        let certs_cmd = CertsCommand::default();
        let certs_response: CertsResponse = transmit(self.transport(), &certs_cmd).await?;

        let check_cmd = CheckCommand::new(app_nonce);
        let check_response: CheckResponse = transmit(self.transport(), &check_cmd).await?;
        self.set_card_nonce(check_response.card_nonce);

        let slot_pubkey = self.slot_pubkey().await?;

        // create message digest with slot pubkey
        let mut message_bytes: Vec<u8> = Vec::new();
        message_bytes.extend("OPENDIME".as_bytes());
        message_bytes.extend(card_nonce);
        message_bytes.extend(app_nonce);
        if let Some(pubkey) = slot_pubkey {
            if self.ver() != "0.9.0" {
                let slot_pubkey_bytes = pubkey.inner.serialize();
                message_bytes.extend(slot_pubkey_bytes);
            }
        }
        let message_bytes_hash = sha256::Hash::hash(message_bytes.as_slice());
        let message = Message::from_digest(message_bytes_hash.to_byte_array());

        // verify the signature with the message and pubkey
        let signature = Signature::from_compact(check_response.auth_sig.as_slice())
            .expect("Failed to construct ECDSA signature from check response");
        self.secp()
            .verify_ecdsa(&message, &signature, &self.pubkey().inner)?;

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
            let rec_id = RecoveryId::from_i32((sig[0] as i32) - subtract_by)?;
            let (_, sig) = sig.split_at(1);
            let result = RecoverableSignature::from_compact(sig, rec_id);
            let rec_sig = result?;
            let pubkey_hash = sha256::Hash::hash(&pubkey.inner.serialize());
            let md = Message::from_digest(pubkey_hash.to_byte_array());
            let result = self.secp().recover_ecdsa(&md, &rec_sig);
            pubkey = PublicKey::new(result?);
        }

        FactoryRootKey::try_from(pubkey.inner)
    }

    async fn slot_pubkey(&mut self) -> Result<Option<PublicKey>, ReadError>;
}

#[cfg(feature = "emulator")]
#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    use crate::emulator::CVC;
    use crate::emulator::find_emulator;
    use crate::emulator::test::{CardTypeOption, EcardSubprocess};
    use crate::rand_chaincode;
    use crate::tap_signer::TapSignerShared;

    #[tokio::test]
    async fn test_new_command() {
        let chain_code = rand_chaincode();
        for card_type in CardTypeOption::values() {
            let pipe_path = format!("/tmp/test-new-command-pipe{card_type}");
            let pipe_path = Path::new(&pipe_path);
            let python = EcardSubprocess::new(pipe_path, &card_type).unwrap();
            let emulator = find_emulator(pipe_path).await.unwrap();
            match emulator {
                CkTapCard::SatsCard(mut sc) => {
                    assert_eq!(card_type, CardTypeOption::SatsCard);
                    let current_slot = sc.slots.0;
                    let response = sc.unseal(current_slot, CVC).await;
                    assert!(response.is_ok());
                    let response = sc.new_slot(current_slot + 1, Some(chain_code), CVC).await;
                    assert!(response.is_ok());
                    assert_eq!(sc.slots.0, current_slot + 1);
                    // test with no new chain_code
                    let current_slot = sc.slots.0;
                    let response = sc.unseal(current_slot, CVC).await;
                    assert!(response.is_ok());
                    let response = sc.new_slot(current_slot + 1, None, CVC).await;
                    assert!(response.is_ok());
                    assert_eq!(sc.slots.0, current_slot + 1);
                }
                CkTapCard::TapSigner(mut ts) => {
                    assert_eq!(card_type, CardTypeOption::TapSigner);
                    let response = ts.init(chain_code, CVC).await;
                    assert!(response.is_ok())
                }
                CkTapCard::SatsChip(mut sc) => {
                    assert_eq!(card_type, CardTypeOption::SatsChip);
                    let response = sc.init(chain_code, CVC).await;
                    assert!(response.is_ok())
                }
            };
            drop(python);
        }
    }

    #[tokio::test]
    async fn test_cert_command() {
        for card_type in CardTypeOption::values() {
            let emulator_root_pubkey =
                "0312d005ca1501b1603c3b00412eefe27c6b20a74c29377263b357b3aff12de6fa".to_string();
            let pipe_path = format!("/tmp/test-cert-command-pipe{card_type}");
            let pipe_path = Path::new(&pipe_path);
            let python = EcardSubprocess::new(pipe_path, &card_type).unwrap();
            let emulator = find_emulator(pipe_path).await.unwrap();
            match emulator {
                CkTapCard::SatsCard(mut sc) => {
                    assert_eq!(card_type, CardTypeOption::SatsCard);
                    let response = sc.check_certificate().await;
                    assert!(response.is_err());
                    matches!(response, Err(CertsError::InvalidRootCert(pubkey)) if pubkey == emulator_root_pubkey);
                }
                CkTapCard::TapSigner(mut ts) => {
                    assert_eq!(card_type, CardTypeOption::TapSigner);
                    let response = ts.check_certificate().await;
                    assert!(response.is_err());
                    matches!(response, Err(CertsError::InvalidRootCert(pubkey)) if pubkey == emulator_root_pubkey);
                }
                CkTapCard::SatsChip(mut sc) => {
                    assert_eq!(card_type, CardTypeOption::SatsChip);
                    let response = sc.check_certificate().await;
                    assert!(response.is_err());
                    matches!(response, Err(CertsError::InvalidRootCert(pubkey)) if pubkey == emulator_root_pubkey);
                }
            };
            drop(python);
        }
    }

    // #[test]
    // fn test_tapsigner_signature() {
    //     let card_pubkey = PublicKey::from_slice(
    //         &from_hex("0335170d9b853440080b0e5d6129f985ebeb919e7a90f28a5fa15c7987ec986a6b")
    //             .as_slice(),
    //     )
    //     .map_err(|e| Error::CiborValue(e.to_string()))
    //     .unwrap();
    //     let signature: Vec<u8> = from_hex("44721225a42eb3496cc38858adf8fafde9a752776d36c719aaa4f255ab121a0864be7d21eb47a5db88e3879b53ea74794d3e9503cc9b56b8bf9f948324198c30");
    //     let card_nonce: Vec<u8> = from_hex("fd4c5d2c9d9c5a647cbc0b2b79ffef91");
    //     let app_nonce: Vec<u8> = from_hex("273faf8a0b270f697bcb6c90dc8cd4ba");
    //     let secp = Secp256k1::new();
    //
    //     assert!(
    //         verify_tapsigner_signature(&card_pubkey, signature, card_nonce, app_nonce, &secp)
    //             .is_ok()
    //     );
    // }
}
