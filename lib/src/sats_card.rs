use async_trait::async_trait;
use bitcoin::key::CompressedPublicKey as BitcoinPublicKey;
use bitcoin::secp256k1::{All, Message, PublicKey, Secp256k1, SecretKey, ecdsa::Signature};
use bitcoin::{Address, Network};
use bitcoin_hashes::sha256;
use std::sync::Arc;

use crate::apdu::{
    CkTapError, CommandApdu as _, DeriveCommand, DeriveResponse, DumpCommand, DumpResponse, Error,
    NewCommand, NewResponse, SignCommand, SignResponse, StatusResponse, UnsealCommand,
    UnsealResponse,
};
use crate::commands::{Authentication, Certificate, CkTransport, Read, Wait, transmit};
use crate::secp256k1;
use crate::tap_signer::PsbtSignError;
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

    /// Dumps the slot key(s) for an unsealed slot.
    ///
    /// With the CVC the private and public slot address keys are returned.
    /// Without the CVC, the private key is not included.
    /// If an unsealed or unused slot number is given an error is returned.
    pub async fn dump(
        &mut self,
        slot: u8,
        cvc: Option<String>,
    ) -> Result<(Option<SecretKey>, PublicKey), Error> {
        let epubkey_eprivkey_xcvc = cvc.map(|cvc| {
            let (eprivkey, epubkey, xcvc) = self.calc_ekeys_xcvc(&cvc, DumpCommand::name());
            (epubkey, eprivkey, xcvc)
        });

        let (epubkey, eprivkey, xcvc) = epubkey_eprivkey_xcvc
            .map(|(epubkey, eprivkey, xcvc)| (Some(epubkey), Some(eprivkey), Some(xcvc)))
            .unwrap_or((None, None, None));

        let dump_command = DumpCommand::new(slot, epubkey, xcvc.clone());
        let dump_response: DumpResponse = transmit(self.transport(), &dump_command).await?;
        self.set_card_nonce(dump_response.card_nonce);

        // throw errors
        if let Some(tampered) = dump_response.tampered {
            if tampered {
                return Err(Error::SlotTampered(slot));
            }
        } else if let Some(sealed) = dump_response.sealed {
            if sealed {
                return Err(Error::SlotSealed(slot));
            }
        } else if let Some(used) = dump_response.used {
            if !used {
                return Err(Error::SlotUnused(slot));
            }
        }

        // at this point pubkey must be available
        let pubkey_bytes = dump_response.pubkey.unwrap();
        let pubkey = PublicKey::from_slice(&pubkey_bytes)?;
        // TODO use chaincode and master public key to verify pubkey or return error

        let seckey = if let (Some(privkey), Some(eprivkey)) = (dump_response.privkey, eprivkey) {
            // the private key is encrypted, XORed with the session key, need to decrypt
            let session_key = secp256k1::ecdh::SharedSecret::new(self.pubkey(), &eprivkey);
            // decrypt the private key by XORing with the session key
            let privkey: Vec<u8> = session_key
                .as_ref()
                .iter()
                .zip(&privkey)
                .map(|(session_key_byte, privkey_byte)| session_key_byte ^ privkey_byte)
                .collect();
            let privkey = SecretKey::from_slice(&privkey)?;
            Some(privkey)
        } else {
            None
        };

        Ok((seckey, pubkey))
    }

    pub async fn address(&mut self) -> Result<String, Error> {
        let network = Network::Bitcoin;
        let slot_pubkey = self.read(None).await?;
        let pk = BitcoinPublicKey::from_slice(&slot_pubkey.serialize())?;
        let address = Address::p2wpkh(&pk, network);
        Ok(address.to_string())
    }

    /// Sign a message digest with the SATSCARD.
    pub async fn sign(
        &mut self,
        digest: [u8; 32],
        slot: u8,
        cvc: &str,
    ) -> Result<SignResponse, Error> {
        let (eprivkey, epubkey, xcvc) = self.calc_ekeys_xcvc(cvc, SignCommand::name());

        // Use the same session key to encrypt the new CVC
        let session_key = secp256k1::ecdh::SharedSecret::new(self.pubkey(), &eprivkey);

        // encrypt the digest by XORing with the session key
        let xdigest_vec: Vec<u8> = session_key
            .as_ref()
            .iter()
            .zip(digest)
            .map(|(session_key_byte, digest_byte)| session_key_byte ^ digest_byte)
            .collect();

        let xdigest: [u8; 32] = xdigest_vec.try_into().expect("input is also 32 bytes");

        let sign_command = SignCommand::for_satscard(slot, xdigest, epubkey, xcvc.clone());

        let mut sign_response: Result<SignResponse, Error> =
            transmit(self.transport(), &sign_command).await;

        let mut unlucky_number_retries = 0;
        while let Err(Error::CkTap(CkTapError::UnluckyNumber)) = sign_response {
            let sign_command = SignCommand::for_satscard(slot, xdigest, epubkey, xcvc.clone());

            sign_response = transmit(self.transport(), &sign_command).await;
            unlucky_number_retries += 1;

            if unlucky_number_retries > 3 {
                // TODO shouldn't this return an Err(UnluckyNumber) ?
                break;
            }
        }

        let sign_response = sign_response?;
        self.set_card_nonce(sign_response.card_nonce);
        Ok(sign_response)
    }

    /// Sign P2WPKH inputs for a PSBT with unsealed slot private key m/0
    /// This function will return a signed but not finalized PSBT. You will need to finalize the
    /// PSBT yourself before it can be broadcast.
    pub async fn sign_psbt(
        &mut self,
        slot: u8,
        mut psbt: bitcoin::Psbt,
        cvc: &str,
    ) -> Result<bitcoin::Psbt, PsbtSignError> {
        use bitcoin::{
            secp256k1::ecdsa,
            sighash::{EcdsaSighashType, SighashCache},
        };

        type Error = PsbtSignError;

        let unsigned_tx = psbt.unsigned_tx.clone();
        let mut sighash_cache = SighashCache::new(&unsigned_tx);

        for (input_index, input) in psbt.inputs.iter_mut().enumerate() {
            // extract previous output data from the PSBT
            let witness_utxo = input
                .witness_utxo
                .as_ref()
                .ok_or(Error::MissingUtxo(input_index))?;

            let amount = witness_utxo.value;

            // extract the P2WPKH script from PSBT
            let script_pubkey = &witness_utxo.script_pubkey;
            if !script_pubkey.is_p2wpkh() {
                return Err(Error::InvalidScript(input_index));
            }

            // get the public key from the PSBT
            let key_pairs = &input.bip32_derivation;
            let (psbt_pubkey, (_fingerprint, path)) = key_pairs
                .iter()
                .next()
                .ok_or(Error::MissingPubkey(input_index))?;

            if !path.is_empty() {
                return Err(Error::InvalidPath(input_index));
            }

            // calculate sighash
            let script = script_pubkey.as_script();
            let sighash = sighash_cache
                .p2wpkh_signature_hash(input_index, script, amount, EcdsaSighashType::All)
                .map_err(|e| Error::SighashError(e.to_string()))?;

            // the digest is the sighash
            let digest: &[u8; 32] = sighash.as_ref();

            // send digest to SATSCARD for signing
            let sign_response = self.sign(*digest, slot, cvc).await?;
            let signature_raw = sign_response.sig;

            // verify that SATSCARD used the same public key as the PSBT
            if sign_response.pubkey != psbt_pubkey.serialize() {
                return Err(Error::PubkeyMismatch(input_index));
            }

            // update the PSBT input with the signature
            let ecdsa_sig = ecdsa::Signature::from_compact(&signature_raw)
                .map_err(|e| Error::SignatureError(e.to_string()))?;

            let final_sig = bitcoin::ecdsa::Signature::sighash_all(ecdsa_sig);
            input.partial_sigs.insert((*psbt_pubkey).into(), final_sig);
        }

        Ok(psbt)
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

/// Slot details for an in-use or unsealed slot.
///
/// Without the CVC, only the public details for each slot, is included.
/// except unsealed slots where the address in full is also provided.
#[derive(Clone, Debug)]
pub struct SlotDetails {
    /// Slot number.
    pub slot: usize,
    /// Private key for spending (for addr) or None if slot not unsealed or no CVC given.
    pub privkey: Option<SecretKey>,
    /// Public key for receiving bitcoin.
    pub pubkey: PublicKey,
    /// Full payment address (not censored).
    pub addr: String,
}

#[cfg(feature = "emulator")]
#[cfg(test)]
mod test {
    use crate::commands::Certificate;
    use crate::emulator::find_emulator;
    use crate::emulator::test::{CardTypeOption, EcardSubprocess};
    use crate::{CkTapCard, Error};
    use bdk_wallet::chain::{BlockId, ConfirmationBlockTime};
    use bdk_wallet::template::P2Wpkh;
    use bdk_wallet::test_utils::{insert_anchor, insert_checkpoint, insert_tx, new_tx};
    use bdk_wallet::{KeychainKind, SignOptions, Wallet};
    use bitcoin::Network::{Bitcoin, Testnet};
    use bitcoin::hashes::Hash;
    use bitcoin::{
        Address, Amount, BlockHash, FeeRate, Network, PrivateKey, PublicKey, Transaction, TxOut,
    };
    use std::path::Path;
    use std::str::FromStr;

    // verify a signed psbt can be finalized
    #[tokio::test]
    async fn test_satscard_sign_psbt() {
        let card_type = CardTypeOption::SatsCard;
        let pipe_path = "/tmp/test-satscard-sign-psbt-pipe";
        let pipe_path = Path::new(&pipe_path);
        let python = EcardSubprocess::new(pipe_path, &card_type).unwrap();
        let emulator = find_emulator(pipe_path).await.unwrap();
        if let CkTapCard::SatsCard(mut sc) = emulator {
            let slot_pubkey = sc.slot_pubkey().await.unwrap().unwrap();
            let card_address = sc.address().await.unwrap();
            let (seckey, pubkey) = sc.unseal(0, "123456").await.unwrap();
            assert_eq!(pubkey, slot_pubkey);

            let _seckey = PrivateKey::new(seckey, Bitcoin);
            let pubkey = PublicKey::new(pubkey);

            let descriptor = P2Wpkh(pubkey);
            let mut wallet = Wallet::create_single(descriptor)
                .network(Network::Bitcoin)
                .create_wallet_no_persist()
                .unwrap();
            let wallet_address = wallet.reveal_next_address(KeychainKind::External).address;
            assert_eq!(&wallet_address.to_string(), &card_address);

            let tx0 = Transaction {
                output: vec![TxOut {
                    value: Amount::from_sat(76_000),
                    script_pubkey: wallet_address.script_pubkey(),
                }],
                ..new_tx(0)
            };

            insert_checkpoint(
                &mut wallet,
                BlockId {
                    height: 1_000,
                    hash: BlockHash::all_zeros(),
                },
            );
            insert_checkpoint(
                &mut wallet,
                BlockId {
                    height: 2_000,
                    hash: BlockHash::all_zeros(),
                },
            );
            insert_tx(&mut wallet, tx0.clone());
            insert_anchor(
                &mut wallet,
                tx0.compute_txid(),
                ConfirmationBlockTime {
                    block_id: BlockId {
                        height: 1_000,
                        hash: BlockHash::all_zeros(),
                    },
                    confirmation_time: 100,
                },
            );
            let balance = wallet.balance();
            assert_eq!(balance.confirmed, Amount::from_sat(76_000));
            let mut builder = wallet.build_tx();
            builder
                .add_recipient(
                    Address::from_str("tb1qlvuuza7al8k6shl67qv00g8va3eepy70a42nxd")
                        .unwrap()
                        .require_network(Testnet)
                        .unwrap(),
                    Amount::from_sat(1000),
                )
                .fee_rate(FeeRate::from_sat_per_vb(2).unwrap());
            let psbt = builder.finish().unwrap();
            let mut signed_psbt = sc.sign_psbt(0, psbt, "123456").await.unwrap();
            let finalized = wallet
                .finalize_psbt(&mut signed_psbt, SignOptions::default())
                .unwrap();
            assert!(finalized);
        } else {
            panic!("Expected SatsCard");
        }

        drop(python);
    }

    // test dumping a sealed, unsealed, and unsealed slot
    #[tokio::test]
    async fn test_satscard_dump() {
        let card_type = CardTypeOption::SatsCard;
        let pipe_path = "/tmp/test-satscard-dump-pipe";
        let pipe_path = Path::new(&pipe_path);
        let python = EcardSubprocess::new(pipe_path, &card_type).unwrap();
        let emulator = find_emulator(pipe_path).await.unwrap();
        if let CkTapCard::SatsCard(mut sc) = emulator {
            // slot 0 is sealed, with cvc return sealed error
            let slot_keys = sc.dump(0, Some("123456".to_string())).await;
            assert!(matches!(slot_keys, Err(Error::SlotSealed(slot)) if slot == 0));
            // slot 0 is sealed, with no cvc return sealed error
            let slot_keys = sc.dump(0, None).await;
            assert!(matches!(slot_keys, Err(Error::SlotSealed(slot)) if slot == 0));
            // unseal slot 0
            sc.unseal(0, "123456").await.unwrap();
            // slot 0 is unsealed, with cvc return privkey
            let slot_keys = sc.dump(0, Some("123456".to_string())).await;
            assert!(slot_keys.is_ok());
            assert!(matches!(slot_keys, Ok((Some(_), _))));
            let slot_keys = slot_keys.unwrap();
            // verify pubkey matches pubkey derived from decrypted private key
            let pubkey_from_privkey = slot_keys.0.unwrap().public_key(&sc.secp);
            assert_eq!(pubkey_from_privkey, slot_keys.1);
            // slot 0 is unsealed, with no cvc don't return privkey
            let slot_keys = sc.dump(0, None).await;
            assert!(slot_keys.is_ok());
            assert!(matches!(slot_keys, Ok((None, _))));
            // slot 1 is unused, with cvc return unused error
            let dump_response = sc.dump(1, Some("123456".to_string())).await;
            assert!(matches!(dump_response, Err(Error::SlotUnused(slot)) if slot == 1));
            // slot 1 is unused, with no cvc also return unused error
            let dump_response = sc.dump(1, None).await;
            assert!(matches!(dump_response, Err(Error::SlotUnused(slot)) if slot == 1));
        }
        drop(python);
    }
}
