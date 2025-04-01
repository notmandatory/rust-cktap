use secp256k1::{
    ecdsa::Signature,
    hashes::{sha256, Hash as _},
    All, Message, PublicKey, Secp256k1,
};

use crate::apdu::{
    tap_signer::{BackupCommand, BackupResponse, ChangeCommand, ChangeResponse},
    CommandApdu as _, DeriveCommand, DeriveResponse, Error, NewCommand, NewResponse, SignCommand,
    SignResponse, StatusCommand, StatusResponse,
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

    #[error(transparent)]
    CvcChangeError(#[from] CvcChangeError),
}

#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum CvcChangeError {
    #[error("new cvc is too short, must be at least 6 bytes, was only {0} bytes")]
    TooShort(usize),

    #[error("new cvc is too long, must be at most 32 bytes, was {0} bytes")]
    TooLong(usize),

    #[error("new cvc is the same as the old one")]
    SameAsOld,
}

#[cfg(feature = "bitcoin")]
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum PsbtSignError {
    #[error("Missing UTXO")]
    MissingUtxo(usize),

    #[error("Missing pubkey")]
    MissingPubkey(usize),

    #[error("Signature error: {0}")]
    SignatureError(String),

    #[error("Witness program error: {0}")]
    WitnessProgramError(String),

    #[error("Sighash error: {0}")]
    SighashError(String),

    #[error("Invalid script: {0}")]
    InvalidScript(usize),

    #[error(transparent)]
    TapSignerError(#[from] Error),
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

    /// Initialize the tap signer, can only be done once
    pub async fn init(
        &mut self,
        chain_code: [u8; 32],
        cvc: &str,
    ) -> Result<NewResponse, TapSignerError> {
        let (_, epubkey, xcvc) = self.calc_ekeys_xcvc(cvc, NewCommand::name());

        let new_command = NewCommand::new(Some(0), Some(chain_code), epubkey, xcvc);
        let new_response: NewResponse = self.transport.transmit(&new_command).await?;

        self.card_nonce = new_response.card_nonce;
        Ok(new_response)
    }

    /// Get the status of the tap signer, including the current card nonce
    pub async fn status(&mut self) -> Result<StatusResponse, Error> {
        let cmd = StatusCommand::default();
        let status_response: StatusResponse = self.transport.transmit(&cmd).await?;
        self.card_nonce = status_response.card_nonce;
        Ok(status_response)
    }

    /// Sign a message digest with the tap signer
    pub async fn sign(&mut self, digest: [u8; 32], cvc: &str) -> Result<SignResponse, Error> {
        let (eprivkey, epubkey, xcvc) = self.calc_ekeys_xcvc(cvc, SignCommand::name());

        // Use the same session key to encrypt the new CVC
        let session_key = secp256k1::ecdh::SharedSecret::new(self.pubkey(), &eprivkey);

        // encrypt the new cvc by XORing with the session key
        let xdigest_vec: Vec<u8> = session_key
            .as_ref()
            .iter()
            .zip(digest.into_iter())
            .map(|(session_key_byte, digest_byte)| session_key_byte ^ digest_byte)
            .collect();

        let xdigest: [u8; 32] = xdigest_vec.try_into().expect("input is also 32 bytes");
        let sign_command = SignCommand::for_tapsigner(None, xdigest, epubkey, xcvc);
        let sign_response: SignResponse = self.transport.transmit(&sign_command).await?;

        self.card_nonce = sign_response.card_nonce;
        Ok(sign_response)
    }

    #[cfg(feature = "bitcoin")]
    pub async fn sign_bip84_psbt(
        &mut self,
        mut psbt: bitcoin::Psbt,
        cvc: &str,
    ) -> Result<bitcoin::Psbt, PsbtSignError> {
        use bitcoin::{
            secp256k1::ecdsa,
            sighash::{EcdsaSighashType, SighashCache},
        };

        type Error = PsbtSignError;

        // 1. Extract the unsigned transaction
        let unsigned_tx = psbt.unsigned_tx.clone();

        // 2. Create sighash cache
        let mut sighash_cache = SighashCache::new(&unsigned_tx);

        // 3. Process each input
        for (input_index, input) in psbt.inputs.iter_mut().enumerate() {
            // Extract previous output data from the PSBT
            let witness_utxo = input
                .witness_utxo
                .as_ref()
                .ok_or(Error::MissingUtxo(input_index))?;

            let amount = witness_utxo.value;

            // Extract the P2WPKH script from PSBT
            let script_buf = &witness_utxo.script_pubkey;

            // Calculate sighash with the correct P2PKH script
            let sighash = sighash_cache
                .p2wpkh_signature_hash(
                    input_index,
                    script_buf.as_script(),
                    amount,
                    EcdsaSighashType::All,
                )
                .map_err(|e| Error::SighashError(e.to_string()))?;

            // Get the digest to sign
            let digest = sighash.to_byte_array();

            // Send digest to TAPSIGNER for signing
            let sign_response = self.sign(digest, cvc).await?;
            let signature = sign_response.sig;

            // Get the public key from TAPSIGNER or from the PSBT
            let key_pairs = &input.bip32_derivation;

            // Extract pubkey from derivation info
            let pubkey = key_pairs
                .iter()
                .next()
                .map(|(pubkey, _)| *pubkey)
                .ok_or(Error::MissingPubkey(input_index))?;

            // Update the PSBT input with the signature
            let signature = ecdsa::Signature::from_compact(&signature[..64])
                .map_err(|e| Error::SignatureError(e.to_string()))?;

            input.partial_sigs.insert(
                pubkey.into(),
                bitcoin::ecdsa::Signature::sighash_all(signature),
            );
        }

        Ok(psbt)
    }
    /// Derive a public key at the given hardened path
    pub async fn derive(
        &mut self,
        path: &[u32],
        cvc: &str,
    ) -> Result<DeriveResponse, TapSignerError> {
        // set most significant bit to 1 to represent hardened path steps
        let path = path.iter().map(|p| p ^ (1 << 31)).collect();
        let app_nonce = crate::rand_nonce();
        let (_, epubkey, xcvc) = self.calc_ekeys_xcvc(cvc, DeriveCommand::name());
        let cmd = DeriveCommand::for_tapsigner(app_nonce, path, epubkey, xcvc);
        let derive_response: DeriveResponse = self.transport.transmit(&cmd).await?;

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
        let pubkey = match &derive_response.pubkey {
            Some(pubkey) => PublicKey::from_slice(pubkey.as_slice()).map_err(Error::from)?,
            None => PublicKey::from_slice(derive_response.master_pubkey.as_slice())
                .map_err(Error::from)?,
        };

        // TODO: actually return as error when we can figure out why its not working on the card
        if self
            .secp()
            .verify_ecdsa(&message, &signature, &pubkey)
            .map_err(Error::from)
            .is_err()
        {
            println!("verify derive command ecdsa signature failed");
        };

        self.card_nonce = derive_response.card_nonce;
        Ok(derive_response)
    }

    /// Change the CVC used for card authentication to a new user provided one
    pub async fn change(
        &mut self,
        new_cvc: &str,
        cvc: &str,
    ) -> Result<ChangeResponse, TapSignerError> {
        if new_cvc.len() < 6 {
            return Err(CvcChangeError::TooShort(new_cvc.len()).into());
        }

        if new_cvc.len() > 32 {
            return Err(CvcChangeError::TooLong(new_cvc.len()).into());
        }

        if new_cvc == cvc {
            return Err(CvcChangeError::SameAsOld.into());
        }

        // Create session key and encrypt current CVC
        let (eprivkey, epubkey, xcvc) = self.calc_ekeys_xcvc(cvc, ChangeCommand::name());

        // Use the same session key to encrypt the new CVC
        let session_key = secp256k1::ecdh::SharedSecret::new(self.pubkey(), &eprivkey);

        // encrypt the new cvc by XORing with the session key
        let xnew_cvc: Vec<u8> = session_key
            .as_ref()
            .iter()
            .zip(new_cvc.as_bytes().iter())
            .map(|(session_key_byte, cvc_byte)| session_key_byte ^ cvc_byte)
            .collect();

        let change_command = ChangeCommand::new(xnew_cvc, epubkey, xcvc);
        let change_response: ChangeResponse = self.transport.transmit(&change_command).await?;

        self.card_nonce = change_response.card_nonce;
        Ok(change_response)
    }

    /// Backup the current card, the backup is encrypted with the "Backup Password" on the back of the card
    pub async fn backup(&mut self, cvc: &str) -> Result<BackupResponse, TapSignerError> {
        let (_, epubkey, xcvc) = self.calc_ekeys_xcvc(cvc, "backup");

        let backup_command = BackupCommand::new(epubkey, xcvc);
        let backup_response: BackupResponse = self.transport.transmit(&backup_command).await?;

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
