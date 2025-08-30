// Copyright (c) 2025 rust-cktap contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

use async_trait::async_trait;
use bitcoin::PublicKey;
use bitcoin::secp256k1::{All, Secp256k1};
use std::sync::Arc;

use crate::apdu::StatusResponse;
use crate::commands::{Authentication, Certificate, CkTransport, Read, Wait};
use crate::error::{ReadError, StatusError};
use crate::tap_signer::TapSignerShared;

/// - SATSCHIP model: this product variant is a TAPSIGNER in all respects,
///   except, as of v1.0.0: `num_backups` in status field is omitted, and
///   a flag `satschip=True` will be present instead. The "backup" command
///   is not supported and will fail with 404 error.
pub struct SatsChip {
    pub transport: Arc<dyn CkTransport>,
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

impl Authentication for SatsChip {
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

#[async_trait]
impl TapSignerShared for SatsChip {}

impl SatsChip {
    pub fn try_from_status(
        transport: Arc<dyn CkTransport>,
        status_response: StatusResponse,
    ) -> Result<Self, StatusError> {
        let pubkey = status_response.pubkey.as_slice();
        let pubkey = PublicKey::from_slice(pubkey).map_err(StatusError::from)?;

        Ok(SatsChip {
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
}

#[async_trait]
impl Wait for SatsChip {}

#[async_trait]
impl Read for SatsChip {
    fn requires_auth(&self) -> bool {
        true
    }

    fn slot(&self) -> Option<u8> {
        None
    }
}

#[async_trait]
impl Certificate for SatsChip {
    async fn slot_pubkey(&mut self) -> Result<Option<PublicKey>, ReadError> {
        Ok(None)
    }
}

impl core::fmt::Debug for SatsChip {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("SatsChip")
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
