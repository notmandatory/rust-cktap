// Copyright (c) 2025 rust-cktap contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

extern crate core;

use crate::CkTapError;
use crate::commands::to_cktap;
use crate::error::StatusError;
use crate::{CkTapCard, CkTransport};
use async_trait::async_trait;
use pcsc::{Card, Context, MAX_BUFFER_SIZE, Protocols, Scope, ShareMode};
use std::sync::Arc;

pub async fn find_first() -> Result<CkTapCard, StatusError> {
    // Establish a PC/SC context.
    let ctx = Context::establish(Scope::User)?;

    // List available readers.
    let mut readers_buf = [0; 2048];
    let mut readers = ctx.list_readers(&mut readers_buf)?;

    // Use the first reader.
    let reader = match readers.next() {
        Some(reader) => Ok(reader),
        None => {
            //println!("No readers are connected.");
            Err(CkTapError::Transport(
                "No readers are connected.".to_string(),
            ))
        }
    }?;

    let card = ctx.connect(reader, ShareMode::Shared, Protocols::ANY)?;
    to_cktap(Arc::new(card)).await
}

#[async_trait]
impl CkTransport for Card {
    async fn transmit_apdu(&self, command_apdu: Vec<u8>) -> Result<Vec<u8>, CkTapError> {
        let mut receive_buffer = vec![0; MAX_BUFFER_SIZE];
        let rapdu = self.transmit(command_apdu.as_slice(), &mut receive_buffer)?;
        Ok(rapdu.to_vec())
    }
}
