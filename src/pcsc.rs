extern crate core;

use crate::commands::{AppletSelect, CommandApdu, Error, ResponseApdu, StatusResponse};
use crate::{CkTapCard, SatsCard, TapSigner, Transport};
use pcsc::{Card, Context, Protocols, Scope, ShareMode, MAX_BUFFER_SIZE};

use secp256k1::{PublicKey, Secp256k1};

pub struct PcscTransport {
    card: Card,
}

impl Transport for PcscTransport {
    fn find_first() -> Result<CkTapCard<Self>, Error> {
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
                Err(Error::PcSc("No readers are connected.".to_string()))
            }
        }?;
        println!("Using reader: {:?}\n", reader);

        // Connect to the card.
        let card = ctx.connect(reader, ShareMode::Shared, Protocols::ANY)?;

        // Create transport
        let transport = Self { card };

        // Get card status
        let applet_select_apdu = AppletSelect::default().apdu_bytes();
        let rapdu = transport.transmit_apdu(applet_select_apdu)?;
        let status_response = StatusResponse::from_cbor(rapdu.to_vec())?;

        // get common fields
        let secp = Secp256k1::new();
        let proto = status_response.proto;
        let ver = status_response.ver;
        let birth = status_response.birth;
        let pubkey = status_response.pubkey.as_slice(); // TODO verify is 33 bytes?
        let pubkey = PublicKey::from_slice(pubkey).map_err(|e| Error::CiborValue(e.to_string()))?;
        let card_nonce = status_response.card_nonce;
        let auth_delay = status_response.auth_delay;

        // Return correct card variant
        match (status_response.tapsigner, status_response.satschip) {
            (Some(true), None) => {
                let path = status_response.path;
                let num_backups = status_response.num_backups;

                Ok(CkTapCard::TapSigner(TapSigner {
                    transport,
                    secp,
                    proto,
                    ver,
                    birth,
                    path,
                    num_backups,
                    pubkey,
                    card_nonce,
                    auth_delay,
                }))
            }
            (Some(true), Some(true)) => {
                let path = status_response.path;
                let num_backups = status_response.num_backups;

                Ok(CkTapCard::SatsChip(TapSigner {
                    transport,
                    secp,
                    proto,
                    ver,
                    birth,
                    path,
                    num_backups,
                    pubkey,
                    card_nonce,
                    auth_delay,
                }))
            }
            (None, None) => {
                let slots = status_response
                    .slots
                    .ok_or(Error::CiborValue("Missing slots".to_string()))?;

                let addr = status_response.addr;

                Ok(CkTapCard::SatsCard(SatsCard {
                    transport,
                    secp,
                    proto,
                    ver,
                    birth,
                    slots,
                    addr,
                    pubkey,
                    card_nonce,
                    auth_delay,
                }))
            }
            (_, _) => {
                // TODO throw error
                todo!()
            }
        }
    }

    fn transmit_apdu(&self, apdu: Vec<u8>) -> Result<Vec<u8>, Error> {
        let mut receive_buffer = vec![0; MAX_BUFFER_SIZE];
        let rapdu = self.card.transmit(&apdu.as_slice(), &mut receive_buffer)?;
        Ok(rapdu.to_vec())
    }
}
