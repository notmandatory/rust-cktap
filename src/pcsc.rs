extern crate core;

use crate::commands::{AppletSelect, CommandApdu, Error, ResponseApdu, StatusResponse};
use crate::{wait_command, CkTapCard, SatsCard, TapSigner, Transport};
use pcsc::{Card, Context, Protocols, Scope, ShareMode, MAX_BUFFER_SIZE};

use secp256k1::{All, PublicKey, Secp256k1};

struct PcscTransport {
    secp: Secp256k1<All>,
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
        let secp = Secp256k1::new();
        let transport = Self { secp, card };

        // Get card status
        let applet_select_apdu = AppletSelect::default().apdu_bytes();
        let rapdu = transport.transmit(applet_select_apdu)?;
        let status_response = StatusResponse::from_cbor(rapdu.to_vec())?;
        dbg!(&status_response);

        // if auth delay call wait
        if status_response.auth_delay.is_some() {
            let mut auth_delay = status_response.auth_delay.unwrap();
            while auth_delay > 0 {
                let wait = wait_command(&transport, None)?;
                auth_delay = wait.auth_delay;
            }
        }

        // get common fields
        let proto = status_response.proto;
        let ver = status_response.ver;
        let birth = status_response.birth;
        let pubkey = status_response.pubkey.as_slice(); // TODO verify is 33 bytes?
        let pubkey = PublicKey::from_slice(pubkey).map_err(|e| Error::CiborValue(e.to_string()))?;
        let card_nonce = status_response.card_nonce;

        // Return correct card variant
        match (status_response.tapsigner, status_response.satschip) {
            (Some(true), None) => {
                let path = status_response.path;
                let num_backups = status_response.num_backups;

                Ok(CkTapCard::TapSigner(TapSigner {
                    transport,
                    proto,
                    ver,
                    birth,
                    path,
                    num_backups,
                    pubkey,
                    card_nonce,
                }))
            }
            (Some(true), Some(true)) => {
                let path = status_response.path;
                let num_backups = status_response.num_backups;

                Ok(CkTapCard::SatsChip(TapSigner {
                    transport,
                    proto,
                    ver,
                    birth,
                    path,
                    num_backups,
                    pubkey,
                    card_nonce,
                }))
            }
            (None, None) => {
                let slots = status_response
                    .slots
                    .ok_or(Error::CiborValue("Missing slots".to_string()))?;

                let addr = status_response
                    .addr
                    .ok_or(Error::CiborValue("Missing addr".to_string()))?;

                Ok(CkTapCard::SatsCard(SatsCard {
                    transport,
                    proto,
                    ver,
                    birth,
                    slots,
                    addr,
                    pubkey,
                    card_nonce,
                }))
            }
            (_, _) => {
                // TODO throw error
                todo!()
            }
        }
    }

    fn secp(&self) -> &Secp256k1<All> {
        &self.secp
    }

    fn transmit(&self, send_buffer: Vec<u8>) -> Result<Vec<u8>, Error> {
        let mut receive_buf = vec![0; MAX_BUFFER_SIZE];
        let rapdu = self
            .card
            .transmit(&send_buffer.as_slice(), &mut receive_buf)?;
        Ok(rapdu.to_vec())
    }
}

// struct CardReader {
//     card: Card,
// }
//
// impl CardReader {
//     fn find_first() -> Result<CardReader, Error> {
//         // Establish a PC/SC context.
//         let ctx = Context::establish(Scope::User)?;
//
//         // List available readers.
//         let mut readers_buf = [0; 2048];
//         let mut readers = ctx.list_readers(&mut readers_buf)?;
//
//         // Use the first reader.
//         let reader = match readers.next() {
//             Some(reader) => Ok(reader),
//             None => {
//                 //println!("No readers are connected.");
//                 Err(Error::PcSc("No readers are connected.".to_string()))
//             }
//         }?;
//         println!("Using reader: {:?}\n", reader);
//
//         // Connect to the card.
//         let card = ctx.connect(reader, ShareMode::Shared, Protocols::ANY)?;
//
//         Ok(Self { card })
//     }
// }

// // testing authenticated commands
//
// use secp256k1::ecdh::SharedSecret;
// use secp256k1::hashes::sha256;
// use secp256k1::rand;
// use secp256k1::{Message, Secp256k1};
//
// let secp = Secp256k1::new();
// let (eseckey, epubkey) = secp.generate_keypair(&mut rand::thread_rng());
// let message = Message::from_hashed_data::<sha256::Hash>("Hello World!".as_bytes());
//
// let sig = secp.sign_ecdsa(&message, &eseckey);
// assert!(secp.verify_ecdsa(&message, &sig, &epubkey).is_ok());
//
// let s = Secp256k1::new();
// let (sk1, pk1) = s.generate_keypair(&mut rand::thread_rng());
// let (sk2, pk2) = s.generate_keypair(&mut rand::thread_rng());
// let sec1 = SharedSecret::new(&pk2, &sk1);
// let sec2 = SharedSecret::new(&pk1, &sk2);
// assert_eq!(sec1, sec2);

// let ssk1 = SecretKey::from_slice(&sec1.secret_bytes()).expect("32 bytes, within curve order");
// let ssk2 = SecretKey::from_slice(&sec2.secret_bytes()).expect("32 bytes, within curve order");
// assert_eq!(ssk1,ssk2);
//
// let spk1 = PublicKey::from_secret_key(&secp, &ssk1);
// let spk2 = PublicKey::from_secret_key(&secp, &ssk2);
// assert_eq!(spk1,spk2);

// byte array xor
// let c: Vec<_> = a.iter().zip(b).map(|(x, y)| x ^ y).collect();

// test authentication with satscard dump command
// let (eseckey, epubkey, xcvc) = calc_xcvc(&secp, &"dump".to_string(), &status, &satscard_cvc);
// let dump_response = dump_command(&card, 0, Some(epubkey.serialize().to_vec()), Some(xcvc))?;
// dbg!(&dump_response);

// if is a TAPSIGNER call new
// if status.addr.is_none() && status.tapsigner.is_some() && status.tapsigner.unwrap() == true {
//     let rng = &mut rand::thread_rng();
//     let chain_code = rand_chaincode(rng);
//     let (eseckey, epubkey, xcvc) = calc_xcvc(&secp, &"new".to_string(), &status, &tapsigner_cvc);
//     let new_response = new_command(&card, 0, Some(chain_code.to_vec()), epubkey.serialize().to_vec(), xcvc)?;
//     dbg!(new_response);
// }
