extern crate core;

use pcsc::{Card, Context, Protocols, Scope, ShareMode, MAX_BUFFER_SIZE};
use rust_cktap::commands::{AppletSelect, CommandApdu, Error, ResponseApdu, StatusResponse};
use rust_cktap::{rand_chaincode, wait_command, CkTapCard, SatsCard, TapSigner, Transport};
use rust_cktap::pcsc::PcscTransport;
use secp256k1::{rand, All, PublicKey, Secp256k1};

fn get_cvc() -> String {
    println!("Enter cvc:");
    let mut cvc: String = String::new();
    let _btye_count = std::io::stdin().read_line(&mut cvc).unwrap();
    cvc.trim().to_string()
}

// Example using pcsc crate
fn main() -> Result<(), Error> {
    let card = PcscTransport::find_first()?;
    dbg!(&card);

    match card {
        CkTapCard::TapSigner(mut card) => {
            // only do this once per card!
            if card.path.is_none() {
                let rng = &mut rand::thread_rng();
                let chain_code = rand_chaincode(rng).to_vec();
                let new_result = card.init(chain_code, get_cvc())?;
                dbg!(new_result);
            }

            let read_result = card.read(get_cvc())?;
            dbg!(read_result);
        }
        CkTapCard::SatsChip(mut card) => {
            // only do this once per card!
            if card.path.is_none() {
                let rng = &mut rand::thread_rng();
                let chain_code = rand_chaincode(rng).to_vec();
                let new_result = card.init(chain_code, get_cvc())?;
                dbg!(new_result);
            }

            let read_result = card.read(get_cvc())?;
            dbg!(read_result);
        }
        CkTapCard::SatsCard(mut card) => {
            let read_result = card.read()?;
            dbg!(read_result);

            // if let Some(slot) = card.slots.first() {
            //     if slot == &0 {
            //         // unseal first
            //
            //         let rng = &mut rand::thread_rng();
            //         let chain_code = rand_chaincode(rng).to_vec();
            //         let new_result = card.new_slot(0, chain_code, get_cvc())?;
            //         dbg!(new_result);
            //     }
            // }

            let certs_result = card.certs()?;
            dbg!(certs_result);
        }
    }

    Ok(())
}

// fn rand_chaincode(rng: &mut ThreadRng) -> [u8; 32] {
//     let mut chain_code = [0u8; 32];
//     rng.fill(&mut chain_code);
//     chain_code
// }
//
// fn rand_nonce(rng: &mut ThreadRng) -> [u8; 16] {
//     let mut nonce = [0u8; 16];
//     rng.fill(&mut nonce);
//     nonce
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
