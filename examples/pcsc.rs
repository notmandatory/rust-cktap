extern crate core;

use pcsc::{Card, Context, Protocols, Scope, ShareMode, MAX_BUFFER_SIZE};
use rust_cktap::{CardType, TapSigner, NfcTransmittor, applet_select, wait_command, read_command, SatsCard};
use rust_cktap::commands::{AppletSelect, Error};

use secp256k1::{rand, All, PublicKey, Secp256k1, SecretKey};
use secp256k1::rand::rngs::ThreadRng;
use secp256k1::rand::Rng;
// use serde_json;


fn main() -> Result<(), Error> {
    let reader = CardReader::find_first()?;

    let status = applet_select(&reader)?;
    dbg!(&status);

    // TODO validate certs auth_sig

    // if auth delay call wait
    if status.auth_delay.is_some() {
        let mut auth_delay = status.auth_delay.unwrap();
        while auth_delay > 0 {
            let wait = wait_command(&reader, None)?;
            auth_delay = wait.auth_delay;
        }
    }

    match CardType::from_status(&status) {
        CardType::SatsCard => {
            let mut card = SatsCard::new(reader, &status);
            let read_response = card.read();
            dbg!(read_response);
            // TODO validate read response sig
        },
        CardType::TapSigner => {
            let mut tapsigner = TapSigner::new(reader, &status);

            if tapsigner.cvc.is_none() {
                println!("Enter cvc:");
                let mut cvc: String = String::new();
                let _btye_count = std::io::stdin().read_line(&mut cvc).unwrap();
                tapsigner.set_cvc(cvc.trim().to_owned());
            }
            
            let read_resp = tapsigner.read()?;
            dbg!(&read_resp);
            // TODO validate read response sig

            let xpub_resp = tapsigner.xpub(true);
            dbg!(&xpub_resp);
            
            let xpub_resp = tapsigner.xpub(false);
            dbg!(&xpub_resp);
            
            // sample pulled from ref impl: https://github.com/coinkite/coinkite-tap-proto/blob/0ab18dd1446c1e21e30d04ab99c2201ccc0197f8/testing/test_crypto.py
            let md = b"3\xa7=Q\x1f\xb3\xfa)>i\x8f\xb2\x8f6\xd2\x97\x9eW\r5\x0b\x82\x0e\xd3\xd6?\xf4G]\x14Fd";
            let sign_resp = tapsigner.sign(md.to_vec(), Some([0,0]))?;
            dbg!(&sign_resp);
            // TODO validate response sig
        }
    }

    Ok(())
}

struct CardReader {
    card: Card
}

impl CardReader {
    fn find_first() -> Result<CardReader, Error> {
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

        Ok(Self { card })
    }

    // fn get_card(&self) -> Card {
    //     self.card
    // }
}

impl NfcTransmittor for CardReader {
    fn transmit(&self, send_buffer: Vec<u8>) -> Result<Vec<u8>, Error> {
        let mut receive_buf = vec![0; MAX_BUFFER_SIZE];
        let rapdu = self.card.transmit(&send_buffer.as_slice(), &mut receive_buf)?;
        Ok(rapdu.to_vec())
    }
}

fn rand_chaincode(rng: &mut ThreadRng) -> [u8; 32] {
    let mut chain_code = [0u8; 32];
    rng.fill(&mut chain_code);
    chain_code
}

fn rand_nonce(rng: &mut ThreadRng) -> [u8; 16] {
    let mut nonce = [0u8; 16];
    rng.fill(&mut nonce);
    nonce
}

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
