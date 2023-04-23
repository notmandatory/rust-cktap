extern crate core;

use ciborium::de::from_reader;
use ciborium::value::Value;
use pcsc::{Card, Context, Protocols, Scope, ShareMode, MAX_BUFFER_SIZE};
use rust_cktap::{
    AppletSelect, CertsCommand, CertsResponse, CheckCommand, CheckResponse, CommandApdu,
    DumpCommand, DumpResponse, Error, NewCommand, NewResponse, ReadCommand, ReadResponse,
    ResponseApdu, StatusCommand, StatusResponse, WaitCommand, WaitResponse,
};
use secp256k1::ecdh::SharedSecret;
use secp256k1::hashes::{sha256, Hash};
use secp256k1::rand::rngs::ThreadRng;
use secp256k1::rand::Rng;
use secp256k1::{rand, All, PublicKey, Secp256k1, SecretKey};
use serde::Deserialize;

fn main() -> Result<(), Error> {
    let card = find_first()?;

    let status = applet_select(&card)?;
    dbg!(&status);

    // TODO validate certs auth_sig

    // if auth delay call wait
    if status.auth_delay.is_some() {
        let mut auth_delay = status.auth_delay.unwrap();
        while auth_delay > 0 {
            let wait = wait_command(&card, None)?;
            auth_delay = wait.auth_delay;
        }
    }

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

    match status.card_type() {
        SatsCard => {
            let rng = &mut rand::thread_rng();
            let nonce = rand_nonce(rng).to_vec();
            // SatsCard.read() // nonce generated in method
            let read_response = read_command(&card, nonce, None, None)?;
            dbg!(read_response);
            // TODO validate read response sig
        },
        TapSigner if status.pubkey.len() == 33 => {
            let tapsigner = TapSigner::from_pcsc(card);
            // tapsigner.set_cvc(cvc);
            dbg!(tapsigner.read(&status));
            
            // TODO validate read response sig
        },
        TapSigner => { print!("TapSigner without 33 byte key") }
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
    Ok(())
}

struct TapSigner {
    card: Card,
    cvc: Option<String>,
    secp: Secp256k1<All>,
    card_nonce: Vec<u8>
}

impl TapSigner {
    fn from_pcsc(card: Card) -> Self {
        let rng = &mut rand::thread_rng();
        let nonce = rand_nonce(rng).to_vec();
        let mut secp: Secp256k1<All> = Secp256k1::new();
        Self { card, cvc: None, card_nonce: nonce, secp }
    }

    fn set_cvc(&mut self, cvc: String) {
        self.cvc = Some(cvc);
    }

    fn read(&self, status: &StatusResponse) -> Result<ReadResponse, Error> {
        if let Some(cvc) = &self.cvc {
            let (eseckey, epubkey, xcvc) =
                calc_xcvc(&self.secp, &"read".to_string(), status, cvc);
            read_command(&self.card, self.card_nonce.clone(), Some(epubkey), Some(xcvc))
        } else {
            Err(Error::PcSc("Requires CVC? No impl".to_string()))
        }
        
    }
}

fn find_first() -> Result<Card, Error> {
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
    Ok(ctx.connect(reader, ShareMode::Shared, Protocols::ANY)?)
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

fn calc_xcvc(
    secp: &Secp256k1<All>,
    command: &String,
    status: &StatusResponse,
    cvc: &String,
) -> (SecretKey, PublicKey, Vec<u8>) {
    dbg!(cvc);
    assert!(6 <= cvc.len() && cvc.len() <= 32);
    let (eseckey, epubkey) = secp.generate_keypair(&mut rand::thread_rng());
    let cvc_bytes = cvc.as_bytes();
    dbg!(&cvc_bytes);
    let card_pubkey_bytes = status.pubkey.as_slice();
    let card_pubkey: PublicKey = PublicKey::from_slice(card_pubkey_bytes).unwrap();
    let session_key = SharedSecret::new(&card_pubkey, &eseckey);
    let card_nonce_bytes = status.card_nonce.as_slice();
    let card_nonce_command = [card_nonce_bytes, command.as_bytes()].concat();
    let md = sha256::Hash::hash(card_nonce_command.as_slice());
    let mask: Vec<u8> = session_key
        .as_ref()
        .iter()
        .zip(md.as_ref())
        .map(|(x, y)| x ^ y)
        .take(cvc.len())
        .collect();
    let xcvc = cvc_bytes.iter().zip(mask).map(|(x, y)| x ^ y).collect();
    (eseckey, epubkey, xcvc)
}

fn applet_select(card: &Card) -> Result<StatusResponse, Error> {
    // Send ISO App Select.
    let applet_select_apdu = AppletSelect::default().apdu_bytes();
    println!(
        "Sending 'ISO Applet Select' APDU: {:?}\n",
        &applet_select_apdu
    );
    let mut rapdu_buf = [0; MAX_BUFFER_SIZE];
    let rapdu = card.transmit(&applet_select_apdu.as_slice(), &mut rapdu_buf)?;
    let status_response = StatusResponse::from_cbor(rapdu.to_vec())?;
    println!("Received 'Status' APDU: {:?}\n", &status_response);
    Ok(status_response)
}

fn status_command(card: &Card) -> Result<StatusResponse, Error> {
    // Send 'status' command.
    let status_apdu = StatusCommand::default().apdu_bytes();
    println!("Sending 'status' APDU: {:?}\n", &status_apdu);
    let mut rapdu_buf = [0; MAX_BUFFER_SIZE];
    let rapdu = card.transmit(&status_apdu.as_slice(), &mut rapdu_buf)?;
    let status_response = StatusResponse::from_cbor(rapdu.to_vec())?;
    println!("Received 'Status' APDU: {:?}\n", &status_response);
    Ok(status_response)
}

fn certs_command(card: &Card) -> Result<CertsResponse, Error> {
    // Send 'certs' command.
    let certs_apdu = CertsCommand::default().apdu_bytes();
    println!("Sending 'certs' APDU: {:?}\n", &certs_apdu);
    let mut rapdu_buf = [0; MAX_BUFFER_SIZE];
    let rapdu = card.transmit(&certs_apdu.as_slice(), &mut rapdu_buf)?;
    let certs_response = CertsResponse::from_cbor(rapdu.to_vec())?;
    println!("Received 'Certs' APDU: {:?}\n", &certs_response);
    println!(
        "Received 'Certs' cert_chain: {:?}\n",
        &certs_response.cert_chain()
    );
    Ok(certs_response)
}

fn check_command(card: &Card, nonce: Vec<u8>) -> Result<CheckResponse, Error> {
    // Send 'check' command.
    let check_apdu = CheckCommand::new(nonce).apdu_bytes();
    println!("Sending 'check' APDU: {:?}\n", &check_apdu);
    let mut rapdu_buf = [0; MAX_BUFFER_SIZE];
    let rapdu = card.transmit(&check_apdu.as_slice(), &mut rapdu_buf)?;
    let check_response = CheckResponse::from_cbor(rapdu.to_vec())?;
    println!("Received 'Check' APDU: {:?}\n", &check_response);
    Ok(check_response)
}

fn read_command(
    card: &Card,
    card_nonce: Vec<u8>,
    epubkey: Option<PublicKey>,
    xcvc: Option<Vec<u8>>,
) -> Result<ReadResponse, Error> {
    // Send 'read' command.
    let read_struct = ReadCommand::new(card_nonce, epubkey, xcvc);
    //let read_struct = ReadCommand::new(status_response.card_nonce, None, None);
    println!("Sending 'read' Struct: {:?}\n", &read_struct);
    let read_apdu = read_struct.apdu_bytes();
    println!("Sending 'read' APDU: {:?}\n", &read_apdu);
    let mut rapdu_buf = [0; MAX_BUFFER_SIZE];
    let rapdu = card.transmit(&read_apdu.as_slice(), &mut rapdu_buf)?;
    let read_response = ReadResponse::from_cbor(rapdu.to_vec())?;
    println!("Received 'read' APDU: {:?}\n", &read_response);
    Ok(read_response)
}

fn new_command(
    card: &Card,
    slot: usize,
    chain_code: Option<Vec<u8>>,
    epubkey: Vec<u8>,
    xcvc: Vec<u8>,
) -> Result<NewResponse, Error> {
    // Send 'new' command.
    let new_apdu = NewCommand::new(slot, chain_code, epubkey, xcvc).apdu_bytes();
    println!("Sending 'new' APDU: {:?}\n", &new_apdu);
    let mut rapdu_buf = [0; MAX_BUFFER_SIZE];
    let rapdu = card.transmit(&new_apdu.as_slice(), &mut rapdu_buf)?;
    let new_response = NewResponse::from_cbor(rapdu.to_vec())?;
    println!("Received 'New' APDU: {:?}\n", &new_response);
    Ok(new_response)
}

fn wait_command(card: &Card, xcvc: Option<Vec<u8>>) -> Result<WaitResponse, Error> {
    // Send 'wait' command.
    let wait_apdu = WaitCommand::new(None, xcvc).apdu_bytes();
    println!("Sending 'Wait' APDU: {:?}\n", &wait_apdu);
    let mut rapdu_buf = [0; MAX_BUFFER_SIZE];
    let rapdu = card.transmit(&wait_apdu.as_slice(), &mut rapdu_buf)?;
    let wait_response = WaitResponse::from_cbor(rapdu.to_vec())?;
    println!("Received 'Wait' APDU: {:?}\n", &wait_response);
    Ok(wait_response)
}

fn dump_command(
    card: &Card,
    slot: usize,
    epubkey: Option<Vec<u8>>,
    xcvc: Option<Vec<u8>>,
) -> Result<DumpResponse, Error> {
    // Send 'dump' command
    let dump_apdu = DumpCommand::new(slot, epubkey, xcvc).apdu_bytes();
    println!("Sending 'dump' APDU: {:?}\n", &dump_apdu);
    let mut rapdu_buf = [0; MAX_BUFFER_SIZE];
    let rapdu = card.transmit(&dump_apdu.as_slice(), &mut rapdu_buf)?;
    let cbor_response: Value = from_reader(rapdu)?;
    let dump_response = DumpResponse::from_cbor(rapdu.to_vec())?;
    println!("Received 'dump' APDU: {:?}\n", &dump_response);
    Ok(dump_response)
}
