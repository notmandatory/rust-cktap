extern crate core;

use ciborium::de::from_reader;
use ciborium::value::Value;
use pcsc::{Card, Context, Protocols, Scope, ShareMode, MAX_BUFFER_SIZE};
use rust_cktap::{
    AppletSelect, CertsCommand, CertsResponse, CheckCommand, CheckResponse, CommandApdu,
    DumpCommand, DumpResponse, Error, NewCommand, NewResponse, ReadCommand, ReadResponse,
    ResponseApdu, StatusCommand, StatusResponse, WaitCommand, WaitResponse, CardType, SignCommand, SignResponse
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
        CardType::SatsCard => {
            let rng = &mut rand::thread_rng();
            let nonce = rand_nonce(rng).to_vec();
            // SatsCard.read() // nonce generated in method
            let read_response = read_command(&card, nonce, None, None)?;
            dbg!(read_response);
            // TODO validate read response sig
        },
        CardType::TapSigner => {
            let mut tapsigner = TapSigner::from_pcsc(card, &status);

            if tapsigner.cvc.is_none() {
                println!("Enter cvc:");
                let mut cvc: String = String::new();
                let _btye_count = std::io::stdin().read_line(&mut cvc).unwrap();
                tapsigner.set_cvc(cvc.trim().to_owned());
            }
            
            let read_resp = tapsigner.read();
            dbg!(read_resp);
            // TODO validate read response sig
            
            // sample pulled from ref impl: https://github.com/coinkite/coinkite-tap-proto/blob/0ab18dd1446c1e21e30d04ab99c2201ccc0197f8/testing/test_crypto.py
            let md = b"3\xa7=Q\x1f\xb3\xfa)>i\x8f\xb2\x8f6\xd2\x97\x9eW\r5\x0b\x82\x0e\xd3\xd6?\xf4G]\x14Fd";
            let sign_resp = tapsigner.sign(md.to_vec());
            dbg!(sign_resp);
            // TODO validate response sig
        }
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
    pubkey: Option<PublicKey>, 
    cvc: Option<String>,
    secp: Secp256k1<All>, // required here?
    card_nonce: Vec<u8>
}

impl TapSigner {
    fn from_pcsc(card: Card, status: &StatusResponse) -> Self {
        // let rng = &mut rand::thread_rng();
        // let nonce = rand_nonce(rng).to_vec();
        let card_nonce = &status.card_nonce;
        let mut secp: Secp256k1<All> = Secp256k1::new();
        let pubkey = if status.pubkey.len() == 33 {
            let as_bytes = status.pubkey.as_slice();
            Some(PublicKey::from_slice(as_bytes).unwrap()) 
        } else {
            None
        };
        Self { 
            card, 
            cvc: None, 
            card_nonce: card_nonce.to_vec(), 
            secp, 
            pubkey 
        }
    }

    fn set_cvc(&mut self, cvc: String) {
        self.cvc = Some(cvc);
    }

    fn calc_xcvc(&self, command: &String) -> (SecretKey, PublicKey, Vec<u8>) {
        let cvc_bytes = match &self.cvc {
            Some(cvc) => cvc.as_bytes(),
            None => panic!("calc_xcvc requires cvc"),
        };
        let pubkey = match &self.pubkey {
            Some(pk) => pk,
            None => panic!("calc_xcvc requires a pubkey"),
        };
        let card_nonce_bytes = self.card_nonce.as_slice();
        let card_nonce_command = [card_nonce_bytes, command.as_bytes()].concat();

        let (eseckey, epubkey) = self.secp.generate_keypair(&mut rand::thread_rng());
        let session_key = SharedSecret::new(&pubkey, &eseckey);
        
        let md = sha256::Hash::hash(card_nonce_command.as_slice());

        let mask: Vec<u8> = session_key
            .as_ref()
            .iter()
            .zip(md.as_ref())
            .map(|(x, y)| x ^ y)
            .take(cvc_bytes.len())
            .collect();
        let xcvc = cvc_bytes.iter().zip(mask).map(|(x, y)| x ^ y).collect();
        (eseckey, epubkey, xcvc)
        
    }

    fn read(&mut self) -> Result<ReadResponse, Error> {
        let (eseckey, epubkey, xcvc) = self.calc_xcvc(&"read".to_string());
        match read_command(&self.card, self.card_nonce.clone(), Some(epubkey), Some(xcvc)) {
            Ok(resp) => {
                self.card_nonce = resp.card_nonce.clone();
                Ok(resp)
            },
            Err(error) => panic!("Failed to read card: {:?}", error),
        }
    }

    fn sign(&mut self, digest: Vec<u8>) -> Result<SignResponse, Error> {
        let (eseckey, epubkey, xcvc) = self.calc_xcvc(&"sign".to_string());
        match sign_command(&self.card, digest, epubkey, xcvc) {
            Ok(resp) => {
                self.card_nonce = resp.card_nonce.clone();
                Ok(resp)
            },
            Err(error) => panic!("Failed to read card: {:?}", error),
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

// fn calc_xcvc(
//     secp: &Secp256k1<All>,
//     command: &String,
//     status: &StatusResponse,
//     cvc: &String,
// ) -> (SecretKey, PublicKey, Vec<u8>) {
//     dbg!(cvc);
//     assert!(6 <= cvc.len() && cvc.len() <= 32);
//     let (eseckey, epubkey) = secp.generate_keypair(&mut rand::thread_rng());
//     let cvc_bytes = cvc.as_bytes();
//     dbg!(&cvc_bytes);
//     let card_pubkey_bytes = status.pubkey.as_slice();
//     let card_pubkey: PublicKey = PublicKey::from_slice(card_pubkey_bytes).unwrap();
//     let session_key = SharedSecret::new(&card_pubkey, &eseckey);
//     let card_nonce_bytes = status.card_nonce.as_slice();
//     let card_nonce_command = [card_nonce_bytes, command.as_bytes()].concat();
//     let md = sha256::Hash::hash(card_nonce_command.as_slice());
//     let mask: Vec<u8> = session_key
//         .as_ref()
//         .iter()
//         .zip(md.as_ref())
//         .map(|(x, y)| x ^ y)
//         .take(cvc.len())
//         .collect();
//     let xcvc = cvc_bytes.iter().zip(mask).map(|(x, y)| x ^ y).collect();
//     (eseckey, epubkey, xcvc)
// }

fn applet_select(card: &Card) -> Result<StatusResponse, Error> {
    // Send ISO App Select.
    let applet_select_apdu = AppletSelect::default().apdu_bytes();
    // println!(
    //     "Sending 'ISO Applet Select' APDU: {:?}\n",
    //     &applet_select_apdu
    // );
    let mut rapdu_buf = [0; MAX_BUFFER_SIZE];
    let rapdu = card.transmit(&applet_select_apdu.as_slice(), &mut rapdu_buf)?;
    let status_response = StatusResponse::from_cbor(rapdu.to_vec())?;
    // println!("Received 'Status' APDU: {:?}\n", &status_response);
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

fn sign_command(
    card: &Card,
    digest: Vec<u8>,
    epubkey: PublicKey,
    xcvc: Vec<u8>,
) -> Result<SignResponse, Error> {
    let command = SignCommand::for_tapsigner(Some([0,0]), digest, epubkey, xcvc);
    println!("Sending SignCommand: {:?}\n", &command);
    let req_apdu = command.apdu_bytes();
    println!("Request APDU: {:?}\n", &req_apdu);
    let mut apdu_buf = [0; MAX_BUFFER_SIZE];
    let resp_apdu = card.transmit(&req_apdu.as_slice(), &mut apdu_buf)?;
    let sign_response = SignResponse::from_cbor(resp_apdu.to_vec())?;
    Ok(sign_response)
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
