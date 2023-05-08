
// use ciborium::de::from_reader;
// use ciborium::value::Value;

use secp256k1::ecdh::SharedSecret;
use secp256k1::hashes::{sha256, Hash};
// use secp256k1::rand::rngs::ThreadRng;
// use secp256k1::rand::Rng;
use secp256k1::{rand, All, PublicKey, Secp256k1, SecretKey};

pub mod commands;
use commands::*;

#[derive(Debug)]
pub enum CardType {
    TapSigner,
    SatsCard
}

impl CardType {
    pub fn from_status(status: &StatusResponse) -> CardType {
        if status.addr.is_none() && status.tapsigner.is_some() && status.tapsigner.unwrap() == true {
            CardType::TapSigner
        } else {
            CardType::SatsCard
        }
    }
}

pub trait NfcTransmittor {
    fn transmit(&self, send_buffer: Vec<u8>) -> Result<Vec<u8>, Error>;
}

pub struct TapSigner<T: NfcTransmittor> {
    card: T,
    pub pubkey: Option<PublicKey>, 
    pub cvc: Option<String>,
    secp: Secp256k1<All>, // required here?
    pub card_nonce: Vec<u8>
}

impl<T: NfcTransmittor> TapSigner<T> {
    pub fn new(card: T, status: &StatusResponse) -> Self {
        let card_nonce = &status.card_nonce;
        let secp: Secp256k1<All> = Secp256k1::new();
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

    pub fn set_cvc(&mut self, cvc: String) {
        self.cvc = Some(cvc);
    }

    fn xcvc(&self, command: &String) -> (SecretKey, PublicKey, Vec<u8>) {
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

    pub fn read(&mut self) -> Result<ReadResponse, Error> {
        let (_eseckey, epubkey, xcvc) = self.xcvc(&"read".to_string());
        let read_cmd = ReadCommand::for_tapsigner(self.card_nonce.clone(), epubkey, xcvc);
        let read_response = self.transmit_read(read_cmd);
        match read_response {
            Ok(resp) => {
                self.card_nonce = resp.card_nonce.clone();
                Ok(resp)
            },
            Err(error) => panic!("Failed to read card: {:?}", error),
        }
    }

    pub fn sign(&mut self, digest: Vec<u8>, subpath: Option<[u32; 2]>) -> Result<SignResponse, Error> {
        let (_eseckey, epubkey, xcvc) = self.xcvc(&"sign".to_string());
        let command = SignCommand::for_tapsigner(subpath, digest, epubkey, xcvc);
        let sign_response = self.transmit_sign(command);    
        match sign_response {
            Ok(resp) => {
                self.card_nonce = resp.card_nonce.clone();
                Ok(resp)
            },
            Err(error) => panic!("Failed to read card: {:?}", error),
        }
    }

    pub fn xpub(&mut self, master: bool) -> Result<XpubResponse, Error>  {
        let (_eseckey, epubkey, xcvc) = self.xcvc(&"xpub".to_string());
        let command = XpubCommand::new(master, epubkey, xcvc);
        let xpub_response = self.transmit_xpub(command);    
        match xpub_response {
            Ok(resp) => {
                self.card_nonce = resp.card_nonce.clone();
                Ok(resp)
            },
            Err(error) => panic!("Failed to read card: {:?}", error),
        }
    }

    // TODO - generalize transmit. can be abstracted to trait for each 
    fn transmit_read(&self, cmd: ReadCommand) -> Result<ReadResponse, Error> {
        let read_apdu = cmd.apdu_bytes();
        let rapdu = self.card.transmit(read_apdu)?;
        Ok(ReadResponse::from_cbor(rapdu.to_vec())?)
    }

    // TODO - generalize transmit. can be abstracted to trait for each 
    fn transmit_sign(&self, cmd: SignCommand) -> Result<SignResponse, Error> {
        let req_apdu = cmd.apdu_bytes();
        let resp_apdu = self.card.transmit(req_apdu)?;
        Ok(SignResponse::from_cbor(resp_apdu.to_vec())?)
    }

    fn transmit_xpub(&self, cmd: XpubCommand) -> Result<XpubResponse, Error> {
        let req_apdu = cmd.apdu_bytes();
        let resp_apdu = self.card.transmit(req_apdu)?;
        Ok(XpubResponse::from_cbor(resp_apdu.to_vec())?)
    }

    // -> Requires dynamic dispatch at for return value?
    // fn transmit<T: Serialize, U: Deserialize>(&self, cmd: T) -> Result<U, Error> {
    //     let req_apdu = cmd.apdu_bytes();
    //     let resp_apdu = self.card.transmit(req_apdu)?;
    //     Ok(U::from_cbor(resp_apdu.to_vec())?)
    // }
}

pub struct SatsCard<T: NfcTransmittor> {
    card: T,
    pub pubkey: Option<PublicKey>, 
    pub cvc: Option<String>,
    secp: Secp256k1<All>, // required here?
    pub card_nonce: Vec<u8>
}

impl<T: NfcTransmittor> SatsCard<T> {
    pub fn new(card: T, status: &StatusResponse) -> Self {
        // let rng = &mut rand::thread_rng();
        // let nonce = rand_nonce(rng).to_vec();
        let card_nonce = &status.card_nonce;
        let secp: Secp256k1<All> = Secp256k1::new();
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

    pub fn read(&mut self) -> Result<ReadResponse, Error> {
        // let (_eseckey, epubkey, xcvc) = self.xcvc(&"read".to_string());
        let read_cmd = ReadCommand::for_satscard(self.card_nonce.clone());
        let read_response = self.transmit_read(read_cmd);
        match read_response {
            Ok(resp) => {
                self.card_nonce = resp.card_nonce.clone();
                Ok(resp)
            },
            Err(error) => panic!("Failed to read card: {:?}", error),
        }
    }

    // TODO - generalize transmit. can be abstracted to trait for each 
    fn transmit_read(&self, cmd: ReadCommand) -> Result<ReadResponse, Error> {
        let read_apdu = cmd.apdu_bytes();
        let rapdu = self.card.transmit(read_apdu)?;
        Ok(ReadResponse::from_cbor(rapdu.to_vec())?)
    }
}

pub fn applet_select<T: NfcTransmittor>(card: &T) -> Result<StatusResponse, Error> {
    let applet_select_apdu = AppletSelect::default().apdu_bytes();
    let rapdu = card.transmit(applet_select_apdu)?;
    let status_response = StatusResponse::from_cbor(rapdu.to_vec())?;
    Ok(status_response)
}

// fn status_command(card: &Card) -> Result<StatusResponse, Error> {
//     // Send 'status' command.
//     let status_apdu = StatusCommand::default().apdu_bytes();
//     println!("Sending 'status' APDU: {:?}\n", &status_apdu);
//     let mut rapdu_buf = [0; MAX_BUFFER_SIZE];
//     let rapdu = card.transmit(&status_apdu.as_slice(), &mut rapdu_buf)?;
//     let status_response = StatusResponse::from_cbor(rapdu.to_vec())?;
//     println!("Received 'Status' APDU: {:?}\n", &status_response);
//     Ok(status_response)
// }

// fn certs_command(card: &Card) -> Result<CertsResponse, Error> {
//     // Send 'certs' command.
//     let certs_apdu = CertsCommand::default().apdu_bytes();
//     println!("Sending 'certs' APDU: {:?}\n", &certs_apdu);
//     let mut rapdu_buf = [0; MAX_BUFFER_SIZE];
//     let rapdu = card.transmit(&certs_apdu.as_slice(), &mut rapdu_buf)?;
//     let certs_response = CertsResponse::from_cbor(rapdu.to_vec())?;
//     println!("Received 'Certs' APDU: {:?}\n", &certs_response);
//     println!(
//         "Received 'Certs' cert_chain: {:?}\n",
//         &certs_response.cert_chain()
//     );
//     Ok(certs_response)
// }

// fn check_command(card: &Card, nonce: Vec<u8>) -> Result<CheckResponse, Error> {
//     // Send 'check' command.
//     let check_apdu = CheckCommand::new(nonce).apdu_bytes();
//     println!("Sending 'check' APDU: {:?}\n", &check_apdu);
//     let mut rapdu_buf = [0; MAX_BUFFER_SIZE];
    // let rapdu = card.transmit(&check_apdu.as_slice(), &mut rapdu_buf)?;
//     let check_response = CheckResponse::from_cbor(rapdu.to_vec())?;
//     println!("Received 'Check' APDU: {:?}\n", &check_response);
//     Ok(check_response)
// }

// fn new_command(
//     card: &Card,
//     slot: usize,
//     chain_code: Option<Vec<u8>>,
//     epubkey: Vec<u8>,
//     xcvc: Vec<u8>,
// ) -> Result<NewResponse, Error> {
//     // Send 'new' command.
//     let new_apdu = NewCommand::new(slot, chain_code, epubkey, xcvc).apdu_bytes();
//     println!("Sending 'new' APDU: {:?}\n", &new_apdu);
//     let mut rapdu_buf = [0; MAX_BUFFER_SIZE];
//     let rapdu = card.transmit(&new_apdu.as_slice(), &mut rapdu_buf)?;
//     let new_response = NewResponse::from_cbor(rapdu.to_vec())?;
//     println!("Received 'New' APDU: {:?}\n", &new_response);
//     Ok(new_response)
// }

pub fn wait_command<T: NfcTransmittor>(card: &T, xcvc: Option<Vec<u8>>) -> Result<WaitResponse, Error> {
    // Send 'wait' command.
    let wait_apdu = WaitCommand::new(None, xcvc).apdu_bytes();
    println!("Sending 'Wait' APDU: {:?}\n", &wait_apdu);
    let rapdu = card.transmit(wait_apdu)?;
    let wait_response = WaitResponse::from_cbor(rapdu.to_vec())?;
    println!("Received 'Wait' APDU: {:?}\n", &wait_response);
    Ok(wait_response)
}

// fn dump_command(
//     card: &Card,
//     slot: usize,
//     epubkey: Option<Vec<u8>>,
//     xcvc: Option<Vec<u8>>,
// ) -> Result<DumpResponse, Error> {
//     // Send 'dump' command
//     let dump_apdu = DumpCommand::new(slot, epubkey, xcvc).apdu_bytes();
//     println!("Sending 'dump' APDU: {:?}\n", &dump_apdu);
//     let mut rapdu_buf = [0; MAX_BUFFER_SIZE];
//     let rapdu = card.transmit(&dump_apdu.as_slice(), &mut rapdu_buf)?;
//     let cbor_response: Value = from_reader(rapdu)?;
//     let dump_response = DumpResponse::from_cbor(rapdu.to_vec())?;
//     println!("Received 'dump' APDU: {:?}\n", &dump_response);
//     Ok(dump_response)
// }

