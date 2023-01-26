extern crate core;

use pcsc::{Context, Protocols, Scope, ShareMode, MAX_BUFFER_SIZE};
use rust_cktap::{
    AppletSelect, CommandApdu, Error, ResponseApdu, StatusCommand, StatusResponse, WaitCommand,
    WaitResponse,
};

fn main() -> Result<(), Error> {
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

    // Send ISO App Select.
    let applet_select_apdu = AppletSelect::default().apdu_bytes();
    println!(
        "Sending 'ISO Applet Select' APDU: {:?}\n",
        &applet_select_apdu
    );
    let mut rapdu_buf = [0; MAX_BUFFER_SIZE];
    let rapdu = card.transmit(&applet_select_apdu.as_slice(), &mut rapdu_buf)?;
    let status_response = StatusResponse::from_cbor(rapdu.to_vec())?;
    println!("Received 'Status' APDU: {:?}\n", status_response);

    // Send 'Status' Command.
    let status_apdu = StatusCommand::default().apdu_bytes();
    println!("Sending 'Status' APDU: {:?}\n", &status_apdu);
    let mut rapdu_buf = [0; MAX_BUFFER_SIZE];
    let rapdu = card.transmit(&status_apdu.as_slice(), &mut rapdu_buf)?;
    let status_response = StatusResponse::from_cbor(rapdu.to_vec())?;
    println!("Received 'Status' APDU: {:?}\n", status_response);

    // Send 'Wait' Command.
    let wait_apdu = WaitCommand::new(None, None).apdu_bytes();
    println!("Sending 'Wait' APDU: {:?}\n", &wait_apdu);
    let mut rapdu_buf = [0; MAX_BUFFER_SIZE];
    let rapdu = card.transmit(&wait_apdu.as_slice(), &mut rapdu_buf)?;
    let wait_response = WaitResponse::from_cbor(rapdu.to_vec())?;
    println!("Received 'Wait' APDU: {:?}\n", wait_response);

    // testing authenticated commands

    use secp256k1::ecdh::SharedSecret;
    use secp256k1::hashes::sha256;
    use secp256k1::rand;
    use secp256k1::{Message, Secp256k1};

    let secp = Secp256k1::new();
    let (eseckey, epubkey) = secp.generate_keypair(&mut rand::thread_rng());
    let message = Message::from_hashed_data::<sha256::Hash>("Hello World!".as_bytes());

    let sig = secp.sign_ecdsa(&message, &eseckey);
    assert!(secp.verify_ecdsa(&message, &sig, &epubkey).is_ok());

    let s = Secp256k1::new();
    let (sk1, pk1) = s.generate_keypair(&mut rand::thread_rng());
    let (sk2, pk2) = s.generate_keypair(&mut rand::thread_rng());
    let sec1 = SharedSecret::new(&pk2, &sk1);
    let sec2 = SharedSecret::new(&pk1, &sk2);
    assert_eq!(sec1, sec2);

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
