extern crate core;

use pcsc::{Context, Error, MAX_BUFFER_SIZE, Protocols, Scope, ShareMode};
use rust_cktap::{AppletSelect, CommandApdu, ResponseApdu, StatusCommand, StatusResponse};

fn main() {
    // Establish a PC/SC context.
    let ctx = match Context::establish(Scope::User) {
        Ok(ctx) => ctx,
        Err(err) => {
            eprintln!("Failed to establish context: {}", err);
            std::process::exit(1);
        }
    };

    // List available readers.
    let mut readers_buf = [0; 2048];
    let mut readers = match ctx.list_readers(&mut readers_buf) {
        Ok(readers) => readers,
        Err(err) => {
            eprintln!("Failed to list readers: {}", err);
            std::process::exit(1);
        }
    };

    // Use the first reader.
    let reader = match readers.next() {
        Some(reader) => reader,
        None => {
            println!("No readers are connected.");
            return;
        }
    };
    println!("Using reader: {:?}\n", reader);

    // Connect to the card.
    let card = match ctx.connect(reader, ShareMode::Shared, Protocols::ANY) {
        Ok(card) => card,
        Err(Error::NoSmartcard) => {
            println!("A smartcard is not present in the reader.");
            return;
        }
        Err(err) => {
            eprintln!("Failed to connect to card: {}", err);
            std::process::exit(1);
        }
    };

    // Send ISO App Select.
    let applet_select_apdu = AppletSelect::default().apdu_bytes();
    println!("Sending 'ISO Applet Select' APDU: {:?}\n", &applet_select_apdu);
    let mut rapdu_buf = [0; MAX_BUFFER_SIZE];
    let rapdu = match card.transmit(&applet_select_apdu.as_slice(), &mut rapdu_buf) {
        Ok(rapdu) => rapdu,
        Err(err) => {
            eprintln!("Failed to transmit APDU command to card: {}", err);
            std::process::exit(1);
        }
    };
    let status_response = StatusResponse::from_cbor(rapdu.to_vec());
    println!("Received 'Status' APDU: {:?}\n", status_response);

    // Send 'Status' Request.
    let status_apdu = StatusCommand::default().apdu_bytes();
    println!("Sending 'Status' APDU: {:?}\n", &status_apdu);
    let mut rapdu_buf = [0; MAX_BUFFER_SIZE];
    let rapdu = match card.transmit(&status_apdu.as_slice(), &mut rapdu_buf) {
        Ok(rapdu) => rapdu,
        Err(err) => {
            eprintln!("Failed to transmit APDU command to card: {}", err);
            std::process::exit(1);
        }
    };

    let status_response = StatusResponse::from_cbor(rapdu.to_vec());
    println!("Received 'Status' APDU: {:?}\n", status_response);
}
