use ciborium::de::from_reader;
use ciborium::value::Value;

use pcsc::*;
use rust_cktap::{ISO_APPLET_SELECT_APDU, StatusResponse};

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

    // Send ISO Applet Select command.
    let apdu = ISO_APPLET_SELECT_APDU;
    println!("Sending 'ISO Applet Select' APDU: {:?}\n", &apdu);
    let mut rapdu_buf = [0; MAX_BUFFER_SIZE];
    let rapdu = match card.transmit(&apdu, &mut rapdu_buf) {
        Ok(rapdu) => rapdu,
        Err(err) => {
            eprintln!("Failed to transmit APDU command to card: {}", err);
            std::process::exit(1);
        }
    };
    println!("APDU response: {:?}\n", &rapdu);
    let rapdu_value: Value = from_reader(&rapdu[..]).unwrap();
    println!("APDU response value: {:?}\n", rapdu_value);
    let rapdu_struct: StatusResponse = rapdu_value.deserialized().unwrap();
    println!("APDU response struct: {:?}\n", rapdu_struct);
}