extern crate core;

use crate::Error;
use crate::{CkTapCard, CkTransport};
use pcsc::{Card, Context, Protocols, Scope, ShareMode, MAX_BUFFER_SIZE};

pub fn find_first() -> Result<CkTapCard<Card>, Error> {
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

    ctx.connect(reader, ShareMode::Shared, Protocols::ANY)?
        .to_cktap()
}

impl CkTransport for Card {
    fn transmit_apdu(&self, apdu: Vec<u8>) -> Result<Vec<u8>, Error> {
        let mut receive_buffer = vec![0; MAX_BUFFER_SIZE];
        let rapdu = self.transmit(apdu.as_slice(), &mut receive_buffer)?;
        Ok(rapdu.to_vec())
    }
}
