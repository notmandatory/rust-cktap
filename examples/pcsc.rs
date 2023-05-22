extern crate core;

use rust_cktap::commands::Error;
use rust_cktap::rand_nonce;
use rust_cktap::{pcsc::PcscTransport, rand_chaincode, CkTapCard, SharedCommands, Transport};
use secp256k1::rand;
use std::io;
use std::io::Write;

fn get_cvc() -> String {
    print!("Enter cvc: ");
    io::stdout().flush().unwrap();
    let mut cvc: String = String::new();
    let _btye_count = std::io::stdin().read_line(&mut cvc).unwrap();
    cvc.trim().to_string()
}

// Example using pcsc crate
fn main() -> Result<(), Error> {
    let card = PcscTransport::find_first()?;
    dbg!(&card);

    let rng = &mut rand::thread_rng();

    match card {
        CkTapCard::TapSigner(mut card) => {
            let cvc: String = get_cvc();

            // if auth delay call wait
            while card.auth_delay.is_some() {
                dbg!(card.auth_delay.unwrap());
                card.wait(None)?;
            }

            // only do this once per card!
            if card.path.is_none() {
                let chain_code = rand_chaincode(rng).to_vec();
                let new_result = card.init(chain_code, cvc.clone())?;
                dbg!(new_result);
            }

            let nonce = rand_nonce(rng);
            dbg!(card.certs_check(nonce.to_vec()));

            //let dump_result = card.dump();

            // let read_result = card.read(cvc.clone())?;
            // dbg!(read_result);

            // let path = vec![2147483732, 2147483648, 2147483648];
            // let derive_result = card.derive(path, cvc.clone())?;
            // dbg!(&derive_result);

            // let nfc_result = card.nfc()?;
            // dbg!(nfc_result);
        }
        CkTapCard::SatsChip(mut card) => {
            let cvc: String = get_cvc();

            // if auth delay call wait
            while card.auth_delay.is_some() {
                dbg!(card.auth_delay.unwrap());
                card.wait(None)?;
            }

            // only do this once per card!
            if card.path.is_none() {
                let chain_code = rand_chaincode(rng).to_vec();
                let new_result = card.init(chain_code, get_cvc())?;
                dbg!(new_result);
            }

            let read_result = card.read(cvc.clone())?;
            dbg!(read_result);

            let nfc_result = card.nfc()?;
            dbg!(nfc_result);
        }
        CkTapCard::SatsCard(mut card) => {
            // if auth delay call wait
            while card.auth_delay.is_some() {
                dbg!(card.auth_delay.unwrap());
                let wait_response = card.wait(None)?;
                dbg!(wait_response);
            }

            // let read_result = card.read()?;
            // dbg!(read_result);

            // let derive_result = card.derive()?;
            // dbg!(&derive_result);

            let nonce = rand_nonce(rng);
            dbg!(card.certs_check(nonce.to_vec()));

            // let nfc_result = card.nfc()?;
            // dbg!(nfc_result);

            // if let Some(slot) = card.slots.first() {
            //     if slot == &0 {
            //         // TODO must unseal first
            //         let chain_code = rand_chaincode(rng).to_vec();
            //         let new_result = card.new_slot(0, chain_code, get_cvc())?;
            //     }
            // }

            // let certs_result = card.certs()?;
            // dbg!(certs_result);

            // let unseal_result = card.unseal(0, get_cvc())?;
            // dbg!(unseal_result);

            // let dump_result = card.dump(0, None)?;
            // dbg!(dump_result);

            // let dump_result = card.dump(0, Some(get_cvc()))?;
            // dbg!(dump_result);
        }
    }

    Ok(())
}
