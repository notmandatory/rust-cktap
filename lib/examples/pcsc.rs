extern crate core;

use rust_cktap::apdu::Error;
use rust_cktap::commands::{Certificate, Wait};
use rust_cktap::{pcsc, rand_chaincode, CkTapCard};

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
    let card = pcsc::find_first()?;
    dbg!(&card);

    let rng = &mut rand::thread_rng();

    match card {
        CkTapCard::TapSigner(mut ts) => {
            let cvc: String = get_cvc();

            // if auth delay call wait
            while ts.auth_delay.is_some() {
                dbg!(ts.auth_delay.unwrap());
                ts.wait(None)?;
            }

            // only do this once per card!
            if ts.path.is_none() {
                let chain_code = rand_chaincode(rng).to_vec();
                let new_result = ts.init(chain_code, cvc)?;
                dbg!(new_result);
            }

            // let read_result = card.read(cvc.clone())?;
            // dbg!(read_result);

            dbg!(ts.check_certificate().unwrap().name());

            //let dump_result = card.dump();

            // let path = vec![2147483732, 2147483648, 2147483648];
            // let derive_result = card.derive(path, cvc.clone())?;
            // dbg!(&derive_result);

            // let nfc_result = card.nfc()?;
            // dbg!(nfc_result);
        }
        CkTapCard::SatsChip(mut chip) => {
            let _cvc: String = get_cvc();

            // if auth delay call wait
            while chip.auth_delay.is_some() {
                dbg!(chip.auth_delay.unwrap());
                chip.wait(None)?;
            }

            // only do this once per card!
            if chip.path.is_none() {
                let chain_code = rand_chaincode(rng).to_vec();
                let new_result = chip.init(chain_code, get_cvc())?;
                dbg!(new_result);
            }

            // let read_result = card.read(cvc)?;
            // dbg!(read_result);

            // let nfc_result = card.nfc()?;
            // dbg!(nfc_result);
        }
        CkTapCard::SatsCard(mut sc) => {
            // if auth delay call wait
            while sc.auth_delay.is_some() {
                dbg!(sc.auth_delay.unwrap());
                let wait_response = sc.wait(None)?;
                dbg!(wait_response);
            }

            // let read_result = sc.read(None)?;
            // dbg!(read_result);

            // let derive_result = card.derive()?;
            // dbg!(&derive_result);

            dbg!(sc.check_certificate().unwrap().name());

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
