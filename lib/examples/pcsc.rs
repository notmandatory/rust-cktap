extern crate core;

use rust_cktap::apdu::Error;
use rust_cktap::commands::{Certificate, Wait};
use rust_cktap::{pcsc, rand_chaincode, CkTapCard};

use bitcoin::secp256k1::rand;
use rust_cktap::tap_signer::TapSignerShared;
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
#[tokio::main]
async fn main() -> Result<(), Error> {
    let card = pcsc::find_first().await?;
    dbg!(&card);

    let rng = &mut rand::thread_rng();

    match card {
        CkTapCard::TapSigner(mut ts) => {
            let cvc: String = get_cvc();

            // if auth delay call wait
            while ts.auth_delay.is_some() {
                dbg!(ts.auth_delay.unwrap());
                ts.wait(None).await?;
            }

            // only do this once per card!
            if ts.path.is_none() {
                let chain_code = rand_chaincode(rng);
                let new_result = ts.init(chain_code, &cvc).await.unwrap();
                dbg!(new_result);
            }

            // let read_result = ts.read(Some(cvc.clone())).await?;
            // dbg!(read_result);

            dbg!(ts.check_certificate().await.unwrap().name());

            //let dump_result = card.dump();

            // let path = vec![2147483732, 2147483648, 2147483648];
            // let derive_result = ts.derive(path, cvc.clone()).await?;
            // dbg!(&derive_result);

            // let nfc_result = card.nfc()?;
            // dbg!(nfc_result);
        }
        CkTapCard::SatsChip(mut chip) => {
            let _cvc: String = get_cvc();

            // if auth delay call wait
            while chip.auth_delay.is_some() {
                dbg!(chip.auth_delay.unwrap());
                chip.wait(None).await?;
            }

            // only do this once per card!
            if chip.path.is_none() {
                let chain_code = rand_chaincode(rng);
                let new_result = chip.init(chain_code, &get_cvc()).await.unwrap();
                dbg!(new_result);
            }

            // let read_result = chip.read(Some(cvc.clone())).await?;
            // dbg!(read_result);

            // let nfc_result = card.nfc()?;
            // dbg!(nfc_result);
        }
        CkTapCard::SatsCard(mut sc) => {
            // if auth delay call wait
            while sc.auth_delay.is_some() {
                dbg!(sc.auth_delay.unwrap());
                let wait_response = sc.wait(None).await?;
                dbg!(wait_response);
            }

            // let read_result = sc.read(None).await?;
            // dbg!(read_result);

            // let derive_result = sc.derive().await?;
            // dbg!(&derive_result);

            dbg!(sc.check_certificate().await.unwrap().name());

            // let nfc_result = card.nfc()?;
            // dbg!(nfc_result);

            // if let Some(slot) = card.slots.first() {
            //     if slot == &0 {
            //         // TODO must unseal first
            //         let chain_code = rand_chaincode(rng).to_vec();
            //         let new_result = sc.new_slot(0, chain_code, get_cvc()).await?;
            //     }
            // }

            // let certs_result = card.certs()?;
            // dbg!(certs_result);

            // let unseal_result = sc.unseal(0, get_cvc()).await?;
            // dbg!(unseal_result);

            // let dump_result = sc.dump(0, None).await?;
            // dbg!(dump_result);

            // let dump_result = sc.dump(0, Some(get_cvc())).await?;
            // dbg!(dump_result);
        }
    }

    Ok(())
}
