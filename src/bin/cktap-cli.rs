/// CLI for rust-cktap
use clap::{Parser, Subcommand};
use rust_cktap::{apdu::Error, commands::Certificate, pcsc, CkTapCard};
use std::io;
use std::io::Write;

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
#[command(propagate_version = true)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Check this card was made by Coinkite: Verifies a certificate chain up to root factory key.
    Certs,
    /// Get website URL used for NFC verification, and optionally open it
    Url,
}

fn main() -> Result<(), Error> {
    let cli = Cli::parse();

    match &cli.command {
        Commands::Certs => {
            let card = pcsc::find_first()?;
            fn print_genuine(key: String) {
                println!("Genuine card from Coinkite.\n\nHas cert signed by: {}", key);
            }
            fn print_failure() {
                println!("Card failed to verify. May not be a genuine card");
            }
            match card {
                CkTapCard::TapSigner(mut ts) => match ts.check_certificate() {
                    Ok(key) => print_genuine(key.name()),
                    Err(_e) => print_failure(),
                },
                CkTapCard::SatsChip(_chip) => todo!(),
                CkTapCard::SatsCard(mut sc) => match sc.check_certificate() {
                    Ok(key) => print_genuine(key.name()),
                    Err(_e) => print_failure(),
                },
            }
        }
        Commands::Url => {
            let card = pcsc::find_first()?;
            match card {
                CkTapCard::TapSigner(mut _ts) => todo!(),
                CkTapCard::SatsChip(mut _chip) => todo!(),
                CkTapCard::SatsCard(mut _sc) => todo!(),
            }
        }
    }

    Ok(())
}

fn _get_cvc() -> String {
    print!("Enter cvc: ");
    io::stdout().flush().unwrap();
    let mut cvc: String = String::new();
    let _btye_count = std::io::stdin().read_line(&mut cvc).unwrap();
    cvc.trim().to_string()
}
