// Copyright (c) 2025 rust-cktap contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

/// CLI for rust-cktap
use clap::{Parser, Subcommand};
use rpassword::read_password;
use rust_cktap::commands::{Authentication, Read, Wait};
#[cfg(feature = "emulator")]
use rust_cktap::emulator;
use rust_cktap::error::{DumpError, StatusError, UnsealError};
#[cfg(not(feature = "emulator"))]
use rust_cktap::pcsc;
use rust_cktap::tap_signer::TapSignerShared;
use rust_cktap::{
    CkTapCard, CkTapError, Psbt, PsbtParseError, SignPsbtError, commands::Certificate,
    rand_chaincode,
};
use std::io;
use std::io::Write;
#[cfg(feature = "emulator")]
use std::path::Path;
use std::str::FromStr;

/// Errors returned by the card, CBOR deserialization or value encoding, or the APDU transport.
#[derive(Debug, thiserror::Error)]
pub enum CliError {
    #[error(transparent)]
    PsbtParse(#[from] PsbtParseError),
    #[error(transparent)]
    Status(#[from] StatusError),
    #[error(transparent)]
    Unseal(#[from] UnsealError),
    #[error(transparent)]
    SignPsbt(#[from] SignPsbtError),
    #[error(transparent)]
    Dump(#[from] DumpError),
    #[error(transparent)]
    CkTap(#[from] CkTapError),
}

/// SatsCard CLI
#[derive(Parser)]
#[command(author, version = option_env ! ("CARGO_PKG_VERSION").unwrap_or("unknown"), about,
long_about = None, propagate_version = true)]
struct SatsCardCli {
    #[command(subcommand)]
    command: SatsCardCommand,
}

/// Commands supported by SatsCard cards
#[derive(Subcommand)]
enum SatsCardCommand {
    /// Show the card status
    Status,
    /// Show current deposit address
    Address,
    /// Check this card was made by Coinkite: Verifies a certificate chain up to root factory key.
    Certs,
    /// Read the pubkey
    Read,
    /// Pick a new private key and start a fresh slot. Current slot must be unsealed.
    New,
    /// Unseal the current slot.
    Unseal,
    /// Get the payment address and verify it follows from the chain code and master public key
    Derive,
    /// This reveals the details for any slot. The current slot is not affected.
    Dump { slot: u8 },
    /// Sign a PSBT with the current slot (must be unsealed)
    Sign {
        /// Slot to sign with
        slot: u8,
        /// Unsigned PSBT
        psbt: String,
    },
    /// Call wait command until no auth delay
    Wait,
}

/// TapSigner CLI
#[derive(Parser)]
#[command(author, version = option_env ! ("CARGO_PKG_VERSION").unwrap_or("unknown"), about,
long_about = None, propagate_version = true)]
struct TapSignerCli {
    #[command(subcommand)]
    command: TapSignerCommand,
}

/// Commands supported by TapSigner cards
#[derive(Subcommand)]
enum TapSignerCommand {
    /// Show the card status
    Status,
    /// Check this card was made by Coinkite: Verifies a certificate chain up to root factory key.
    Certs,
    /// Read the pubkey (requires CVC)
    Read,
    /// This command is used once to initialize a new card.
    Init,
    /// Derive a public key at the given hardened path
    Derive {
        /// path, eg. for 84'/0'/0'/* use 84,0,0
        #[clap(short, long, value_delimiter = ',', num_args = 1..)]
        path: Option<Vec<u32>>,
    },
    /// Get an encrypted backup of the card's private key
    Backup,
    /// Change the PIN (CVC) used for card authentication to a new user provided one
    Change { new_cvc: String },
    /// Sign a digest
    Sign { to_sign: String },
    /// Call wait command until no auth delay
    Wait,
}

/// TapSigner CLI
#[derive(Parser)]
#[command(author, version = option_env ! ("CARGO_PKG_VERSION").unwrap_or("unknown"), about,
long_about = None, propagate_version = true)]
struct SatsChipCli {
    #[command(subcommand)]
    command: SatsChipCommand,
}

/// Commands supported by SatsChip cards
#[derive(Subcommand)]
enum SatsChipCommand {
    /// Show the card status
    Status,
    /// Check this card was made by Coinkite: Verifies a certificate chain up to root factory key.
    Certs,
    /// Read the pubkey (requires CVC)
    Read,
    /// This command is used once to initialize a new card.
    Init,
    /// Derive a public key at the given hardened path
    Derive {
        /// path, eg. for 84'/0'/0'/* use 84,0,0
        #[clap(short, long, value_delimiter = ',', num_args = 1..)]
        path: Option<Vec<u32>>,
    },
    /// Change the PIN (CVC) used for card authentication to a new user provided one
    Change { new_cvc: String },
    /// Sign a digest
    Sign { to_sign: String },
    /// Call wait command until no auth delay
    Wait,
}

#[tokio::main]
async fn main() -> Result<(), CliError> {
    // figure out what type of card we have before parsing cli args
    #[cfg(not(feature = "emulator"))]
    let mut card = pcsc::find_first().await?;

    // if emulator feature enabled override pcsc card
    #[cfg(feature = "emulator")]
    let mut card = emulator::find_emulator(Path::new("/tmp/ecard-pipe")).await?;

    match &mut card {
        CkTapCard::SatsCard(sc) => {
            let cli = SatsCardCli::parse();
            match cli.command {
                SatsCardCommand::Status => {
                    dbg!(&sc);
                }
                SatsCardCommand::Address => println!("Address: {}", sc.address().await.unwrap()),
                SatsCardCommand::Certs => check_cert(sc).await,
                SatsCardCommand::Read => read(sc, None).await,
                SatsCardCommand::New => {
                    let slot = sc.slot().expect("current slot number");
                    let chain_code = Some(rand_chaincode());
                    let response = &sc.new_slot(slot, chain_code, &cvc()).await?;
                    println!("{response}")
                }
                SatsCardCommand::Unseal => {
                    let slot = sc.slot().expect("current slot number");
                    let (privkey, pubkey) = &sc.unseal(slot, &cvc()).await?;
                    println!("privkey: {}, pubkey: {pubkey}", privkey.to_wif())
                }
                SatsCardCommand::Sign { slot, psbt } => {
                    let psbt = Psbt::from_str(&psbt)?;
                    let signed_psbt = sc.sign_psbt(slot, psbt, &cvc()).await?;
                    println!("signed_psbt: {signed_psbt}");
                }
                SatsCardCommand::Derive => {
                    dbg!(&sc.derive().await);
                }
                SatsCardCommand::Dump { slot } => {
                    let cvc = cvc();
                    let cvc = if cvc.is_empty() { None } else { Some(cvc) };
                    let response = sc.dump(slot, cvc).await?;
                    dbg!(response);
                }
                SatsCardCommand::Wait => wait(sc).await,
            }
        }
        CkTapCard::TapSigner(ts) => {
            let cli = TapSignerCli::parse();
            match cli.command {
                TapSignerCommand::Status => {
                    dbg!(&ts);
                }
                TapSignerCommand::Certs => check_cert(ts).await,
                TapSignerCommand::Read => read(ts, Some(cvc())).await,
                TapSignerCommand::Init => {
                    let chain_code = rand_chaincode();
                    let response = &ts.init(chain_code, &cvc()).await;
                    dbg!(response);
                }
                TapSignerCommand::Derive { path } => {
                    // let test_path:Vec<usize> = ts.path.clone().unwrap().iter().map(|p| p ^ (1 << 31)).collect();
                    // dbg!(test_path);
                    dbg!(&ts.derive(path.unwrap_or_default(), &cvc()).await);
                }

                TapSignerCommand::Backup => {
                    let response = &ts.backup(&cvc()).await;
                    println!("{response:?}");
                }

                TapSignerCommand::Change { new_cvc } => {
                    let response = &ts.change(&new_cvc, &cvc()).await;
                    println!("{response:?}");
                }
                TapSignerCommand::Sign { to_sign } => {
                    let digest: [u8; 32] =
                        rust_cktap::Hash::hash(to_sign.as_bytes()).to_byte_array();

                    let response = &ts.sign(digest, vec![], &cvc()).await;
                    println!("{response:?}");
                }
                TapSignerCommand::Wait => wait(ts).await,
            }
        }
        CkTapCard::SatsChip(sc) => {
            let cli = SatsChipCli::parse();
            match cli.command {
                SatsChipCommand::Status => {
                    dbg!(&sc);
                }
                SatsChipCommand::Certs => check_cert(sc).await,
                SatsChipCommand::Read => read(sc, Some(cvc())).await,
                SatsChipCommand::Init => {
                    let chain_code = rand_chaincode();
                    let response = &sc.init(chain_code, &cvc()).await;
                    dbg!(response);
                }
                SatsChipCommand::Derive { path } => {
                    dbg!(&sc.derive(path.unwrap_or_default(), &cvc()).await);
                }

                SatsChipCommand::Change { new_cvc } => {
                    let response = &sc.change(&new_cvc, &cvc()).await;
                    println!("{response:?}");
                }
                SatsChipCommand::Sign { to_sign } => {
                    let digest: [u8; 32] =
                        rust_cktap::Hash::hash(to_sign.as_bytes()).to_byte_array();

                    let response = &sc.sign(digest, vec![], &cvc()).await;
                    println!("{response:?}");
                }
                SatsChipCommand::Wait => wait(sc).await,
            }
        }
    }

    Ok(())
}

// handler functions for each command

async fn check_cert<C>(card: &mut C)
where
    C: Certificate + Send,
{
    if let Ok(k) = card.check_certificate().await {
        println!(
            "Genuine card from Coinkite.\nHas cert signed by: {}",
            k.name()
        )
    } else {
        println!("Card failed to verify. Not a genuine card")
    }
}

async fn read<C>(card: &mut C, cvc: Option<String>)
where
    C: Read + Send,
{
    match card.read(cvc).await {
        Ok(resp) => println!("{resp}"),
        Err(e) => {
            dbg!(&e);
            println!("Failed to read with error: ")
        }
    }
}

fn cvc() -> String {
    print!("Enter cvc: ");
    io::stdout().flush().unwrap();
    let cvc = read_password().unwrap();
    cvc.trim().to_string()
}

async fn wait<C>(card: &mut C)
where
    C: Authentication + Wait + Send,
{
    // if auth delay call wait
    if card.auth_delay().is_some() {
        while card.auth_delay().is_some() {
            print!(" {}", card.auth_delay().unwrap());
            io::stdout().flush().unwrap();
            card.wait(None).await.expect("wait failed");
        }
        println!();
    }
    println!("No auth delay.");
}
