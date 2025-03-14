use crate::apdu::{AppletSelect, CommandApdu, Error, StatusCommand};
use crate::commands::CkTransport;
use crate::CkTapCard;
use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::string::ToString;

pub const CVC: &str = "123456";

pub async fn find_emulator() -> Result<CkTapCard<CardEmulator>, Error> {
    let pipe_path = Path::new("/tmp/ecard-pipe");
    if !pipe_path.exists() {
        return Err(Error::Emulator("Emulator pipe doesn't exist.".to_string()));
    }
    let stream = UnixStream::connect("/tmp/ecard-pipe").expect("unix stream");
    let card_emulator = CardEmulator { stream };
    card_emulator.to_cktap().await
}

#[derive(Debug)]
pub struct CardEmulator {
    stream: UnixStream,
}

impl CkTransport for CardEmulator {
    async fn transmit_apdu(&self, command_apdu: Vec<u8>) -> Result<Vec<u8>, Error> {
        // convert select_apdu into StatusCommand apdu bytes
        let select_apdu: Vec<u8> = AppletSelect::default().apdu_bytes();
        let command_apdu = if command_apdu.eq(&select_apdu) {
            StatusCommand::default().apdu_bytes()
        } else {
            command_apdu
        };

        let mut stream = self.stream.try_clone().expect("clone unix stream");

        // trim first 5 bytes from command apdu bytes to get the cbor data
        stream
            .write_all(&command_apdu.as_slice()[5..])
            .map_err(|e| Error::Emulator(e.to_string()))?;
        let mut buffer = [0; 4096];
        // read up to 4096 bytes
        stream
            .read(&mut buffer[..])
            .map_err(|e| Error::Emulator(e.to_string()))?;
        Ok(buffer.to_vec())
    }
}

#[cfg(test)]
pub mod test {
    use crate::emulator::find_emulator;

    #[tokio::test]
    pub async fn test_transmit() {
        let emulator = find_emulator().await.unwrap();
        dbg!(emulator);
    }
}
