use std::collections::VecDeque;
use std::io::ErrorKind;

use crate::commands;
use crate::messages::BtcMessage;
use tokio::net::tcp::{ReadHalf, WriteHalf};

#[derive(Debug)]
pub(crate) struct Receiver<'a> {
    rx: ReadHalf<'a>,
}

#[derive(Debug)]
pub(crate) struct Transmitter<'a> {
    tx: WriteHalf<'a>,
}

impl Receiver<'_> {
    pub fn new(rx: ReadHalf) -> Receiver {
        Receiver { rx }
    }

    pub async fn read_message(&self) -> Result<BtcMessage, Box<dyn std::error::Error>> {
        self.rx.readable().await?;
        println!("Waiting for message");
        self.seek_magic_number().await?;
        println!("Found magic number");
        let command = self.read_command().await?;
        println!("Read command: {:?}", command);
        let payload_size = self.read_payload_size().await?;
        println!("Read payload size: {:?}", payload_size);
        let checksum = self.read_checksum().await?;
        println!("Read checksum: {:?}", checksum);
        let payload = self.read_payload(payload_size).await?;
        println!("Read payload: {:?}", payload);
        Ok(BtcMessage::from_fields(
            command,
            payload_size,
            checksum,
            payload,
        ))
    }

    async fn seek_magic_number(&self) -> Result<(), Box<dyn std::error::Error>> {
        let mut last_four_bytes: VecDeque<u8> = VecDeque::new();
        loop {
            self.rx.readable().await?;
            let mut buf: [u8; 1] = [0; 1];
            match self.rx.try_read(&mut buf) {
                Ok(n) => {
                    if last_four_bytes.len() == 4 {
                        last_four_bytes.pop_front();
                    }
                    last_four_bytes.push_back(buf[0]);
                    if buf != [0x0] {
                        println!("{:?}", last_four_bytes);
                    }
                }
                Err(ref e) if e.kind() == ErrorKind::WouldBlock => {
                    continue;
                }
                Err(e) => {
                    return Err(e.into());
                }
            }
            if last_four_bytes == [0xF9, 0xBE, 0xB4, 0xD9] {
                return Ok(());
            }
        }
    }

    async fn read_command(&self) -> Result<commands::BtcCommand, Box<dyn std::error::Error>> {
        let mut buf: [u8; 12] = [0; 12];
        match self.rx.try_read(&mut buf) {
            Ok(n) => {
                if n != 12 {
                    return Err("Received not enough bytes to read command".into());
                }
                return commands::from_bytes(buf);
            }
            Err(e) => {
                println!("Error: {}", e);
                return Err(e.into());
            }
        }
    }

    async fn read_payload_size(&self) -> Result<usize, Box<dyn std::error::Error>> {
        let mut buf: [u8; 4] = [0; 4];
        match self.rx.try_read(&mut buf) {
            Ok(n) => {
                if n != 4 {
                    return Err("Received not enough bytes to read payload size".into());
                }
                let size = u32::from_le_bytes(buf);
                if let Ok(s) = usize::try_from(size) {
                    return Ok(s);
                } else {
                    return Err("Could not convert payload size to usize".into());
                }
            }
            Err(e) => {
                println!("Error: {}", e);
                return Err(e.into());
            }
        }
    }

    async fn read_checksum(&self) -> Result<[u8; 4], Box<dyn std::error::Error>> {
        let mut buf: [u8; 4] = [0; 4];
        match self.rx.try_read(&mut buf) {
            Ok(n) => {
                if n != 4 {
                    return Err("Received not enough bytes to read payload size".into());
                }
                return Ok(buf);
            }
            Err(e) => {
                println!("Error: {}", e);
                return Err(e.into());
            }
        }
    }

    async fn read_payload(
        &self,
        payload_size: usize,
    ) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        let payload_size_usize: usize =
            usize::try_from(payload_size).expect("Could not convert payload size to usize");
        let mut buf = vec![0u8; payload_size_usize];
        match self.rx.try_read(&mut buf) {
            Ok(n) => {
                if n != payload_size_usize {
                    return Err(format!(
                        "Received fewer bytes than expected in payload. Expected {}, got {}",
                        payload_size_usize, n
                    )
                    .into());
                }
                return Ok(buf);
            }
            Err(e) => {
                println!("Error: {}", e);
                return Err(e.into());
            }
        }
    }
}

impl Transmitter<'_> {
    pub fn new(tx: WriteHalf) -> Transmitter {
        Transmitter { tx }
    }

    pub async fn send_message(&self, msg_bytes: Vec<u8>) -> Result<(), Box<dyn std::error::Error>> {
        loop {
            self.tx.writable().await?;
            match self.tx.try_write(&msg_bytes) {
                Ok(_n) => {
                    println!("{} bytes written to stream", _n);
                    return Ok(());
                }
                Err(ref e) if e.kind() == ErrorKind::WouldBlock => {
                    continue;
                }
                Err(e) => {
                    return Err(e.into());
                }
            }
        }
    }
}
