use std::{
    collections::VecDeque,
    io::{self, ErrorKind},
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    str::FromStr,
    time::SystemTime,
};

use domain::dep::octseq::OctetsInto;
use sha2::{Digest, Sha256};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::tcp::{ReadHalf, WriteHalf},
};

use crate::node_acquisition::BtcNode;

mod commands;
mod node_acquisition;

#[derive(Debug)]
struct VersionMessagePayload {
    // PAYLOAD
    protocol_version: u32,
    services: u64,
    time: u64,
    remote_services: u64,
    remote_ip: Ipv6Addr,
    remote_port: u16,
    local_services: u64,
    local_ip: Ipv6Addr,
    local_port: u16,
    nonce: u64,
    user_agent: String, // currently no user agent will ever be set
    last_block: u32,
    relay_flag: bool,
}

#[derive(Debug)]
struct VersionMessageHeader {
    // HEADER
    magic_bytes: [u8; 4],
    command: [u8; 12],
    payload_size: [u8; 4],
    checksum: [u8; 4],
}

#[derive(Debug)]
struct VersionMessage {
    header: VersionMessageHeader,
    payload: VersionMessagePayload,
}

#[derive(Debug)]
struct Receiver<'a> {
    rx: ReadHalf<'a>,
}

#[derive(Debug)]
struct Transmitter<'a> {
    tx: WriteHalf<'a>,
}

#[derive(Debug)]
struct BtcMessage {
    command: commands::BtcCommand,
    payload_size: u32,
    checksum: [u8; 4],
    payload: Vec<u8>,
}

impl BtcMessage {
    fn into_bytes(&self) -> Vec<u8> {
        let command = commands::from_enum(&self.command);
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&[0xF9, 0xBE, 0xB4, 0xD9]);
        bytes.extend_from_slice(&command.0);
        bytes.extend_from_slice(&self.payload_size.to_le_bytes());
        bytes.extend_from_slice(&self.checksum);
        bytes.extend_from_slice(&self.payload);
        bytes
    }
}

impl VersionMessage {
    fn new(payload: VersionMessagePayload) -> Self {
        let payload_size = payload.get_size();
        let payload_checksum = payload.get_checksum();
        let header: VersionMessageHeader =
            VersionMessageHeader::new(payload_size, payload_checksum);
        Self { header, payload }
    }

    fn into_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&self.header.into_bytes());
        bytes.extend_from_slice(&self.payload.into_bytes());

        bytes
    }
}

impl VersionMessageHeader {
    fn new(payload_size: u32, payload_checksum: [u8; 4]) -> Self {
        Self {
            magic_bytes: [0xF9, 0xBE, 0xB4, 0xD9],
            command: [
                0x76, 0x65, 0x72, 0x73, 0x69, 0x6F, 0x6E, 0x00, 0x00, 0x00, 0x00, 0x00,
            ],
            payload_size: payload_size.to_le_bytes(),
            checksum: payload_checksum,
        }
    }

    fn into_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&self.magic_bytes);
        bytes.extend_from_slice(&self.command);
        bytes.extend_from_slice(&self.payload_size);
        bytes.extend_from_slice(&self.checksum);

        bytes
    }
}

impl VersionMessagePayload {
    fn into_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();

        bytes.extend_from_slice(&self.protocol_version.to_le_bytes());
        bytes.extend_from_slice(&self.services.to_le_bytes());
        bytes.extend_from_slice(&self.time.to_le_bytes());
        bytes.extend_from_slice(&self.remote_services.to_le_bytes());

        bytes.extend_from_slice(&self.remote_ip.octets());

        bytes.extend_from_slice(&self.remote_port.to_be_bytes());
        bytes.extend_from_slice(&self.local_services.to_le_bytes());

        bytes.extend_from_slice(&self.local_ip.octets());

        bytes.extend_from_slice(&self.local_port.to_be_bytes());
        bytes.extend_from_slice(&self.nonce.to_le_bytes());

        bytes.extend_from_slice(&[0x00]); // user agent workaround

        bytes.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // last block workaround

        bytes.push(self.relay_flag as u8);

        bytes
    }

    fn get_size(&self) -> u32 {
        self.into_bytes().len().try_into().unwrap()
    }

    fn get_checksum(&self) -> [u8; 4] {
        let payload = self.into_bytes();
        print!("Payload: {:X?}", payload);
        let hash1 = Sha256::digest(payload).to_vec();
        print!("Hash1: {:X?}", hash1);
        let hash2 = Sha256::digest(&hash1).to_vec();
        print!("Hash2: {:X?}", hash2);
        let mut result: [u8; 4] = [0x00; 4];

        result.clone_from_slice(&hash2[0..4]);
        print!("Result: {:X?}", result);
        result
    }
}

impl Receiver<'_> {
    async fn read_message(&self) -> Result<BtcMessage, Box<dyn std::error::Error>> {
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
        Ok(BtcMessage {
            command,
            payload_size,
            checksum,
            payload,
        })
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

    async fn read_payload_size(&self) -> Result<u32, Box<dyn std::error::Error>> {
        let mut buf: [u8; 4] = [0; 4];
        match self.rx.try_read(&mut buf) {
            Ok(n) => {
                if n != 4 {
                    return Err("Received not enough bytes to read payload size".into());
                }
                return Ok(u32::from_le_bytes(buf));
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

    async fn read_payload(&self, payload_size: u32) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
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
    async fn send_message(&self, msg_bytes: Vec<u8>) -> Result<(), Box<dyn std::error::Error>> {
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

// from https://stackoverflow.com/questions/69444896/how-to-pad-an-array-with-zeros
fn pad_zeroes<const A: usize, const B: usize>(arr: [u8; A]) -> [u8; B] {
    assert!(B >= A); //just for a nicer error message, adding #[track_caller] to the function may also be desirable
    let mut b = [0; B];
    b[..A].copy_from_slice(&arr);
    b
}

// from https://gist.github.com/jweinst1/0f0f2e9e31e487469e5367d42ad29253
fn get_sys_time_in_secs() -> u64 {
    match SystemTime::now().duration_since(SystemTime::UNIX_EPOCH) {
        Ok(n) => n.as_secs(),
        Err(_) => panic!("SystemTime before UNIX EPOCH!"),
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("Hello, Bitcoin Network!");

    //println!("{:X?}", msg.into_bytes());
    let node_address = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(148, 170, 213, 11)), 8333);
    let node = BtcNode {
        address: node_address,
    };

    let mut stream = node_acquisition::connect_to_node(node).await?;
    let (rx, tx) = stream.split();

    let transmitter = Transmitter { tx };
    let receiver = Receiver { rx };

    let payload: VersionMessagePayload = VersionMessagePayload {
        protocol_version: 70016,
        services: 0,
        time: get_sys_time_in_secs(),
        remote_services: 0,
        remote_ip: Ipv6Addr::from_str("::ffff:7f00:1").unwrap(),
        remote_port: 8333,
        local_services: 0,
        local_ip: Ipv6Addr::from_str("::ffff:7f00:1").unwrap(),
        local_port: 8333,
        nonce: 0,
        user_agent: "test".to_string(),
        last_block: 0,
        relay_flag: false,
    };
    let msg: VersionMessage = VersionMessage::new(payload);

    transmitter.send_message(msg.into_bytes()).await?;

    loop {
        let msg = match receiver.read_message().await {
            Ok(message) => {
                println!("Received Message: {:?}", message);
                message
            }
            Err(err) => {
                println!("Error reading Message: {:?}", err);
                continue;
            }
        };

        if msg.command == commands::BtcCommand::Version {
            break;
        }
    }

    let verack_message: Vec<u8> = vec![
        0xF9, 0xBE, 0xB4, 0xD9, 0x76, 0x65, 0x72, 0x61, 0x63, 0x6B, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x5D, 0xF6, 0xE0, 0xE2,
    ];
    transmitter.send_message(verack_message).await?;
    println!("Sent Verack");

    loop {
        let msg = match receiver.read_message().await {
            Ok(message) => {
                println!("Received Message: {:?}", message);
                message
            }
            Err(err) => {
                println!("Error reading Message: {:?}", err);
                continue;
            }
        };

        if msg.command == commands::BtcCommand::Ping {
            println!("Received Ping");
            let new_msg = BtcMessage {
                command: commands::BtcCommand::Pong,
                payload_size: msg.payload_size,
                checksum: msg.checksum,
                payload: msg.payload,
            };
            transmitter.send_message(new_msg.into_bytes()).await?;
        }
    }

    // node_acquisition::acquire_nodes().await?;
    // node_acquisition::do_dns().await;
    Ok(())
}
