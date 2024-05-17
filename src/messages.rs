use crate::commands;
use crate::commands::BtcCommand;
use crate::hashes;
use crate::util;

use std::net::Ipv6Addr;
use std::str::FromStr;

const MAGIC_BYTES: [u8; 4] = [0xF9, 0xBE, 0xB4, 0xD9];

pub trait ByteMessage {
    fn as_bytes(&self) -> Vec<u8>;
    fn len(&self) -> u32;
}

#[derive(Debug)]
pub struct BtcMessage {
    magic_bytes: [u8; 4],
    pub command: commands::BtcCommand,
    pub payload_size: usize,
    pub checksum: [u8; 4],
    pub payload: Vec<u8>,
}

impl BtcMessage {
    pub fn new(command: commands::BtcCommand, payload: Vec<u8>) -> BtcMessage {
        return BtcMessage {
            magic_bytes: MAGIC_BYTES,
            command: command,
            payload_size: payload.len(),
            checksum: hashes::get_checksum(payload.clone()),
            payload: payload,
        };
    }

    pub fn from_fields(
        command: BtcCommand,
        payload_size: usize,
        checksum: [u8; 4],
        payload: Vec<u8>,
    ) -> BtcMessage {
        BtcMessage {
            magic_bytes: MAGIC_BYTES,
            command: command,
            payload_size: payload_size,
            checksum: checksum,
            payload: payload,
        }
    }
}

impl ByteMessage for BtcMessage {
    fn as_bytes(&self) -> Vec<u8> {
        let command = commands::from_enum(&self.command);
        let converted_payload_size: u32 = u32::try_from(self.payload_size).unwrap();
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&self.magic_bytes);
        bytes.extend_from_slice(&command.0);
        bytes.extend_from_slice(&converted_payload_size.to_le_bytes());
        bytes.extend_from_slice(&self.checksum);
        bytes.extend_from_slice(&self.payload);
        bytes
    }

    fn len(&self) -> u32 {
        self.as_bytes().len().try_into().unwrap()
    }
}

#[derive(Debug)]
pub struct VersionMessagePayload {
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

impl VersionMessagePayload {
    pub fn default() -> VersionMessagePayload {
        VersionMessagePayload {
            protocol_version: 70016,
            services: 0,
            time: util::get_sys_time_in_secs(),
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
        }
    }
}

impl ByteMessage for VersionMessagePayload {
    fn as_bytes(&self) -> Vec<u8> {
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

    fn len(&self) -> u32 {
        self.as_bytes().len().try_into().unwrap()
    }
}
