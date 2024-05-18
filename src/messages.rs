use crate::commands;
use crate::commands::BtcCommand;
use crate::hashes;
use crate::hashes::get_checksum;
use crate::util::{self, bits_to_difficulty, byte_array_from_vec, take_byte_array, VarInt};

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

#[derive(Debug)]
pub struct InvMessagePayload {
    pub count: VarInt,
    pub inv_vectors: Vec<InventoryVector>,
}

#[derive(Debug)]
pub struct InventoryVector {
    pub entry_type: u32,
    pub hash: [u8; 32],
}

#[derive(Debug)]
pub struct BlockMessagePayload {
    pub version: i32,
    pub prev_block: [u8; 32],
    pub merkle_root: [u8; 32],
    pub timestamp: u32,
    pub difficulty: f64,
    pub nonce: u32,
    pub txn_count: VarInt,
    pub txns: Vec<TXMessage>,
}

#[derive(Debug)]
pub struct TXMessage {
    pub version: u32,
    pub witness_flag: bool,
    pub tx_in_count: VarInt,
    pub tx_in: Vec<TXIn>,
    pub tx_out_count: VarInt,
    pub tx_out: Vec<TXOut>,
    pub tx_witness: Option<Vec<TXWitness>>,
    pub locktime: u32,
}

#[derive(Debug)]
pub struct TXIn {
    pub prev_output: OutPoint,
    pub script_length: VarInt,
    pub script: Vec<u8>,
    pub sequence: u32,
}

#[derive(Debug)]
pub struct OutPoint {
    pub hash: [u8; 32],
    pub index: u32,
}

#[derive(Debug)]
pub struct TXOut {
    pub value: i64,
    pub pk_script_length: VarInt,
    pub pk_script: Vec<u8>,
}

#[derive(Debug)]
pub struct TXWitness {
    pub count: VarInt,
    pub data: Vec<WitnessData>,
}

#[derive(Debug)]
pub struct WitnessData {
    pub length: VarInt,
    pub data: Vec<u8>,
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

    pub fn is_valid(&self) -> bool {
        let calculated_checksum = get_checksum(self.payload.clone());
        let received_checksum = self.checksum;
        calculated_checksum == received_checksum
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
            relay_flag: true,
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

impl InvMessagePayload {
    pub fn from_bytes(bytes: Vec<u8>) -> Result<InvMessagePayload, Box<dyn std::error::Error>> {
        let count = VarInt::from_bytes(bytes.clone());
        let mut inv_vectors: Vec<InventoryVector> = Vec::new();
        for n in 0..count.value {
            let x = n as usize;
            let start = (x * 36) + count.offset;
            let mut object_type_bytes = [0u8; 4];
            object_type_bytes.copy_from_slice(&bytes[start..start + 4]);

            let mut hash_bytes = [0u8; 32];
            hash_bytes.copy_from_slice(&bytes[start + 4..start + 36]);
            let inv_vector = InventoryVector {
                entry_type: u32::from_le_bytes(object_type_bytes),
                hash: hash_bytes,
            };
            inv_vectors.push(inv_vector);
        }
        Ok(InvMessagePayload {
            count: count,
            inv_vectors,
        })
    }

    pub fn as_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        let count = self.count.as_bytes();
        bytes.extend_from_slice(&count);
        for v in &self.inv_vectors {
            bytes.extend_from_slice(&v.as_bytes());
        }
        bytes
    }
}

impl InventoryVector {
    pub fn as_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&self.entry_type.to_le_bytes());
        bytes.extend_from_slice(&self.hash);
        bytes
    }
}

impl BlockMessagePayload {
    pub fn from_bytes(bytes: Vec<u8>) -> Result<BlockMessagePayload, Box<dyn std::error::Error>> {
        if bytes.len() < 81 {
            return Err("Could not parse block message".into());
        }

        let mut bytes_iter = bytes.iter().cloned();

        let version_bytes = take_byte_array(bytes_iter.by_ref());
        let prev_block_bytes = take_byte_array(bytes_iter.by_ref());
        let merkle_root_bytes = take_byte_array(bytes_iter.by_ref());
        let timestamp_bytes = take_byte_array(bytes_iter.by_ref());
        let difficulty_bytes = take_byte_array(bytes_iter.by_ref());
        let nonce_bytes = take_byte_array(bytes_iter.by_ref());
        let txn_count = VarInt::from_bytes(bytes.iter().cloned().skip(80).collect());

        Ok(BlockMessagePayload {
            version: i32::from_le_bytes(version_bytes),
            prev_block: prev_block_bytes,
            merkle_root: merkle_root_bytes,
            timestamp: u32::from_le_bytes(timestamp_bytes),
            difficulty: bits_to_difficulty(u32::from_le_bytes(difficulty_bytes)),
            nonce: u32::from_le_bytes(nonce_bytes),
            txn_count,
            txns: Vec::new(),
        })
    }
}

// impl TXIn {
//     pub fn from_bytes(bytes: Vec<u8>) -> TXIn {}
// }

// impl OutPoint {
//     pub fn from_bytes(bytes: Vec<u8>) -> OutPoint {}
// }

// impl TXOut {
//     pub fn from_bytes(bytes: Vec<u8>) -> TXOut {}
// }

// impl TXWitness {
//     pub fn from_bytes(bytes: Vec<u8>) -> TXWitness {}
// }

// impl WitnessData {
//     pub fn from_bytes(bytes: Vec<u8>) -> WitnessData {}
// }
