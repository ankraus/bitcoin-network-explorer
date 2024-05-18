use crate::commands;
use crate::commands::BtcCommand;
use crate::hashes::get_checksum;
use crate::hashes::{self, get_double_sha256};
use crate::util::{self, bits_to_difficulty, byte_array_from_vec, take_byte_array, VarInt};

use std::mem;
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
    _user_agent: String, // currently no user agent will ever be set
    _last_block: u32,
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
    pub expected_hash: [u8; 32],
    pub version: i32,
    pub prev_block: [u8; 32],
    pub merkle_root: [u8; 32],
    pub timestamp: u32,
    pub difficulty_bits: u32,
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
            _user_agent: "test".to_string(),
            _last_block: 0,
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
    pub fn from_bytes(
        bytes: Vec<u8>,
        expected_hash: Option<[u8; 32]>,
    ) -> Result<BlockMessagePayload, Box<dyn std::error::Error>> {
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

        let tx_bytes: Vec<u8> = bytes.iter().cloned().skip(80 + txn_count.offset).collect();

        let mut tx_offset: usize = 0;
        let mut txns: Vec<TXMessage> = Vec::new();
        for _ in 0..txn_count.as_usize() {
            let (tx, size) = TXMessage::from_bytes(tx_bytes[tx_offset..].to_vec());
            txns.push(tx);
            tx_offset += size;
        }

        Ok(BlockMessagePayload {
            expected_hash: match expected_hash {
                Some(hash) => hash,
                None => [0u8; 32],
            },
            version: i32::from_le_bytes(version_bytes),
            prev_block: prev_block_bytes,
            merkle_root: merkle_root_bytes,
            timestamp: u32::from_le_bytes(timestamp_bytes),
            difficulty_bits: u32::from_le_bytes(difficulty_bytes),
            difficulty: bits_to_difficulty(u32::from_le_bytes(difficulty_bytes)),
            nonce: u32::from_le_bytes(nonce_bytes),
            txn_count,
            txns: txns,
        })
    }

    pub fn calculate_hash(&self) -> [u8; 32] {
        let mut bytes: Vec<u8> = Vec::new();
        bytes.extend_from_slice(&self.version.to_le_bytes());
        bytes.extend_from_slice(&self.prev_block);
        bytes.extend_from_slice(&self.merkle_root);
        bytes.extend_from_slice(&self.timestamp.to_le_bytes());
        bytes.extend_from_slice(&self.difficulty_bits.to_le_bytes());
        bytes.extend_from_slice(&self.nonce.to_le_bytes());

        get_double_sha256(bytes)
    }
}

impl TXMessage {
    pub fn from_bytes(bytes: Vec<u8>) -> (TXMessage, usize) {
        let mut offset: usize = 0;
        let version: u32 = u32::from_le_bytes(byte_array_from_vec(
            bytes.clone()[offset..offset + 4].to_vec(),
        ));
        offset += mem::size_of::<u32>();

        let mut witness_flag = false;
        if bytes[offset] == 0u8 {
            witness_flag = true;
            offset += 2;
        }
        let tx_in_count: VarInt = VarInt::from_bytes(bytes[offset..].to_vec());
        offset += tx_in_count.offset;

        let mut tx_in: Vec<TXIn> = Vec::new();
        for _ in 0..tx_in_count.as_usize() {
            let (new_tx_in, size) = TXIn::from_bytes(bytes[offset..].to_vec());
            tx_in.push(new_tx_in);
            offset += size;
        }

        let tx_out_count: VarInt = VarInt::from_bytes(bytes[offset..].to_vec());
        offset += tx_out_count.offset;
        let mut tx_out: Vec<TXOut> = Vec::new();
        for _ in 0..tx_out_count.as_usize() {
            let (new_tx_out, size) = TXOut::from_bytes(bytes[offset..].to_vec());
            tx_out.push(new_tx_out);
            offset += size;
        }

        let mut tx_witness: Option<Vec<TXWitness>> = None;
        if witness_flag {
            let mut witnesses: Vec<TXWitness> = Vec::new();
            for _ in 0..tx_in_count.as_usize() {
                let (witness, size) = TXWitness::from_bytes(bytes[offset..].to_vec());
                offset += size;
                witnesses.push(witness);
            }
            tx_witness = Some(witnesses);
        }
        let locktime: u32 =
            u32::from_le_bytes(byte_array_from_vec(bytes[offset..offset + 4].to_vec()));
        offset += mem::size_of::<u32>();
        (
            TXMessage {
                version,
                witness_flag,
                tx_in_count,
                tx_in,
                tx_out_count,
                tx_out,
                tx_witness,
                locktime,
            },
            offset,
        )
    }

    pub fn get_total_value(&self) -> i64 {
        self.tx_out.iter().map(|tx_out| tx_out.value).sum::<i64>()
    }
}

impl TXIn {
    pub fn from_bytes(bytes: Vec<u8>) -> (TXIn, usize) {
        let mut offset: usize = 0;
        let (prev_output, size) = OutPoint::from_bytes(bytes.clone());
        offset += size;

        let script_length: VarInt = VarInt::from_bytes(bytes[offset..].to_vec());
        offset += script_length.offset;

        let script: Vec<u8> = bytes[offset..offset + script_length.as_usize()].to_vec();
        offset += script_length.as_usize();

        let sequence: u32 =
            u32::from_le_bytes(byte_array_from_vec(bytes[offset..offset + 4].to_vec()));
        offset += mem::size_of::<u32>();

        (
            TXIn {
                prev_output,
                script_length,
                script,
                sequence,
            },
            offset,
        )
    }
}

impl OutPoint {
    pub fn from_bytes(bytes: Vec<u8>) -> (OutPoint, usize) {
        let mut offset: usize = 0;
        let hash: [u8; 32] = byte_array_from_vec(bytes[offset..offset + 32].to_vec());
        offset += mem::size_of::<[u8; 32]>();

        let index: u32 =
            u32::from_le_bytes(byte_array_from_vec(bytes[offset..offset + 4].to_vec()));
        offset += mem::size_of::<u32>();

        (OutPoint { hash, index }, offset)
    }
}

impl TXOut {
    pub fn from_bytes(bytes: Vec<u8>) -> (TXOut, usize) {
        let mut offset: usize = 0;
        let value: i64 =
            i64::from_le_bytes(byte_array_from_vec(bytes[offset..offset + 8].to_vec()));
        offset += mem::size_of::<i64>();

        let pk_script_length: VarInt = VarInt::from_bytes(bytes[offset..].to_vec());
        offset += pk_script_length.offset;

        let pk_script: Vec<u8> = bytes[offset..offset + pk_script_length.as_usize()].to_vec();
        offset += pk_script_length.as_usize();

        (
            TXOut {
                value,
                pk_script_length,
                pk_script,
            },
            offset,
        )
    }
}

impl TXWitness {
    pub fn from_bytes(bytes: Vec<u8>) -> (TXWitness, usize) {
        let mut offset: usize = 0;
        let count = VarInt::from_bytes(bytes[offset..].to_vec());
        offset += count.offset;

        let mut data: Vec<WitnessData> = Vec::new();
        for _ in 0..count.as_usize() {
            let (witness_data, size) = WitnessData::from_bytes(bytes[offset..].to_vec());
            data.push(witness_data);
            offset += size;
        }

        (TXWitness { count, data }, offset)
    }
}

impl WitnessData {
    pub fn from_bytes(bytes: Vec<u8>) -> (WitnessData, usize) {
        let mut offset: usize = 0;
        let length: VarInt = VarInt::from_bytes(bytes[offset..].to_vec());
        offset += length.offset;

        let data: Vec<u8> = bytes[offset..offset + length.as_usize()].to_vec();

        (WitnessData { length, data }, offset)
    }
}
