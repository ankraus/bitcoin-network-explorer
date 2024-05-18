extern crate num_bigint;
extern crate num_traits;

use num_bigint::BigUint;
use num_traits::FromPrimitive;
use num_traits::ToPrimitive;
use std::fmt;
use std::time::SystemTime;

#[derive(Debug)]
pub struct VarInt {
    pub value: u64,
    pub offset: usize,
}

impl VarInt {
    pub fn new(value: u64) -> VarInt {
        VarInt {
            value: value,
            offset: Self::calculate_offset(value),
        }
    }

    pub fn from_usize(value: usize) -> VarInt {
        let v = u64::try_from(value).unwrap();
        Self::new(v)
    }

    pub fn as_usize(&self) -> usize {
        usize::try_from(self.value).unwrap()
    }

    pub fn as_bytes(&self) -> Vec<u8> {
        let bytes = self.value.to_le_bytes();
        let mut array = [0u8; 9];
        match self.value {
            v if v > 0xFFFFFFFF => {
                array[0] = 0xFF;
                array.copy_from_slice(&bytes[1..=8]);
            }
            v if v > 0xFFFF => {
                array[0] = 0xFE;
                array.copy_from_slice(&bytes[1..=4]);
            }
            v if v >= 0xFD => {
                array[0] = 0xFD;
                array.copy_from_slice(&bytes[1..=2]);
            }
            _ => {
                array[0] = bytes[0];
            }
        }
        let mut vec = array.to_vec();
        vec.resize(self.offset, 0u8);
        vec
    }
    pub fn from_bytes(mut bytes: Vec<u8>) -> VarInt {
        let mut array = [0u8; 8];
        let mut offset: usize = 1;
        bytes.resize(9, 0u8);
        let extracted_bytes = match bytes[0] {
            0xFF => {
                array.copy_from_slice(&bytes[1..=8]);
                offset = 9;
                array
            }
            0xFE => {
                array[..4].copy_from_slice(&bytes[1..=4]);
                offset = 5;
                array
            }
            0xFD => {
                array[..2].copy_from_slice(&bytes[1..=2]);
                offset = 3;
                array
            }
            _ => {
                array[0] = bytes[0];
                array
            }
        };
        VarInt {
            value: u64::from_le_bytes(extracted_bytes),
            offset: offset,
        }
    }

    fn calculate_offset(value: u64) -> usize {
        match value {
            v if v > 0xFFFFFFFF => 9,
            v if v > 0xFFFF => 5,
            v if v >= 0xFD => 3,
            _ => 1,
        }
    }
}

impl fmt::Display for VarInt {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.value)
    }
}

pub fn byte_array_from_vec<const L: usize>(bytes: Vec<u8>) -> [u8; L] {
    assert!(bytes.len() >= L);
    let mut array = [0x0; L];
    array.copy_from_slice(bytes.as_slice());
    array
}

pub fn take_byte_array<const L: usize>(byte_iterator: impl Iterator<Item = u8>) -> [u8; L] {
    byte_array_from_vec(byte_iterator.take(L).collect())
}

pub fn bits_to_difficulty(bits: u32) -> f64 {
    // Extract exponent and coefficient
    let exponent = (bits >> 24) as u32;
    let coefficient = bits & 0x00ffffff;

    // Calculate the current target
    let target =
        BigUint::from_u32(coefficient).unwrap() * BigUint::from_u32(256).unwrap().pow(exponent - 3);

    // Difficulty 1
    let difficulty_1_target = BigUint::parse_bytes(
        b"00000000FFFF0000000000000000000000000000000000000000000000000000",
        16,
    )
    .unwrap();

    let difficulty = difficulty_1_target.to_f64().unwrap() / target.to_f64().unwrap();

    difficulty
}

pub fn format_hex(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|b| format!("{:02x}", b))
        .collect::<Vec<String>>()
        .join("")
}

pub fn format_value(value: i64) -> String {
    format!("{:.8} BTC", (value as f64) / 100000000.0)
}

// from https://gist.github.com/jweinst1/0f0f2e9e31e487469e5367d42ad29253
pub fn get_sys_time_in_secs() -> u64 {
    match SystemTime::now().duration_since(SystemTime::UNIX_EPOCH) {
        Ok(n) => n.as_secs(),
        Err(_) => panic!("SystemTime before UNIX EPOCH!"),
    }
}
