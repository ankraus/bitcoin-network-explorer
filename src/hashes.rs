use sha2::{Digest, Sha256};

pub fn get_checksum(message: Vec<u8>) -> [u8; 4] {
    let hash = get_double_sha256(message);
    let mut result: [u8; 4] = [0u8; 4];
    result.clone_from_slice(&hash[0..4]);
    result
}

pub fn get_double_sha256(message: Vec<u8>) -> [u8; 32] {
    let mut result: [u8; 32] = [0u8; 32];
    let payload = message;
    let hash1 = Sha256::digest(payload).to_vec();
    let hash2 = Sha256::digest(&hash1).to_vec();
    result.clone_from_slice(&hash2[0..32]);
    result
}
