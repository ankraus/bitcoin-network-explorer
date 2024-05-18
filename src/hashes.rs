use sha2::{Digest, Sha256};

pub fn get_checksum(message: Vec<u8>) -> [u8; 4] {
    let payload = message;
    let hash1 = Sha256::digest(payload).to_vec();
    let hash2 = Sha256::digest(&hash1).to_vec();
    let mut result: [u8; 4] = [0x00; 4];

    result.clone_from_slice(&hash2[0..4]);
    result
}
