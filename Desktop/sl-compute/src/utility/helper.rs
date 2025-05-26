use crypto_bigint::Encoding;
use crypto_bigint::U256;
use crypto_bigint::U512;
use hex::decode;
use rand::thread_rng;
use std::ops::Index;

use crate::constants::P;

pub trait ExtractBit: Index<usize, Output = u8> {
    fn extract_bit(&self, idx: usize) -> bool {
        let byte_idx = idx >> 3;
        let bit_idx = idx & 0x7;
        let byte = self[byte_idx];

        ((byte >> bit_idx) & 1) != 0
    }
}

impl ExtractBit for Vec<u8> {}
impl<const T: usize> ExtractBit for [u8; T] {}

pub fn convert_str_to_u256(s: &str) -> U256 {
    let p_bytes = decode(s).expect("Invalid hex string");
    let mut p_bytes_padded = [0u8; 32];
    p_bytes_padded[32 - p_bytes.len()..].copy_from_slice(&p_bytes);
    U256::from_be_bytes(p_bytes_padded)
}

pub fn get_modulus() -> U256 {
    let p_bytes = decode(P).expect("Invalid hex string");
    let mut p_bytes_padded = [0u8; 32];
    p_bytes_padded[32 - p_bytes.len()..].copy_from_slice(&p_bytes);
    U256::from_be_bytes(p_bytes_padded)
}

pub fn get_modulus_u512() -> U512 {
    let p_bytes = decode(P).expect("Invalid hex string");
    let mut p_bytes_padded = [0u8; 64]; // 64 bytes for U512
    p_bytes_padded[64 - p_bytes.len()..].copy_from_slice(&p_bytes);
    U512::from_be_bytes(p_bytes_padded)
}

pub fn random_permutation(n: usize) -> Vec<usize> {
    let _rng = thread_rng();
    let vec: Vec<usize> = (0..=n - 1).collect();
    // TODO temporary fix
    // vec.shuffle(&mut rng);
    vec
}
