use sl_mpc_mate::message::MessageTag;

// Security parameter in bytes
pub const LAMBDA: usize = 16;

// Constants used in GeneratingValidTriples
pub const N: usize = 1 << 20; // 1M
pub const B: usize = 2;
pub const C: usize = 1;
pub const L: usize = 1 << 9;
pub const Z: usize = N / L;
pub const M: usize = (N + C * L) * (B - 1) + N;
pub const X: usize = N / L + C;

pub const FIELD_SIZE: usize = 64;
pub const FIELD_SIZE_BYTES: usize = FIELD_SIZE >> 3;
pub const EC_FIELD_SIZE: usize = 256;
pub const EC_FIELD_SIZE_BYTES: usize = EC_FIELD_SIZE >> 3;
pub const SHA_CHAIN_LEN: usize = 256;
pub const SHA_BLOCK_LEN: usize = 512;
pub const EC_FIELD_LOG: usize = 8;
pub const FIELD_LOG: usize = 6;
pub const FRACTION_LENGTH: usize = 10;

pub const BLOCK_SIZE: usize = 128;
pub const AES_KEY_BYTES: usize = 32;
pub const AES_ROUND_KEYS: usize = 15;

pub const IRREDUCIBLE_POLY: u64 =
    0b000000000000000000000000000000000000000000000000000000000000000011101; // x^64 + x^4 + x^3 + x^2 + 1
pub const P: &str = "7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFED"; // 2^255 - 19 in hex
pub const A24: u64 = 121665;

pub const REC_SIZE_L1: usize = 270;
pub const REC_SIZE_L2: usize = 70;
pub const REC_DECIMAL_SIZE_L2: usize = 12;

pub const DELIM_1: &str = ">";
pub const DELIM_2: &str = "\"";
pub const PAD_CHAR: &str = "~";
pub const DOT_CHAR: &str = ".";

/// P2P CommonRandomness message
pub const COMMON_RAND_MSG: MessageTag = MessageTag::tag(2);

/// B_TO_A_OPEN_MSG
pub const B_TO_A_OPEN_MSG: u32 = 1;

/// MUL_EC_SHARES_MSG
pub const MUL_EC_SHARES_MSG: u32 = 2;

/// OPEN_MSG
pub const OPEN_MSG: u32 = 3;

/// OPEN_TO_MSG
pub const OPEN_TO_MSG: u32 = 4;

/// AND_MSG
pub const AND_MSG: u32 = 5;

/// VERIFY_ARRAY_OF_BITS_MSG
pub const VERIFY_ARRAY_OF_BITS_MSG: u32 = 6;
