use curve25519_dalek::edwards::CompressedEdwardsY;
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::EdwardsPoint;

/// POINT_BYTES_SIZE for RistrettoPoint representation
pub const POINT_BYTES_SIZE: usize = 32;

/// External RistrettoPoint representation
pub type PointBytes = [u8; POINT_BYTES_SIZE];

/// External Scalar representation
pub type ScalarBytes = [u8; 32];

/// Encode RistrettoPoint
pub fn encode_point(p: &EdwardsPoint) -> PointBytes {
    p.compress().to_bytes()
}

/// Decode RistrettoPoint
pub fn decode_point(bytes: &PointBytes) -> Option<EdwardsPoint> {
    let Ok(compressed_point) = CompressedEdwardsY::from_slice(bytes) else {
        return None;
    };
    compressed_point.decompress()
}

/// Encode a Scalar
pub fn encode_scalar(s: &Scalar) -> ScalarBytes {
    s.to_bytes()
}

/// Decode a Scalar
pub fn decode_scalar(bytes: &ScalarBytes) -> Option<Scalar> {
    let s = Scalar::from_canonical_bytes(*bytes);
    if s.is_some().unwrap_u8() == 1 {
        Some(s.unwrap())
    } else {
        None
    }
}
