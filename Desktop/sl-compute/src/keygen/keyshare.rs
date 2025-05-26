use crate::keygen::field25519::{EdwardsPointInternal, WeiCoordinates};
use crate::keygen::proto::{decode_point, decode_scalar, PointBytes, ScalarBytes};
use curve25519_dalek::edwards::CompressedEdwardsY;
use curve25519_dalek::{EdwardsPoint, Scalar};
use pkcs8::der::asn1::BitStringRef;
use pkcs8::der::EncodePem;
use pkcs8::spki::AlgorithmIdentifier;
use pkcs8::{LineEnding, ObjectIdentifier, SubjectPublicKeyInfo};
use x25519_dalek::PublicKey;

/// Key share of a party.
#[derive(Clone)]
pub struct Keyshare {
    /// A marker
    pub magic: [u8; 4],

    /// Party ID of the sender
    pub party_id: u8,

    /// Public key of the generated key.
    pub public_key: PointBytes,

    /// share (s_i, s_{i+1})
    pub(crate) share: (ScalarBytes, ScalarBytes),
}

impl Keyshare {
    /// Identified of key share data
    pub const MAGIC: [u8; 4] = [0, 0, 0, 1];

    /// new
    pub fn new(
        party_id: u8,
        public_key: PointBytes,
        share: (ScalarBytes, ScalarBytes),
    ) -> Keyshare {
        Keyshare {
            magic: Self::MAGIC,
            party_id,
            public_key,
            share,
        }
    }

    /// Return public key as EdwardsPoint.
    pub fn public_key(&self) -> EdwardsPoint {
        decode_point(&self.public_key).unwrap()
    }

    /// Return compressed public key.
    pub fn compressed_public_key(&self) -> CompressedEdwardsY {
        self.public_key().compress()
    }

    /// Return X25519 public key.
    pub fn public_key_as_montgomery_point(&self) -> PublicKey {
        PublicKey::from(*self.public_key().to_montgomery().as_bytes())
    }

    /// Return public key as (x,y) Wei25519 coordinates.
    pub fn public_key_to_wei_coordinates(&self) -> WeiCoordinates {
        EdwardsPointInternal::from_compressed(&self.compressed_public_key())
            .unwrap()
            .to_wei_coordinates()
    }

    /// Return public key in X.509 SubjectPublicKeyInfo (SPKI) format
    pub fn public_key_to_pem(&self) -> String {
        // 1.3.101.110 (id-X125519 RFC 8410 s3)
        let alg_oid = "1.3.101.110".parse::<ObjectIdentifier>().unwrap();
        let public_key_bytes = *self.public_key_as_montgomery_point().as_bytes();
        let spki_test = SubjectPublicKeyInfo {
            algorithm: AlgorithmIdentifier::<ObjectIdentifier> {
                oid: alg_oid,
                parameters: None,
            },
            subject_public_key: BitStringRef::new(0, &public_key_bytes).unwrap(),
        };
        spki_test.to_pem(LineEnding::LF).unwrap()
    }

    /// Return share as (Scalar, Scalar).
    pub fn share(&self) -> (Scalar, Scalar) {
        (
            decode_scalar(&self.share.0).unwrap(),
            decode_scalar(&self.share.1).unwrap(),
        )
    }
}
