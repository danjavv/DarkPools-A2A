//! Parties should create the shares in a distributed way. A simple way is:
//! 1. Pi samples s_i and sends it to Pi-1
//! 2. Pi computes pk_i=s_i*G and pk_i+1=s_i+1 * G
//! 3. Pi sends pk_i+1 to Pi-1 and pk_i to Pi+1
//! 4. Pi verifies that pk_i-1 that it received from Pi+1 and Pi-1 match. If they do not match, then abort
//! 5. Pi sets pk=pk0+pk1+pk2 and outputs its shares s_i, s_i+1

// The current implementation of Edwards point operations relies on a third-party library that may not meet production security standards.
// A review and potential upgrade of this implementation is recommended before deployment.

use crate::keygen::asn::parse_asn1_public_key;
use crate::keygen::field25519::WeiCoordinates;
use crate::keygen::keyshare::Keyshare;
use crate::keygen::proto::{
    decode_point, decode_scalar, encode_point, encode_scalar, PointBytes, ScalarBytes,
};
use crate::types::ArithmeticECShare;
use crate::utility::helper::get_modulus;
use base64::prelude::BASE64_STANDARD;
use base64::Engine;
use chrono::{Duration, Utc};
use crypto_bigint::{Encoding, U256};
use curve25519_dalek::{EdwardsPoint, Scalar};
use rand::{CryptoRng, Rng, RngCore};
use serde::{Deserialize, Serialize};

use super::asn::parse_asn1_private_key;

#[derive(Debug, thiserror::Error)]
/// DKG errors
pub enum KeygenError {
    /// invalid SessionID
    #[error("Invalid SessionID")]
    InvalidSessionID,

    /// error while serializing or deserializing or invalid message data length
    #[error("Error while deserializing message")]
    InvalidMessage,

    /// error while checking
    #[error("Invalid Keygen")]
    InvalidKeygen,
}

/// Type for the key generation protocol's message 1
#[derive(Clone, Copy, Serialize, Deserialize)]
pub struct KeygenMsg1 {
    /// session id
    pub session_id: [u8; 32],

    /// s_i
    pub s_i: ScalarBytes,
}

/// Type for the key generation protocol's message 2
#[derive(Clone, Copy, Serialize, Deserialize)]
pub struct KeygenMsg2 {
    /// session id
    pub session_id: [u8; 32],

    /// pk_i
    pub pk_i: PointBytes,
}

/// Party State for R1
#[derive(Clone, Copy, Serialize, Deserialize)]
pub struct PartyStateR1 {
    /// session id
    pub session_id: [u8; 32],

    /// party id
    pub party_id: u8,

    /// s_i
    pub s_i: Scalar,
}

/// Party State for R2
#[derive(Clone, Copy, Serialize, Deserialize)]
pub struct PartyStateR2 {
    /// session id
    pub session_id: [u8; 32],

    /// party id
    pub party_id: u8,

    /// s_i
    pub s_i: Scalar,

    /// s_i_plus_1
    pub s_i_plus_1: Scalar,

    /// public_key
    pub public_key: EdwardsPoint,
}

/// Party creates KeygenMsg1 and sends to left party
pub fn dkg_create_msg1<R: CryptoRng + RngCore>(
    session_id: &[u8; 32],
    party_id: u8,
    rng: &mut R,
) -> (PartyStateR1, KeygenMsg1) {
    let mut bytes = [0u8; 32];
    rng.fill_bytes(&mut bytes);
    let s_i = Scalar::from_bytes_mod_order(bytes);

    let state = PartyStateR1 {
        session_id: *session_id,
        party_id,
        s_i,
    };

    let msg1 = KeygenMsg1 {
        session_id: *session_id,
        s_i: encode_scalar(&s_i),
    };

    (state, msg1)
}

/// Party processes KeygenMsg1 and sends (KeygenMsg2, KeygenMsg2) to other parties
pub fn dkg_process_msg1(
    state: &PartyStateR1,
    msg1: &KeygenMsg1,
) -> Result<(PartyStateR2, KeygenMsg2, KeygenMsg2), KeygenError> {
    if state.session_id != msg1.session_id {
        return Err(KeygenError::InvalidSessionID);
    }

    let s_i_plus_1 = match decode_scalar(&msg1.s_i) {
        None => {
            return Err(KeygenError::InvalidMessage);
        }
        Some(v) => v,
    };

    let pk_i = EdwardsPoint::mul_base(&state.s_i);
    let pk_i_plus_1 = EdwardsPoint::mul_base(&s_i_plus_1);

    let state = PartyStateR2 {
        session_id: state.session_id,
        party_id: state.party_id,
        s_i: state.s_i,
        s_i_plus_1,
        public_key: pk_i + pk_i_plus_1,
    };

    let prev_msg2 = KeygenMsg2 {
        session_id: state.session_id,
        pk_i: encode_point(&pk_i_plus_1),
    };

    let next_msg2 = KeygenMsg2 {
        session_id: state.session_id,
        pk_i: encode_point(&pk_i),
    };

    Ok((state, prev_msg2, next_msg2))
}

/// Party processes (KeygenMsg2, KeygenMsg2)
pub fn dkg_process_msg2(
    state: &PartyStateR2,
    msg2_from_prev: &KeygenMsg2,
    msg2_from_next: &KeygenMsg2,
) -> Result<Keyshare, KeygenError> {
    if state.session_id != msg2_from_prev.session_id {
        return Err(KeygenError::InvalidSessionID);
    }

    if state.session_id != msg2_from_next.session_id {
        return Err(KeygenError::InvalidSessionID);
    }

    let other_pk_prev = match decode_point(&msg2_from_prev.pk_i) {
        None => {
            return Err(KeygenError::InvalidMessage);
        }
        Some(v) => v,
    };

    let other_pk_next = match decode_point(&msg2_from_next.pk_i) {
        None => {
            return Err(KeygenError::InvalidMessage);
        }
        Some(v) => v,
    };

    if other_pk_prev != other_pk_next {
        return Err(KeygenError::InvalidKeygen);
    }

    let public_key = state.public_key + other_pk_next;

    let keyshare = Keyshare::new(
        state.party_id,
        encode_point(&public_key),
        (encode_scalar(&state.s_i), encode_scalar(&state.s_i_plus_1)),
    );

    Ok(keyshare)
}

#[derive(Serialize)]
struct DHPublicKey {
    expiry: String,
    #[serde(rename = "Parameters")]
    parameters: String,
    #[serde(rename = "KeyValue")]
    key_value: String,
}

#[derive(Serialize)]
struct KeyMaterial {
    #[serde(rename = "cryptoAlg")]
    crypto_alg: String,
    curve: String,
    params: String,
    #[serde(rename = "DHPublicKey")]
    dhpublic_key: DHPublicKey,
    #[serde(rename = "Nonce")]
    nonce: String,
}

pub fn get_serialized_public_key(encoded_public_key: String, encoded_nonce: String) -> String {
    let now = Utc::now();
    let future_time = now + Duration::hours(30);
    let timestamp = future_time.format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string();

    let public_key = DHPublicKey {
        expiry: timestamp,
        parameters: "".to_string(),
        key_value: encoded_public_key,
    };

    let json_file = KeyMaterial {
        crypto_alg: "ECDH".to_string(),
        curve: "Curve25519".to_string(),
        params: "".to_string(),
        nonce: encoded_nonce,
        dhpublic_key: public_key,
    };

    serde_json::to_string_pretty(&json_file).unwrap()
}

pub fn test_run_dkg() -> (
    String,
    String,
    ArithmeticECShare,
    ArithmeticECShare,
    ArithmeticECShare,
) {
    use rand::thread_rng;

    let mut rng = thread_rng();

    let session_id: [u8; 32] = rng.gen();

    let (p0_state_r1, p0_msg1_to_p2) = dkg_create_msg1(&session_id, 0, &mut rng);
    let (p1_state_r1, p1_msg1_to_p0) = dkg_create_msg1(&session_id, 1, &mut rng);
    let (p2_state_r1, p2_msg1_to_p1) = dkg_create_msg1(&session_id, 2, &mut rng);

    let (p0_state_r2, p0_msg2_to_p2, p0_msg2_to_p1) =
        dkg_process_msg1(&p0_state_r1, &p1_msg1_to_p0).unwrap();
    let (p1_state_r2, p1_msg2_to_p0, p1_msg2_to_p2) =
        dkg_process_msg1(&p1_state_r1, &p2_msg1_to_p1).unwrap();
    let (p2_state_r2, p2_msg2_to_p1, p2_msg2_to_p0) =
        dkg_process_msg1(&p2_state_r1, &p0_msg1_to_p2).unwrap();

    let p0_keyshare = dkg_process_msg2(&p0_state_r2, &p2_msg2_to_p0, &p1_msg2_to_p0).unwrap();
    let p1_keyshare = dkg_process_msg2(&p1_state_r2, &p0_msg2_to_p1, &p2_msg2_to_p1).unwrap();
    let p2_keyshare = dkg_process_msg2(&p2_state_r2, &p1_msg2_to_p2, &p0_msg2_to_p2).unwrap();

    let wei_coordinates = p0_keyshare.public_key_to_wei_coordinates();
    let encoded_public_key = wei_coordinates.to_pem();

    let p0_s = p0_keyshare.share().0;
    let p1_s = p1_keyshare.share().0;
    let p2_s = p2_keyshare.share().0;

    let p0_share = ArithmeticECShare {
        value1: U256::from_be_bytes(*(p0_s + p2_s).as_bytes()),
        value2: U256::from_be_bytes(p0_s.to_bytes()),
    };

    let p1_share = ArithmeticECShare {
        value1: U256::from_be_bytes(*(p1_s + p0_s).as_bytes()),
        value2: U256::from_be_bytes(p1_s.to_bytes()),
    };

    let p2_share = ArithmeticECShare {
        value1: U256::from_be_bytes(*(p2_s + p1_s).as_bytes()),
        value2: U256::from_be_bytes(p2_s.to_bytes()),
    };

    let nonce: [u8; 32] = rng.gen();
    let encoded_nonce = BASE64_STANDARD.encode(nonce);

    (
        encoded_public_key,
        encoded_nonce,
        p0_share,
        p1_share,
        p2_share,
    )
}

pub fn parse_remote_public_key(remote_public_recv: String) -> WeiCoordinates {
    let base64_str = remote_public_recv
        .replace("-----BEGIN PUBLIC KEY-----", "")
        .replace("-----END PUBLIC KEY-----", "");

    let decoded = BASE64_STANDARD.decode(base64_str).unwrap();

    let (x, y) = parse_asn1_public_key(&decoded).unwrap();

    WeiCoordinates { x, y }
}

pub fn get_private_key_shares(
    our_private_key: String,
) -> (ArithmeticECShare, ArithmeticECShare, ArithmeticECShare) {
    let base64_str = our_private_key
        .replace("-----BEGIN PRIVATE KEY-----", "")
        .replace("-----END PRIVATE KEY-----", "");

    let decoded = BASE64_STANDARD.decode(base64_str).unwrap();

    let x = parse_asn1_private_key(&decoded).unwrap();

    let s1 = U256::from_be_bytes(x);
    let s2 = U256::ZERO;
    let s3 = U256::ZERO;

    let p = get_modulus();

    let p1_share = ArithmeticECShare {
        value1: s1.add_mod(&s3, &p),
        value2: s1,
    };

    let p2_share = ArithmeticECShare {
        value1: s2.add_mod(&s1, &p),
        value2: s2,
    };

    let p3_share = ArithmeticECShare {
        value1: s3.add_mod(&s2, &p),
        value2: s3,
    };

    (p1_share, p2_share, p3_share)
}

#[cfg(test)]
mod tests {
    use crate::keygen::dkg::{dkg_create_msg1, dkg_process_msg1, dkg_process_msg2};
    use crate::keygen::field25519::{EdwardsPointInternal, WeiCoordinates};
    use crate::utility::helper::get_modulus;
    use base64::prelude::BASE64_STANDARD;
    use base64::Engine;
    use crypto_bigint::{Encoding, U256};
    use curve25519_dalek::{EdwardsPoint, MontgomeryPoint, Scalar};
    use elliptic_curve::Group;
    use rand::Rng;
    use x25519_dalek::{PublicKey, StaticSecret};

    #[test]
    pub fn keygen() {
        use rand::thread_rng;

        let mut rng = thread_rng();

        let session_id: [u8; 32] = rng.gen();
        let p = get_modulus();

        let (p0_state_r1, p0_msg1_to_p2) = dkg_create_msg1(&session_id, 0, &mut rng);
        let (p1_state_r1, p1_msg1_to_p0) = dkg_create_msg1(&session_id, 1, &mut rng);
        let (p2_state_r1, p2_msg1_to_p1) = dkg_create_msg1(&session_id, 2, &mut rng);

        let (p0_state_r2, p0_msg2_to_p2, p0_msg2_to_p1) =
            dkg_process_msg1(&p0_state_r1, &p1_msg1_to_p0).unwrap();
        let (p1_state_r2, p1_msg2_to_p0, p1_msg2_to_p2) =
            dkg_process_msg1(&p1_state_r1, &p2_msg1_to_p1).unwrap();
        let (p2_state_r2, p2_msg2_to_p1, p2_msg2_to_p0) =
            dkg_process_msg1(&p2_state_r1, &p0_msg1_to_p2).unwrap();

        let p0_keyshare = dkg_process_msg2(&p0_state_r2, &p2_msg2_to_p0, &p1_msg2_to_p0).unwrap();
        let p1_keyshare = dkg_process_msg2(&p1_state_r2, &p0_msg2_to_p1, &p2_msg2_to_p1).unwrap();
        let p2_keyshare = dkg_process_msg2(&p2_state_r2, &p1_msg2_to_p2, &p0_msg2_to_p2).unwrap();

        let public_key = p0_keyshare.public_key();

        //println!("Public key: {:?}", p0_keyshare.public_key_as_montgomery_point());
        // println!("Public key as PEM: {:?}", p0_keyshare.public_key_to_pem());

        let wei_coordinates = p0_keyshare.public_key_to_wei_coordinates();
        println!("Public key as PEM: {:?}", wei_coordinates.to_pem());

        assert_eq!(p1_keyshare.public_key(), public_key);
        assert_eq!(p2_keyshare.public_key(), public_key);

        let p0_share = p0_keyshare.share();
        let p1_share = p1_keyshare.share();
        let p2_share = p2_keyshare.share();

        assert_eq!(p0_share.1, p1_share.0);
        assert_eq!(p1_share.1, p2_share.0);
        assert_eq!(p2_share.1, p0_share.0);

        let sk = p0_share.0 + p1_share.0 + p2_share.0;
        let s0 = U256::from_be_bytes(p0_share.0.to_bytes());
        let s1 = U256::from_be_bytes(p1_share.0.to_bytes());
        let s2 = U256::from_be_bytes(p2_share.0.to_bytes());

        println!("share 0: {} ", s0);
        println!("share 1: {} ", s1);
        println!("share 2: {} ", s2);
        println!("sk: {} ", U256::from_be_bytes(sk.to_bytes()));
        println!("{}", (s0.add_mod(&s1, &p)).add_mod(&s2, &p));

        assert_eq!(EdwardsPoint::mul_base(&sk), public_key);
    }

    #[test]
    pub fn x25519_shared_key() {
        use curve25519_dalek::EdwardsPoint;
        use elliptic_curve::Group;

        use rand::thread_rng;
        let mut rng = thread_rng();

        // X25519 keypair
        let sk_alice = StaticSecret::random();
        let pk_alice = PublicKey::from(&sk_alice);

        let generator = EdwardsPoint::generator();

        let scalar_bob = Scalar::random(&mut rng);
        let pk_bob = PublicKey::from(*(generator * scalar_bob).to_montgomery().as_bytes());

        let shared_key_alice = sk_alice.diffie_hellman(&pk_bob);
        let shared_key_bob = MontgomeryPoint(pk_alice.to_bytes()) * scalar_bob;

        assert_eq!(shared_key_alice.to_bytes(), shared_key_bob.to_bytes());

        println!("shared_key_alice: {:?}", shared_key_alice.to_bytes());
        println!("shared_key_bob: {:?}", shared_key_bob.to_bytes());
    }

    #[test]
    pub fn test_shared_key() {
        // Alice generates key pair
        // -----BEGIN PRIVATE KEY-----MIICRwIBADCB6gYHKoZIzj0CATCB3gIBATArBgcqhkjOPQEBAiB/////////////////////////////////////////7TBEBCAqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqYSRShRAQge0Je0Je0Je0Je0Je0Je0Je0Je0Je0Je0JgtenHcQyGQEQQQqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq0kWiCuGaG4oIa04B7dLHdI0UySPU1+bXxhsinpxaJ+ztPZAiAQAAAAAAAAAAAAAAAAAAAAFN753qL3nNZYEmMaXPXT7QIBCASCAVMwggFPAgEBBCAIND427PzqSw8bRe4pdtIvEpycM2zENrLpCaDnD/tqdqCB4TCB3gIBATArBgcqhkjOPQEBAiB/////////////////////////////////////////7TBEBCAqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqYSRShRAQge0Je0Je0Je0Je0Je0Je0Je0Je0Je0Je0JgtenHcQyGQEQQQqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq0kWiCuGaG4oIa04B7dLHdI0UySPU1+bXxhsinpxaJ+ztPZAiAQAAAAAAAAAAAAAAAAAAAAFN753qL3nNZYEmMaXPXT7QIBCKFEA0IABCQTJuwdLU27aj+hHXioDKQ/2MtvJHJPI9cUVGU9bvb1UXtJ3IVfap9oobTK8ikS2TYiXvDyKMrkNn80jSgsD2o=-----END PRIVATE KEY-----
        // -----BEGIN PUBLIC KEY-----MIIBMTCB6gYHKoZIzj0CATCB3gIBATArBgcqhkjOPQEBAiB/////////////////////////////////////////7TBEBCAqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqYSRShRAQge0Je0Je0Je0Je0Je0Je0Je0Je0Je0Je0JgtenHcQyGQEQQQqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq0kWiCuGaG4oIa04B7dLHdI0UySPU1+bXxhsinpxaJ+ztPZAiAQAAAAAAAAAAAAAAAAAAAAFN753qL3nNZYEmMaXPXT7QIBCANCAAQkEybsHS1Nu2o/oR14qAykP9jLbyRyTyPXFFRlPW729VF7SdyFX2qfaKG0yvIpEtk2Il7w8ijK5DZ/NI0oLA9q-----END PUBLIC KEY-----
        // wei public key:
        // 0x04241326ec1d2d4dbb6a3fa11d78a80ca43fd8cb6f24724f23d71454653d6ef6f5517b49dc855f6a9f68a1b4caf22912d936225ef0f228cae4367f348d282c0f6a
        // x: 241326ec1d2d4dbb6a3fa11d78a80ca43fd8cb6f24724f23d71454653d6ef6f5
        // y: 517b49dc855f6a9f68a1b4caf22912d936225ef0f228cae4367f348d282c0f6a
        let pk_alice_x = "241326ec1d2d4dbb6a3fa11d78a80ca43fd8cb6f24724f23d71454653d6ef6f5";
        let pk_alice_y = "517b49dc855f6a9f68a1b4caf22912d936225ef0f228cae4367f348d282c0f6a";
        let secret_bob = "c4b1d3c33b1e26ef307b5642e3740a5c1526b87ffe1dd81e4a80ba1136875e07";
        let expected_shared_key = "VKHpzkwLHURlgW/+6GW22udyMJRXMeUKXPvdfEPob4I=";

        let wei_pk_alice = WeiCoordinates {
            x: hex::decode(pk_alice_x).unwrap()[..].try_into().unwrap(),
            y: hex::decode(pk_alice_y).unwrap()[..].try_into().unwrap(),
        };

        let ed_pk_alice = wei_pk_alice.to_ed_compressed().decompress().unwrap();

        let secret_bytes: [u8; 32] = hex::decode(secret_bob).unwrap()[..].try_into().unwrap();
        let scalar_bob = Scalar::from_canonical_bytes(secret_bytes).unwrap();
        let pk_bob = EdwardsPoint::generator() * scalar_bob;
        let wei_public_key = EdwardsPointInternal::from_compressed(&pk_bob.compress())
            .unwrap()
            .to_wei_coordinates()
            .to_pem();

        println!("public_key_bob: {:?}", wei_public_key);

        let shared_point =
            EdwardsPointInternal::from_compressed(&(ed_pk_alice * scalar_bob).compress()).unwrap();
        let wei_coordinates = shared_point.to_wei_coordinates();
        let shared_key = BASE64_STANDARD.encode(wei_coordinates.x);
        println!("shared_key is X coordinate: {:?}", shared_key);

        assert_eq!(expected_shared_key, &shared_key);
    }

    // #[test]
    // pub fn test_shared_key_flow() {
    //     let pk_alice_x = "241326ec1d2d4dbb6a3fa11d78a80ca43fd8cb6f24724f23d71454653d6ef6f5";
    //     let pk_alice_y = "517b49dc855f6a9f68a1b4caf22912d936225ef0f228cae4367f348d282c0f6a";
    //
    //     let wei_pk_alice = WeiCoordinates {
    //         x: hex::decode(pk_alice_x).unwrap()[..].try_into().unwrap(),
    //         y: hex::decode(pk_alice_y).unwrap()[..].try_into().unwrap(),
    //     };
    //
    //     let (mut serverstate_p1, mut serverstate_p2, mut serverstate_p3) =
    //         test_run_get_serverstate();
    //
    //     let ed_pk_alice = wei_pk_alice.to_ed_compressed().decompress().unwrap();
    //
    //     let (pubk, _non, sk_int_1, sk_int_2, sk_int_3) = test_run_dkg();
    //
    //     let (sk1, sk2, sk3) = (
    //         Scalar::from_bytes_mod_order(sk_int_1.value2.to_be_bytes()),
    //         Scalar::from_bytes_mod_order(sk_int_2.value2.to_be_bytes()),
    //         Scalar::from_bytes_mod_order(sk_int_3.value2.to_be_bytes()),
    //     );
    //
    //     let (shk_p1, shk_p2, shk_p3) = (ed_pk_alice * sk1, ed_pk_alice * sk2, ed_pk_alice * sk3);
    //     // TESTing getting public key of FIU.
    //     let total_secret = sk1 + sk2 + sk3;
    //     let pk_bob = EdwardsPoint::generator() * total_secret;
    //     let wei_public_key = EdwardsPointInternal::from_compressed(&pk_bob.compress())
    //         .unwrap()
    //         .to_wei_coordinates()
    //         .to_pem();
    //
    //     println!("public_key_bob: {:?}", wei_public_key);
    //     println!("public key 2: {:?}", pubk);
    //
    //     // Testing done.
    //
    //     let oursh_p1 = EdwardsPointInternal::from_compressed(&shk_p1.compress())
    //         .unwrap()
    //         .to_wei_coordinates();
    //     let oursh_p2 = EdwardsPointInternal::from_compressed(&shk_p2.compress())
    //         .unwrap()
    //         .to_wei_coordinates();
    //     let oursh_p3 = EdwardsPointInternal::from_compressed(&shk_p3.compress())
    //         .unwrap()
    //         .to_wei_coordinates();
    //
    //     let p1_x = U256::from_be_bytes(oursh_p1.x);
    //     let p1_y = U256::from_be_bytes(oursh_p1.y);
    //
    //     let p2_x = U256::from_be_bytes(oursh_p2.x);
    //     let p2_y = U256::from_be_bytes(oursh_p2.y);
    //
    //     let p3_x = U256::from_be_bytes(oursh_p3.x);
    //     let p3_y = U256::from_be_bytes(oursh_p3.y);
    //
    //     let key_x1_p1 = get_default_ec_share(p1_x, 1);
    //     let key_x1_p2 = get_default_ec_share(p1_x, 2);
    //     let key_x1_p3 = get_default_ec_share(p1_x, 3);
    //
    //     let key_y1_p1 = get_default_ec_share(p1_y, 1);
    //     let key_y1_p2 = get_default_ec_share(p1_y, 2);
    //     let key_y1_p3 = get_default_ec_share(p1_y, 3);
    //
    //     let key_x2_p1 = get_default_ec_share(p2_x, 1);
    //     let key_x2_p2 = get_default_ec_share(p2_x, 2);
    //     let key_x2_p3 = get_default_ec_share(p2_x, 3);
    //
    //     let key_y2_p1 = get_default_ec_share(p2_y, 1);
    //     let key_y2_p2 = get_default_ec_share(p2_y, 2);
    //     let key_y2_p3 = get_default_ec_share(p2_y, 3);
    //
    //     let key_x3_p1 = get_default_ec_share(p3_x, 1);
    //     let key_x3_p2 = get_default_ec_share(p3_x, 2);
    //     let key_x3_p3 = get_default_ec_share(p3_x, 3);
    //
    //     let key_y3_p1 = get_default_ec_share(p3_y, 1);
    //     let key_y3_p2 = get_default_ec_share(p3_y, 2);
    //     let key_y3_p3 = get_default_ec_share(p3_y, 3);
    //
    //     let points_p1: Vec<ArithmeticECShare> = vec![
    //         key_x1_p1, key_x2_p1, key_x3_p1, key_y1_p1, key_y2_p1, key_y3_p1,
    //     ];
    //     let points_p2: Vec<ArithmeticECShare> = vec![
    //         key_x1_p2, key_x2_p2, key_x3_p2, key_y1_p2, key_y2_p2, key_y3_p2,
    //     ];
    //     let points_p3: Vec<ArithmeticECShare> = vec![
    //         key_x1_p3, key_x2_p3, key_x3_p3, key_y1_p3, key_y2_p3, key_y3_p3,
    //     ];
    //     let (shared_key_p1, shared_key_p2, shared_key_p3) = ec_to_b(
    //         points_p1,
    //         points_p2,
    //         points_p3,
    //         &mut serverstate_p1,
    //         &mut serverstate_p2,
    //         &mut serverstate_p3,
    //     );
    //     let mut out: BinaryString = BinaryString::with_capacity(256);
    //     for i in 0..256 {
    //         out.push(reconstruct_binary_share(
    //             shared_key_p1.get_binary_share(i),
    //             shared_key_p2.get_binary_share(i),
    //             shared_key_p3.get_binary_share(i),
    //             &mut serverstate_p1,
    //             &mut serverstate_p2,
    //             &mut serverstate_p3,
    //         ));
    //     }
    //     out.reverse();
    //     println!(
    //         "test out: {:?}\n{}",
    //         binary_string_to_u8_vec(out.clone()),
    //         BASE64_STANDARD.encode(binary_string_to_u8_vec(out))
    //     );
    // }
}
