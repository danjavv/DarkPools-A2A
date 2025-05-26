use super::hkdf::run_hkdf;
use crate::aes::aes_gcm::run_aes_gcm;
use crate::constants::B_TO_A_OPEN_MSG;
use crate::conversion::ec_to_b::run_ec_to_b;
#[cfg(any(test, feature = "test-support"))]
use crate::transport::init::run_init;
use crate::transport::proto::{FilteredMsgRelay, Wrap};
use crate::transport::setup::common::MPCEncryption;
use crate::transport::setup::CommonSetupMessage;
use crate::transport::types::ProtocolError;
#[cfg(any(test, feature = "test-support"))]
use crate::transport::utils::Seed;
use crate::transport::utils::{receive_from_parties, send_to_party, TagOffsetCounter};
use crate::types::ServerState;
use crate::{
    keygen::field25519::EdwardsPointInternal,
    proto::get_default_ec_share,
    types::{ArithmeticECShare, BinaryString, BinaryStringShare},
};
use crypto_bigint::{Encoding, U256};
use curve25519_dalek::{EdwardsPoint, Scalar};
use sl_mpc_mate::coord::Relay;
use sl_mpc_mate::message::MessageTag;

pub async fn run_get_session_key<T, R>(
    setup: &T,
    mpc_encryption: &mut MPCEncryption,
    tag_offset_counter: &mut TagOffsetCounter,
    relay: &mut FilteredMsgRelay<R>,
    xored_nonce: &BinaryStringShare,
    shared_key: &BinaryStringShare,
    serverstate: &mut ServerState,
) -> Result<BinaryStringShare, ProtocolError>
where
    T: CommonSetupMessage,
    R: Relay,
{
    // TODO xored_nonce.length = 256, why do we truncate to 160?
    let mut salt_p = BinaryStringShare::with_capacity(160);
    for i in 0..160 {
        salt_p.push_binary_share(xored_nonce.get_binary_share(i));
    }
    let info_p = BinaryStringShare::new();

    let session_key_p = run_hkdf(
        setup,
        mpc_encryption,
        tag_offset_counter,
        relay,
        256,
        &salt_p,
        shared_key,
        &info_p,
        serverstate,
    )
    .await?;

    Ok(session_key_p)
}

pub fn get_iv(xored_nonce_p: &BinaryStringShare) -> BinaryStringShare {
    let mut iv_p = BinaryStringShare::with_capacity(96);
    for i in 0..96 {
        iv_p.push_binary_share(xored_nonce_p.get_binary_share(160 + i));
    }
    iv_p
}

#[derive(Clone)]
pub struct ThresholdDecMsg1 {
    pub x: ArithmeticECShare,
    pub y: ArithmeticECShare,
}

/// Securely simluates the decrypt function defined in
/// https://github.com/Sahamati/rahasya/blob/main/src/main/java/io/yaazhi/forwardsecrecy/service/CipherService.java#L75.
#[allow(clippy::too_many_arguments)]
pub async fn run_threshold_decrypt<T, R>(
    setup: &T,
    mpc_encryption: &mut MPCEncryption,
    tag_offset_counter: &mut TagOffsetCounter,
    relay: &mut FilteredMsgRelay<R>,
    pub_key: EdwardsPoint,
    r_nonce: &BinaryString,
    o_nonce: &BinaryString,
    ciphertext: &[u8],
    privk: &ArithmeticECShare,
    serverstate: &mut ServerState,
) -> Result<BinaryStringShare, ProtocolError>
where
    T: CommonSetupMessage,
    R: Relay,
{
    let party_index = setup.participant_index();

    let r_nonce_p = BinaryStringShare::from_constant(r_nonce, party_index);
    let o_nonce_p = BinaryStringShare::from_constant(o_nonce, party_index);

    let xor_nonce_p = r_nonce_p.xor(&o_nonce_p);

    let sk = Scalar::from_bytes_mod_order(privk.value2.to_be_bytes());
    let shk_p = pub_key * sk;
    let oursh_p = EdwardsPointInternal::from_compressed(&shk_p.compress())
        .unwrap()
        .to_wei_coordinates();

    let p_x = U256::from_be_bytes(oursh_p.x);
    let p_y = U256::from_be_bytes(oursh_p.y);

    ////
    let (key_x1_p1, key_x1_p2, key_x1_p3) = (
        get_default_ec_share(p_x, 1),
        get_default_ec_share(p_x, 2),
        get_default_ec_share(p_x, 3),
    );
    let (key_y1_p1, key_y1_p2, key_y1_p3) = (
        get_default_ec_share(p_y, 1),
        get_default_ec_share(p_y, 2),
        get_default_ec_share(p_y, 3),
    );

    // p2p messages all to all
    let msg_tag = MessageTag::tag1(B_TO_A_OPEN_MSG, tag_offset_counter.next_value());
    relay.ask_messages(setup, msg_tag, true).await?;

    // TODO why?
    let points_p: Vec<ArithmeticECShare> = match party_index {
        0 => {
            // party_1 sends key_x1_p2 to party_2
            let msg = ThresholdDecMsg1 {
                x: key_x1_p2,
                y: key_y1_p2,
            };
            send_to_party(setup, mpc_encryption, msg_tag, msg, 1, relay).await?;
            // party_1 sends key_x1_p3 to party_3
            let msg = ThresholdDecMsg1 {
                x: key_x1_p3,
                y: key_y1_p3,
            };
            let msg_size = msg.external_size();
            send_to_party(setup, mpc_encryption, msg_tag, msg, 2, relay).await?;

            // party_1 receives points from party_2 and party_3
            let values: Vec<ThresholdDecMsg1> =
                receive_from_parties(setup, mpc_encryption, msg_tag, msg_size, vec![1, 2], relay)
                    .await?;
            vec![
                key_x1_p1,
                values[0].x.clone(),
                values[1].x.clone(),
                key_y1_p1,
                values[0].y.clone(),
                values[1].y.clone(),
            ]
        }
        1 => {
            // party_2 sends key_x2_p1 to party_1
            let msg = ThresholdDecMsg1 {
                x: key_x1_p1,
                y: key_y1_p1,
            };
            send_to_party(setup, mpc_encryption, msg_tag, msg, 0, relay).await?;
            // party_2 sends key_x1_p3 to party_3
            let msg = ThresholdDecMsg1 {
                x: key_x1_p3,
                y: key_y1_p3,
            };
            let msg_size = msg.external_size();
            send_to_party(setup, mpc_encryption, msg_tag, msg, 2, relay).await?;

            // party_2 receives points from party_1 and party_3
            let values: Vec<ThresholdDecMsg1> =
                receive_from_parties(setup, mpc_encryption, msg_tag, msg_size, vec![0, 2], relay)
                    .await?;
            vec![
                values[0].x.clone(),
                key_x1_p2,
                values[1].x.clone(),
                values[0].y.clone(),
                key_y1_p2,
                values[1].y.clone(),
            ]
        }
        _ => {
            // party_3 sends key_x3_p1 to party_1
            let msg = ThresholdDecMsg1 {
                x: key_x1_p1,
                y: key_y1_p1,
            };
            send_to_party(setup, mpc_encryption, msg_tag, msg, 0, relay).await?;
            // party_3 sends key_x3_p2 to party_2
            let msg = ThresholdDecMsg1 {
                x: key_x1_p2,
                y: key_y1_p2,
            };
            let msg_size = msg.external_size();
            send_to_party(setup, mpc_encryption, msg_tag, msg, 1, relay).await?;

            // party_3 receives points from party_1 and party_2
            let values: Vec<ThresholdDecMsg1> =
                receive_from_parties(setup, mpc_encryption, msg_tag, msg_size, vec![0, 1], relay)
                    .await?;

            vec![
                values[0].x.clone(),
                values[1].x.clone(),
                key_x1_p3,
                values[0].y.clone(),
                values[1].y.clone(),
                key_y1_p3,
            ]
        }
    };

    println!("pre run_ec_to_b {}", tag_offset_counter.next_value());

    let (key_x_p, _key_y_p) = run_ec_to_b(
        setup,
        mpc_encryption,
        tag_offset_counter,
        relay,
        &points_p,
        serverstate,
    )
    .await?;
    println!("run_ec_to_b {}", tag_offset_counter.next_value());

    let mut shared_key_p = key_x_p;
    shared_key_p.reverse();

    let session_key_p = run_get_session_key(
        setup,
        mpc_encryption,
        tag_offset_counter,
        relay,
        &xor_nonce_p,
        &shared_key_p,
        serverstate,
    )
    .await?;
    println!("run_get_session_key {}", tag_offset_counter.next_value());

    let iv_p = get_iv(&xor_nonce_p);

    // test_run_aes_gcm_encrypt_decrypt
    let decrypted_p = run_aes_gcm(
        setup,
        mpc_encryption,
        tag_offset_counter,
        relay,
        ciphertext,
        session_key_p,
        iv_p,
        serverstate,
    )
    .await?;
    println!("run_aes_gcm {}", tag_offset_counter.next_value());

    Ok(decrypted_p)
}

/// Test threshold decrypt protocol
#[cfg(any(test, feature = "test-support"))]
async fn test_threshold_decrypt_protocol<T, R>(
    setup: T,
    seed: Seed,
    params: (
        EdwardsPoint,
        BinaryString,
        BinaryString,
        Vec<u8>,
        ArithmeticECShare,
    ),
    relay: R,
) -> Result<(usize, BinaryStringShare), ProtocolError>
where
    T: CommonSetupMessage,
    R: Relay,
{
    use crate::mpc::common_randomness::run_common_randomness;
    use merlin::Transcript;
    use sl_mpc_mate::coord::SinkExt;

    let mut relay = FilteredMsgRelay::new(relay);
    // let abort_msg = create_abort_message(&setup);
    // relay.ask_messages(&setup, ABORT_MESSAGE_TAG, false).await?;

    let mut init_seed = [0u8; 32];
    let mut common_randomness_seed = [0u8; 32];
    let mut transcript = Transcript::new(b"test");
    transcript.append_message(b"seed", &seed);
    transcript.challenge_bytes(b"init-seed", &mut init_seed);
    transcript.challenge_bytes(b"common-randomness-seed", &mut common_randomness_seed);

    let (_sid, mut mpc_encryption) = run_init(&setup, init_seed, &mut relay).await?;

    let common_randomness = run_common_randomness(
        &setup,
        common_randomness_seed,
        &mut mpc_encryption,
        &mut relay,
    )
    .await?;

    let mut serverstate = ServerState::new(common_randomness);

    let mut tag_offset_counter = TagOffsetCounter::new();

    let pub_key = params.0;
    let r_nonce = params.1;
    let o_nonce = params.2;
    let ciphertext = params.3;
    let privk = params.4;

    let result = run_threshold_decrypt(
        &setup,
        &mut mpc_encryption,
        &mut tag_offset_counter,
        &mut relay,
        pub_key,
        &r_nonce,
        &o_nonce,
        &ciphertext,
        &privk,
        &mut serverstate,
    )
    .await;

    let _ = relay.close().await;

    match result {
        Ok(v) => Ok((setup.participant_index(), v)),
        Err(e) => Err(e),
    }
}

#[cfg(test)]
mod tests {
    use super::test_threshold_decrypt_protocol;
    use crate::transport::test_utils::setup_mpc;
    use crate::{
        keygen::dkg::parse_remote_public_key,
        proto::reconstruct_binary_string_share_to_string,
        types::{ArithmeticECShare, BinaryString, BinaryStringShare},
        utility::helper::convert_str_to_u256,
    };
    use curve25519_dalek::EdwardsPoint;
    use sl_mpc_mate::coord::{MessageRelayService, Relay, SimpleMessageRelay};
    use tokio::task::JoinSet;

    async fn sim<S, R>(
        coord: S,
        sim_params: &[(
            EdwardsPoint,
            BinaryString,
            BinaryString,
            Vec<u8>,
            ArithmeticECShare,
        ); 3],
    ) -> Vec<BinaryStringShare>
    where
        S: MessageRelayService<MessageRelay = R>,
        R: Relay + Send + 'static,
    {
        let parties = setup_mpc(None, sim_params);

        let mut jset = JoinSet::new();
        for (setup, seed, params) in parties {
            let relay = coord.connect().await.unwrap();

            jset.spawn(test_threshold_decrypt_protocol(setup, seed, params, relay));
        }

        let mut results = vec![];
        while let Some(fini) = jset.join_next().await {
            let fini = fini.unwrap();

            if let Err(ref err) = fini {
                println!("error {}", err);
            }

            let res = fini.unwrap();
            results.push(res);
        }

        results.sort_by_key(|r| r.0);
        results.into_iter().map(|r| r.1).collect()
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_threshold_dec_i() {
        let remote_public_key = r###"-----BEGIN PUBLIC KEY-----MIIBMTCB6gYHKoZIzj0CATCB3gIBATArBgcqhkjOPQEBAiB/////////////////////////////////////////7TBEBCAqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqYSRShRAQge0Je0Je0Je0Je0Je0Je0Je0Je0Je0Je0JgtenHcQyGQEQQQqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq0kWiCuGaG4oIa04B7dLHdI0UySPU1+bXxhsinpxaJ+ztPZAiAQAAAAAAAAAAAAAAAAAAAAFN753qL3nNZYEmMaXPXT7QIBCANCAAQkEybsHS1Nu2o/oR14qAykP9jLbyRyTyPXFFRlPW729VF7SdyFX2qfaKG0yvIpEtk2Il7w8ijK5DZ/NI0oLA9q-----END PUBLIC KEY-----"###.to_string();

        let remote_public_key = parse_remote_public_key(remote_public_key)
            .to_ed_compressed()
            .decompress()
            .unwrap();
        let r_nonce_bool = vec![
            false, false, true, false, true, false, true, false, true, false, true, false, true,
            false, false, false, false, true, true, true, false, false, true, false, false, true,
            false, true, false, false, false, true, false, false, false, false, true, false, false,
            true, false, false, true, false, false, true, true, false, true, false, false, true,
            false, false, true, false, false, false, true, false, true, true, false, false, true,
            false, true, true, false, true, true, false, true, true, true, false, false, true,
            false, false, false, true, true, true, true, false, false, true, false, true, true,
            true, false, true, true, true, false, true, false, true, true, false, false, true,
            false, true, true, true, false, true, false, false, false, true, true, false, false,
            false, false, true, true, true, false, true, true, false, false, false, false, true,
            true, true, true, true, true, true, false, false, false, true, true, true, true, true,
            false, true, true, true, true, false, true, true, true, true, false, false, true,
            false, false, false, false, false, false, true, false, true, false, true, true, false,
            true, false, false, true, false, true, true, false, true, true, false, true, true,
            true, true, true, false, false, false, false, false, true, true, false, true, false,
            true, true, false, true, true, false, false, false, false, true, false, false, false,
            true, true, true, true, false, true, true, true, true, false, true, false, false, true,
            false, true, false, false, true, true, true, true, false, true, false, true, true,
            false, false, true, false, true, false, true, true, true, true, false, true, true,
            true, true, false, false, false, false, true,
        ];
        let o_nonce_bool = vec![
            true, false, false, true, true, false, false, false, false, true, false, false, false,
            true, true, false, true, false, false, false, true, true, true, true, false, false,
            true, false, true, true, true, true, true, false, false, true, false, true, true,
            false, true, true, true, true, false, false, true, false, false, false, false, false,
            true, true, false, true, false, false, false, true, false, true, false, true, true,
            false, true, false, true, true, true, true, false, true, true, false, true, true, true,
            false, true, true, true, true, false, false, false, false, false, false, false, true,
            true, false, false, true, true, false, false, false, false, true, true, false, true,
            false, true, false, false, true, true, false, true, true, false, true, true, false,
            false, true, false, false, true, false, false, false, false, true, false, true, false,
            false, true, false, true, true, true, false, false, true, true, true, false, true,
            false, true, false, false, false, false, true, false, false, true, true, false, true,
            false, false, false, false, false, true, true, false, true, true, false, false, false,
            false, true, true, false, false, false, false, false, false, false, true, false, false,
            true, true, true, true, false, true, false, false, true, false, false, true, true,
            false, true, false, false, true, false, true, true, true, true, true, false, true,
            true, false, false, true, false, false, true, false, true, false, true, false, false,
            false, false, false, true, true, true, true, true, true, true, true, true, true, true,
            true, true, true, true, false, true, true, false, true, false, false, true, true, true,
            true, false, false, true, false, true,
        ];
        let ciphertext = vec![
            246, 65, 44, 192, 226, 24, 92, 208, 80, 38, 32, 0, 149, 177, 151, 162, 146, 200, 244,
            15, 218, 47, 6, 197, 210, 88, 151, 146, 156, 72, 106, 3, 222, 129, 66, 199, 41, 26, 90,
            57, 127, 29, 52, 212, 4, 169, 8, 21, 42, 134, 134, 163, 185, 128, 221, 220, 88, 243,
            177, 8, 218, 242, 155, 121, 149, 181, 211, 117, 119, 109, 205, 86, 170, 5, 130, 116,
            37, 23, 190, 198, 46, 210, 58, 14, 60, 105, 89, 176, 147, 35, 5, 134, 46, 49, 24, 85,
            128, 17, 139, 204, 58, 54, 60, 49, 3, 155, 10, 111, 6, 248, 107, 154, 254, 239, 224,
            201, 47, 59, 243, 245, 114, 213, 63, 67, 92, 227, 210, 86, 41, 76, 105, 58, 252, 86,
            191, 238, 219, 184, 255, 16, 47, 100, 40, 23, 118, 218, 128, 55, 13, 56, 50, 121, 190,
            62, 1, 0, 171, 27, 93, 223, 183, 129, 200, 120, 34, 211, 59, 58, 208, 77, 136, 207, 36,
            218, 194, 60, 118, 95, 124, 1, 19, 136, 166, 88, 4, 167, 225, 60, 69, 194, 62, 223, 36,
            132, 53, 131, 19, 16, 186, 234, 11, 29, 224, 23, 164, 61, 84, 49, 220, 81, 100, 239,
            155, 31, 54, 90, 137, 136, 142, 128, 23, 186, 74, 240, 137, 119, 30, 180, 185, 232, 32,
            187, 98, 110, 242, 53, 225, 80, 21, 219, 203, 4, 128, 27, 48, 85, 3, 71, 184, 83, 60,
            252, 231, 38, 67, 172, 104, 78, 150, 88, 5, 171, 183, 215, 105, 205, 231, 161, 171,
            201, 198, 73, 11, 58, 112, 175, 128, 243, 27, 237, 41, 234, 246, 246, 192, 66, 86, 85,
            70, 251, 247, 8, 255, 98, 154, 111, 83, 146, 91, 28, 53, 226, 167, 213, 63, 189, 250,
            216, 96, 115, 41, 115, 62, 199, 116, 61, 34, 30, 95, 45, 86, 126, 222, 223, 100, 122,
            222, 174, 172, 234, 194, 68, 78, 191, 194, 253, 80, 54, 22, 93, 29, 93, 188, 177, 156,
            197, 15, 53, 134, 126, 30, 72, 36, 226, 39, 180, 216, 117, 206, 212, 193, 95, 70, 32,
            57, 210, 118, 182, 106, 237, 58, 210, 26, 162, 202, 30, 54, 30, 12, 244, 75, 162, 106,
            153, 83, 16, 80, 52, 21, 73, 216, 167, 27, 32, 217, 159, 67, 98, 213, 45, 6, 139, 213,
            104, 169, 161, 29, 177, 200, 219, 151, 21, 237, 57, 183, 51, 130, 55, 236, 251, 6, 165,
            63, 170, 179, 104, 113, 27, 178, 9, 140, 94, 30, 45, 32, 155, 73, 255, 147, 89, 192,
            166, 232, 176, 64, 37, 63, 102, 249, 158, 216, 186, 28, 124, 154, 176, 63, 25, 79, 163,
            230, 101, 200, 104, 42, 159, 102, 218, 69, 102, 193, 81, 3, 20, 55, 242, 61, 21, 246,
            2, 47, 251, 76, 22, 179, 77, 121, 139, 254, 215, 208, 94, 125, 214, 119, 29, 81, 21,
            203, 135, 134, 3, 29, 134, 251, 96, 91, 16, 27, 206, 165, 161, 45, 148, 4, 141, 221,
            220, 25, 40, 228, 53, 126, 74, 185, 212, 1, 18, 16, 63, 95, 170, 118, 17, 61, 147, 129,
            9, 12, 75, 171, 193, 172, 47, 137, 106, 111, 230, 215, 126, 78, 145, 158, 247, 138, 29,
            146, 252, 71, 171, 168, 227, 17, 85, 44, 140, 100, 138, 168, 253, 40, 204, 144, 26,
            101, 25, 148, 160, 188, 190, 37, 50, 18, 36, 169, 187, 36, 170, 79, 54, 230, 163, 120,
            66, 109, 79, 158, 239, 4, 1, 188, 240, 151, 223, 92, 81, 176, 247, 131, 41, 234, 171,
            97, 254, 75, 145, 37, 239, 68, 40, 36, 225, 26, 237, 118, 160, 197, 160, 234, 108, 32,
            153, 247, 10, 158, 216, 3, 36, 68, 181, 137, 215, 152, 24, 104, 169, 92, 230, 191, 44,
            198, 136, 225, 24, 84, 144, 246, 43, 247, 52, 18, 142, 104, 51, 39, 235, 237, 55, 231,
            130, 142, 88, 128, 234, 179, 223, 245, 204, 201, 203, 233, 205, 3, 245, 214, 86, 246,
            235, 1, 86, 9, 70, 229, 46, 165, 75, 20, 43, 136, 209, 113, 133, 70, 173, 148, 99, 198,
            15, 55, 249, 224, 45, 196, 124, 69, 171, 86, 93, 138, 201, 245, 181, 219, 55, 202, 42,
            189, 190, 8, 80, 100, 7, 13, 37, 52, 125, 8, 214, 109, 252, 248, 228, 54, 72, 158, 73,
            241, 12, 153, 231, 59, 182, 71, 158, 74, 18, 34, 80, 207, 118, 143, 152, 153, 240, 65,
            112, 110, 87, 93, 87, 226, 12, 47, 67, 36, 168, 130, 179, 135, 25, 129, 208, 210, 137,
            231, 100, 163, 67, 228, 27, 149, 210, 242, 46, 224, 97, 72, 155, 127, 152, 67, 24, 156,
            124, 4, 171, 45, 87, 111, 55, 177, 21, 68, 142, 150, 103, 59, 59, 36, 202, 97, 39, 195,
            183, 183, 187, 58, 33, 82, 56, 7, 153, 244, 78, 49, 216, 149, 92, 233, 193, 205, 66,
            237, 27, 244, 67, 195, 1, 228, 136, 100, 130, 48, 127, 110, 103, 53, 217, 252, 147, 93,
            131, 193, 13, 238, 223, 204, 167, 35, 205, 84, 62, 149, 79, 68, 12, 155, 107, 207, 185,
            233, 71, 185, 155, 102, 133, 237, 239, 47, 27, 98, 230, 107, 86, 234, 181, 131, 214,
            146, 85, 178, 11, 152, 186, 183, 219, 250, 129, 40, 219, 246, 177, 130, 65, 109, 147,
            157, 28, 227, 26, 114, 247, 243, 237, 174, 62, 168, 174, 204, 255, 128, 168, 114, 233,
            4, 130, 66, 7, 120, 80, 202, 4, 176, 197, 166, 248, 106, 150, 37, 128, 137, 167, 93,
            24, 46, 205, 98, 254, 182, 194, 168, 17, 137, 204, 163, 107, 169, 50, 21, 86, 128, 13,
            12, 90, 110, 230, 222, 44, 243, 218, 137, 33, 84, 18, 100, 237, 126, 49, 171, 251, 157,
            236, 22, 45, 233, 249, 70, 10, 27, 80, 250, 135, 119, 107, 152, 8, 230, 237, 91, 5,
            175, 30, 147, 240, 214, 228, 33, 88, 250, 136, 13, 254, 188, 122, 193, 243, 204, 213,
            32, 227, 130, 34, 129, 126, 78, 102, 142, 229, 84, 111, 124, 25, 70, 155, 13, 215, 164,
            109, 75, 253, 88, 50, 27, 115, 167, 136, 224, 86, 119, 186, 177, 35, 29, 132, 238, 75,
            112, 96, 203, 52, 254, 247, 189, 194, 19, 34, 24, 125, 210, 201, 86, 187, 213, 149,
            244, 21, 67, 163, 230, 46, 190, 53, 121, 196, 19, 5, 102, 137, 36, 252, 188, 214, 153,
            115, 213, 20, 90, 117, 246, 71, 25, 18, 187, 242, 150, 70, 118, 8, 240, 99, 120, 61,
            65, 69, 206, 146, 168, 251, 48, 238, 70, 61, 74, 226, 53, 204, 41, 26, 69, 85, 247, 79,
            227, 228, 46, 52, 104, 176, 17, 28, 13, 233, 138, 167, 50, 242, 32, 243, 74, 48, 26,
            254, 231, 214, 102, 203, 97, 96, 95, 213, 178, 131, 75, 42, 143, 155, 175, 216, 30, 59,
            62, 98, 38, 95, 108, 230, 188, 149, 108, 192, 167, 101, 231, 39, 146, 7, 160, 123, 117,
            207, 169, 66, 81, 223, 11, 181, 27, 230, 182, 58, 192, 20, 154, 222, 189, 204, 176,
            190, 15, 182, 131, 162, 62, 126, 65, 222, 251, 182, 98, 217, 253, 217, 184, 137, 37,
            108, 187, 69, 66, 12, 4, 124, 135, 241, 168, 7, 30, 22, 192, 252, 45, 126, 46, 33, 179,
            233, 176, 61, 78, 138, 192, 52, 90, 222, 87, 35, 109, 46, 140, 232, 90, 39, 32, 36,
            241, 91, 214, 216, 31, 53, 178, 109, 158, 26, 63, 110, 29, 102, 69, 254, 218, 255, 193,
            163, 92, 91, 210, 242, 150, 52, 119, 229, 222, 177, 219, 229, 94, 246, 220, 132, 11,
            13, 100, 22, 227, 253, 50, 213, 60, 137, 197, 201, 42, 34, 254, 177, 166, 70, 160, 152,
            145, 113, 181, 69, 18, 189, 20, 153, 248, 90, 124, 202, 24, 197, 238, 238, 204, 85,
            195, 70, 222, 219, 100, 2, 71, 99, 176, 193, 230, 60, 238, 109, 10, 121, 124, 120, 99,
            32, 190, 253, 101, 45, 226, 135, 99, 227, 184, 15, 244, 35, 183, 149, 2, 191, 222, 106,
            96, 134, 32, 139, 113, 152, 73, 194, 43, 98, 139, 140, 234, 3, 47, 222, 114, 223, 58,
            107, 244, 137, 246, 100, 239, 50, 243, 73, 252, 111, 96, 2, 89, 171, 201, 2, 154, 73,
            26, 0, 197, 29, 24, 242, 15, 60, 141, 8, 31, 59, 63, 100,
        ];
        let mut r_nonce = BinaryString::with_capacity(r_nonce_bool.len());
        for x in r_nonce_bool {
            r_nonce.push(x);
        }

        let mut o_nonce = BinaryString::with_capacity(o_nonce_bool.len());
        for x in o_nonce_bool {
            o_nonce.push(x);
        }
        let our_private_key_p1 = ArithmeticECShare {
            value1: convert_str_to_u256(
                "F319C19CFF14BDE7A386245BB7442BD14722C8B79E904823077A2B80DB2FDA05",
            ),
            value2: convert_str_to_u256(
                "4B3DD1D6DE5306925FDA07BAC1880BBBAB22F628E98200A486E45F9BD10B2A08",
            ),
        };
        let our_private_key_p2 = ArithmeticECShare {
            value1: convert_str_to_u256(
                "57E7B6DE346FF5CB515902477A4BEAA6EF859B9227A4AE426C6BAD6D42C6B10A",
            ),
            value2: convert_str_to_u256(
                "0CAAE507561BEF39F27EFA8CB8C2DEEB4363A5693E21AE9EE5864DD270BA8702",
            ),
        };
        let our_private_key_p3 = ArithmeticECShare {
            value1: convert_str_to_u256(
                "B486D5CD76DCA58F362B172EAE7EFE01E06277F8F32EF61D661C19B77ADE3700",
            ),
            value2: convert_str_to_u256(
                "95B0E5223B24C9AD1A491444D4B5FE2A9CFFD18EB50D487F8095CBE40924B00D",
            ),
        };

        let params = [
            (
                remote_public_key,
                r_nonce.clone(),
                o_nonce.clone(),
                ciphertext.clone(),
                our_private_key_p1,
            ),
            (
                remote_public_key,
                r_nonce.clone(),
                o_nonce.clone(),
                ciphertext.clone(),
                our_private_key_p2,
            ),
            (
                remote_public_key,
                r_nonce.clone(),
                o_nonce.clone(),
                ciphertext.clone(),
                our_private_key_p3,
            ),
        ];

        let results = sim(SimpleMessageRelay::new(), &params).await;
        assert_eq!(results.len(), 3);

        let out_p1 = results[0].clone();
        let out_p2 = results[1].clone();
        let out_p3 = results[2].clone();

        let output = reconstruct_binary_string_share_to_string(
            convert_2_bytes(out_p1),
            convert_2_bytes(out_p2),
            convert_2_bytes(out_p3),
        );
        let required_output = r###"<Account xmlns="http://api.rebit.org.in/FISchema/deposit" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:schemaLocation="http://api.rebit.org.in/FISchema/deposit ../FISchema/deposit.xsd" linkedAccRef="f5192fed-6c9c-493b-b85d-aa8235c7399c" maskedAccNumber="XXXXXX8988" version="1.2" type="deposit"><Profile><Holders type="SINGLE"><Holder name="YOGESH  MALVIYA" dob="1992-09-04" mobile="9098597913" nominee="NOT-REGISTERED" email="yogzmalviya@gmail.com" pan="ECEPM3212A" ckycCompliance="false" /></Holders></Profile><Summary currentBalance="163.8" currency="INR" exchgeRate="" balanceDateTime="2022-12-14T14:01:16.628+05:30" type="SAVINGS" branch="BHOPAL - ARERA COLONY" facility="CC" ifscCode="KKBK0005886" micrCode="" openingDate="2021-10-13" currentODLimit="0" drawingLimit="163.80" status="ACTIVE"><Pending amount="0.0" /></Summary><Transactions startDate="2022-06-12" endDate="2022-12-14"><Transaction txnId="S25836278" type="DEBIT" mode="OTHERS" amount="400.0" currentBalance="1193.44" transactionTimestamp="2022-06-12T00:00:00+05:30" valueDate="2022-06-12" narration="1PCD/8587/KARNIKA MARKETING PRIV/REWA120622/16:56" reference="216311406416" /><Transaction txnId="S18628747" type="CREDIT" mode="OTHERS" amount="100.0" currentBalance="1193.44" transactionTimestamp="2022-06-12T00:00:00+05:30" valueDate="2022-06-12" narration="9UPI/YOGESH MALVIYA/216305036794/NA" reference="UPI-216377280207" /></Transactions></Account>""###;

        assert_eq!(required_output, output);
    }

    fn convert_2_bytes(vec: BinaryStringShare) -> Vec<BinaryStringShare> {
        let mut out: Vec<BinaryStringShare> = Vec::with_capacity((vec.length / 8) as usize);
        if vec.length % 8 != 0 {
            println!("incorrect sharings!!!");
        }
        for i in 0..((vec.length / 8) as usize) {
            let mut temp: BinaryStringShare = BinaryStringShare::with_capacity(8);
            for j in 0..8 {
                temp.push(vec.get(8 * i + j).0, vec.get(8 * i + j).1);
            }
            out.push(temp);
        }
        out
    }
}
