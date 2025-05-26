use super::hmac::run_hmac;
use crate::transport::proto::FilteredMsgRelay;
use crate::transport::setup::common::MPCEncryption;
use crate::transport::setup::CommonSetupMessage;
use crate::transport::types::ProtocolError;
#[cfg(any(test, feature = "test-support"))]
use crate::transport::utils::Seed;
use crate::transport::utils::TagOffsetCounter;
use crate::types::{FieldElement, ServerState};
use crate::{
    constants::{FIELD_SIZE, SHA_BLOCK_LEN},
    proto::convert_arith_to_bin,
    types::BinaryStringShare,
};
use sl_mpc_mate::coord::Relay;

/// HKDF function. Follows the standards in https://datatracker.ietf.org/doc/html/rfc5869.
#[allow(clippy::too_many_arguments)]
pub async fn run_hkdf<T, R>(
    setup: &T,
    mpc_encryption: &mut MPCEncryption,
    tag_offset_counter: &mut TagOffsetCounter,
    relay: &mut FilteredMsgRelay<R>,
    length: usize,
    salt: &BinaryStringShare,
    input_key_material: &BinaryStringShare,
    info: &BinaryStringShare,
    serverstate: &mut ServerState,
) -> Result<BinaryStringShare, ProtocolError>
where
    T: CommonSetupMessage,
    R: Relay,
{
    let prk_p = run_hmac(
        setup,
        mpc_encryption,
        tag_offset_counter,
        relay,
        salt,
        input_key_material,
        serverstate,
    )
    .await?;

    if length > 255 * SHA_BLOCK_LEN {
        println!("Cannot expand to more than 255 * HashLen bits of output")
    }

    let mut output_key_p = BinaryStringShare::with_capacity(length);
    let block_p: BinaryStringShare = BinaryStringShare::with_capacity(length);
    let mut block_index = 1;
    while (output_key_p.length as usize) < length {
        let block_id_bool =
            convert_arith_to_bin(FIELD_SIZE, &FieldElement::from(block_index as u64));
        let mut blockidshares = BinaryStringShare::with_capacity(8);

        for i in 0..8 {
            blockidshares.push(false, block_id_bool.get(7 - i));
        }

        let mut message_p = BinaryStringShare::with_capacity(256 + info.length as usize + 8);

        message_p.extend(&block_p);
        message_p.extend(info);
        message_p.extend(&blockidshares);

        let block_p = run_hmac(
            setup,
            mpc_encryption,
            tag_offset_counter,
            relay,
            &prk_p,
            &message_p,
            serverstate,
        )
        .await?;

        let mut count = 0;
        while (output_key_p.length as usize) < length && count < (block_p.length as usize) {
            output_key_p.push_binary_share(block_p.get_binary_share(count));
            count += 1;
        }
        block_index += 1;
    }

    Ok(output_key_p)
}

/// Test HKDF protocol
#[cfg(any(test, feature = "test-support"))]
async fn test_hkdf_protocol<T, R>(
    setup: T,
    seed: Seed,
    params: (
        usize,
        BinaryStringShare,
        BinaryStringShare,
        BinaryStringShare,
    ),
    relay: R,
) -> Result<(usize, BinaryStringShare), ProtocolError>
where
    T: CommonSetupMessage,
    R: Relay,
{
    use crate::mpc::common_randomness::run_common_randomness;
    use crate::transport::init::run_init;
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

    let length = params.0;
    let salt = params.1;
    let input_key_material = params.2;
    let info = params.3;
    let result = run_hkdf(
        &setup,
        &mut mpc_encryption,
        &mut tag_offset_counter,
        &mut relay,
        length,
        &salt,
        &input_key_material,
        &info,
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
    use crate::transport::test_utils::setup_mpc;
    use crate::utility::hkdf::test_hkdf_protocol;
    use crate::{
        proto::{binary_string_to_u8_vec, reconstruct_binary_share},
        types::{BinaryString, BinaryStringShare},
    };
    use sl_mpc_mate::coord::{MessageRelayService, Relay, SimpleMessageRelay};
    use tokio::task::JoinSet;

    async fn sim<S, R>(
        coord: S,
        sim_params: &[(
            usize,
            BinaryStringShare,
            BinaryStringShare,
            BinaryStringShare,
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

            jset.spawn(test_hkdf_protocol(setup, seed, params, relay));
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
    async fn test_hkdf() {
        let mut salt_p1: BinaryStringShare = BinaryStringShare::new();
        let mut salt_p2: BinaryStringShare = BinaryStringShare::new();
        let mut salt_p3: BinaryStringShare = BinaryStringShare::new();
        for _ in 0..160 {
            salt_p1.push(false, true);
            salt_p2.push(false, true);
            salt_p3.push(false, true);
        }

        let mut input_key_material_p1: BinaryStringShare = BinaryStringShare::new();
        let mut input_key_material_p2: BinaryStringShare = BinaryStringShare::new();
        let mut input_key_material_p3: BinaryStringShare = BinaryStringShare::new();
        for _ in 0..256 {
            input_key_material_p1.push(false, true);
            input_key_material_p2.push(false, true);
            input_key_material_p3.push(false, true);
        }

        let info_p1: BinaryStringShare = BinaryStringShare::new();
        let info_p2: BinaryStringShare = BinaryStringShare::new();
        let info_p3: BinaryStringShare = BinaryStringShare::new();

        let length = 256usize;

        let params = [
            (length, salt_p1, input_key_material_p1, info_p1),
            (length, salt_p2, input_key_material_p2, info_p2),
            (length, salt_p3, input_key_material_p3, info_p3),
        ];

        let results = sim(SimpleMessageRelay::new(), &params).await;
        assert_eq!(results.len(), 3);

        let output_share_p1 = results[0].clone();
        let output_share_p2 = results[1].clone();
        let output_share_p3 = results[2].clone();

        let mut out: BinaryString = BinaryString::with_capacity(length);
        for i in 0..length {
            out.push(reconstruct_binary_share(
                output_share_p1.get_binary_share(i),
                output_share_p2.get_binary_share(i),
                output_share_p3.get_binary_share(i),
            ));
        }
        let output = binary_string_to_u8_vec(out);

        let expected_output: Vec<u8> = vec![
            202, 12, 106, 243, 59, 178, 4, 55, 143, 166, 102, 230, 77, 34, 86, 58, 153, 108, 141,
            175, 117, 11, 122, 128, 123, 63, 52, 60, 217, 243, 233, 57,
        ];
        assert_eq!(expected_output, output);
    }
}
