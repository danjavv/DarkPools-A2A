use crate::transport::proto::FilteredMsgRelay;
use crate::transport::setup::common::MPCEncryption;
use crate::transport::setup::CommonSetupMessage;
use crate::transport::types::ProtocolError;
#[cfg(any(test, feature = "test-support"))]
use crate::transport::utils::Seed;
use crate::transport::utils::TagOffsetCounter;
use crate::types::ServerState;
use crate::utility::sha256::run_sha_256;
use crate::{
    constants::{FIELD_SIZE, SHA_BLOCK_LEN},
    types::BinaryStringShare,
};
use sl_mpc_mate::coord::Relay;

/// HMAC function. Follows the standards in https://datatracker.ietf.org/doc/html/rfc2104.
pub async fn run_hmac<T, R>(
    setup: &T,
    mpc_encryption: &mut MPCEncryption,
    tag_offset_counter: &mut TagOffsetCounter,
    relay: &mut FilteredMsgRelay<R>,
    key: &BinaryStringShare,
    message: &BinaryStringShare,
    serverstate: &mut ServerState,
) -> Result<BinaryStringShare, ProtocolError>
where
    T: CommonSetupMessage,
    R: Relay,
{
    let mut resized_key: BinaryStringShare;

    if key.length as usize > SHA_BLOCK_LEN {
        let temp_resized_key = run_sha_256(
            setup,
            mpc_encryption,
            tag_offset_counter,
            relay,
            key,
            serverstate,
        )
        .await?;
        resized_key = temp_resized_key;
    } else {
        resized_key = key.clone();
        for _ in key.length as usize..SHA_BLOCK_LEN {
            resized_key.push(false, false);
        }
    }

    let mut i_key_pad_p = resized_key.clone();
    let mut o_key_pad_p = resized_key.clone();
    for i in 0..FIELD_SIZE {
        o_key_pad_p.set_binary_share(8 * i + 1, &o_key_pad_p.get_binary_share(8 * i + 1).not());

        o_key_pad_p.set_binary_share(8 * i + 3, &o_key_pad_p.get_binary_share(8 * i + 3).not());

        o_key_pad_p.set_binary_share(8 * i + 4, &o_key_pad_p.get_binary_share(8 * i + 4).not());

        o_key_pad_p.set_binary_share(8 * i + 5, &o_key_pad_p.get_binary_share(8 * i + 5).not());

        i_key_pad_p.set_binary_share(8 * i + 3, &i_key_pad_p.get_binary_share(8 * i + 3).not());

        i_key_pad_p.set_binary_share(8 * i + 2, &i_key_pad_p.get_binary_share(8 * i + 2).not());

        i_key_pad_p.set_binary_share(8 * i + 6, &i_key_pad_p.get_binary_share(8 * i + 6).not());

        i_key_pad_p.set_binary_share(8 * i + 5, &i_key_pad_p.get_binary_share(8 * i + 5).not());
    }

    for i in 0..(message.length as usize) {
        i_key_pad_p.push_binary_share(message.get_binary_share(i));
    }

    let inner_hash_p = run_sha_256(
        setup,
        mpc_encryption,
        tag_offset_counter,
        relay,
        &i_key_pad_p,
        serverstate,
    )
    .await?;

    for i in 0..(inner_hash_p.length as usize) {
        o_key_pad_p.push_binary_share(inner_hash_p.get_binary_share(i));
    }

    let output_p = run_sha_256(
        setup,
        mpc_encryption,
        tag_offset_counter,
        relay,
        &o_key_pad_p,
        serverstate,
    )
    .await?;

    Ok(output_p)
}

/// Test HMAC protocol
#[cfg(any(test, feature = "test-support"))]
async fn test_hmac_protocol<T, R>(
    setup: T,
    seed: Seed,
    params: (BinaryStringShare, BinaryStringShare),
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

    let key = params.0;
    let message = params.1;
    let result = run_hmac(
        &setup,
        &mut mpc_encryption,
        &mut tag_offset_counter,
        &mut relay,
        &key,
        &message,
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
    use crate::utility::hmac::test_hmac_protocol;
    use crate::{
        constants::SHA_CHAIN_LEN,
        proto::{binary_string_to_u8_vec, reconstruct_binary_share},
        types::{BinaryString, BinaryStringShare},
    };
    use sl_mpc_mate::coord::{MessageRelayService, Relay, SimpleMessageRelay};
    use tokio::task::JoinSet;

    async fn sim<S, R>(
        coord: S,
        sim_params: &[(BinaryStringShare, BinaryStringShare); 3],
    ) -> Vec<BinaryStringShare>
    where
        S: MessageRelayService<MessageRelay = R>,
        R: Relay + Send + 'static,
    {
        let parties = setup_mpc(None, sim_params);

        let mut jset = JoinSet::new();
        for (setup, seed, params) in parties {
            let relay = coord.connect().await.unwrap();

            jset.spawn(test_hmac_protocol(setup, seed, params, relay));
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
    async fn test_hmac() {
        let mut key_p1: BinaryStringShare = BinaryStringShare::with_capacity(128);
        let mut key_p2: BinaryStringShare = BinaryStringShare::with_capacity(128);
        let mut key_p3: BinaryStringShare = BinaryStringShare::with_capacity(128);

        let mut message_p1: BinaryStringShare = BinaryStringShare::with_capacity(128);
        let mut message_p2: BinaryStringShare = BinaryStringShare::with_capacity(128);
        let mut message_p3: BinaryStringShare = BinaryStringShare::with_capacity(128);

        for _ in 0..128 {
            key_p1.push(false, false);
            key_p2.push(false, false);
            key_p3.push(false, false);

            message_p1.push(false, false);
            message_p2.push(false, false);
            message_p3.push(false, false);
        }

        let params = [
            (key_p1, message_p1),
            (key_p2, message_p2),
            (key_p3, message_p3),
        ];

        let results = sim(SimpleMessageRelay::new(), &params).await;
        assert_eq!(results.len(), 3);

        let output_share_p1 = results[0].clone();
        let output_share_p2 = results[1].clone();
        let output_share_p3 = results[2].clone();

        let mut out: BinaryString = BinaryString::with_capacity(SHA_CHAIN_LEN);
        for i in 0..SHA_CHAIN_LEN {
            out.push(reconstruct_binary_share(
                output_share_p1.get_binary_share(i),
                output_share_p2.get_binary_share(i),
                output_share_p3.get_binary_share(i),
            ));
        }
        let output = binary_string_to_u8_vec(out);

        let expected_output: Vec<u8> = vec![
            133, 60, 116, 3, 147, 125, 139, 98, 57, 86, 155, 24, 78, 183, 153, 63, 197, 247, 81,
            174, 252, 234, 40, 242, 200, 99, 133, 142, 45, 41, 197, 11,
        ];

        assert_eq!(expected_output, output)
    }
}
