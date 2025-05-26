use crate::conversion::helper_function::{run_full_adder_bit, run_parallel_prefix_adder};
use crate::mpc::common_randomness::run_common_randomness;
use crate::mpc::verify::run_verify;
use crate::transport::init::run_init;
use crate::transport::proto::FilteredMsgRelay;
use crate::transport::setup::common::MPCEncryption;
use crate::transport::setup::CommonSetupMessage;
use crate::transport::types::ProtocolError;
use crate::transport::utils::{Seed, TagOffsetCounter};
use crate::{
    constants::EC_FIELD_SIZE,
    proto::convert_u256_to_bin,
    types::{BinaryShare, BinaryStringShare, ServerState},
    utility::helper::get_modulus,
};
use sl_mpc_mate::coord::Relay;

/// Implementation of Protocol 2.1 (BinaryECSubtract) from https://github.com/silence-laboratories/sl-compute/blob/sahamati-queries/docs.pdf
pub async fn run_binary_ec_subtract<T, R>(
    setup: &T,
    mpc_encryption: &mut MPCEncryption,
    tag_offset_counter: &mut TagOffsetCounter,
    relay: &mut FilteredMsgRelay<R>,
    share: &BinaryStringShare,
    serverstate: &mut ServerState,
) -> Result<BinaryStringShare, ProtocolError>
where
    T: CommonSetupMessage,
    R: Relay,
{
    assert_eq!(share.length as usize, EC_FIELD_SIZE);

    let my_party_id = setup.participant_index();

    let p = get_modulus();
    let pbin = convert_u256_to_bin(p);
    let pbin_p = BinaryStringShare::from_constant(&pbin, my_party_id);

    let (output_p, carry_p) = run_parallel_prefix_adder(
        setup,
        mpc_encryption,
        tag_offset_counter,
        relay,
        share,
        &pbin_p.not(),
        serverstate,
    )
    .await?;

    let mut t = BinaryStringShare::zero(EC_FIELD_SIZE);
    t.set_binary_share(0, &carry_p);

    let (output_p, _) = run_parallel_prefix_adder(
        setup,
        mpc_encryption,
        tag_offset_counter,
        relay,
        &output_p,
        &t,
        serverstate,
    )
    .await?;

    Ok(output_p)
}

/// Implementation of Section 2.2 from https://github.com/silence-laboratories/sl-compute/blob/sahamati-queries/docs.pdf
pub async fn run_binary_ec_long_subtract<T, R>(
    setup: &T,
    mpc_encryption: &mut MPCEncryption,
    tag_offset_counter: &mut TagOffsetCounter,
    relay: &mut FilteredMsgRelay<R>,
    share: &BinaryStringShare,
    serverstate: &mut ServerState,
) -> Result<BinaryStringShare, ProtocolError>
where
    T: CommonSetupMessage,
    R: Relay,
{
    assert_eq!(share.length as usize, EC_FIELD_SIZE + 1);

    let my_party_id = setup.participant_index();

    let p = get_modulus();
    let pbin = convert_u256_to_bin(p);
    let pbin_p = BinaryStringShare::from_constant(&pbin, my_party_id);

    let share_last_bit = share.get_binary_share(EC_FIELD_SIZE);
    let share_1 = share._slice(0, EC_FIELD_SIZE);

    let (output, carry_bit) = run_parallel_prefix_adder(
        setup,
        mpc_encryption,
        tag_offset_counter,
        relay,
        &share_1,
        &pbin_p.not(),
        serverstate,
    )
    .await?;

    let (carry_bit, output_last_bit) = run_full_adder_bit(
        setup,
        mpc_encryption,
        tag_offset_counter,
        relay,
        share_last_bit,
        BinaryShare::ZERO.not(),
        carry_bit,
        serverstate,
    )
    .await?;

    let mut t = BinaryStringShare::zero(EC_FIELD_SIZE);
    t.set_binary_share(0, &carry_bit);

    let (output, carry_bit) = run_parallel_prefix_adder(
        setup,
        mpc_encryption,
        tag_offset_counter,
        relay,
        &output,
        &t,
        serverstate,
    )
    .await?;

    let (_, output_last_bit) = run_full_adder_bit(
        setup,
        mpc_encryption,
        tag_offset_counter,
        relay,
        output_last_bit,
        BinaryShare::ZERO,
        carry_bit,
        serverstate,
    )
    .await?;

    let mut output = output;
    output.push_binary_share(output_last_bit);

    Ok(output)
}

/// Test BinaryECSubtract protocol
#[cfg(any(test, feature = "test-support"))]
async fn test_binary_ec_subtract_protocol<T, R>(
    setup: T,
    seed: Seed,
    share: BinaryStringShare,
    relay: R,
) -> Result<(usize, BinaryStringShare), ProtocolError>
where
    T: CommonSetupMessage,
    R: Relay,
{
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
    let result = run_binary_ec_subtract(
        &setup,
        &mut mpc_encryption,
        &mut tag_offset_counter,
        &mut relay,
        &share,
        &mut serverstate,
    )
    .await;

    run_verify(
        &setup,
        &mut mpc_encryption,
        &mut tag_offset_counter,
        &mut relay,
        &mut serverstate,
    )
    .await?;

    let _ = relay.close().await;

    match result {
        Ok(v) => Ok((setup.participant_index(), v)),
        Err(e) => Err(e),
    }
}

/// Test BinaryECLongSubtract protocol
#[cfg(any(test, feature = "test-support"))]
async fn test_binary_ec_long_subtract_protocol<T, R>(
    setup: T,
    seed: Seed,
    share: BinaryStringShare,
    relay: R,
) -> Result<(usize, BinaryStringShare), ProtocolError>
where
    T: CommonSetupMessage,
    R: Relay,
{
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
    let result = run_binary_ec_long_subtract(
        &setup,
        &mut mpc_encryption,
        &mut tag_offset_counter,
        &mut relay,
        &share,
        &mut serverstate,
    )
    .await;

    run_verify(
        &setup,
        &mut mpc_encryption,
        &mut tag_offset_counter,
        &mut relay,
        &mut serverstate,
    )
    .await?;

    let _ = relay.close().await;

    match result {
        Ok(v) => Ok((setup.participant_index(), v)),
        Err(e) => Err(e),
    }
}

#[cfg(test)]
mod tests {
    use crate::conversion::binary_ec_subtract::{
        test_binary_ec_long_subtract_protocol, test_binary_ec_subtract_protocol,
    };
    use crate::transport::test_utils::setup_mpc;
    use crate::{
        constants::EC_FIELD_SIZE,
        proto::{convert_bin_to_u256, convert_u256_to_bin, reconstruct_binary_share},
        types::{BinaryString, BinaryStringShare},
        utility::helper::get_modulus,
    };
    use crypto_bigint::{CheckedAdd, U256};
    use sl_mpc_mate::coord::{MessageRelayService, Relay, SimpleMessageRelay};
    use tokio::task::JoinSet;

    async fn sim1<S, R>(coord: S, sim_params: &[BinaryStringShare; 3]) -> Vec<BinaryStringShare>
    where
        S: MessageRelayService<MessageRelay = R>,
        R: Relay + Send + 'static,
    {
        let parties = setup_mpc(None, sim_params);

        let mut jset = JoinSet::new();
        for (setup, seed, share) in parties {
            let relay = coord.connect().await.unwrap();

            jset.spawn(test_binary_ec_subtract_protocol(setup, seed, share, relay));
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

    async fn sim2<S, R>(coord: S, sim_params: &[BinaryStringShare; 3]) -> Vec<BinaryStringShare>
    where
        S: MessageRelayService<MessageRelay = R>,
        R: Relay + Send + 'static,
    {
        let parties = setup_mpc(None, sim_params);

        let mut jset = JoinSet::new();
        for (setup, seed, share) in parties {
            let relay = coord.connect().await.unwrap();

            jset.spawn(test_binary_ec_long_subtract_protocol(
                setup, seed, share, relay,
            ));
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
    async fn test_binary_ec_subtract() {
        let a = get_modulus().checked_add(&U256::from(10u8)).unwrap();
        let p = get_modulus();
        let abin = convert_u256_to_bin(a);

        let mut share_p1 = BinaryStringShare::from_constant(&abin, 0);
        let mut share_p2 = BinaryStringShare::from_constant(&abin, 1);
        let mut share_p3 = BinaryStringShare::from_constant(&abin, 2);

        let params = [share_p1, share_p2, share_p3];

        let results = sim1(SimpleMessageRelay::new(), &params).await;
        assert_eq!(results.len(), 3);

        let output_p1 = results[0].clone();
        let output_p2 = results[1].clone();
        let output_p3 = results[2].clone();

        let mut output: BinaryString = BinaryString::with_capacity(EC_FIELD_SIZE);
        for i in 0..EC_FIELD_SIZE {
            output.push(reconstruct_binary_share(
                output_p1.get_binary_share(i),
                output_p2.get_binary_share(i),
                output_p3.get_binary_share(i),
            ));
        }

        let outar = convert_bin_to_u256(output);
        let required_output = a.wrapping_sub(&p);
        assert_eq!(outar, required_output)
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_binary_ec_long_subtract() {
        let a = get_modulus().checked_add(&U256::from(10u8)).unwrap();
        let p = get_modulus();
        let abin = convert_u256_to_bin(a);

        let mut share_p1 = BinaryStringShare::from_constant(&abin, 0);
        let mut share_p2 = BinaryStringShare::from_constant(&abin, 1);
        let mut share_p3 = BinaryStringShare::from_constant(&abin, 2);
        share_p1.push(false, false);
        share_p2.push(false, false);
        share_p3.push(false, false);

        let params = [share_p1, share_p2, share_p3];

        let results = sim2(SimpleMessageRelay::new(), &params).await;
        assert_eq!(results.len(), 3);

        let output_p1 = results[0].clone();
        let output_p2 = results[1].clone();
        let output_p3 = results[2].clone();

        assert_eq!(output_p1.length as usize, EC_FIELD_SIZE + 1);
        assert_eq!(output_p2.length as usize, EC_FIELD_SIZE + 1);
        assert_eq!(output_p3.length as usize, EC_FIELD_SIZE + 1);

        let mut output: BinaryString = BinaryString::with_capacity(EC_FIELD_SIZE);
        for i in 0..EC_FIELD_SIZE {
            output.push(reconstruct_binary_share(
                output_p1.get_binary_share(i),
                output_p2.get_binary_share(i),
                output_p3.get_binary_share(i),
            ));
        }

        let outar = convert_bin_to_u256(output);
        let required_output = a.wrapping_sub(&p);
        assert_eq!(outar, required_output)
    }
}
