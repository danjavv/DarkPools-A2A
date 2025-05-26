use crate::transport::proto::FilteredMsgRelay;
use crate::transport::setup::common::MPCEncryption;
use crate::transport::setup::CommonSetupMessage;
use crate::transport::types::ProtocolError;
#[cfg(any(test, feature = "test-support"))]
use crate::transport::utils::Seed;
use crate::transport::utils::TagOffsetCounter;

use crate::mpc::multiply_binary_shares::{
    run_and_binary_shares, run_and_binary_string_shares, run_batch_and_binary_shares,
    run_batch_and_binary_string_shares,
};
use crate::types::{BinaryArithmeticShare, ServerState};
use crate::types::{BinaryShare, BinaryStringShare};
use sl_mpc_mate::coord::Relay;

/// Implementation Protocol 2.9.1 IfThenElse
#[allow(clippy::too_many_arguments)]
pub async fn run_multiplexer_array<T, R>(
    setup: &T,
    mpc_encryption: &mut MPCEncryption,
    tag_offset_counter: &mut TagOffsetCounter,
    relay: &mut FilteredMsgRelay<R>,
    choice: &BinaryShare,
    x: &BinaryArithmeticShare,
    y: &BinaryArithmeticShare,
    serverstate: &mut ServerState,
) -> Result<BinaryArithmeticShare, ProtocolError>
where
    T: CommonSetupMessage,
    R: Relay,
{
    let z = x.xor(y);
    let c = BinaryArithmeticShare::from_choice(choice);
    let d = run_and_binary_string_shares(
        setup,
        mpc_encryption,
        tag_offset_counter,
        relay,
        &z.to_binary_string_share(),
        &c.to_binary_string_share(),
        serverstate,
    )
    .await?;
    let d = BinaryArithmeticShare::from_binary_string_share(&d);
    let r = d.xor(y);
    Ok(r)
}

/// Implementation Protocol 2.9.1 IfThenElse
#[allow(clippy::too_many_arguments)]
pub async fn run_batch_multiplexer_array<T, R>(
    setup: &T,
    mpc_encryption: &mut MPCEncryption,
    tag_offset_counter: &mut TagOffsetCounter,
    relay: &mut FilteredMsgRelay<R>,
    choice_values: &[BinaryShare],
    x_values: &[BinaryArithmeticShare],
    y_values: &[BinaryArithmeticShare],
    serverstate: &mut ServerState,
) -> Result<Vec<BinaryArithmeticShare>, ProtocolError>
where
    T: CommonSetupMessage,
    R: Relay,
{
    assert_eq!(choice_values.len(), x_values.len());
    assert_eq!(x_values.len(), y_values.len());

    let z_values: Vec<BinaryStringShare> = x_values
        .iter()
        .zip(y_values.iter())
        .map(|(x, y)| x.xor(y).to_binary_string_share())
        .collect();

    let c_values: Vec<BinaryStringShare> = choice_values
        .iter()
        .map(|c| BinaryArithmeticShare::from_choice(c).to_binary_string_share())
        .collect();

    let d_values = run_batch_and_binary_string_shares(
        setup,
        mpc_encryption,
        tag_offset_counter,
        relay,
        &z_values,
        &c_values,
        serverstate,
    )
    .await?;

    let r_values: Vec<BinaryArithmeticShare> = d_values
        .iter()
        .zip(y_values.iter())
        .map(|(d, y)| {
            let d = BinaryArithmeticShare::from_binary_string_share(d);
            d.xor(y)
        })
        .collect();

    Ok(r_values)
}

/// Test multiplexer_array protocol
#[cfg(any(test, feature = "test-support"))]
async fn test_multiplexer_array_protocol<T, R>(
    setup: T,
    seed: Seed,
    params: (BinaryShare, BinaryArithmeticShare, BinaryArithmeticShare),
    relay: R,
) -> Result<(usize, BinaryArithmeticShare), ProtocolError>
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

    let choice = params.0;
    let a = params.1;
    let b = params.2;
    let result = run_multiplexer_array(
        &setup,
        &mut mpc_encryption,
        &mut tag_offset_counter,
        &mut relay,
        &choice,
        &a,
        &b,
        &mut serverstate,
    )
    .await;

    let _ = relay.close().await;

    match result {
        Ok(v) => Ok((setup.participant_index(), v)),
        Err(e) => Err(e),
    }
}

/// Implementation Protocol 2.9.1 IfThenElse
#[allow(clippy::too_many_arguments)]
pub async fn run_multiplexer_bit<T, R>(
    setup: &T,
    mpc_encryption: &mut MPCEncryption,
    tag_offset_counter: &mut TagOffsetCounter,
    relay: &mut FilteredMsgRelay<R>,
    choice: &BinaryShare,
    x: &BinaryShare,
    y: &BinaryShare,
    serverstate: &mut ServerState,
) -> Result<BinaryShare, ProtocolError>
where
    T: CommonSetupMessage,
    R: Relay,
{
    let z = x.xor(y);
    let d = run_and_binary_shares(
        setup,
        mpc_encryption,
        tag_offset_counter,
        relay,
        &z,
        choice,
        serverstate,
    )
    .await?;
    let r = d.xor(y);
    Ok(r)
}

/// Implementation Protocol 2.9.1 IfThenElse
#[allow(clippy::too_many_arguments)]
pub async fn run_batch_multiplexer_bit<T, R>(
    setup: &T,
    mpc_encryption: &mut MPCEncryption,
    tag_offset_counter: &mut TagOffsetCounter,
    relay: &mut FilteredMsgRelay<R>,
    choice_values: &[BinaryShare],
    x_values: &[BinaryShare],
    y_values: &[BinaryShare],
    serverstate: &mut ServerState,
) -> Result<Vec<BinaryShare>, ProtocolError>
where
    T: CommonSetupMessage,
    R: Relay,
{
    assert_eq!(choice_values.len(), x_values.len());
    assert_eq!(x_values.len(), y_values.len());

    let z_values: Vec<BinaryShare> = x_values
        .iter()
        .zip(y_values.iter())
        .map(|(x, y)| x.xor(y))
        .collect();

    let d_values = run_batch_and_binary_shares(
        setup,
        mpc_encryption,
        tag_offset_counter,
        relay,
        &z_values,
        choice_values,
        serverstate,
    )
    .await?;

    let r_values: Vec<BinaryShare> = d_values
        .iter()
        .zip(y_values.iter())
        .map(|(d, y)| d.xor(y))
        .collect();

    Ok(r_values)
}

/// Test multiplexer_bit protocol
#[cfg(any(test, feature = "test-support"))]
async fn test_multiplexer_bit_protocol<T, R>(
    setup: T,
    seed: Seed,
    params: (BinaryShare, BinaryShare, BinaryShare),
    relay: R,
) -> Result<(usize, BinaryShare), ProtocolError>
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

    let choice = params.0;
    let a = params.1;
    let b = params.2;
    let result = run_multiplexer_bit(
        &setup,
        &mut mpc_encryption,
        &mut tag_offset_counter,
        &mut relay,
        &choice,
        &a,
        &b,
        &mut serverstate,
    )
    .await;

    let _ = relay.close().await;

    match result {
        Ok(v) => Ok((setup.participant_index(), v)),
        Err(e) => Err(e),
    }
}

/// Implementation Protocol 2.9.1 IfThenElse
#[allow(clippy::too_many_arguments)]
pub async fn run_multiplexer_vec<T, R>(
    setup: &T,
    mpc_encryption: &mut MPCEncryption,
    tag_offset_counter: &mut TagOffsetCounter,
    relay: &mut FilteredMsgRelay<R>,
    choice: &BinaryShare,
    x: &BinaryStringShare,
    y: &BinaryStringShare,
    serverstate: &mut ServerState,
) -> Result<BinaryStringShare, ProtocolError>
where
    T: CommonSetupMessage,
    R: Relay,
{
    assert_eq!(x.length, y.length);
    let z = x.xor(y);
    let c = BinaryStringShare::from_choice(choice, x.length as usize);
    let d = run_and_binary_string_shares(
        setup,
        mpc_encryption,
        tag_offset_counter,
        relay,
        &z,
        &c,
        serverstate,
    )
    .await?;
    let r = d.xor(y);
    Ok(r)
}

/// Test multiplexer_vec protocol
#[cfg(any(test, feature = "test-support"))]
async fn test_multiplexer_vec_protocol<T, R>(
    setup: T,
    seed: Seed,
    params: (BinaryShare, BinaryStringShare, BinaryStringShare),
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

    let choice = params.0;
    let a = params.1;
    let b = params.2;
    let result = run_multiplexer_vec(
        &setup,
        &mut mpc_encryption,
        &mut tag_offset_counter,
        &mut relay,
        &choice,
        &a,
        &b,
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
    use super::{
        test_multiplexer_array_protocol, test_multiplexer_bit_protocol,
        test_multiplexer_vec_protocol,
    };
    use crate::transport::test_utils::setup_mpc;
    use crate::types::{BinaryArithmeticShare, BinaryString};
    use crate::{
        constants::FIELD_SIZE,
        mpc::common_randomness::test_run_get_serverstate,
        proto::{binary_string_to_u8_vec, reconstruct_binary_share},
        types::{BinaryShare, BinaryStringShare},
    };
    use sl_mpc_mate::coord::{MessageRelayService, Relay, SimpleMessageRelay};
    use tokio::task::JoinSet;

    async fn sim_array<S, R>(
        coord: S,
        sim_params: &[(BinaryShare, BinaryArithmeticShare, BinaryArithmeticShare); 3],
    ) -> Vec<BinaryArithmeticShare>
    where
        S: MessageRelayService<MessageRelay = R>,
        R: Relay + Send + 'static,
    {
        let parties = setup_mpc(None, sim_params);

        let mut jset = JoinSet::new();
        for (setup, seed, params) in parties {
            let relay = coord.connect().await.unwrap();

            jset.spawn(test_multiplexer_array_protocol(setup, seed, params, relay));
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

    async fn sim_bit<S, R>(
        coord: S,
        sim_params: &[(BinaryShare, BinaryShare, BinaryShare); 3],
    ) -> Vec<BinaryShare>
    where
        S: MessageRelayService<MessageRelay = R>,
        R: Relay + Send + 'static,
    {
        let parties = setup_mpc(None, sim_params);

        let mut jset = JoinSet::new();
        for (setup, seed, params) in parties {
            let relay = coord.connect().await.unwrap();

            jset.spawn(test_multiplexer_bit_protocol(setup, seed, params, relay));
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

    async fn sim_vec<S, R>(
        coord: S,
        sim_params: &[(BinaryShare, BinaryStringShare, BinaryStringShare); 3],
    ) -> Vec<BinaryStringShare>
    where
        S: MessageRelayService<MessageRelay = R>,
        R: Relay + Send + 'static,
    {
        let parties = setup_mpc(None, sim_params);

        let mut jset = JoinSet::new();
        for (setup, seed, params) in parties {
            let relay = coord.connect().await.unwrap();

            jset.spawn(test_multiplexer_vec_protocol(setup, seed, params, relay));
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
    async fn test_multiplexer_array() {
        let choice_p1 = BinaryShare {
            value1: false,
            value2: true,
        };
        let choice_p2 = BinaryShare {
            value1: false,
            value2: true,
        };
        let choice_p3 = BinaryShare {
            value1: false,
            value2: true,
        };

        let mut a_p1: BinaryStringShare = BinaryStringShare::new();
        let mut a_p2: BinaryStringShare = BinaryStringShare::new();
        let mut a_p3: BinaryStringShare = BinaryStringShare::new();

        let mut b_p1: BinaryStringShare = BinaryStringShare::new();
        let mut b_p2: BinaryStringShare = BinaryStringShare::new();
        let mut b_p3: BinaryStringShare = BinaryStringShare::new();

        for _ in 0..FIELD_SIZE {
            a_p1.push(false, false);
            a_p2.push(false, false);
            a_p3.push(false, false);

            b_p1.push(false, true);
            b_p2.push(false, true);
            b_p3.push(false, true);
        }

        let params = [
            (
                choice_p1,
                BinaryArithmeticShare::from_binary_string_share(&a_p1),
                BinaryArithmeticShare::from_binary_string_share(&b_p1),
            ),
            (
                choice_p2,
                BinaryArithmeticShare::from_binary_string_share(&a_p2),
                BinaryArithmeticShare::from_binary_string_share(&b_p2),
            ),
            (
                choice_p3,
                BinaryArithmeticShare::from_binary_string_share(&a_p3),
                BinaryArithmeticShare::from_binary_string_share(&b_p3),
            ),
        ];

        let results = sim_array(SimpleMessageRelay::new(), &params).await;
        assert_eq!(results.len(), 3);

        let output_share_p1 = results[0].clone().to_binary_string_share();
        let output_share_p2 = results[1].clone().to_binary_string_share();
        let output_share_p3 = results[2].clone().to_binary_string_share();

        let mut out: BinaryString = BinaryString::with_capacity(FIELD_SIZE);
        for i in 0..FIELD_SIZE {
            out.push(reconstruct_binary_share(
                output_share_p1.get_binary_share(i),
                output_share_p2.get_binary_share(i),
                output_share_p3.get_binary_share(i),
            ));
        }
        let output = binary_string_to_u8_vec(out);

        let expected = vec![0, 0, 0, 0, 0, 0, 0, 0];
        assert_eq!(expected, output);
    }
}
