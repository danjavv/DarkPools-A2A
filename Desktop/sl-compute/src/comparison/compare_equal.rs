use crate::constants::{FIELD_LOG, FIELD_SIZE};
use crate::mpc::multiply_binary_shares::{run_batch_and_binary_shares, run_batch_or_binary_shares};
use crate::transport::proto::FilteredMsgRelay;
use crate::transport::setup::common::MPCEncryption;
use crate::transport::setup::CommonSetupMessage;
use crate::transport::types::ProtocolError;
#[cfg(any(test, feature = "test-support"))]
use crate::transport::utils::Seed;
use crate::transport::utils::TagOffsetCounter;
use crate::types::{BinaryArithmeticShare, BinaryShare, ByteShare, ServerState};
use sl_mpc_mate::coord::Relay;

/// Run CompareEqual protocol
pub async fn run_compare_eq<T, R>(
    setup: &T,
    mpc_encryption: &mut MPCEncryption,
    tag_offset_counter: &mut TagOffsetCounter,
    relay: &mut FilteredMsgRelay<R>,
    a_bin: &BinaryArithmeticShare,
    b_bin: &BinaryArithmeticShare,
    serverstate: &mut ServerState,
) -> Result<BinaryShare, ProtocolError>
where
    T: CommonSetupMessage,
    R: Relay,
{
    let temp = a_bin.xor(b_bin);

    let mut or_values = Vec::new();
    for i in 0..FIELD_SIZE {
        or_values.push(temp.get_binary_share(i));
    }

    for _ in 0..FIELD_LOG {
        let mut x_values = Vec::new();
        let mut y_values = Vec::new();
        for j in 0..(or_values.len() / 2) {
            x_values.push(or_values[j * 2]);
            y_values.push(or_values[j * 2 + 1]);
        }
        or_values = run_batch_or_binary_shares(
            setup,
            mpc_encryption,
            tag_offset_counter,
            relay,
            &x_values,
            &y_values,
            serverstate,
        )
        .await?;
    }
    assert_eq!(or_values.len(), 1);

    Ok(or_values[0].not())
}

/// Run CompareEqual protocol
pub async fn run_batch_compare_eq<T, R>(
    setup: &T,
    mpc_encryption: &mut MPCEncryption,
    tag_offset_counter: &mut TagOffsetCounter,
    relay: &mut FilteredMsgRelay<R>,
    a: &[BinaryArithmeticShare],
    b: &[BinaryArithmeticShare],
    serverstate: &mut ServerState,
) -> Result<Vec<BinaryShare>, ProtocolError>
where
    T: CommonSetupMessage,
    R: Relay,
{
    assert_eq!(a.len(), b.len());

    let n = a.len();
    let temp_values: Vec<BinaryArithmeticShare> =
        a.iter().zip(b.iter()).map(|(a, b)| a.xor(b)).collect();
    let mut or_values = Vec::new();
    for v in temp_values {
        for i in 0..FIELD_SIZE {
            or_values.push(v.get_binary_share(i));
        }
    }

    for k in 0..FIELD_LOG {
        let q = FIELD_SIZE >> k;
        let l = FIELD_SIZE >> (k + 1);
        let mut x_values = Vec::new();
        let mut y_values = Vec::new();
        for i in 0..n {
            for j in 0..l {
                x_values.push(or_values[i * q + j * 2]);
                y_values.push(or_values[i * q + (j * 2 + 1)]);
            }
        }
        or_values = run_batch_or_binary_shares(
            setup,
            mpc_encryption,
            tag_offset_counter,
            relay,
            &x_values,
            &y_values,
            serverstate,
        )
        .await?;
    }
    assert_eq!(or_values.len(), n);

    let out: Vec<BinaryShare> = or_values.iter().map(|x| x.not()).collect();

    Ok(out)
}

/// Run CompareEqual of two Vec<ByteShare>
pub async fn run_compare_eq_vec_bytes<T, R>(
    setup: &T,
    mpc_encryption: &mut MPCEncryption,
    tag_offset_counter: &mut TagOffsetCounter,
    relay: &mut FilteredMsgRelay<R>,
    a: &[ByteShare],
    b: &[ByteShare],
    serverstate: &mut ServerState,
) -> Result<BinaryShare, ProtocolError>
where
    T: CommonSetupMessage,
    R: Relay,
{
    let my_party_id = setup.participant_index();

    if a.len() != b.len() {
        return Ok(BinaryShare {
            value1: false,
            value2: false,
        });
    }

    let mut comp_res = BinaryShare::from_constant(true, my_party_id);

    let comp_out_values = run_batch_compare_eq_byte(
        setup,
        mpc_encryption,
        tag_offset_counter,
        relay,
        a,
        b,
        serverstate,
    )
    .await?;

    // TODO implement a more efficient algorithm with fewer messages
    #[allow(clippy::needless_range_loop)]
    for i in 0..a.len() {
        comp_res = run_batch_and_binary_shares(
            setup,
            mpc_encryption,
            tag_offset_counter,
            relay,
            &[comp_res],
            &[comp_out_values[i]],
            serverstate,
        )
        .await?[0];
    }

    Ok(comp_res)
}

/// Run CompareEqualByte protocol
pub async fn run_compare_eq_byte<T, R>(
    setup: &T,
    mpc_encryption: &mut MPCEncryption,
    tag_offset_counter: &mut TagOffsetCounter,
    relay: &mut FilteredMsgRelay<R>,
    a: &ByteShare,
    b: &ByteShare,
    serverstate: &mut ServerState,
) -> Result<BinaryShare, ProtocolError>
where
    T: CommonSetupMessage,
    R: Relay,
{
    let temp = a.xor(b);

    let mut or_values = Vec::new();
    for i in 0..8 {
        or_values.push(temp.get_binary_share(i));
    }

    for k in 0..3 {
        let l = 8 >> (k + 1);
        let mut x_values = Vec::new();
        let mut y_values = Vec::new();
        for j in 0..l {
            x_values.push(or_values[j * 2]);
        }
        for j in 0..l {
            y_values.push(or_values[j * 2 + 1]);
        }
        or_values = run_batch_or_binary_shares(
            setup,
            mpc_encryption,
            tag_offset_counter,
            relay,
            &x_values,
            &y_values,
            serverstate,
        )
        .await?;
    }
    assert_eq!(or_values.len(), 1);

    Ok(or_values[0].not())
}

/// Run batch CompareEqualByte protocol
pub async fn run_batch_compare_eq_byte<T, R>(
    setup: &T,
    mpc_encryption: &mut MPCEncryption,
    tag_offset_counter: &mut TagOffsetCounter,
    relay: &mut FilteredMsgRelay<R>,
    a: &[ByteShare],
    b: &[ByteShare],
    serverstate: &mut ServerState,
) -> Result<Vec<BinaryShare>, ProtocolError>
where
    T: CommonSetupMessage,
    R: Relay,
{
    assert_eq!(a.len(), b.len());

    let n = a.len();
    let temp_values: Vec<ByteShare> = a.iter().zip(b.iter()).map(|(a, b)| a.xor(b)).collect();
    let mut or_values = Vec::new();
    for v in temp_values {
        for i in 0..8 {
            or_values.push(v.get_binary_share(i));
        }
    }

    for k in 0..3 {
        let q = 8 >> k;
        let l = 8 >> (k + 1);
        let mut x_values = Vec::new();
        let mut y_values = Vec::new();
        for i in 0..n {
            for j in 0..l {
                x_values.push(or_values[i * q + j * 2]);
            }
            for j in 0..l {
                y_values.push(or_values[i * q + (j * 2 + 1)]);
            }
        }
        or_values = run_batch_or_binary_shares(
            setup,
            mpc_encryption,
            tag_offset_counter,
            relay,
            &x_values,
            &y_values,
            serverstate,
        )
        .await?;
    }
    assert_eq!(or_values.len(), n);

    let out: Vec<BinaryShare> = or_values.iter().map(|x| x.not()).collect();

    Ok(out)
}

/// Test CompareEqual of two Vec<ByteShare> protocol
#[cfg(any(test, feature = "test-support"))]
async fn test_compare_eq_vec_bytes_protocol<T, R>(
    setup: T,
    seed: Seed,
    params: (Vec<ByteShare>, Vec<ByteShare>),
    relay: R,
) -> Result<(usize, bool), ProtocolError>
where
    T: CommonSetupMessage,
    R: Relay,
{
    use crate::mpc::common_randomness::run_common_randomness;
    use crate::mpc::open_protocol::run_batch_open_binary_share;
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
    let result = run_compare_eq_vec_bytes(
        &setup,
        &mut mpc_encryption,
        &mut tag_offset_counter,
        &mut relay,
        &params.0,
        &params.1,
        &mut serverstate,
    )
    .await?;

    let result = run_batch_open_binary_share(
        &setup,
        &mut mpc_encryption,
        &mut tag_offset_counter,
        &mut relay,
        &[result],
        &mut serverstate,
    )
    .await?[0];

    let _ = relay.close().await;

    Ok((setup.participant_index(), result))
}

#[cfg(test)]
mod tests {
    use super::test_compare_eq_vec_bytes_protocol;
    use crate::proto::default_bytes_share;
    use crate::transport::test_utils::setup_mpc;
    use crate::types::{Binary, ByteShare};
    use sl_mpc_mate::coord::{MessageRelayService, Relay, SimpleMessageRelay};
    use tokio::task::JoinSet;

    async fn sim<S, R>(coord: S, sim_params: &[(Vec<ByteShare>, Vec<ByteShare>); 3]) -> Vec<Binary>
    where
        S: MessageRelayService<MessageRelay = R>,
        R: Relay + Send + 'static,
    {
        let parties = setup_mpc(None, sim_params);

        let mut jset = JoinSet::new();
        for (setup, seed, params) in parties {
            let relay = coord.connect().await.unwrap();

            jset.spawn(test_compare_eq_vec_bytes_protocol(
                setup, seed, params, relay,
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
    async fn test_compare_eq_vec_bytes() {
        let str_a_p1 = default_bytes_share("Amazon.com", 0);
        let str_a_p2 = default_bytes_share("Amazon.com", 1);
        let str_a_p3 = default_bytes_share("Amazon.com", 2);

        let str_b_p1 = default_bytes_share("Amazon.com", 0);
        let str_b_p2 = default_bytes_share("Amazon.com", 1);
        let str_b_p3 = default_bytes_share("Amazon.com", 2);

        let str_c_p1 = default_bytes_share("amazon.com", 0);
        let str_c_p2 = default_bytes_share("amazon.com", 1);
        let str_c_p3 = default_bytes_share("amazon.com", 2);

        let params = [
            (str_a_p1.clone(), str_b_p1.clone()),
            (str_a_p2.clone(), str_b_p2.clone()),
            (str_a_p3.clone(), str_b_p3.clone()),
        ];
        let results = sim(SimpleMessageRelay::new(), &params).await;
        assert_eq!(results.len(), 3);
        assert!(results[0]);
        assert!(results[1]);
        assert!(results[2]);

        let params = [
            (str_b_p1.clone(), str_c_p1.clone()),
            (str_b_p2.clone(), str_c_p2.clone()),
            (str_b_p3.clone(), str_c_p3.clone()),
        ];
        let results = sim(SimpleMessageRelay::new(), &params).await;
        assert_eq!(results.len(), 3);
        assert!(!results[0]);
        assert!(!results[1]);
        assert!(!results[2]);
    }
}
