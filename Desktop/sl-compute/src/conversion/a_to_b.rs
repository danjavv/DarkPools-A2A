use super::helper_function::{
    run_batch_full_adder, run_full_adder, run_parallel_prefix_adder, FAInput, PPAState,
};
use crate::constants::{FIELD_LOG, FIELD_SIZE, FIELD_SIZE_BYTES};
#[cfg(any(test, feature = "test-support"))]
use crate::mpc::common_randomness::run_common_randomness;
use crate::mpc::multiply_binary_shares::{
    run_batch_and_binary_string_shares, run_batch_or_binary_string_shares,
};
use crate::mpc::verify::run_verify;
#[cfg(any(test, feature = "test-support"))]
use crate::transport::init::run_init;
use crate::transport::proto::FilteredMsgRelay;
use crate::transport::setup::common::MPCEncryption;
use crate::transport::setup::CommonSetupMessage;
use crate::transport::types::ProtocolError;
#[cfg(any(test, feature = "test-support"))]
use crate::transport::utils::Seed;
use crate::transport::utils::TagOffsetCounter;
use crate::types::{ArithmeticShare, BinaryArithmeticShare, BinaryStringShare, ServerState};
use crypto_bigint::Encoding;
use sl_mpc_mate::coord::Relay;

fn a2b_create_msg1(share: &ArithmeticShare, party_index: usize) -> FAInput {
    let sub = share.v1_sub_v2();
    let binary_share1: [u8; FIELD_SIZE_BYTES] = sub.to_le_bytes();
    let binary_share2: [u8; FIELD_SIZE_BYTES] = share.value2().to_le_bytes();

    let binary_x1 = BinaryStringShare {
        length: FIELD_SIZE as u64,
        value1: binary_share2.to_vec(),
        value2: binary_share2.to_vec(),
    };

    let binary_x2 = BinaryStringShare {
        length: FIELD_SIZE as u64,
        value1: [0u8; FIELD_SIZE_BYTES].to_vec(),
        value2: [0u8; FIELD_SIZE_BYTES].to_vec(),
    };

    let binary_x3 = BinaryStringShare {
        length: FIELD_SIZE as u64,
        value1: binary_share1.to_vec(),
        value2: [0u8; FIELD_SIZE_BYTES].to_vec(),
    };

    match party_index {
        0 => FAInput {
            a: binary_x1,
            b: binary_x2,
            carry: binary_x3,
        },
        1 => FAInput {
            a: binary_x3,
            b: binary_x1,
            carry: binary_x2,
        },
        _ => FAInput {
            a: binary_x2,
            b: binary_x3,
            carry: binary_x1,
        },
    }
}

/// Implementation of Protocol 2.1 (A2B) from https://github.com/silence-laboratories/research-silent-compute/blob/main/paper/main.pdf.
pub async fn run_arithmetic_to_boolean<T, R>(
    setup: &T,
    mpc_encryption: &mut MPCEncryption,
    tag_offset_counter: &mut TagOffsetCounter,
    relay: &mut FilteredMsgRelay<R>,
    share: &ArithmeticShare,
    serverstate: &mut ServerState,
) -> Result<BinaryArithmeticShare, ProtocolError>
where
    T: CommonSetupMessage,
    R: Relay,
{
    let my_party_id = setup.participant_index();

    let fa_in = a2b_create_msg1(share, my_party_id);
    let (carry, sum) = run_full_adder(
        setup,
        mpc_encryption,
        tag_offset_counter,
        relay,
        fa_in,
        serverstate,
    )
    .await?;

    let carry = BinaryArithmeticShare::from_binary_string_share(&carry)
        .left_shift(1)
        .to_binary_string_share();

    let (res, _) = run_parallel_prefix_adder(
        setup,
        mpc_encryption,
        tag_offset_counter,
        relay,
        &carry,
        &sum,
        serverstate,
    )
    .await?;

    Ok(BinaryArithmeticShare::from_binary_string_share(&res))
}

/// Implementation of Protocol 2.1 (A2B) from https://github.com/silence-laboratories/research-silent-compute/blob/main/paper/main.pdf.
pub async fn run_batch_arithmetic_to_boolean<T, R>(
    setup: &T,
    mpc_encryption: &mut MPCEncryption,
    tag_offset_counter: &mut TagOffsetCounter,
    relay: &mut FilteredMsgRelay<R>,
    shares: &[ArithmeticShare],
    serverstate: &mut ServerState,
) -> Result<Vec<BinaryArithmeticShare>, ProtocolError>
where
    T: CommonSetupMessage,
    R: Relay,
{
    let my_party_id = setup.participant_index();

    let fa_in_values = shares
        .iter()
        .map(|share| a2b_create_msg1(share, my_party_id))
        .collect::<Vec<_>>();

    let (carry_values, sum_values) = run_batch_full_adder(
        setup,
        mpc_encryption,
        tag_offset_counter,
        relay,
        &fa_in_values,
        serverstate,
    )
    .await?;

    let mut p_values = Vec::new();
    let mut new_carry_values = Vec::new();
    for i in 0..carry_values.len() {
        let carry = BinaryArithmeticShare::from_binary_string_share(&carry_values[i])
            .left_shift(1)
            .to_binary_string_share();

        // PPA Pre-computation
        // p = c xor s
        let p = carry.xor(&sum_values[i]);

        p_values.push(p);
        new_carry_values.push(carry);
    }

    // g = c ^ s
    let g_values = run_batch_and_binary_string_shares(
        setup,
        mpc_encryption,
        tag_offset_counter,
        relay,
        &new_carry_values,
        &sum_values,
        serverstate,
    )
    .await?;

    let mut ppa_state: Vec<PPAState> = g_values
        .iter()
        .zip(p_values.iter())
        .map(|(g, p)| PPAState {
            g: g.clone(),
            p: p.clone(),
        })
        .collect();

    // PPA Prefix-propagation
    for step in 0..FIELD_LOG {
        let mut and_a_values = Vec::new();
        let mut and_b_values = Vec::new();
        let mut or_b_values = Vec::new();
        for state in ppa_state.iter() {
            let pc = &state.p;
            let gc = &state.g;

            let g_to_and_1 = gc._slice(0, FIELD_SIZE - (1usize << step));
            let p_to_and_2 = pc._slice(0, FIELD_SIZE - (1usize << step));
            let p_to_and_1_2 = pc._slice(1usize << step, FIELD_SIZE);
            let g_to_or = gc._slice(1usize << step, FIELD_SIZE);

            and_a_values.push(g_to_and_1);
            and_a_values.push(p_to_and_2);
            and_b_values.push(p_to_and_1_2.clone());
            and_b_values.push(p_to_and_1_2);

            or_b_values.push(g_to_or);
        }

        let res_values = run_batch_and_binary_string_shares(
            setup,
            mpc_encryption,
            tag_offset_counter,
            relay,
            &and_a_values,
            &and_b_values,
            serverstate,
        )
        .await?;

        let mut or_a_values = Vec::new();
        let mut pc_after_and_values = Vec::new();
        for i in 0..(res_values.len() / 2) {
            or_a_values.push(res_values[i * 2].clone());
            pc_after_and_values.push(res_values[i * 2 + 1].clone())
        }

        let gc_after_or_values = run_batch_or_binary_string_shares(
            setup,
            mpc_encryption,
            tag_offset_counter,
            relay,
            &or_a_values,
            &or_b_values,
            serverstate,
        )
        .await?;

        let mut new_ppa_state = Vec::new();
        for (j, state) in ppa_state.iter().enumerate() {
            let mut pc = state.p.clone();
            let mut gc = state.g.clone();

            for i in (1usize << step)..FIELD_SIZE {
                pc.set_binary_share(
                    i,
                    &pc_after_and_values[j].get_binary_share(i - (1usize << step)),
                );
                gc.set_binary_share(
                    i,
                    &gc_after_or_values[j].get_binary_share(i - (1usize << step)),
                );
            }
            new_ppa_state.push(PPAState { g: gc, p: pc });
        }

        ppa_state = new_ppa_state;
    }

    // PPA Sum computation
    let sum_p1: Vec<BinaryArithmeticShare> = p_values
        .iter()
        .zip(ppa_state.iter())
        .map(|(p, state)| {
            let p = BinaryArithmeticShare::from_binary_string_share(p);
            let g = BinaryArithmeticShare::from_binary_string_share(&state.g);
            p.xor(&g.left_shift(1))
        })
        .collect();

    Ok(sum_p1)
}

/// Test ArithmeticToBoolean protocol
#[cfg(any(test, feature = "test-support"))]
async fn test_a_to_b_protocol<T, R>(
    setup: T,
    seed: Seed,
    share: ArithmeticShare,
    relay: R,
) -> Result<(usize, BinaryArithmeticShare), ProtocolError>
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
    let result = run_batch_arithmetic_to_boolean(
        &setup,
        &mut mpc_encryption,
        &mut tag_offset_counter,
        &mut relay,
        &[share],
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
        Ok(v) => Ok((setup.participant_index(), v[0])),
        Err(e) => Err(e),
    }
}

#[cfg(test)]
mod tests {
    use crate::conversion::a_to_b::test_a_to_b_protocol;
    use crate::proto::{convert_bin_to_arith, reconstruct_binary_arith_share};
    use crate::transport::test_utils::setup_mpc;
    use crate::types::{ArithmeticShare, BinaryArithmeticShare, FieldElement};
    use sl_mpc_mate::coord::{MessageRelayService, Relay, SimpleMessageRelay};
    use tokio::task::JoinSet;

    async fn sim<S, R>(coord: S, sim_params: &[ArithmeticShare; 3]) -> Vec<BinaryArithmeticShare>
    where
        S: MessageRelayService<MessageRelay = R>,
        R: Relay + Send + 'static,
    {
        let parties = setup_mpc(None, sim_params);

        let mut jset = JoinSet::new();
        for (setup, seed, share) in parties {
            let relay = coord.connect().await.unwrap();

            jset.spawn(test_a_to_b_protocol(setup, seed, share, relay));
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
    async fn test_arithmetic_to_boolean_protocol() {
        let share_p1 =
            ArithmeticShare::new(FieldElement::from(38829u64), FieldElement::from(12123u64));
        let share_p2 =
            ArithmeticShare::new(FieldElement::from(38830u64), FieldElement::from(26707u64));
        let share_p3 =
            ArithmeticShare::new(FieldElement::from(53413u64), FieldElement::from(26706u64));

        let arithmetic_shares = [share_p1, share_p2, share_p3];

        let results = sim(SimpleMessageRelay::new(), &arithmetic_shares).await;
        assert_eq!(results.len(), 3);

        let outbin = reconstruct_binary_arith_share(&results[0], &results[1], &results[2]);
        let outarr = convert_bin_to_arith(outbin);
        let required_output = FieldElement::from(65536u64);

        assert_eq!(required_output, outarr);
    }
}
