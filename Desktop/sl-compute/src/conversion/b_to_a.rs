use super::helper_function::{run_full_adder, run_parallel_prefix_adder, FAInput, PPAState};
use crate::constants::{FIELD_LOG, FIELD_SIZE};
#[cfg(any(test, feature = "test-support"))]
use crate::mpc::common_randomness::run_common_randomness;
use crate::mpc::multiply_binary_shares::{
    run_batch_and_binary_string_shares, run_batch_or_binary_string_shares,
};
use crate::mpc::open_protocol::run_batch_open_bin_arith_to_party_1_and_2;
use crate::proto::convert_bin_to_arith;
#[cfg(any(test, feature = "test-support"))]
use crate::transport::init::run_init;
use crate::transport::proto::FilteredMsgRelay;
use crate::transport::setup::common::MPCEncryption;
use crate::transport::setup::CommonSetupMessage;
use crate::transport::types::ProtocolError;
#[cfg(any(test, feature = "test-support"))]
use crate::transport::utils::Seed;
use crate::transport::utils::TagOffsetCounter;
use crate::types::{
    ArithmeticShare, BinaryArithmeticShare, BinaryString, BinaryStringShare, Block, ServerState,
};
use rand::{Rng, SeedableRng};
use rand_xorshift::XorShiftRng;
use sl_mpc_mate::coord::Relay;

#[derive(Clone)]
struct B2AMsg1 {
    pub value: BinaryString,
    pub share: BinaryStringShare,
}

#[derive(Clone)]
struct B2AMsg2 {
    pub value: BinaryString,
    pub share: BinaryStringShare,
}

fn b2a_create_msg1_p1(key1: Block, key3: Block) -> B2AMsg1 {
    let mut rng1 = XorShiftRng::from_seed(key1);
    let mut rng3 = XorShiftRng::from_seed(key3);

    let mut temp: BinaryString = BinaryString::with_capacity(FIELD_SIZE);
    for _ in 0..FIELD_SIZE {
        temp.push(false);
    }
    let mut x2_binary: BinaryStringShare = BinaryStringShare::with_capacity(FIELD_SIZE);
    for _ in 0..FIELD_SIZE {
        let s1 = rng1.gen_bool(0.5);
        let s3 = rng3.gen_bool(0.5);
        x2_binary.push(s3 ^ s1, s1);
    }
    B2AMsg1 {
        value: temp,
        share: x2_binary,
    }
}

fn b2a_create_msg1_p2(key1: Block, key2: Block, key3: Block) -> B2AMsg1 {
    let mut rng1 = XorShiftRng::from_seed(key1);
    let mut rng2 = XorShiftRng::from_seed(key2);
    let mut rng3 = XorShiftRng::from_seed(key3);

    let mut x2: BinaryString = BinaryString::with_capacity(FIELD_SIZE);
    let mut x2_binary: BinaryStringShare = BinaryStringShare::with_capacity(FIELD_SIZE);

    for _ in 0..FIELD_SIZE {
        let s1 = rng1.gen_bool(0.5);
        let s2 = rng2.gen_bool(0.5);
        let s3 = rng3.gen_bool(0.5);
        x2_binary.push(s2 ^ s1, s2);
        x2.push(s1 ^ s2 ^ s3);
    }

    B2AMsg1 {
        value: x2,
        share: x2_binary,
    }
}

fn b2a_create_msg1_p3(key1: Block, key2: Block, key3: Block) -> B2AMsg1 {
    let mut rng1 = XorShiftRng::from_seed(key1);
    let mut rng2 = XorShiftRng::from_seed(key2);
    let mut rng3 = XorShiftRng::from_seed(key3);

    let mut x2: BinaryString = BinaryString::with_capacity(FIELD_SIZE);
    let mut x2_binary: BinaryStringShare = BinaryStringShare::with_capacity(FIELD_SIZE);

    for _ in 0..FIELD_SIZE {
        let s1 = rng1.gen_bool(0.5);
        let s2 = rng2.gen_bool(0.5);
        let s3 = rng3.gen_bool(0.5);
        x2_binary.push(s2 ^ s3, s3);
        x2.push(s1 ^ s2 ^ s3);
    }

    B2AMsg1 {
        value: x2,
        share: x2_binary,
    }
}

fn b2a_create_msg2_p1(key1: Block, key2: Block, key3: Block) -> B2AMsg2 {
    let mut rng1 = XorShiftRng::from_seed(key1);
    let mut rng2 = XorShiftRng::from_seed(key2);
    let mut rng3 = XorShiftRng::from_seed(key3);

    let mut x3: BinaryString = BinaryString::with_capacity(FIELD_SIZE);
    let mut x3_binary: BinaryStringShare = BinaryStringShare::with_capacity(FIELD_SIZE);

    for _ in 0..FIELD_SIZE {
        let s1 = rng1.gen_bool(0.5);
        let s2 = rng2.gen_bool(0.5);
        let s3 = rng3.gen_bool(0.5);
        x3_binary.push(s3 ^ s1, s1);
        x3.push(s1 ^ s2 ^ s3);
    }

    B2AMsg2 {
        value: x3,
        share: x3_binary,
    }
}

fn b2a_create_msg2_p2(key1: Block, key2: Block) -> B2AMsg2 {
    let mut rng1 = XorShiftRng::from_seed(key1);
    let mut rng2 = XorShiftRng::from_seed(key2);

    let mut temp: BinaryString = BinaryString::with_capacity(FIELD_SIZE);
    for _ in 0..FIELD_SIZE {
        temp.push(false);
    }
    let mut x3_binary: BinaryStringShare = BinaryStringShare::with_capacity(FIELD_SIZE);
    for _ in 0..FIELD_SIZE {
        let s1 = rng1.gen_bool(0.5);
        let s2 = rng2.gen_bool(0.5);
        x3_binary.push(s1 ^ s2, s2);
    }
    B2AMsg2 {
        value: temp,
        share: x3_binary,
    }
}

fn b2a_create_msg2_p3(key1: Block, key2: Block, key3: Block) -> B2AMsg2 {
    let mut rng1 = XorShiftRng::from_seed(key1);
    let mut rng2 = XorShiftRng::from_seed(key2);
    let mut rng3 = XorShiftRng::from_seed(key3);

    let mut x3: BinaryString = BinaryString::with_capacity(FIELD_SIZE);
    let mut x3_binary: BinaryStringShare = BinaryStringShare::with_capacity(FIELD_SIZE);

    for _ in 0..FIELD_SIZE {
        let s1 = rng1.gen_bool(0.5);
        let s2 = rng2.gen_bool(0.5);
        let s3 = rng3.gen_bool(0.5);
        x3_binary.push(s3 ^ s2, s3);
        x3.push(s1 ^ s2 ^ s3);
    }

    B2AMsg2 {
        value: x3,
        share: x3_binary,
    }
}

/// Run BooleanToArithmetic protocol
pub async fn run_boolean_to_arithmetic<T, R>(
    setup: &T,
    mpc_encryption: &mut MPCEncryption,
    tag_offset_counter: &mut TagOffsetCounter,
    relay: &mut FilteredMsgRelay<R>,
    share: &BinaryArithmeticShare,
    serverstate: &mut ServerState,
) -> Result<ArithmeticShare, ProtocolError>
where
    T: CommonSetupMessage,
    R: Relay,
{
    let share = &share.to_binary_string_share();

    let my_party_id = setup.participant_index();

    let x2_key1: Block = [0; 16];
    let x2_key2: Block = [0; 16];
    let x2_key3: Block = [0; 16];

    let x3_key1: Block = [0; 16];
    let x3_key2: Block = [0; 16];
    let x3_key3: Block = [0; 16];

    let binary_x2 = match my_party_id {
        0 => b2a_create_msg1_p1(x2_key1, x2_key3),
        1 => b2a_create_msg1_p2(x2_key1, x2_key2, x2_key3),
        _ => b2a_create_msg1_p3(x2_key1, x2_key2, x2_key3),
    };

    let binary_x3 = match my_party_id {
        0 => b2a_create_msg2_p1(x3_key1, x3_key2, x3_key3),
        1 => b2a_create_msg2_p2(x3_key1, x3_key2),
        _ => b2a_create_msg2_p3(x3_key1, x3_key2, x3_key3),
    };

    let fa_in = FAInput {
        a: share.clone(),
        b: binary_x2.share,
        carry: binary_x3.share,
    };
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

    let sum_p = BinaryArithmeticShare::from_binary_string_share(&res);

    let opened_value = run_batch_open_bin_arith_to_party_1_and_2(
        setup,
        mpc_encryption,
        tag_offset_counter,
        relay,
        &[sum_p],
        serverstate,
    )
    .await?[0];

    let share_arithmetic = match my_party_id {
        0 => {
            // Open x1 to P1 and generate arithmetic sharing of x
            let x1_p1 = convert_bin_to_arith(opened_value.to_binary_string(FIELD_SIZE));
            let x3_p1 = ArithmeticShare::neg_field(&convert_bin_to_arith(binary_x3.value));
            ArithmeticShare::from_own_value_and_other(&x1_p1, &x3_p1)
        }
        1 => {
            // Open x1 to P2 and generate arithmetic sharing of x
            let x1_p2 = convert_bin_to_arith(opened_value.to_binary_string(FIELD_SIZE));
            let x2_p2 = ArithmeticShare::neg_field(&convert_bin_to_arith(binary_x2.value));
            ArithmeticShare::from_own_value_and_other(&x2_p2, &x1_p2)
        }
        _ => {
            // Generate arithmetic sharing of x for P3
            let x2_p3 = ArithmeticShare::neg_field(&convert_bin_to_arith(binary_x2.value));
            let x3_p3 = ArithmeticShare::neg_field(&convert_bin_to_arith(binary_x3.value));
            ArithmeticShare::from_own_value_and_other(&x3_p3, &x2_p3)
        }
    };

    Ok(share_arithmetic)
}

/// Run batch BooleanToArithmetic protocol
pub async fn run_batch_boolean_to_arithmetic<T, R>(
    setup: &T,
    mpc_encryption: &mut MPCEncryption,
    tag_offset_counter: &mut TagOffsetCounter,
    relay: &mut FilteredMsgRelay<R>,
    shares: &[BinaryArithmeticShare],
    serverstate: &mut ServerState,
) -> Result<Vec<ArithmeticShare>, ProtocolError>
where
    T: CommonSetupMessage,
    R: Relay,
{
    let my_party_id = setup.participant_index();

    let x2_key1: Block = [0; 16];
    let x2_key2: Block = [0; 16];
    let x2_key3: Block = [0; 16];

    let x3_key1: Block = [0; 16];
    let x3_key2: Block = [0; 16];
    let x3_key3: Block = [0; 16];

    let mut binary_x2 = Vec::new();
    let mut binary_x3 = Vec::new();
    for _ in 0..shares.len() {
        binary_x2.push(match my_party_id {
            0 => b2a_create_msg1_p1(x2_key1, x2_key3),
            1 => b2a_create_msg1_p2(x2_key1, x2_key2, x2_key3),
            _ => b2a_create_msg1_p3(x2_key1, x2_key2, x2_key3),
        });
        binary_x3.push(match my_party_id {
            0 => b2a_create_msg2_p1(x3_key1, x3_key2, x3_key3),
            1 => b2a_create_msg2_p2(x3_key1, x3_key2),
            _ => b2a_create_msg2_p3(x3_key1, x3_key2, x3_key3),
        });
    }

    let mut sum_values = Vec::new();
    let mut a_and_values = Vec::new();
    let mut b_and_values = Vec::new();
    for i in 0..shares.len() {
        let x1 = shares[i].to_binary_string_share();
        let x2 = binary_x2[i].share.clone();
        let x3 = binary_x3[i].share.clone();

        let xor_temp = x1.xor(&x2);
        let sum = xor_temp.xor(&x3);

        sum_values.push(sum);

        a_and_values.push(x1);
        a_and_values.push(xor_temp);
        b_and_values.push(x2);
        b_and_values.push(x3);
    }

    let res = run_batch_and_binary_string_shares(
        setup,
        mpc_encryption,
        tag_offset_counter,
        relay,
        &a_and_values,
        &b_and_values,
        serverstate,
    )
    .await?;

    let mut p_values = Vec::new();
    let mut carry_values = Vec::new();
    for i in 0..(res.len() / 2) {
        let carry = res[i * 2].xor(&res[i * 2 + 1]);
        let carry = BinaryArithmeticShare::from_binary_string_share(&carry)
            .left_shift(1)
            .to_binary_string_share();

        // PPA Pre-computation
        // p = c xor s
        let p = carry.xor(&sum_values[i]);

        p_values.push(p);
        carry_values.push(carry);
    }

    // g = c ^ s
    let g_values = run_batch_and_binary_string_shares(
        setup,
        mpc_encryption,
        tag_offset_counter,
        relay,
        &carry_values,
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
    let sum_p: Vec<BinaryArithmeticShare> = p_values
        .iter()
        .zip(ppa_state.iter())
        .map(|(p, state)| {
            let p = BinaryArithmeticShare::from_binary_string_share(p);
            let g = BinaryArithmeticShare::from_binary_string_share(&state.g);
            p.xor(&g.left_shift(1))
        })
        .collect();

    let opened_values = run_batch_open_bin_arith_to_party_1_and_2(
        setup,
        mpc_encryption,
        tag_offset_counter,
        relay,
        &sum_p,
        serverstate,
    )
    .await?;

    let share_arithmetic_values = match my_party_id {
        0 => {
            opened_values
                .iter()
                .zip(binary_x3.iter())
                .map(|(opened_value, binary_x3)| {
                    // Open x1 to P1 and generate arithmetic sharing of x
                    let x1_p1 = convert_bin_to_arith(opened_value.to_binary_string(FIELD_SIZE));
                    let x3_p1 =
                        ArithmeticShare::neg_field(&convert_bin_to_arith(binary_x3.value.clone()));
                    ArithmeticShare::from_own_value_and_other(&x1_p1, &x3_p1)
                })
                .collect()
        }
        1 => {
            opened_values
                .iter()
                .zip(binary_x2.iter())
                .map(|(opened_value, binary_x2)| {
                    // Open x1 to P2 and generate arithmetic sharing of x
                    let x1_p2 = convert_bin_to_arith(opened_value.to_binary_string(FIELD_SIZE));
                    let x2_p2 =
                        ArithmeticShare::neg_field(&convert_bin_to_arith(binary_x2.value.clone()));
                    ArithmeticShare::from_own_value_and_other(&x2_p2, &x1_p2)
                })
                .collect()
        }
        _ => {
            binary_x2
                .iter()
                .zip(binary_x3.iter())
                .map(|(binary_x2, binary_x3)| {
                    // Generate arithmetic sharing of x for P3
                    let x2_p3 =
                        ArithmeticShare::neg_field(&convert_bin_to_arith(binary_x2.value.clone()));
                    let x3_p3 =
                        ArithmeticShare::neg_field(&convert_bin_to_arith(binary_x3.value.clone()));
                    ArithmeticShare::from_own_value_and_other(&x3_p3, &x2_p3)
                })
                .collect()
        }
    };

    Ok(share_arithmetic_values)
}

/// Test BooleanToArithmetic protocol
#[cfg(any(test, feature = "test-support"))]
async fn test_boolean_to_arithmetic<T, R>(
    setup: T,
    seed: Seed,
    share: BinaryArithmeticShare,
    relay: R,
) -> Result<(usize, ArithmeticShare), ProtocolError>
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
    let result = run_batch_boolean_to_arithmetic(
        &setup,
        &mut mpc_encryption,
        &mut tag_offset_counter,
        &mut relay,
        &[share],
        &mut serverstate,
    )
    .await;

    let _ = relay.close().await;

    match result {
        Ok(v) => Ok((setup.participant_index(), v[0])),
        Err(e) => Err(e),
    }
}

#[cfg(test)]
mod tests {
    use crate::conversion::b_to_a::test_boolean_to_arithmetic;
    use crate::proto::reconstruct_arith;
    use crate::transport::test_utils::setup_mpc;
    use crate::types::{ArithmeticShare, BinaryArithmeticShare, FieldElement};
    use sl_mpc_mate::coord::{MessageRelayService, Relay, SimpleMessageRelay};
    use tokio::task::JoinSet;

    async fn sim<S, R>(coord: S, shares: &[BinaryArithmeticShare; 3]) -> Vec<ArithmeticShare>
    where
        S: MessageRelayService<MessageRelay = R>,
        R: Relay + Send + 'static,
    {
        let parties = setup_mpc(None, shares);

        let mut jset = JoinSet::new();
        for (setup, seed, share) in parties {
            let relay = coord.connect().await.unwrap();

            jset.spawn(test_boolean_to_arithmetic(setup, seed, share, relay));
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
    async fn test_boolean_to_arithmetic_protocol() {
        let required_output = FieldElement::from(1234u64);

        let share_p1 = BinaryArithmeticShare::from_constant(&required_output, 0);
        let share_p2 = BinaryArithmeticShare::from_constant(&required_output, 1);
        let share_p3 = BinaryArithmeticShare::from_constant(&required_output, 2);

        let binary_shares = [share_p1, share_p2, share_p3];

        let results = sim(SimpleMessageRelay::new(), &binary_shares).await;
        assert_eq!(results.len(), 3);
        let share_arithmetic_p1 = results[0];
        let share_arithmetic_p2 = results[1];
        let share_arithmetic_p3 = results[2];

        let out = reconstruct_arith(
            share_arithmetic_p1,
            share_arithmetic_p2,
            share_arithmetic_p3,
        );
        println!("{:?}", out);
        assert_eq!(required_output, out);
    }
}
