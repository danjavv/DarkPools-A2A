use crate::constants::OPEN_TO_MSG;
use crate::galois_abb::{
    run_batch_receive_input_galois_from, run_batch_send_input_galois_from,
    run_galois_inner_product_with_error, run_galois_multiplication_with_error,
    run_map_galois_multiplication_with_error, run_output_galois, GaloisElement, GaloisShare,
};
use crate::mpc::common_randomness::run_common_randomness;
use crate::transport::init::run_init;
use crate::transport::proto::FilteredMsgRelay;
use crate::transport::setup::common::MPCEncryption;
use crate::transport::setup::CommonSetupMessage;
use crate::transport::types::ProtocolError;
use crate::transport::utils::{p2p_send_to_next_receive_from_prev, Seed, TagOffsetCounter};
use crate::types::{BinaryArithmeticShare, ServerState};
use aead::rand_core::{CryptoRng, RngCore, SeedableRng};
use rand::Rng;
use rand_chacha::ChaCha20Rng;
use sl_mpc_mate::coord::Relay;
use sl_mpc_mate::message::MessageTag;

fn permute<R>(mut d: Vec<usize>, rng: &mut R) -> Vec<usize>
where
    R: CryptoRng + RngCore,
{
    let m = d.len();
    for j in 0..m {
        let index = rng.gen_range(j..m);
        d.swap(j, index);
    }
    d
}

fn apply_permutation(arr: &[GaloisElement], perm: &[usize]) -> Vec<GaloisElement> {
    assert_eq!(arr.len(), perm.len());
    let mut permuted_vec = vec![GaloisElement::ZERO; arr.len()];
    for (i, &p) in perm.iter().enumerate() {
        permuted_vec[i].clone_from(&arr[p]);
    }
    permuted_vec
}

/// Two Party Shuffle With Error
pub async fn run_shuffle_with_error<T, R, G>(
    setup: &T,
    mpc_encryption: &mut MPCEncryption,
    tag_offset_counter: &mut TagOffsetCounter,
    relay: &mut FilteredMsgRelay<R>,
    shares_0: &[GaloisShare],
    shares_1: &[GaloisShare],
    perm: &[usize],
    party_i: usize,
    party_j: usize,
    rng: &mut G,
) -> Result<(Vec<GaloisShare>, Vec<GaloisShare>), ProtocolError>
where
    T: CommonSetupMessage,
    R: Relay,
    G: CryptoRng + RngCore,
{
    assert_eq!(shares_0.len(), perm.len());
    assert_eq!(shares_1.len(), perm.len());
    assert_ne!(party_i, party_j);
    assert!(party_i <= 2);
    assert!(party_j <= 2);
    let n = shares_0.len();

    let my_party_index = setup.participant_index();

    let open_tag_1 = MessageTag::tag1(OPEN_TO_MSG, tag_offset_counter.next_value());
    let open_tag_2 = MessageTag::tag1(OPEN_TO_MSG, tag_offset_counter.next_value());
    relay.ask_messages(setup, open_tag_1, true).await?;
    relay.ask_messages(setup, open_tag_2, true).await?;

    let check_tag = MessageTag::tag1(OPEN_TO_MSG, tag_offset_counter.next_value());
    relay.ask_messages(setup, check_tag, true).await?;

    let (e_shares, f_shares) = if my_party_index == party_i {
        // acts as P_i
        let c_values_0: Vec<GaloisElement> = shares_0
            .iter()
            .map(|share| share.value1.add(&share.value2))
            .collect();
        let c_values_1: Vec<GaloisElement> = shares_1
            .iter()
            .map(|share| share.value1.add(&share.value2))
            .collect();

        let mut e_values_0 = apply_permutation(&c_values_0, perm);
        let e_values_1 = apply_permutation(&c_values_1, perm);

        e_values_0.extend_from_slice(&e_values_1);
        let e_shares = run_batch_send_input_galois_from(
            setup,
            mpc_encryption,
            open_tag_1,
            relay,
            &e_values_0,
            rng,
        )
        .await?;

        let f_shares = run_batch_receive_input_galois_from(
            setup,
            mpc_encryption,
            open_tag_2,
            check_tag,
            relay,
            party_j,
            2 * n,
        )
        .await?;

        (e_shares, f_shares)
    } else if my_party_index == party_j {
        // acts as P_j
        let d_values_0: Vec<GaloisElement> = shares_0.iter().map(|share| share.value2).collect();
        let d_values_1: Vec<GaloisElement> = shares_1.iter().map(|share| share.value2).collect();

        let mut f_values_0 = apply_permutation(&d_values_0, perm);
        let f_values_1 = apply_permutation(&d_values_1, perm);

        f_values_0.extend_from_slice(&f_values_1);
        let f_shares = run_batch_send_input_galois_from(
            setup,
            mpc_encryption,
            open_tag_2,
            relay,
            &f_values_0,
            rng,
        )
        .await?;

        let e_shares = run_batch_receive_input_galois_from(
            setup,
            mpc_encryption,
            open_tag_1,
            check_tag,
            relay,
            party_i,
            2 * n,
        )
        .await?;

        (e_shares, f_shares)
    } else {
        // acts as third party
        let e_shares = run_batch_receive_input_galois_from(
            setup,
            mpc_encryption,
            open_tag_1,
            check_tag,
            relay,
            party_i,
            2 * n,
        )
        .await?;

        let f_shares = run_batch_receive_input_galois_from(
            setup,
            mpc_encryption,
            open_tag_2,
            check_tag,
            relay,
            party_j,
            2 * n,
        )
        .await?;

        (e_shares, f_shares)
    };

    assert_eq!(e_shares.len(), 2 * n);
    assert_eq!(f_shares.len(), 2 * n);

    let g_shares: Vec<GaloisShare> = e_shares
        .iter()
        .zip(f_shares.iter())
        .map(|(e, f)| e.add_share(f))
        .collect();

    let (a, b) = g_shares.split_at(n);
    Ok((a.to_vec(), b.to_vec()))
}

/// Three-party Shuffle
pub async fn run_shuffle<T, R, G>(
    setup: &T,
    mpc_encryption: &mut MPCEncryption,
    tag_offset_counter: &mut TagOffsetCounter,
    relay: &mut FilteredMsgRelay<R>,
    shares: &[BinaryArithmeticShare],
    serverstate: &mut ServerState,
    rng: &mut G,
) -> Result<Vec<BinaryArithmeticShare>, ProtocolError>
where
    T: CommonSetupMessage,
    R: Relay,
    G: CryptoRng + RngCore,
{
    let my_party_index = setup.participant_index();
    let n = shares.len();

    let b_shares: Vec<GaloisShare> = shares
        .iter()
        .map(|share| GaloisShare::from_bit_arr(share))
        .collect();

    let tag_offset = tag_offset_counter.next_value();
    let open_tag = MessageTag::tag1(OPEN_TO_MSG, tag_offset);
    relay.ask_messages(setup, open_tag, true).await?;

    let k_i: [u8; 32] = rng.gen();
    let k_from_prev =
        p2p_send_to_next_receive_from_prev(setup, mpc_encryption, open_tag, k_i, relay).await?;
    if k_i == k_from_prev {
        return Err(ProtocolError::VerificationError);
    }
    let mut rng1 = ChaCha20Rng::from_seed(k_i);
    let mut rng2 = ChaCha20Rng::from_seed(k_from_prev);

    let p: Vec<usize> = (0..n).collect();
    let (p01, p12, p20) = match my_party_index {
        0 => (
            permute(p.clone(), &mut rng1),
            p.clone(),
            permute(p, &mut rng2),
        ),
        1 => (
            permute(p.clone(), &mut rng2),
            permute(p.clone(), &mut rng1),
            p,
        ),
        _ => (
            p.clone(),
            permute(p.clone(), &mut rng2),
            permute(p, &mut rng1),
        ),
    };

    let alpha = GaloisShare::galois_rand(&mut serverstate.common_randomness);
    let u_shares = run_map_galois_multiplication_with_error(
        setup,
        mpc_encryption,
        tag_offset_counter,
        relay,
        &b_shares,
        &alpha,
        rng,
    )
    .await?;

    // shuffle p0-p1
    let (mut c_shares, mut v_shares) = run_shuffle_with_error(
        setup,
        mpc_encryption,
        tag_offset_counter,
        relay,
        &b_shares,
        &u_shares,
        &p01,
        0,
        1,
        rng,
    )
    .await?;

    // shuffle p1-p2
    let (d_shares, w_shares) = run_shuffle_with_error(
        setup,
        mpc_encryption,
        tag_offset_counter,
        relay,
        &c_shares,
        &v_shares,
        &p12,
        1,
        2,
        rng,
    )
    .await?;

    // shuffle p2-p0
    let (e_shares, x_shares) = run_shuffle_with_error(
        setup,
        mpc_encryption,
        tag_offset_counter,
        relay,
        &d_shares,
        &w_shares,
        &p20,
        2,
        0,
        rng,
    )
    .await?;

    let a_shares = vec![GaloisShare::galois_rand(&mut serverstate.common_randomness); 3 * n];
    c_shares.extend_from_slice(&d_shares);
    c_shares.extend_from_slice(&e_shares);
    v_shares.extend_from_slice(&w_shares);
    v_shares.extend_from_slice(&x_shares);

    let s = run_galois_inner_product_with_error(
        setup,
        mpc_encryption,
        tag_offset_counter,
        relay,
        &a_shares,
        &c_shares,
        rng,
    )
    .await?;

    let t = run_galois_inner_product_with_error(
        setup,
        mpc_encryption,
        tag_offset_counter,
        relay,
        &a_shares,
        &v_shares,
        rng,
    )
    .await?;

    let u = run_galois_multiplication_with_error(
        setup,
        mpc_encryption,
        tag_offset_counter,
        relay,
        &s,
        &alpha,
        rng,
    )
    .await?
    .add_share(&t);

    let open_u = run_output_galois(setup, mpc_encryption, tag_offset_counter, relay, &u).await?;

    if open_u != GaloisElement::ZERO {
        return Err(ProtocolError::VerificationError);
    }

    let output: Vec<BinaryArithmeticShare> =
        e_shares.iter().map(|share| share.to_bit_arr()).collect();

    Ok(output)
}

/// Test Shuffle protocol
#[cfg(any(test, feature = "test-support"))]
async fn test_shuffle_protocol<T, R>(
    setup: T,
    seed: Seed,
    shares: Vec<BinaryArithmeticShare>,
    relay: R,
) -> Result<(usize, Vec<BinaryArithmeticShare>), ProtocolError>
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
    let mut rng_seed = [0u8; 32];
    let mut transcript = Transcript::new(b"test");
    transcript.append_message(b"seed", &seed);
    transcript.challenge_bytes(b"init-seed", &mut init_seed);
    transcript.challenge_bytes(b"common-randomness-seed", &mut common_randomness_seed);
    transcript.challenge_bytes(b"rng_seed", &mut rng_seed);

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
    let mut rng = ChaCha20Rng::from_seed(rng_seed);
    let result = run_shuffle(
        &setup,
        &mut mpc_encryption,
        &mut tag_offset_counter,
        &mut relay,
        &shares,
        &mut serverstate,
        &mut rng,
    )
    .await;

    let _ = relay.close().await;

    println!("tag_offset_counter = {}", tag_offset_counter.next_value());

    match result {
        Ok(v) => Ok((setup.participant_index(), v)),
        Err(e) => Err(e),
    }
}

#[cfg(test)]
mod tests {
    use crate::constants::FIELD_SIZE;
    use crate::proto::{
        convert_arith_to_bin, convert_bin_to_arith, get_default_bin_share_from_bin_string,
        reconstruct_binary_arith_share,
    };
    use crate::transport::test_utils::setup_mpc;
    use crate::types::{BinaryArithmeticShare, FieldElement};
    use crate::utility::shuffle::test_shuffle_protocol;
    use sl_mpc_mate::coord::{MessageRelayService, Relay, SimpleMessageRelay};
    use tokio::task::JoinSet;

    async fn sim<S, R>(
        coord: S,
        shares: &[Vec<BinaryArithmeticShare>; 3],
    ) -> Vec<Vec<BinaryArithmeticShare>>
    where
        S: MessageRelayService<MessageRelay = R>,
        R: Relay + Send + 'static,
    {
        let parties = setup_mpc(None, shares);

        let mut jset = JoinSet::new();
        for (setup, seed, share) in parties {
            let relay = coord.connect().await.unwrap();

            jset.spawn(test_shuffle_protocol(setup, seed, share, relay));
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
    async fn test_shuffle() {
        let values = vec![
            FieldElement::from(1u64),
            FieldElement::from(2u64),
            FieldElement::from(3u64),
            FieldElement::from(4u64),
            FieldElement::from(5u64),
            FieldElement::from(6u64),
            FieldElement::from(7u64),
            FieldElement::from(8u64),
            FieldElement::from(9u64),
            FieldElement::from(10u64),
        ];

        let mut shares_p1 = Vec::new();
        let mut shares_p2 = Vec::new();
        let mut shares_p3 = Vec::new();
        for v in values.iter() {
            let (s1, s2, s3) =
                get_default_bin_share_from_bin_string(&convert_arith_to_bin(FIELD_SIZE, &v));
            shares_p1.push(BinaryArithmeticShare::from_binary_string_share(&s1));
            shares_p2.push(BinaryArithmeticShare::from_binary_string_share(&s2));
            shares_p3.push(BinaryArithmeticShare::from_binary_string_share(&s3));
        }

        let params = [shares_p1, shares_p2, shares_p3];

        let results = sim(SimpleMessageRelay::new(), &params).await;
        assert_eq!(results.len(), 3);
        let share_arithmetic_p1 = &results[0];
        let share_arithmetic_p2 = &results[1];
        let share_arithmetic_p3 = &results[2];

        let mut shuffled_values = Vec::new();
        for i in 0..share_arithmetic_p1.len() {
            let value = reconstruct_binary_arith_share(
                &share_arithmetic_p1[i],
                &share_arithmetic_p2[i],
                &share_arithmetic_p3[i],
            );
            shuffled_values.push(convert_bin_to_arith(value));
        }
        println!("shuffle values{:?}", shuffled_values);

        shuffled_values.sort();
        assert_eq!(values, shuffled_values);
    }
}
