use crate::comparison::compare_equal::run_compare_eq;
use crate::comparison::compare_ge::run_compare_ge;
use crate::conversion::a_to_b::run_arithmetic_to_boolean;
use crate::conversion::b_to_a::run_boolean_to_arithmetic;
use crate::transport::proto::FilteredMsgRelay;
use crate::transport::setup::common::MPCEncryption;
use crate::transport::setup::CommonSetupMessage;
use crate::transport::types::ProtocolError;
#[cfg(any(test, feature = "test-support"))]
use crate::transport::utils::Seed;
use crate::transport::utils::TagOffsetCounter;
use crate::types::{BinaryArithmeticShare, ServerState};
use crate::utility::multiplexer::run_multiplexer_array;
use crate::{
    constants::{FIELD_SIZE, FRACTION_LENGTH},
    types::{ArithmeticShare, BinaryShare},
};
use sl_mpc_mate::coord::Relay;

/// Implementation of Protocol 3.3 (LongDivision) from https://github.com/silence-laboratories/sl-compute/blob/sahamati-queries/docs.pdf
pub async fn run_long_division<T, R>(
    setup: &T,
    mpc_encryption: &mut MPCEncryption,
    tag_offset_counter: &mut TagOffsetCounter,
    relay: &mut FilteredMsgRelay<R>,
    a: &ArithmeticShare,
    b: &ArithmeticShare,
    serverstate: &mut ServerState,
) -> Result<ArithmeticShare, ProtocolError>
where
    T: CommonSetupMessage,
    R: Relay,
{
    let abin_p = run_arithmetic_to_boolean(
        setup,
        mpc_encryption,
        tag_offset_counter,
        relay,
        a,
        serverstate,
    )
    .await?;

    let bbin_p = run_arithmetic_to_boolean(
        setup,
        mpc_encryption,
        tag_offset_counter,
        relay,
        b,
        serverstate,
    )
    .await?;

    let zero = BinaryArithmeticShare::ZERO;

    let zerocomp_p = run_compare_eq(
        setup,
        mpc_encryption,
        tag_offset_counter,
        relay,
        &zero,
        &bbin_p,
        serverstate,
    )
    .await?;

    let mut quotient_p = BinaryArithmeticShare::ZERO;
    let mut remainder_p = BinaryArithmeticShare::ZERO;

    for i in (0..FIELD_SIZE).rev() {
        remainder_p = remainder_p.left_shift(1);
        let temp = abin_p.to_binary_string_share().get_binary_share(i);
        remainder_p.set_binary_share(0, temp);

        let comp_p = run_compare_ge(
            setup,
            mpc_encryption,
            tag_offset_counter,
            relay,
            &remainder_p,
            &bbin_p,
            serverstate,
        )
        .await?;

        let rem_ar_p = run_boolean_to_arithmetic(
            setup,
            mpc_encryption,
            tag_offset_counter,
            relay,
            &remainder_p,
            serverstate,
        )
        .await?;

        let sub_p = rem_ar_p.sub_share(b);

        let sub_bin_p = run_arithmetic_to_boolean(
            setup,
            mpc_encryption,
            tag_offset_counter,
            relay,
            &sub_p,
            serverstate,
        )
        .await?;

        remainder_p = run_multiplexer_array(
            setup,
            mpc_encryption,
            tag_offset_counter,
            relay,
            &comp_p,
            &sub_bin_p,
            &remainder_p,
            serverstate,
        )
        .await?;

        quotient_p.set_binary_share(i, comp_p);
    }

    let mut fraction_p = [BinaryShare::ZERO; FRACTION_LENGTH];

    for j in 0..FRACTION_LENGTH {
        remainder_p = remainder_p.left_shift(1);

        let comp_p = run_compare_ge(
            setup,
            mpc_encryption,
            tag_offset_counter,
            relay,
            &remainder_p,
            &bbin_p,
            serverstate,
        )
        .await?;

        let rem_ar_p = run_boolean_to_arithmetic(
            setup,
            mpc_encryption,
            tag_offset_counter,
            relay,
            &remainder_p,
            serverstate,
        )
        .await?;

        let sub_p = rem_ar_p.sub_share(b);

        let sub_bin_p = run_arithmetic_to_boolean(
            setup,
            mpc_encryption,
            tag_offset_counter,
            relay,
            &sub_p,
            serverstate,
        )
        .await?;

        remainder_p = run_multiplexer_array(
            setup,
            mpc_encryption,
            tag_offset_counter,
            relay,
            &comp_p,
            &sub_bin_p,
            &remainder_p,
            serverstate,
        )
        .await?;

        fraction_p[FRACTION_LENGTH - j - 1] = comp_p;
    }

    let mut output_p = quotient_p;
    output_p = output_p.left_shift(FRACTION_LENGTH);
    #[allow(clippy::needless_range_loop)]
    for i in 0..FRACTION_LENGTH {
        output_p.set_binary_share(i, fraction_p[i]);
    }

    let output_p = run_multiplexer_array(
        setup,
        mpc_encryption,
        tag_offset_counter,
        relay,
        &zerocomp_p,
        &zero,
        &output_p,
        serverstate,
    )
    .await?;

    let out = run_boolean_to_arithmetic(
        setup,
        mpc_encryption,
        tag_offset_counter,
        relay,
        &output_p,
        serverstate,
    )
    .await?;

    Ok(out)
}

/// Test long division protocol
#[cfg(any(test, feature = "test-support"))]
async fn test_long_division_protocol<T, R>(
    setup: T,
    seed: Seed,
    params: (ArithmeticShare, ArithmeticShare),
    relay: R,
) -> Result<(usize, ArithmeticShare), ProtocolError>
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

    let a = params.0;
    let b = params.1;
    let result = run_long_division(
        &setup,
        &mut mpc_encryption,
        &mut tag_offset_counter,
        &mut relay,
        &a,
        &b,
        &mut serverstate,
    )
    .await;

    println!("tag_offset_counter = {}", tag_offset_counter.next_value());

    let _ = relay.close().await;

    match result {
        Ok(v) => Ok((setup.participant_index(), v)),
        Err(e) => Err(e),
    }
}

#[cfg(test)]
mod tests {
    use super::test_long_division_protocol;
    use crate::transport::test_utils::setup_mpc;
    use crate::types::FieldElement;
    use crate::{constants::FRACTION_LENGTH, proto::reconstruct_arith, types::ArithmeticShare};
    use crypto_bigint::NonZero;
    use sl_mpc_mate::coord::{MessageRelayService, Relay, SimpleMessageRelay};
    use tokio::task::JoinSet;

    async fn sim<S, R>(
        coord: S,
        sim_params: &[(ArithmeticShare, ArithmeticShare); 3],
    ) -> Vec<ArithmeticShare>
    where
        S: MessageRelayService<MessageRelay = R>,
        R: Relay + Send + 'static,
    {
        let parties = setup_mpc(None, sim_params);

        let mut jset = JoinSet::new();
        for (setup, seed, params) in parties {
            let relay = coord.connect().await.unwrap();

            jset.spawn(test_long_division_protocol(setup, seed, params, relay));
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
    async fn test_long_division() {
        let fraction_multiplier = FieldElement::from(1u64 << FRACTION_LENGTH);
        let a_p1 = ArithmeticShare::new(
            fraction_multiplier.wrapping_mul(&FieldElement::from(9u64)),
            fraction_multiplier.wrapping_mul(&FieldElement::from(4u64)),
        );
        let a_p2 = ArithmeticShare::new(
            fraction_multiplier.wrapping_mul(&FieldElement::from(8u64)),
            fraction_multiplier.wrapping_mul(&FieldElement::from(4u64)),
        );
        let a_p3 = ArithmeticShare::new(
            fraction_multiplier.wrapping_mul(&FieldElement::from(9u64)),
            fraction_multiplier.wrapping_mul(&FieldElement::from(5u64)),
        );

        let b_p1 = ArithmeticShare::new(
            fraction_multiplier.wrapping_mul(&FieldElement::from(4u64)),
            fraction_multiplier,
        );
        let b_p2 = ArithmeticShare::new(
            fraction_multiplier.wrapping_mul(&FieldElement::from(3u64)),
            fraction_multiplier.wrapping_mul(&FieldElement::from(2u64)),
        );
        let b_p3 = ArithmeticShare::new(
            fraction_multiplier.wrapping_mul(&FieldElement::from(5u64)),
            fraction_multiplier.wrapping_mul(&FieldElement::from(3u64)),
        );

        let params = [(a_p1, b_p1), (a_p2, b_p2), (a_p3, b_p3)];

        let results = sim(SimpleMessageRelay::new(), &params).await;
        assert_eq!(results.len(), 3);

        let output_share_p1 = results[0].clone();
        let output_share_p2 = results[1].clone();
        let output_share_p3 = results[2].clone();

        let a = reconstruct_arith(a_p1, a_p2, a_p3);

        let b = reconstruct_arith(b_p1, b_p2, b_p3);
        let b = NonZero::new(b).unwrap();

        let (expected_output, _rem) = a.div_rem(&b);

        let output = reconstruct_arith(output_share_p1, output_share_p2, output_share_p3);

        assert_eq!(expected_output, output);
    }
}
