use crate::constants::{OPEN_MSG, OPEN_TO_MSG};
#[cfg(any(test, feature = "test-support"))]
use crate::mpc::common_randomness::run_common_randomness;
use crate::mpc::preprocess::run_verify_array_of_bits;
use crate::mpc::verify::run_verify;
#[cfg(any(test, feature = "test-support"))]
use crate::transport::init::run_init;
use crate::transport::proto::{FilteredMsgRelay, Wrap};
use crate::transport::setup::common::MPCEncryption;
use crate::transport::setup::CommonSetupMessage;
use crate::transport::types::ProtocolError;
#[cfg(any(test, feature = "test-support"))]
use crate::transport::utils::Seed;
use crate::transport::utils::{
    p2p_send_to_next_receive_from_prev, receive_from_parties, send_to_party, TagOffsetCounter,
};
use crate::types::{
    ArithmeticECShare, ArithmeticShare, Binary, BinaryArithmetic, BinaryArithmeticShare,
    BinaryShare, BinaryString, BinaryStringShare, ByteShare, FieldElement, ServerState,
};
use crate::utility::helper::get_modulus;
use crypto_bigint::{Encoding, U256};
use sl_mpc_mate::coord::Relay;
use sl_mpc_mate::message::MessageTag;

/// Implementation of Protocol 2.4.3 OutputWithoutVerification
pub async fn run_output_without_verification<T, R>(
    setup: &T,
    mpc_encryption: &mut MPCEncryption,
    tag_offset_counter: &mut TagOffsetCounter,
    relay: &mut FilteredMsgRelay<R>,
    x: BinaryStringShare,
) -> Result<BinaryString, ProtocolError>
where
    T: CommonSetupMessage,
    R: Relay,
{
    let tag_offset = tag_offset_counter.next_value();
    relay
        .ask_messages(setup, MessageTag::tag1(OPEN_MSG, tag_offset), true)
        .await?;

    let msg = BinaryString {
        length: x.length,
        value: x.value1,
    };

    let msg_from_prev = p2p_send_to_next_receive_from_prev(
        setup,
        mpc_encryption,
        MessageTag::tag1(OPEN_MSG, tag_offset),
        msg,
        relay,
    )
    .await?;

    let mut res_value = BinaryString {
        length: x.length,
        value: x.value2,
    };
    res_value = res_value.xor(&msg_from_prev);

    Ok(res_value)
}

/// Run Open Binary String Share protocol
pub async fn run_open_binary_string_share<T, R>(
    setup: &T,
    mpc_encryption: &mut MPCEncryption,
    tag_offset_counter: &mut TagOffsetCounter,
    relay: &mut FilteredMsgRelay<R>,
    x: &BinaryStringShare,
    serverstate: &mut ServerState,
) -> Result<BinaryString, ProtocolError>
where
    T: CommonSetupMessage,
    R: Relay,
{
    let output = run_output_without_verification(
        setup,
        mpc_encryption,
        tag_offset_counter,
        relay,
        x.clone(),
    )
    .await?;

    // add to UnverifiedList
    serverstate
        .unverified_list
        .append_bytes_with_padding(&output.value);

    run_verify(
        setup,
        mpc_encryption,
        tag_offset_counter,
        relay,
        serverstate,
    )
    .await?;

    Ok(output)
}

/// Run Open for Gen Triples
pub async fn run_open_for_gen_triples<T, R>(
    setup: &T,
    mpc_encryption: &mut MPCEncryption,
    tag_offset_counter: &mut TagOffsetCounter,
    relay: &mut FilteredMsgRelay<R>,
    x: &BinaryStringShare,
    serverstate: &mut ServerState,
) -> Result<BinaryString, ProtocolError>
where
    T: CommonSetupMessage,
    R: Relay,
{
    let output = run_output_without_verification(
        setup,
        mpc_encryption,
        tag_offset_counter,
        relay,
        x.clone(),
    )
    .await?;

    // add to UnverifiedList
    serverstate
        .unverified_list
        .append_bytes_with_padding(&output.value);

    // VerifyArrayOfBits
    run_verify_array_of_bits(
        setup,
        mpc_encryption,
        tag_offset_counter,
        relay,
        &serverstate.unverified_list,
    )
    .await?;
    serverstate.unverified_list = BinaryString::new();

    Ok(output)
}

/// Run batch Open Binary Share protocol
pub async fn run_batch_open_binary_share<T, R>(
    setup: &T,
    mpc_encryption: &mut MPCEncryption,
    tag_offset_counter: &mut TagOffsetCounter,
    relay: &mut FilteredMsgRelay<R>,
    shares: &[BinaryShare],
    serverstate: &mut ServerState,
) -> Result<Vec<Binary>, ProtocolError>
where
    T: CommonSetupMessage,
    R: Relay,
{
    let tag_offset = tag_offset_counter.next_value();
    relay
        .ask_messages(setup, MessageTag::tag1(OPEN_MSG, tag_offset), true)
        .await?;

    let msg: Vec<u8> = shares.iter().map(|share| share.value1 as u8).collect();

    let msg_from_prev = p2p_send_to_next_receive_from_prev(
        setup,
        mpc_encryption,
        MessageTag::tag1(OPEN_MSG, tag_offset),
        msg,
        relay,
    )
    .await?;

    let output: Vec<bool> = shares
        .iter()
        .zip(msg_from_prev.iter())
        .map(|(share, v)| share.value2 ^ (*v == 1u8))
        .collect();

    // add to UnverifiedList
    for v in output.iter() {
        serverstate.unverified_list.push(*v);
    }
    // serverstate.unverified_list.append_bytes_with_padding(&vec_bool_to_vec_bytes(&output));

    run_verify(
        setup,
        mpc_encryption,
        tag_offset_counter,
        relay,
        serverstate,
    )
    .await?;

    Ok(output)
}

/// Run Open ByteShare protocol
pub async fn run_open_byte_share<T, R>(
    setup: &T,
    mpc_encryption: &mut MPCEncryption,
    tag_offset_counter: &mut TagOffsetCounter,
    relay: &mut FilteredMsgRelay<R>,
    share: &ByteShare,
    serverstate: &mut ServerState,
) -> Result<u8, ProtocolError>
where
    T: CommonSetupMessage,
    R: Relay,
{
    let tag_offset = tag_offset_counter.next_value();
    relay
        .ask_messages(setup, MessageTag::tag1(OPEN_MSG, tag_offset), true)
        .await?;

    let msg = share.value1;

    let msg_from_prev = p2p_send_to_next_receive_from_prev(
        setup,
        mpc_encryption,
        MessageTag::tag1(OPEN_MSG, tag_offset),
        msg,
        relay,
    )
    .await?;

    let out = share.value2 ^ msg_from_prev;

    // add to UnverifiedList
    serverstate
        .unverified_list
        .append_bytes_with_padding(&[out]);

    run_verify(
        setup,
        mpc_encryption,
        tag_offset_counter,
        relay,
        serverstate,
    )
    .await?;

    let mut value_p = 0u8;
    for i in 0..8 {
        let mask = 1 << i;
        if (out & mask) != 0 {
            value_p |= 1 << (7 - i);
        }
    }

    Ok(value_p)
}

/// Run batch ByteShare protocol
pub async fn run_batch_open_byte_share<T, R>(
    setup: &T,
    mpc_encryption: &mut MPCEncryption,
    tag_offset_counter: &mut TagOffsetCounter,
    relay: &mut FilteredMsgRelay<R>,
    shares: &[ByteShare],
    serverstate: &mut ServerState,
) -> Result<Vec<u8>, ProtocolError>
where
    T: CommonSetupMessage,
    R: Relay,
{
    let tag_offset = tag_offset_counter.next_value();
    relay
        .ask_messages(setup, MessageTag::tag1(OPEN_MSG, tag_offset), true)
        .await?;

    let msg: Vec<u8> = shares.iter().map(|share| share.value1).collect();

    let msg_from_prev = p2p_send_to_next_receive_from_prev(
        setup,
        mpc_encryption,
        MessageTag::tag1(OPEN_MSG, tag_offset),
        msg,
        relay,
    )
    .await?;

    let output: Vec<u8> = shares
        .iter()
        .zip(msg_from_prev.iter())
        .map(|(share, v)| share.value2 ^ *v)
        .collect();

    // add to UnverifiedList
    serverstate
        .unverified_list
        .append_bytes_with_padding(&output);

    run_verify(
        setup,
        mpc_encryption,
        tag_offset_counter,
        relay,
        serverstate,
    )
    .await?;

    let mut res = Vec::new();
    for out in output {
        let mut value_p = 0u8;
        for i in 0..8 {
            let mask = 1 << i;
            if (out & mask) != 0 {
                value_p |= 1 << (7 - i);
            }
        }
        res.push(value_p);
    }

    Ok(res)
}

/// Run batch OpenArithmetic protocol
pub async fn run_batch_open_arith<T, R>(
    setup: &T,
    mpc_encryption: &mut MPCEncryption,
    tag_offset_counter: &mut TagOffsetCounter,
    relay: &mut FilteredMsgRelay<R>,
    shares: &[ArithmeticShare],
    serverstate: &mut ServerState,
) -> Result<Vec<FieldElement>, ProtocolError>
where
    T: CommonSetupMessage,
    R: Relay,
{
    let tag_offset = tag_offset_counter.next_value();
    relay
        .ask_messages(setup, MessageTag::tag1(OPEN_MSG, tag_offset), true)
        .await?;

    let msg: Vec<FieldElement> = shares.iter().map(|share| share.open_value1()).collect();

    let msg_from_prev = p2p_send_to_next_receive_from_prev(
        setup,
        mpc_encryption,
        MessageTag::tag1(OPEN_MSG, tag_offset),
        msg,
        relay,
    )
    .await?;

    let output: Vec<FieldElement> = shares
        .iter()
        .zip(msg_from_prev.iter())
        .map(|(share, v)| share.reconstruct(v))
        .collect();

    // add to UnverifiedList
    for el in output.iter() {
        serverstate
            .unverified_list
            .append_bytes_with_padding(&el.to_le_bytes());
    }

    run_verify(
        setup,
        mpc_encryption,
        tag_offset_counter,
        relay,
        serverstate,
    )
    .await?;

    Ok(output)
}

/// Run batch OpenFloat protocol
pub async fn run_batch_open_float<T, R>(
    setup: &T,
    mpc_encryption: &mut MPCEncryption,
    tag_offset_counter: &mut TagOffsetCounter,
    relay: &mut FilteredMsgRelay<R>,
    shares: &[ArithmeticShare],
    serverstate: &mut ServerState,
) -> Result<Vec<f64>, ProtocolError>
where
    T: CommonSetupMessage,
    R: Relay,
{
    let tag_offset = tag_offset_counter.next_value();
    relay
        .ask_messages(setup, MessageTag::tag1(OPEN_MSG, tag_offset), true)
        .await?;

    let msg: Vec<FieldElement> = shares.iter().map(|share| share.open_value1()).collect();

    let msg_from_prev = p2p_send_to_next_receive_from_prev(
        setup,
        mpc_encryption,
        MessageTag::tag1(OPEN_MSG, tag_offset),
        msg,
        relay,
    )
    .await?;

    let output = shares
        .iter()
        .zip(msg_from_prev.iter())
        .map(|(share, v)| {
            let (a, b) = share.reconstruct_to_float(v);
            // add to UnverifiedList
            serverstate
                .unverified_list
                .append_bytes_with_padding(&a.value);
            b
        })
        .collect();

    run_verify(
        setup,
        mpc_encryption,
        tag_offset_counter,
        relay,
        serverstate,
    )
    .await?;

    Ok(output)
}

/// run_open_arith_ec protocol
pub async fn run_open_arith_ec<T, R>(
    setup: &T,
    mpc_encryption: &mut MPCEncryption,
    tag_offset_counter: &mut TagOffsetCounter,
    relay: &mut FilteredMsgRelay<R>,
    share: &ArithmeticECShare,
    serverstate: &mut ServerState,
) -> Result<U256, ProtocolError>
where
    T: CommonSetupMessage,
    R: Relay,
{
    let tag_offset = tag_offset_counter.next_value();

    relay
        .ask_messages(setup, MessageTag::tag1(OPEN_MSG, tag_offset), true)
        .await?;

    let msg = share.value1;

    let msg_from_next = p2p_send_to_next_receive_from_prev(
        setup,
        mpc_encryption,
        MessageTag::tag1(OPEN_MSG, tag_offset),
        msg,
        relay,
    )
    .await?;

    let p = get_modulus();
    let output = share.value2.add_mod(&msg_from_next, &p);

    // add to UnverifiedList
    serverstate
        .unverified_list
        .append_bytes_with_padding(&output.to_le_bytes());

    run_verify(
        setup,
        mpc_encryption,
        tag_offset_counter,
        relay,
        serverstate,
    )
    .await?;

    Ok(output)
}

/// Run Open BinaryArithmeticShare To party 1 and party2 protocol
pub async fn run_batch_open_bin_arith_to_party_1_and_2<T, R>(
    setup: &T,
    mpc_encryption: &mut MPCEncryption,
    tag_offset_counter: &mut TagOffsetCounter,
    relay: &mut FilteredMsgRelay<R>,
    shares: &[BinaryArithmeticShare],
    serverstate: &mut ServerState,
) -> Result<Vec<BinaryArithmetic>, ProtocolError>
where
    T: CommonSetupMessage,
    R: Relay,
{
    run_verify(
        setup,
        mpc_encryption,
        tag_offset_counter,
        relay,
        serverstate,
    )
    .await?;

    let tag_offset = tag_offset_counter.next_value();
    let open_tag = MessageTag::tag1(OPEN_TO_MSG, tag_offset);
    relay.ask_messages(setup, open_tag, true).await?;

    let my_party_id = setup.participant_index();

    let open_values: Vec<BinaryArithmetic> = shares
        .iter()
        .map(|sum_p| BinaryArithmetic {
            value: sum_p.value1,
        })
        .collect();

    let out: Vec<BinaryArithmetic> = match my_party_id {
        0 => {
            // party_1 sends own open_value to party_2
            send_to_party(
                setup,
                mpc_encryption,
                open_tag,
                open_values.clone(),
                1,
                relay,
            )
            .await?;

            // party_1 receives open_value from party_2
            // and open_value from party_3
            let values: Vec<Vec<BinaryArithmetic>> = receive_from_parties(
                setup,
                mpc_encryption,
                open_tag,
                open_values.external_size(),
                vec![1, 2],
                relay,
            )
            .await?;

            let mut error = false;
            let res: Vec<BinaryArithmetic> = shares
                .iter()
                .zip(values[0].iter())
                .zip(values[1].iter())
                .map(|((share, v0), v1)| {
                    let value_from_p2 = v0;
                    let value_from_p3 = v1;
                    // check
                    if value_from_p2.xor(value_from_p3).value != share.value1 {
                        error = true;
                    }
                    share.reconstruct(value_from_p3)
                })
                .collect();

            if error {
                return Err(ProtocolError::VerificationError);
            }
            res
        }
        1 => {
            // party_2 sends own open_value to party_1
            send_to_party(
                setup,
                mpc_encryption,
                open_tag,
                open_values.clone(),
                0,
                relay,
            )
            .await?;

            // party_2 receives open_value from party_1
            // and open_value from party_3
            let values: Vec<Vec<BinaryArithmetic>> = receive_from_parties(
                setup,
                mpc_encryption,
                open_tag,
                open_values.external_size(),
                vec![0, 2],
                relay,
            )
            .await?;

            let mut error = false;
            let res: Vec<BinaryArithmetic> = shares
                .iter()
                .zip(values[0].iter())
                .zip(values[1].iter())
                .map(|((share, v0), v1)| {
                    let value_from_p1 = v0;
                    let value_from_p3 = v1;
                    // check
                    if value_from_p1.xor(value_from_p3).value != share.value1 {
                        error = true;
                    }
                    share.reconstruct(value_from_p1)
                })
                .collect();

            if error {
                return Err(ProtocolError::VerificationError);
            }
            res
        }
        _ => {
            // party_3 sends open_value to party_1
            send_to_party(
                setup,
                mpc_encryption,
                open_tag,
                open_values.clone(),
                0,
                relay,
            )
            .await?;
            // party_3 sends open_value to party_2
            send_to_party(setup, mpc_encryption, open_tag, open_values, 1, relay).await?;

            shares.iter().map(|_| BinaryArithmetic::ZERO).collect()
        }
    };

    Ok(out)
}

/// Test OpenArithmetic protocol
#[cfg(any(test, feature = "test-support"))]
async fn test_batch_open_arith<T, R>(
    setup: T,
    seed: Seed,
    share: Vec<ArithmeticShare>,
    relay: R,
) -> Result<(usize, Vec<FieldElement>), ProtocolError>
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
    let result = run_batch_open_arith(
        &setup,
        &mut mpc_encryption,
        &mut tag_offset_counter,
        &mut relay,
        &share,
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
    use crate::mpc::open_protocol::test_batch_open_arith;
    use crate::transport::test_utils::setup_mpc;
    use crate::types::{ArithmeticShare, FieldElement};
    use sl_mpc_mate::coord::{MessageRelayService, Relay, SimpleMessageRelay};
    use tokio::task::JoinSet;

    async fn sim<S, R>(coord: S, shares: &[Vec<ArithmeticShare>; 3]) -> Vec<Vec<FieldElement>>
    where
        S: MessageRelayService<MessageRelay = R>,
        R: Relay + Send + 'static,
    {
        let parties = setup_mpc(None, shares);

        let mut jset = JoinSet::new();
        for (setup, seed, share) in parties {
            let relay = coord.connect().await.unwrap();

            jset.spawn(test_batch_open_arith(setup, seed, share, relay));
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
    async fn test_open_protocol() {
        let share_p1 =
            ArithmeticShare::new(FieldElement::from(38829u64), FieldElement::from(12123u64));
        let share_p2 =
            ArithmeticShare::new(FieldElement::from(38830u64), FieldElement::from(26707u64));
        let share_p3 =
            ArithmeticShare::new(FieldElement::from(53413u64), FieldElement::from(26706u64));
        //let required_output = 65536;
        // TODO fix it
        let required_output = FieldElement::from(64u64);

        let arithmetic_batch_shares = [vec![share_p1], vec![share_p2], vec![share_p3]];

        let results = sim(SimpleMessageRelay::new(), &arithmetic_batch_shares).await;
        assert_eq!(results.len(), 3);

        println!("{:?}", results);
        assert_eq!(results[0], results[1]);
        assert_eq!(results[1], results[2]);
        assert_eq!(results[0][0], required_output);
    }
}
