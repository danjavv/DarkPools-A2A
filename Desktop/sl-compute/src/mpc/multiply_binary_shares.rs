use crate::constants::AND_MSG;
use crate::transport::proto::FilteredMsgRelay;
use crate::transport::setup::common::MPCEncryption;
use crate::transport::setup::CommonSetupMessage;
use crate::transport::types::ProtocolError;
use crate::transport::utils::{p2p_send_to_next_receive_from_prev, TagOffsetCounter};
use crate::types::{Binary, BinaryShare, BinaryString, BinaryStringShare, ServerState};
use sl_mpc_mate::coord::Relay;
use sl_mpc_mate::message::MessageTag;

/// Implementation of ANDwithError Protocol 2.7.1.
pub async fn run_and_with_error<T, R>(
    setup: &T,
    mpc_encryption: &mut MPCEncryption,
    tag_offset_counter: &mut TagOffsetCounter,
    relay: &mut FilteredMsgRelay<R>,
    a: &BinaryStringShare,
    b: &BinaryStringShare,
    serverstate: &mut ServerState,
) -> Result<BinaryStringShare, ProtocolError>
where
    T: CommonSetupMessage,
    R: Relay,
{
    assert_eq!(a.length, b.length);

    let tag_offset = tag_offset_counter.next_value();
    relay
        .ask_messages(setup, MessageTag::tag1(AND_MSG, tag_offset), true)
        .await?;

    let and_point = a.and_bitwise(b, &mut serverstate.common_randomness);
    let and_point_from_prev = p2p_send_to_next_receive_from_prev(
        setup,
        mpc_encryption,
        MessageTag::tag1(AND_MSG, tag_offset),
        and_point.clone(),
        relay,
    )
    .await?;

    let res = and_binary_string_complete(&and_point, &and_point_from_prev);
    Ok(res)
}

pub async fn run_and_binary_shares<T, R>(
    setup: &T,
    mpc_encryption: &mut MPCEncryption,
    tag_offset_counter: &mut TagOffsetCounter,
    relay: &mut FilteredMsgRelay<R>,
    a: &BinaryShare,
    b: &BinaryShare,
    serverstate: &mut ServerState,
) -> Result<BinaryShare, ProtocolError>
where
    T: CommonSetupMessage,
    R: Relay,
{
    let tag_offset = tag_offset_counter.next_value();
    relay
        .ask_messages(setup, MessageTag::tag1(AND_MSG, tag_offset), true)
        .await?;

    let and_point = a.and_bitwise(b, &mut serverstate.common_randomness);
    serverstate.and_triples.push(*a, *b);

    let and_point_from_prev = p2p_send_to_next_receive_from_prev(
        setup,
        mpc_encryption,
        MessageTag::tag1(AND_MSG, tag_offset),
        and_point,
        relay,
    )
    .await?;

    let res = BinaryShare {
        value1: and_point ^ and_point_from_prev,
        value2: and_point,
    };
    serverstate.and_triples.insert_c(res);

    Ok(res)
}

fn vec_bool_to_vec_bytes(a: &[bool]) -> Vec<u8> {
    let size_in_bytes = (a.len() + 7) / 8;
    let mut output: Vec<u8> = Vec::with_capacity(size_in_bytes);
    for i in 0..size_in_bytes {
        let mut b = 0u8;
        for j in 0..8 {
            let bit = match a.get(i * 8 + j) {
                None => false,
                Some(v) => *v,
            };
            b |= (bit as u8) << j
        }
        output.push(b)
    }
    output
}

fn vec_bytes_to_vec_bool(a: &[u8], size_in_bits: usize) -> Vec<bool> {
    let size_in_bytes = (size_in_bits + 7) / 8;
    assert_eq!(a.len(), size_in_bytes);

    let mut output: Vec<bool> = Vec::with_capacity(size_in_bits);
    for idx in 0..size_in_bits {
        let byte_idx = idx >> 3;
        let bit_idx = idx & 0x7;
        let byte = a[byte_idx];
        let mask = 1 << bit_idx;
        output.push((byte & mask) != 0);
    }
    output
}

pub async fn run_batch_and_binary_shares<T, R>(
    setup: &T,
    mpc_encryption: &mut MPCEncryption,
    tag_offset_counter: &mut TagOffsetCounter,
    relay: &mut FilteredMsgRelay<R>,
    a: &[BinaryShare],
    b: &[BinaryShare],
    serverstate: &mut ServerState,
) -> Result<Vec<BinaryShare>, ProtocolError>
where
    T: CommonSetupMessage,
    R: Relay,
{
    assert_eq!(a.len(), b.len());

    let tag_offset = tag_offset_counter.next_value();
    relay
        .ask_messages(setup, MessageTag::tag1(AND_MSG, tag_offset), true)
        .await?;

    let and_point_values: Vec<Binary> = a
        .iter()
        .zip(b.iter())
        .map(|(a, b)| {
            serverstate.and_triples.push(*a, *b);
            a.and_bitwise(b, &mut serverstate.common_randomness)
        })
        .collect();

    let size_in_bits = and_point_values.len();
    let and_point_from_prev = p2p_send_to_next_receive_from_prev(
        setup,
        mpc_encryption,
        MessageTag::tag1(AND_MSG, tag_offset),
        vec_bool_to_vec_bytes(&and_point_values),
        relay,
    )
    .await?;
    let and_point_from_prev = vec_bytes_to_vec_bool(&and_point_from_prev, size_in_bits);

    let res_values: Vec<BinaryShare> = and_point_values
        .iter()
        .zip(and_point_from_prev.iter())
        .map(|(and_point, and_point_from_prev)| {
            let v = BinaryShare {
                value1: *and_point ^ *and_point_from_prev,
                value2: *and_point,
            };
            serverstate.and_triples.insert_c(v);
            v
        })
        .collect();

    Ok(res_values)
}

fn and_binary_string_complete(own: &BinaryString, from_prev: &BinaryString) -> BinaryStringShare {
    assert_eq!(own.length, from_prev.length);
    let mut value1 = own.value.clone();
    #[allow(clippy::needless_range_loop)]
    for i in 0..own.length_in_bytes() {
        value1[i] ^= from_prev.value[i];
    }

    BinaryStringShare {
        length: own.length,
        value1,
        value2: own.value.clone(),
    }
}

pub async fn run_and_binary_string_shares<T, R>(
    setup: &T,
    mpc_encryption: &mut MPCEncryption,
    tag_offset_counter: &mut TagOffsetCounter,
    relay: &mut FilteredMsgRelay<R>,
    a: &BinaryStringShare,
    b: &BinaryStringShare,
    serverstate: &mut ServerState,
) -> Result<BinaryStringShare, ProtocolError>
where
    T: CommonSetupMessage,
    R: Relay,
{
    assert_eq!(a.length, b.length);

    let tag_offset = tag_offset_counter.next_value();
    relay
        .ask_messages(setup, MessageTag::tag1(AND_MSG, tag_offset), true)
        .await?;

    let and_point = a.and_bitwise(b, &mut serverstate.common_randomness);
    // for i in 0..(a.length as usize) {
    //     serverstate
    //         .and_triples
    //         .push(a.get_binary_share(i), b.get_binary_share(i));
    // }
    serverstate.and_triples.push_a_b_binary_string_share(a, b);

    let and_point_from_prev = p2p_send_to_next_receive_from_prev(
        setup,
        mpc_encryption,
        MessageTag::tag1(AND_MSG, tag_offset),
        and_point.clone(),
        relay,
    )
    .await?;

    let res = and_binary_string_complete(&and_point, &and_point_from_prev);
    // for i in 0..(res.length as usize) {
    //     serverstate.and_triples.insert_c(res.get_binary_share(i));
    // }
    serverstate.and_triples.insert_c_binary_string_share(&res);

    Ok(res)
}

pub async fn run_batch_and_binary_string_shares<T, R>(
    setup: &T,
    mpc_encryption: &mut MPCEncryption,
    tag_offset_counter: &mut TagOffsetCounter,
    relay: &mut FilteredMsgRelay<R>,
    a: &[BinaryStringShare],
    b: &[BinaryStringShare],
    serverstate: &mut ServerState,
) -> Result<Vec<BinaryStringShare>, ProtocolError>
where
    T: CommonSetupMessage,
    R: Relay,
{
    assert_eq!(a.len(), b.len());
    for (v1, v2) in a.iter().zip(b.iter()) {
        assert_eq!(v1.length, v2.length);
    }

    let tag_offset = tag_offset_counter.next_value();
    relay
        .ask_messages(setup, MessageTag::tag1(AND_MSG, tag_offset), true)
        .await?;

    let and_point_values: Vec<BinaryString> = a
        .iter()
        .zip(b.iter())
        .map(|(a, b)| {
            // for i in 0..(a.length as usize) {
            //     serverstate
            //         .and_triples
            //         .push(a.get_binary_share(i), b.get_binary_share(i));
            // }
            serverstate.and_triples.push_a_b_binary_string_share(a, b);

            a.and_bitwise(b, &mut serverstate.common_randomness)
        })
        .collect();

    let lengths: Vec<(u64, usize)> = and_point_values
        .iter()
        .map(|v| (v.length, v.length_in_bytes()))
        .collect();

    let mut msg = Vec::new();
    for v in and_point_values.iter() {
        msg.extend_from_slice(&v.value);
    }
    let msg_from_prev = p2p_send_to_next_receive_from_prev(
        setup,
        mpc_encryption,
        MessageTag::tag1(AND_MSG, tag_offset),
        msg,
        relay,
    )
    .await?;
    let mut and_point_from_prev_values: Vec<BinaryString> = Vec::new();
    let mut offset = 0;
    for (l, l_bytes) in lengths {
        let v = BinaryString {
            length: l,
            value: msg_from_prev[offset..offset + l_bytes].to_vec(),
        };
        offset += l_bytes;
        and_point_from_prev_values.push(v)
    }

    let res_values: Vec<BinaryStringShare> = and_point_values
        .iter()
        .zip(and_point_from_prev_values.iter())
        .map(|(and_point, and_point_from_prev)| {
            and_binary_string_complete(and_point, and_point_from_prev)
        })
        .collect();
    for res in res_values.iter() {
        // for i in 0..(res.length as usize) {
        //     serverstate.and_triples.insert_c(res.get_binary_share(i));
        // }
        serverstate.and_triples.insert_c_binary_string_share(res);
    }

    Ok(res_values)
}

pub async fn run_or_binary_shares<T, R>(
    setup: &T,
    mpc_encryption: &mut MPCEncryption,
    tag_offset_counter: &mut TagOffsetCounter,
    relay: &mut FilteredMsgRelay<R>,
    x: &BinaryShare,
    y: &BinaryShare,
    serverstate: &mut ServerState,
) -> Result<BinaryShare, ProtocolError>
where
    T: CommonSetupMessage,
    R: Relay,
{
    let temp = x.xor(y);
    let and_res = run_and_binary_shares(
        setup,
        mpc_encryption,
        tag_offset_counter,
        relay,
        x,
        y,
        serverstate,
    )
    .await?;
    let out = temp.xor(&and_res);
    Ok(out)
}

pub async fn run_batch_or_binary_shares<T, R>(
    setup: &T,
    mpc_encryption: &mut MPCEncryption,
    tag_offset_counter: &mut TagOffsetCounter,
    relay: &mut FilteredMsgRelay<R>,
    x: &[BinaryShare],
    y: &[BinaryShare],
    serverstate: &mut ServerState,
) -> Result<Vec<BinaryShare>, ProtocolError>
where
    T: CommonSetupMessage,
    R: Relay,
{
    let temp: Vec<BinaryShare> = x.iter().zip(y.iter()).map(|(a, b)| a.xor(b)).collect();

    let and_res = run_batch_and_binary_shares(
        setup,
        mpc_encryption,
        tag_offset_counter,
        relay,
        x,
        y,
        serverstate,
    )
    .await?;

    let out_values = temp
        .iter()
        .zip(and_res.iter())
        .map(|(a, b)| a.xor(b))
        .collect();

    Ok(out_values)
}

pub async fn run_or_binary_string_shares<T, R>(
    setup: &T,
    mpc_encryption: &mut MPCEncryption,
    tag_offset_counter: &mut TagOffsetCounter,
    relay: &mut FilteredMsgRelay<R>,
    x: &BinaryStringShare,
    y: &BinaryStringShare,
    serverstate: &mut ServerState,
) -> Result<BinaryStringShare, ProtocolError>
where
    T: CommonSetupMessage,
    R: Relay,
{
    let temp = x.xor(y);
    let and_res = run_and_binary_string_shares(
        setup,
        mpc_encryption,
        tag_offset_counter,
        relay,
        x,
        y,
        serverstate,
    )
    .await?;
    let out = temp.xor(&and_res);
    Ok(out)
}

pub async fn run_batch_or_binary_string_shares<T, R>(
    setup: &T,
    mpc_encryption: &mut MPCEncryption,
    tag_offset_counter: &mut TagOffsetCounter,
    relay: &mut FilteredMsgRelay<R>,
    x: &[BinaryStringShare],
    y: &[BinaryStringShare],
    serverstate: &mut ServerState,
) -> Result<Vec<BinaryStringShare>, ProtocolError>
where
    T: CommonSetupMessage,
    R: Relay,
{
    let temp: Vec<BinaryStringShare> = x.iter().zip(y.iter()).map(|(a, b)| a.xor(b)).collect();

    let and_res = run_batch_and_binary_string_shares(
        setup,
        mpc_encryption,
        tag_offset_counter,
        relay,
        x,
        y,
        serverstate,
    )
    .await?;

    let out_values = temp
        .iter()
        .zip(and_res.iter())
        .map(|(a, b)| a.xor(b))
        .collect();

    Ok(out_values)
}
