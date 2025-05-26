use crate::mpc::multiply_binary_shares::{
    run_and_binary_string_shares, run_batch_and_binary_shares, run_batch_and_binary_string_shares,
    run_or_binary_string_shares,
};
use crate::transport::proto::FilteredMsgRelay;
use crate::transport::setup::common::MPCEncryption;
use crate::transport::setup::CommonSetupMessage;
use crate::transport::types::ProtocolError;
use crate::transport::utils::TagOffsetCounter;
use crate::types::ServerState;
use crate::types::{BinaryShare, BinaryStringShare};
use sl_mpc_mate::coord::Relay;

#[derive(Clone)]
pub struct FAInput {
    pub a: BinaryStringShare,
    pub b: BinaryStringShare,
    pub carry: BinaryStringShare,
}

#[derive(Clone)]
pub struct FAOutput {
    pub carry: BinaryStringShare,
    pub sum: BinaryStringShare,
}

#[derive(Clone)]
pub struct PPAState {
    pub g: BinaryStringShare,
    pub p: BinaryStringShare,
}

pub async fn run_full_adder_bit<T, R>(
    setup: &T,
    mpc_encryption: &mut MPCEncryption,
    tag_offset_counter: &mut TagOffsetCounter,
    relay: &mut FilteredMsgRelay<R>,
    a: BinaryShare,
    b: BinaryShare,
    carry: BinaryShare,
    serverstate: &mut ServerState,
) -> Result<(BinaryShare, BinaryShare), ProtocolError>
where
    T: CommonSetupMessage,
    R: Relay,
{
    let temp = a.xor(&b);
    let sum = temp.xor(&carry);

    let res = run_batch_and_binary_shares(
        setup,
        mpc_encryption,
        tag_offset_counter,
        relay,
        &[a, temp],
        &[b, carry],
        serverstate,
    )
    .await?;

    // originally it should be OR, but with XOR it works correctly too
    let carry = res[0].xor(&res[1]);

    Ok((carry, sum))
}

pub async fn run_full_adder<T, R>(
    setup: &T,
    mpc_encryption: &mut MPCEncryption,
    tag_offset_counter: &mut TagOffsetCounter,
    relay: &mut FilteredMsgRelay<R>,
    data: FAInput,
    serverstate: &mut ServerState,
) -> Result<(BinaryStringShare, BinaryStringShare), ProtocolError>
where
    T: CommonSetupMessage,
    R: Relay,
{
    let temp = data.a.xor(&data.b);
    let sum = temp.xor(&data.carry);

    let res = run_batch_and_binary_string_shares(
        setup,
        mpc_encryption,
        tag_offset_counter,
        relay,
        &[data.a, temp],
        &[data.b, data.carry],
        serverstate,
    )
    .await?;

    // originally it should be OR, but with XOR it works correctly too
    let carry = res[0].xor(&res[1]);

    Ok((carry, sum))
}

pub async fn run_batch_full_adder<T, R>(
    setup: &T,
    mpc_encryption: &mut MPCEncryption,
    tag_offset_counter: &mut TagOffsetCounter,
    relay: &mut FilteredMsgRelay<R>,
    fa_inputs: &[FAInput],
    serverstate: &mut ServerState,
) -> Result<(Vec<BinaryStringShare>, Vec<BinaryStringShare>), ProtocolError>
where
    T: CommonSetupMessage,
    R: Relay,
{
    let n = fa_inputs.len();
    let mut sum_values = Vec::with_capacity(n);
    let mut a_and_values = Vec::with_capacity(n * 2);
    let mut b_and_values = Vec::with_capacity(n * 2);

    for data in fa_inputs {
        let temp = data.a.xor(&data.b);
        let sum = temp.xor(&data.carry);

        sum_values.push(sum);

        a_and_values.push(data.a.clone());
        a_and_values.push(temp);
        b_and_values.push(data.b.clone());
        b_and_values.push(data.carry.clone());
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

    let mut carry_values = Vec::with_capacity(n);
    for i in 0..(res.len() / 2) {
        let carry = res[i * 2].xor(&res[i * 2 + 1]);
        carry_values.push(carry)
    }

    Ok((carry_values, sum_values))
}

fn is_power_of_two(n: usize) -> bool {
    n != 0 && (n & (n - 1)) == 0
}

pub async fn run_parallel_prefix_adder<T, R>(
    setup: &T,
    mpc_encryption: &mut MPCEncryption,
    tag_offset_counter: &mut TagOffsetCounter,
    relay: &mut FilteredMsgRelay<R>,
    x: &BinaryStringShare,
    y: &BinaryStringShare,
    serverstate: &mut ServerState,
) -> Result<(BinaryStringShare, BinaryShare), ProtocolError>
where
    T: CommonSetupMessage,
    R: Relay,
{
    assert_eq!(x.length, y.length);
    let n = x.length as usize;
    assert!(is_power_of_two(n));
    let n_log2 = n.ilog2() as usize;

    // PPA Pre-computation
    // p = x xor y
    let p = x.xor(y);

    // g = x and y
    let g = run_and_binary_string_shares(
        setup,
        mpc_encryption,
        tag_offset_counter,
        relay,
        x,
        y,
        serverstate,
    )
    .await?;

    let mut ppa_state = PPAState { g, p: p.clone() };

    // PPA Prefix-propagation
    for step in 0..n_log2 {
        let mut pc = ppa_state.p;
        let mut gc = ppa_state.g;

        let g_to_and_1 = gc._slice(0, n - (1usize << step));
        let p_to_and_2 = pc._slice(0, n - (1usize << step));
        let p_to_and_1_2 = pc._slice(1usize << step, n);
        let g_to_or = gc._slice(1usize << step, n);

        let res = run_batch_and_binary_string_shares(
            setup,
            mpc_encryption,
            tag_offset_counter,
            relay,
            &[g_to_and_1, p_to_and_2],
            &[p_to_and_1_2.clone(), p_to_and_1_2],
            serverstate,
        )
        .await?;

        let gc_to_or = res[0].clone();
        let pc_after_and = res[1].clone();

        let gc_after_or = run_or_binary_string_shares(
            setup,
            mpc_encryption,
            tag_offset_counter,
            relay,
            &gc_to_or,
            &g_to_or,
            serverstate,
        )
        .await?;

        for i in (1usize << step)..n {
            pc.set_binary_share(i, &pc_after_and.get_binary_share(i - (1usize << step)));
            gc.set_binary_share(i, &gc_after_or.get_binary_share(i - (1usize << step)));
        }

        ppa_state = PPAState { g: gc, p: pc };
    }

    let g = ppa_state.g;
    let g_n = g.get_binary_share(n - 1);

    let mut g_mul_2: BinaryStringShare = BinaryStringShare::with_capacity(n);
    g_mul_2.push_binary_share(BinaryShare::ZERO);
    for i in 0..(n - 1) {
        g_mul_2.push_binary_share(g.get_binary_share(i));
    }

    // PPA Sum computation
    let sum = p.xor(&g_mul_2);

    Ok((sum, g_n))
}
