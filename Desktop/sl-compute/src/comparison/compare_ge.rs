use crate::constants::{FIELD_LOG, FIELD_SIZE};
use crate::mpc::multiply_binary_shares::{
    run_and_binary_string_shares, run_batch_and_binary_string_shares, run_batch_or_binary_shares,
};
use crate::transport::proto::FilteredMsgRelay;
use crate::transport::setup::common::MPCEncryption;
use crate::transport::setup::CommonSetupMessage;
use crate::transport::types::ProtocolError;
use crate::transport::utils::TagOffsetCounter;
use crate::types::{BinaryArithmeticShare, BinaryShare, BinaryStringShare, ServerState};
use crate::utility::multiplexer::run_batch_multiplexer_bit;
use sl_mpc_mate::coord::Relay;

/// Implementation of CompareGE protocol 3.6.2.
pub async fn run_compare_ge<T, R>(
    setup: &T,
    mpc_encryption: &mut MPCEncryption,
    tag_offset_counter: &mut TagOffsetCounter,
    relay: &mut FilteredMsgRelay<R>,
    x: &BinaryArithmeticShare,
    y: &BinaryArithmeticShare,
    serverstate: &mut ServerState,
) -> Result<BinaryShare, ProtocolError>
where
    T: CommonSetupMessage,
    R: Relay,
{
    let a = x.xor(y);
    let t = run_and_binary_string_shares(
        setup,
        mpc_encryption,
        tag_offset_counter,
        relay,
        &y.to_binary_string_share(),
        &a.to_binary_string_share(),
        serverstate,
    )
    .await?;
    let t = BinaryArithmeticShare::from_binary_string_share(&t).not();

    let mut subres_values = Vec::new();
    let mut diff_values = Vec::new();
    for i in 0..FIELD_SIZE {
        subres_values.push(t.get_binary_share(i));
        diff_values.push(a.get_binary_share(i));
    }

    for _ in 0..FIELD_LOG {
        let mut diff_l = Vec::new();
        let mut diff_h = Vec::new();
        let mut subres_l = Vec::new();
        let mut subres_h = Vec::new();
        for i in 0..(diff_values.len() / 2) {
            diff_l.push(diff_values[2 * i]);
            diff_h.push(diff_values[2 * i + 1]);
            subres_l.push(subres_values[2 * i]);
            subres_h.push(subres_values[2 * i + 1]);
        }
        subres_values = run_batch_multiplexer_bit(
            setup,
            mpc_encryption,
            tag_offset_counter,
            relay,
            &diff_h,
            &subres_h,
            &subres_l,
            serverstate,
        )
        .await?;
        diff_values = run_batch_or_binary_shares(
            setup,
            mpc_encryption,
            tag_offset_counter,
            relay,
            &diff_l,
            &diff_h,
            serverstate,
        )
        .await?;
    }
    assert_eq!(subres_values.len(), 1);

    Ok(subres_values[0])
}

/// Implementation of CompareGE protocol 3.6.2.
pub async fn run_batch_compare_ge<T, R>(
    setup: &T,
    mpc_encryption: &mut MPCEncryption,
    tag_offset_counter: &mut TagOffsetCounter,
    relay: &mut FilteredMsgRelay<R>,
    x_values: &[BinaryArithmeticShare],
    y_values: &[BinaryArithmeticShare],
    serverstate: &mut ServerState,
) -> Result<Vec<BinaryShare>, ProtocolError>
where
    T: CommonSetupMessage,
    R: Relay,
{
    assert_eq!(x_values.len(), y_values.len());
    let n = x_values.len();

    let a_values: Vec<BinaryStringShare> = x_values
        .iter()
        .zip(y_values.iter())
        .map(|(x, y)| x.xor(y).to_binary_string_share())
        .collect();

    let y_values: Vec<BinaryStringShare> = y_values
        .iter()
        .map(|y| y.to_binary_string_share())
        .collect();

    let t_values = run_batch_and_binary_string_shares(
        setup,
        mpc_encryption,
        tag_offset_counter,
        relay,
        &y_values,
        &a_values,
        serverstate,
    )
    .await?;

    let mut subres_values = Vec::new();
    let mut diff_values = Vec::new();
    for (t, a) in t_values.iter().zip(a_values.iter()) {
        for i in 0..FIELD_SIZE {
            subres_values.push(t.get_binary_share(i).not());
            diff_values.push(a.get_binary_share(i));
        }
    }

    for k in 0..FIELD_LOG {
        let q = FIELD_SIZE >> k;
        let l = FIELD_SIZE >> (k + 1);
        let mut diff_l = Vec::new();
        let mut diff_h = Vec::new();
        let mut subres_l = Vec::new();
        let mut subres_h = Vec::new();
        for i in 0..n {
            for j in 0..l {
                diff_l.push(diff_values[i * q + 2 * j]);
                diff_h.push(diff_values[i * q + 2 * j + 1]);
                subres_l.push(subres_values[i * q + 2 * j]);
                subres_h.push(subres_values[i * q + 2 * j + 1]);
            }
        }
        subres_values = run_batch_multiplexer_bit(
            setup,
            mpc_encryption,
            tag_offset_counter,
            relay,
            &diff_h,
            &subres_h,
            &subres_l,
            serverstate,
        )
        .await?;
        diff_values = run_batch_or_binary_shares(
            setup,
            mpc_encryption,
            tag_offset_counter,
            relay,
            &diff_l,
            &diff_h,
            serverstate,
        )
        .await?;
    }
    assert_eq!(subres_values.len(), n);

    Ok(subres_values)
}
