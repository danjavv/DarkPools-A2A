use crate::constants::{EC_FIELD_LOG, EC_FIELD_SIZE};
use crate::mpc::multiply_binary_shares::{
    run_and_binary_string_shares, run_batch_or_binary_shares,
};
use crate::transport::proto::FilteredMsgRelay;
use crate::transport::setup::common::MPCEncryption;
use crate::transport::setup::CommonSetupMessage;
use crate::transport::types::ProtocolError;
use crate::transport::utils::TagOffsetCounter;
use crate::types::{BinaryShare, BinaryStringShare, ServerState};
use crate::utility::multiplexer::{run_batch_multiplexer_bit, run_multiplexer_bit};
use sl_mpc_mate::coord::Relay;

/// Implementation of Section 1.3 from https://github.com/silence-laboratories/sl-compute/blob/sahamati-queries/docs.pdf
/// for an input size of EC_FIELD_SIZE
pub async fn run_compare_ge_ec<T, R>(
    setup: &T,
    mpc_encryption: &mut MPCEncryption,
    tag_offset_counter: &mut TagOffsetCounter,
    relay: &mut FilteredMsgRelay<R>,
    x: &BinaryStringShare,
    y: &BinaryStringShare,
    serverstate: &mut ServerState,
) -> Result<BinaryShare, ProtocolError>
where
    T: CommonSetupMessage,
    R: Relay,
{
    assert_eq!(x.length as usize, EC_FIELD_SIZE);
    assert_eq!(x.length, y.length);

    let a = x.xor(y);
    let t = run_and_binary_string_shares(
        setup,
        mpc_encryption,
        tag_offset_counter,
        relay,
        y,
        &a,
        serverstate,
    )
    .await?;
    let t = t.not();

    let mut subres_values = Vec::new();
    let mut diff_values = Vec::new();
    for i in 0..EC_FIELD_SIZE {
        subres_values.push(t.get_binary_share(i));
        diff_values.push(a.get_binary_share(i));
    }

    for _ in 0..EC_FIELD_LOG {
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

/// Implementation of Section 1.3 from https://github.com/silence-laboratories/sl-compute/blob/sahamati-queries/docs.pdf
/// for an input size of EC_FIELD_SIZE + 1
pub async fn run_compare_ge_long_ec<T, R>(
    setup: &T,
    mpc_encryption: &mut MPCEncryption,
    tag_offset_counter: &mut TagOffsetCounter,
    relay: &mut FilteredMsgRelay<R>,
    x: &BinaryStringShare,
    y: &BinaryStringShare,
    serverstate: &mut ServerState,
) -> Result<BinaryShare, ProtocolError>
where
    T: CommonSetupMessage,
    R: Relay,
{
    assert_eq!(x.length as usize, EC_FIELD_SIZE + 1);
    assert_eq!(x.length, y.length);

    let a = x.xor(y);
    let t = run_and_binary_string_shares(
        setup,
        mpc_encryption,
        tag_offset_counter,
        relay,
        y,
        &a,
        serverstate,
    )
    .await?;
    let t = t.not();

    let mut subres_values = Vec::new();
    let mut diff_values = Vec::new();
    for i in 0..EC_FIELD_SIZE {
        subres_values.push(t.get_binary_share(i));
        diff_values.push(a.get_binary_share(i));
    }

    for _ in 0..EC_FIELD_LOG {
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

    let diff_h = a.get_binary_share(EC_FIELD_SIZE);
    let subres_l = subres_values[0];
    let subres_h = t.get_binary_share(EC_FIELD_SIZE);

    let subres_value = run_multiplexer_bit(
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

    Ok(subres_value)
}
