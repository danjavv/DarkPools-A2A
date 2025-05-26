use crate::eod_balances::run_eod_balances;
use crate::process_plaintext_sh::TransactionEntry;
use sl_compute::comparison::compare_equal::run_batch_compare_eq;
use sl_compute::conversion::a_to_b::run_batch_arithmetic_to_boolean;
use sl_compute::conversion::b_to_a::run_boolean_to_arithmetic;
use sl_compute::transport::proto::FilteredMsgRelay;
use sl_compute::transport::setup::common::MPCEncryption;
use sl_compute::transport::setup::CommonSetupMessage;
use sl_compute::transport::types::ProtocolError;
use sl_compute::transport::utils::TagOffsetCounter;
use sl_compute::types::BinaryArithmeticShare;
use sl_compute::types::{ArithmeticShare, ServerState};
use sl_compute::utility::multiplexer::run_multiplexer_array;
use sl_mpc_mate::coord::Relay;

pub async fn run_all_eom_balance<T, R>(
    setup: &T,
    mpc_encryption: &mut MPCEncryption,
    tag_offset_counter: &mut TagOffsetCounter,
    relay: &mut FilteredMsgRelay<R>,
    transaction_entry: &[TransactionEntry],
    serverstate: &mut ServerState,
) -> Result<Vec<ArithmeticShare>, ProtocolError>
where
    T: CommonSetupMessage,
    R: Relay,
{
    let mut output = Vec::new();
    for month in 1..13 {
        let p1_mon_i_out = run_eom_balance(
            setup,
            mpc_encryption,
            tag_offset_counter,
            relay,
            month,
            transaction_entry,
            serverstate,
        )
        .await?;

        output.push(p1_mon_i_out);
    }
    Ok(output)
}

// TODO verify implementation
pub async fn run_eom_balance<T, R>(
    setup: &T,
    mpc_encryption: &mut MPCEncryption,
    tag_offset_counter: &mut TagOffsetCounter,
    relay: &mut FilteredMsgRelay<R>,
    month: usize,
    transaction_entry: &[TransactionEntry],
    serverstate: &mut ServerState,
) -> Result<ArithmeticShare, ProtocolError>
where
    T: CommonSetupMessage,
    R: Relay,
{
    let eod_balance_p = run_eod_balances(
        setup,
        mpc_encryption,
        tag_offset_counter,
        relay,
        month,
        transaction_entry,
        serverstate,
    )
    .await?;

    let mut output_p = BinaryArithmeticShare::ZERO;

    let balance_p_values = run_batch_arithmetic_to_boolean(
        setup,
        mpc_encryption,
        tag_offset_counter,
        relay,
        &eod_balance_p,
        serverstate,
    )
    .await?;

    let compare_res_p_values = run_batch_compare_eq(
        setup,
        mpc_encryption,
        tag_offset_counter,
        relay,
        &balance_p_values,
        &vec![BinaryArithmeticShare::ZERO; eod_balance_p.len()],
        serverstate,
    )
    .await?;

    for i in 0..eod_balance_p.len() {
        let balance_p = balance_p_values[i];
        let compare_res_p = compare_res_p_values[i];

        output_p = run_multiplexer_array(
            setup,
            mpc_encryption,
            tag_offset_counter,
            relay,
            &compare_res_p,
            &output_p,
            &balance_p,
            serverstate,
        )
        .await?;
    }

    let eom_balance_p = run_boolean_to_arithmetic(
        setup,
        mpc_encryption,
        tag_offset_counter,
        relay,
        &output_p,
        serverstate,
    )
    .await?;

    Ok(eom_balance_p)
}

// #[cfg(test)]
// mod tests {
//     use super::test_run_eom_balance;
//     use crate::process_plaintext_sh::TransactionEntry;
//     use crate::sample_transaction_entries::{TRANSAC_STR_P1, TRANSAC_STR_P2, TRANSAC_STR_P3};
//     use sl_compute::{
//         mpc::{common_randomness::test_run_get_serverstate, verify::test_run_verify},
//         proto::reconstruct_arith_to_float,
//     };
//
//     #[test]
//     fn test_eom_balance() {
//         let (mut serverstate_p1, mut serverstate_p2, mut serverstate_p3) =
//             test_run_get_serverstate();
//
//         let transac_p1: Vec<TransactionEntry> = serde_json::from_str(TRANSAC_STR_P1).unwrap();
//         let transac_p2: Vec<TransactionEntry> = serde_json::from_str(TRANSAC_STR_P2).unwrap();
//         let transac_p3: Vec<TransactionEntry> = serde_json::from_str(TRANSAC_STR_P3).unwrap();
//
//         let month = 6;
//
//         let (output_p1, output_p2, output_p3) = test_run_eom_balance(
//             month,
//             &transac_p1,
//             &transac_p2,
//             &transac_p3,
//             &mut serverstate_p1,
//             &mut serverstate_p2,
//             &mut serverstate_p3,
//         );
//
//         test_run_verify(
//             &mut serverstate_p1,
//             &mut serverstate_p2,
//             &mut serverstate_p3,
//         );
//
//         reconstruct_arith_to_float(
//             output_p1,
//             output_p2,
//             output_p3,
//             &mut serverstate_p1,
//             &mut serverstate_p2,
//             &mut serverstate_p3,
//         );
//     }
// }
