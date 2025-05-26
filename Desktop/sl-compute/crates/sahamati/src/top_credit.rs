use crate::process_plaintext_sh::TransactionEntry;
use sl_compute::conversion::a_to_b::run_batch_arithmetic_to_boolean;
use sl_compute::conversion::b_to_a::run_batch_boolean_to_arithmetic;
use sl_compute::transport::proto::{FilteredMsgRelay, Relay};
use sl_compute::transport::setup::common::MPCEncryption;
use sl_compute::transport::setup::CommonSetupMessage;
use sl_compute::transport::types::ProtocolError;
use sl_compute::transport::utils::TagOffsetCounter;
use sl_compute::types::BinaryArithmeticShare;
use sl_compute::types::{ArithmeticShare, ServerState};
use sl_compute::utility::decimal_share_convert::decimal_to_arithmetic;
use sl_compute::utility::multiplexer::run_multiplexer_array;
use sl_compute::utility::sort::run_quick_sort;

pub async fn run_top_credit<T, R>(
    setup: &T,
    mpc_encryption: &mut MPCEncryption,
    tag_offset_counter: &mut TagOffsetCounter,
    relay: &mut FilteredMsgRelay<R>,
    transactions: &[TransactionEntry],
    serverstate: &mut ServerState,
) -> Result<Vec<ArithmeticShare>, ProtocolError>
where
    T: CommonSetupMessage,
    R: Relay,
{
    let mut credit = Vec::new();

    let a_values: Vec<ArithmeticShare> = transactions
        .iter()
        .map(|t| decimal_to_arithmetic(&t.txn_amt))
        .collect();
    let trasac_amt_p_values = run_batch_arithmetic_to_boolean(
        setup,
        mpc_encryption,
        tag_offset_counter,
        relay,
        &a_values,
        serverstate,
    )
    .await?;

    for i in 0..transactions.len() {
        let amount_credit_p = run_multiplexer_array(
            setup,
            mpc_encryption,
            tag_offset_counter,
            relay,
            &transactions[i].type_credit,
            &trasac_amt_p_values[i],
            &BinaryArithmeticShare::ZERO,
            serverstate,
        )
        .await?;
        credit.push(amount_credit_p);
    }

    let sorted_credit_p = run_quick_sort(
        setup,
        mpc_encryption,
        tag_offset_counter,
        relay,
        false,
        &credit,
        serverstate,
    )
    .await?;

    let top_credit_p = run_batch_boolean_to_arithmetic(
        setup,
        mpc_encryption,
        tag_offset_counter,
        relay,
        &sorted_credit_p,
        serverstate,
    )
    .await?;

    Ok(top_credit_p)
}

// #[cfg(test)]
// mod tests {
//     use super::test_run_top_credit;
//     use crate::process_plaintext_sh::TransactionEntry;
//     use crate::sample_transaction_entries::{TRANSAC_STR_P1, TRANSAC_STR_P2, TRANSAC_STR_P3};
//     use sl_compute::{
//         mpc::{common_randomness::test_run_get_serverstate, verify::test_run_verify},
//         proto::reconstruct_arith_to_float,
//     };
//
//     #[test]
//     fn test_top_credit() {
//         let (mut serverstate_p1, mut serverstate_p2, mut serverstate_p3) =
//             test_run_get_serverstate();
//
//         let transac_p1: Vec<TransactionEntry> = serde_json::from_str(TRANSAC_STR_P1).unwrap();
//         let transac_p2: Vec<TransactionEntry> = serde_json::from_str(TRANSAC_STR_P2).unwrap();
//         let transac_p3: Vec<TransactionEntry> = serde_json::from_str(TRANSAC_STR_P3).unwrap();
//
//         let (top_credit_p1, top_credit_p2, top_credit_p3) = test_run_top_credit(
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
//         for i in 0..10 {
//             reconstruct_arith_to_float(
//                 top_credit_p1[i],
//                 top_credit_p2[i],
//                 top_credit_p3[i],
//                 &mut serverstate_p1,
//                 &mut serverstate_p2,
//                 &mut serverstate_p3,
//             );
//         }
//     }
// }
