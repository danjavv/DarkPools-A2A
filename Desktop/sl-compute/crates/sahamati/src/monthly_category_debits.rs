use crate::process_plaintext_sh::TransactionEntry;
use sl_compute::comparison::compare_equal::run_batch_compare_eq;
use sl_compute::conversion::a_to_b::run_batch_arithmetic_to_boolean;
use sl_compute::conversion::b_to_a::run_batch_boolean_to_arithmetic;
use sl_compute::transport::proto::FilteredMsgRelay;
use sl_compute::transport::setup::common::MPCEncryption;
use sl_compute::transport::setup::CommonSetupMessage;
use sl_compute::transport::types::ProtocolError;
use sl_compute::transport::utils::TagOffsetCounter;
use sl_compute::types::{ArithmeticShare, ServerState};
use sl_compute::types::{BinaryArithmeticShare, FieldElement};
use sl_compute::utility::decimal_share_convert::decimal_to_arithmetic;
use sl_compute::utility::multiplexer::run_batch_multiplexer_array;
use sl_mpc_mate::coord::Relay;
use std::collections::HashMap;

pub async fn run_cat_debit_month<T, R>(
    setup: &T,
    mpc_encryption: &mut MPCEncryption,
    tag_offset_counter: &mut TagOffsetCounter,
    relay: &mut FilteredMsgRelay<R>,
    month: usize,
    transactions: &[TransactionEntry],
    serverstate: &mut ServerState,
) -> Result<HashMap<usize, ArithmeticShare>, ProtocolError>
where
    T: CommonSetupMessage,
    R: Relay,
{
    let my_party_index = setup.participant_index();

    let n = transactions.len();

    let default_month =
        BinaryArithmeticShare::from_constant(&FieldElement::from(month as u64), my_party_index);

    let a_values: Vec<ArithmeticShare> = transactions.iter().map(|t| t.time_stamp.month).collect();

    let month_p_values = run_batch_arithmetic_to_boolean(
        setup,
        mpc_encryption,
        tag_offset_counter,
        relay,
        &a_values,
        serverstate,
    )
    .await?;

    let mut compare_b_values = Vec::new();
    for _ in 0..n {
        compare_b_values.push(default_month)
    }
    let compare_res_values = run_batch_compare_eq(
        setup,
        mpc_encryption,
        tag_offset_counter,
        relay,
        &month_p_values,
        &compare_b_values,
        serverstate,
    )
    .await?;

    let txn_amt_ar_p_values: Vec<ArithmeticShare> = transactions
        .iter()
        .map(|t| decimal_to_arithmetic(&t.txn_amt))
        .collect();

    let trasac_amt_p_values = run_batch_arithmetic_to_boolean(
        setup,
        mpc_encryption,
        tag_offset_counter,
        relay,
        &txn_amt_ar_p_values,
        serverstate,
    )
    .await?;

    let mut multiplexer_b_values = Vec::new();
    for _ in 0..n {
        multiplexer_b_values.push(BinaryArithmeticShare::ZERO);
    }
    let multiplexer_res_values = run_batch_multiplexer_array(
        setup,
        mpc_encryption,
        tag_offset_counter,
        relay,
        &compare_res_values,
        &trasac_amt_p_values,
        &multiplexer_b_values,
        serverstate,
    )
    .await?;

    let addval_p_values = run_batch_boolean_to_arithmetic(
        setup,
        mpc_encryption,
        tag_offset_counter,
        relay,
        &multiplexer_res_values,
        serverstate,
    )
    .await?;

    let mut output_p = HashMap::new();
    for j in 1..8 {
        let mut sum_p = ArithmeticShare::ZERO;
        for i in 0..n {
            if transactions[i].category == j {
                sum_p.mut_add_share(&addval_p_values[i]);
            }
        }
        output_p.insert(j, sum_p);
    }

    Ok(output_p)
}

// #[cfg(test)]
// mod tests {
//     use super::test_run_cat_debit_month;
//     use crate::process_plaintext_sh::TransactionEntry;
//     use crate::sample_transaction_entries::{TRANSAC_STR_P1, TRANSAC_STR_P2, TRANSAC_STR_P3};
//     use sl_compute::{
//         mpc::{common_randomness::test_run_get_serverstate, verify::test_run_verify},
//         proto::reconstruct_arith_to_float,
//     };
//
//     #[test]
//     fn test_monthly_category_debit() {
//         let (mut serverstate_p1, mut serverstate_p2, mut serverstate_p3) =
//             test_run_get_serverstate();
//
//         let transac_p1: Vec<TransactionEntry> = serde_json::from_str(TRANSAC_STR_P1).unwrap();
//         let transac_p2: Vec<TransactionEntry> = serde_json::from_str(TRANSAC_STR_P2).unwrap();
//         let transac_p3: Vec<TransactionEntry> = serde_json::from_str(TRANSAC_STR_P3).unwrap();
//
//         let month = 6;
//
//         let (output_p1, output_p2, output_p3) = test_run_cat_debit_month(
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
//         for x in output_p1.keys() {
//             print!("{} ", x);
//             reconstruct_arith_to_float(
//                 *output_p1.get(x).unwrap(),
//                 *output_p2.get(x).unwrap(),
//                 *output_p3.get(x).unwrap(),
//                 &mut serverstate_p1,
//                 &mut serverstate_p2,
//                 &mut serverstate_p3,
//             );
//         }
//     }
// }
