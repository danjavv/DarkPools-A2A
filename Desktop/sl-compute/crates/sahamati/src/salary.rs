use crate::process_plaintext_sh::TransactionEntry;
use sl_compute::comparison::compare_equal::run_batch_compare_eq;
use sl_compute::comparison::compare_ge::run_compare_ge;
use sl_compute::conversion::a_to_b::run_batch_arithmetic_to_boolean;
use sl_compute::conversion::b_to_a::run_boolean_to_arithmetic;
use sl_compute::mpc::multiply_binary_shares::run_batch_and_binary_shares;
use sl_compute::transport::proto::FilteredMsgRelay;
use sl_compute::transport::setup::common::MPCEncryption;
use sl_compute::transport::setup::CommonSetupMessage;
use sl_compute::transport::types::ProtocolError;
use sl_compute::transport::utils::TagOffsetCounter;
use sl_compute::types::{ArithmeticShare, ServerState};
use sl_compute::types::{BinaryArithmeticShare, BinaryShare, FieldElement};
use sl_compute::utility::decimal_share_convert::decimal_to_arithmetic;
use sl_compute::utility::multiplexer::{run_batch_multiplexer_array, run_multiplexer_array};
use sl_mpc_mate::coord::Relay;

pub async fn run_get_salary<T, R>(
    setup: &T,
    mpc_encryption: &mut MPCEncryption,
    tag_offset_counter: &mut TagOffsetCounter,
    relay: &mut FilteredMsgRelay<R>,
    month: usize,
    transactions: &[TransactionEntry],
    serverstate: &mut ServerState,
) -> Result<ArithmeticShare, ProtocolError>
where
    T: CommonSetupMessage,
    R: Relay,
{
    let my_party_index = setup.participant_index();

    let mut salary_p = BinaryArithmeticShare::ZERO;

    let default_month =
        BinaryArithmeticShare::from_constant(&FieldElement::from(month as u64), my_party_index);

    let n = transactions.len();

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

    let multiplexer_choice_values: Vec<BinaryShare> =
        transactions.iter().map(|t| t.type_credit).collect();
    let multiplexer_res_values = run_batch_multiplexer_array(
        setup,
        mpc_encryption,
        tag_offset_counter,
        relay,
        &multiplexer_choice_values,
        &trasac_amt_p_values,
        &vec![BinaryArithmeticShare::ZERO; n],
        serverstate,
    )
    .await?;

    for i in 0..transactions.len() {
        let amount_credit_p = multiplexer_res_values[i];
        let compare_output_p = run_compare_ge(
            setup,
            mpc_encryption,
            tag_offset_counter,
            relay,
            &amount_credit_p,
            &salary_p,
            serverstate,
        )
        .await?;

        let res_month_p = compare_res_values[i];

        let temp1_share_p = run_batch_and_binary_shares(
            setup,
            mpc_encryption,
            tag_offset_counter,
            relay,
            &[res_month_p],
            &[compare_output_p],
            serverstate,
        )
        .await?[0];

        salary_p = run_multiplexer_array(
            setup,
            mpc_encryption,
            tag_offset_counter,
            relay,
            &temp1_share_p,
            &amount_credit_p,
            &salary_p,
            serverstate,
        )
        .await?;
    }

    let output_p = run_boolean_to_arithmetic(
        setup,
        mpc_encryption,
        tag_offset_counter,
        relay,
        &salary_p,
        serverstate,
    )
    .await?;

    Ok(output_p)
}

// #[cfg(test)]
// mod tests {
//     use super::test_run_get_salary;
//     use crate::process_plaintext_sh::TransactionEntry;
//     use crate::sample_transaction_entries::{TRANSAC_STR_P1, TRANSAC_STR_P2, TRANSAC_STR_P3};
//     use sl_compute::{
//         mpc::{common_randomness::test_run_get_serverstate, verify::test_run_verify},
//         proto::reconstruct_arith_to_float,
//     };
//
//     #[test]
//     fn test_get_salary() {
//         let (mut serverstate_p1, mut serverstate_p2, mut serverstate_p3) =
//             test_run_get_serverstate();
//
//         let transac_p1: Vec<TransactionEntry> = serde_json::from_str(TRANSAC_STR_P1).unwrap();
//         let transac_p2: Vec<TransactionEntry> = serde_json::from_str(TRANSAC_STR_P2).unwrap();
//         let transac_p3: Vec<TransactionEntry> = serde_json::from_str(TRANSAC_STR_P3).unwrap();
//
//         let month = 6;
//
//         let (salary_p1, salary_p2, salary_p3) = test_run_get_salary(
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
//             salary_p1,
//             salary_p2,
//             salary_p3,
//             &mut serverstate_p1,
//             &mut serverstate_p2,
//             &mut serverstate_p3,
//         );
//     }
// }
