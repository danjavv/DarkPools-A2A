use crate::process_plaintext_sh::TransactionEntry;
use sl_compute::conversion::a_to_b::run_batch_arithmetic_to_boolean;
use sl_compute::conversion::b_to_a::run_batch_boolean_to_arithmetic;
use sl_compute::transport::proto::FilteredMsgRelay;
use sl_compute::transport::setup::common::MPCEncryption;
use sl_compute::transport::setup::CommonSetupMessage;
use sl_compute::transport::types::ProtocolError;
use sl_compute::transport::utils::TagOffsetCounter;
use sl_compute::types::BinaryArithmeticShare;
use sl_compute::types::{ArithmeticShare, ServerState};
use sl_compute::utility::decimal_share_convert::decimal_to_arithmetic;
use sl_compute::utility::multiplexer::run_multiplexer_array;
use sl_mpc_mate::coord::Relay;

pub async fn run_total_debit<T, R>(
    setup: &T,
    mpc_encryption: &mut MPCEncryption,
    tag_offset_counter: &mut TagOffsetCounter,
    relay: &mut FilteredMsgRelay<R>,
    transactions: &[TransactionEntry],
    serverstate: &mut ServerState,
) -> Result<ArithmeticShare, ProtocolError>
where
    T: CommonSetupMessage,
    R: Relay,
{
    let mut debit = Vec::new();

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
            &BinaryArithmeticShare::ZERO,
            &trasac_amt_p_values[i],
            serverstate,
        )
        .await?;
        debit.push(amount_credit_p);
    }

    let debit_values = run_batch_boolean_to_arithmetic(
        setup,
        mpc_encryption,
        tag_offset_counter,
        relay,
        &debit,
        serverstate,
    )
    .await?;

    let mut debit_p = ArithmeticShare::ZERO;
    for v in debit_values {
        debit_p.mut_add_share(&v);
    }

    Ok(debit_p)
}

// #[cfg(test)]
// mod tests {
//     use super::test_run_total_debit;
//     use crate::process_plaintext_sh::TransactionEntry;
//     use crate::sample_transaction_entries::{TRANSAC_STR_P1, TRANSAC_STR_P2, TRANSAC_STR_P3};
//     use sl_compute::{
//         mpc::{common_randomness::test_run_get_serverstate, verify::test_run_verify},
//         proto::reconstruct_arith_to_float,
//     };
//
//     #[test]
//     fn test_total_debit() {
//         let (mut serverstate_p1, mut serverstate_p2, mut serverstate_p3) =
//             test_run_get_serverstate();
//
//         let transac_p1: Vec<TransactionEntry> = serde_json::from_str(TRANSAC_STR_P1).unwrap();
//         let transac_p2: Vec<TransactionEntry> = serde_json::from_str(TRANSAC_STR_P2).unwrap();
//         let transac_p3: Vec<TransactionEntry> = serde_json::from_str(TRANSAC_STR_P3).unwrap();
//
//         let (total_debit_p1, total_debit_p2, total_debit_p3) = test_run_total_debit(
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
//             total_debit_p1,
//             total_debit_p2,
//             total_debit_p3,
//             &mut serverstate_p1,
//             &mut serverstate_p2,
//             &mut serverstate_p3,
//         );
//     }
// }
