use super::average_eod_balance::run_avg_eod_balance;
use crate::process_plaintext_sh::TransactionEntry;
use sl_compute::transport::proto::{FilteredMsgRelay, Relay};
use sl_compute::transport::setup::common::MPCEncryption;
use sl_compute::transport::setup::CommonSetupMessage;
use sl_compute::transport::types::ProtocolError;
use sl_compute::transport::utils::TagOffsetCounter;
use sl_compute::types::{ArithmeticShare, ServerState};

pub async fn run_avg_eod_balance_all<T, R>(
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
        let p1_mon_i_out = run_avg_eod_balance(
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

// #[cfg(test)]
// mod tests {
//     use super::test_run_avg_eod_balance_all;
//     use crate::process_plaintext_sh::TransactionEntry;
//     use crate::sample_transaction_entries::{TRANSAC_STR_P1, TRANSAC_STR_P2, TRANSAC_STR_P3};
//     use sl_compute::{
//         mpc::{common_randomness::test_run_get_serverstate, verify::test_run_verify},
//         proto::reconstruct_arith_to_float,
//     };
//
//     #[test]
//     fn test_avg_eod_balance_all() {
//         let (mut serverstate_p1, mut serverstate_p2, mut serverstate_p3) =
//             test_run_get_serverstate();
//
//         let transac_p1: Vec<TransactionEntry> = serde_json::from_str(TRANSAC_STR_P1).unwrap();
//         let transac_p2: Vec<TransactionEntry> = serde_json::from_str(TRANSAC_STR_P2).unwrap();
//         let transac_p3: Vec<TransactionEntry> = serde_json::from_str(TRANSAC_STR_P3).unwrap();
//
//         let (output_p1, output_p2, output_p3) = test_run_avg_eod_balance_all(
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
//         for i in 0..output_p1.len() {
//             reconstruct_arith_to_float(
//                 output_p1[i],
//                 output_p2[i],
//                 output_p3[i],
//                 &mut serverstate_p1,
//                 &mut serverstate_p2,
//                 &mut serverstate_p3,
//             );
//         }
//     }
// }
