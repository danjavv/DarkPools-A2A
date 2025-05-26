use crate::eod_balances::run_eod_balances;
use crate::process_plaintext_sh::TransactionEntry;
use sl_compute::transport::proto::{FilteredMsgRelay, Relay};
use sl_compute::transport::setup::common::MPCEncryption;
use sl_compute::transport::setup::CommonSetupMessage;
use sl_compute::transport::types::ProtocolError;
use sl_compute::transport::utils::TagOffsetCounter;
use sl_compute::types::FieldElement;
use sl_compute::types::{ArithmeticShare, ServerState};
use sl_compute::utility::long_division::run_long_division;

pub async fn run_avg_eod_balance<T, R>(
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
    let days = [31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
    let my_party_index = setup.participant_index();

    let eod_balances = run_eod_balances(
        setup,
        mpc_encryption,
        tag_offset_counter,
        relay,
        month,
        transaction_entry,
        serverstate,
    )
    .await?;

    let mut balance = ArithmeticShare::ZERO;
    let _ = eod_balances.iter().map(|v| balance.mut_add_share(v));

    let d = FieldElement::from(days[month - 1] as u64);
    let month_p = ArithmeticShare::from_constant(&d, my_party_index);

    let output = run_long_division(
        setup,
        mpc_encryption,
        tag_offset_counter,
        relay,
        &balance,
        &month_p,
        serverstate,
    )
    .await?;

    Ok(output)
}

// #[cfg(test)]
// mod tests {
//     use super::test_run_avg_eod_balance;
//     use crate::process_plaintext_sh::TransactionEntry;
//     use crate::sample_transaction_entries::{TRANSAC_STR_P1, TRANSAC_STR_P2, TRANSAC_STR_P3};
//     use sl_compute::{
//         mpc::{common_randomness::test_run_get_serverstate, verify::test_run_verify},
//         proto::reconstruct_arith_to_float,
//     };
//
//     #[test]
//     fn test_avg_eod_balances() {
//         let (mut serverstate_p1, mut serverstate_p2, mut serverstate_p3) =
//             test_run_get_serverstate();
//
//         let transac_p1: Vec<TransactionEntry> = serde_json::from_str(TRANSAC_STR_P1).unwrap();
//         let transac_p2: Vec<TransactionEntry> = serde_json::from_str(TRANSAC_STR_P2).unwrap();
//         let transac_p3: Vec<TransactionEntry> = serde_json::from_str(TRANSAC_STR_P3).unwrap();
//
//         let month = 6;
//
//         let (output_p1, output_p2, output_p3) = test_run_avg_eod_balance(
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
