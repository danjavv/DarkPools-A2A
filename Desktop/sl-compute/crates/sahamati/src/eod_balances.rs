use crate::process_plaintext_sh::{TimeStamp, TransactionEntry};
use sl_compute::comparison::compare_equal::{run_batch_compare_eq, run_compare_eq};
use sl_compute::comparison::compare_ge::run_batch_compare_ge;
use sl_compute::conversion::a_to_b::run_batch_arithmetic_to_boolean;
use sl_compute::conversion::b_to_a::run_batch_boolean_to_arithmetic;
use sl_compute::mpc::multiply_binary_shares::run_batch_and_binary_shares;
use sl_compute::transport::proto::FilteredMsgRelay;
use sl_compute::transport::setup::common::MPCEncryption;
use sl_compute::transport::setup::CommonSetupMessage;
use sl_compute::transport::types::ProtocolError;
use sl_compute::transport::utils::TagOffsetCounter;
use sl_compute::types::{ArithmeticShare, BinaryShare, ServerState};
use sl_compute::types::{BinaryArithmeticShare, FieldElement};
use sl_compute::utility::decimal_share_convert::decimal_to_arithmetic;
use sl_compute::utility::multiplexer::{
    run_batch_multiplexer_array, run_multiplexer_array, run_multiplexer_bit,
};
use sl_mpc_mate::coord::Relay;

pub async fn run_compare_time_ge<T, R>(
    setup: &T,
    mpc_encryption: &mut MPCEncryption,
    tag_offset_counter: &mut TagOffsetCounter,
    relay: &mut FilteredMsgRelay<R>,
    time1: &TimeStamp,
    time2: &TimeStamp,
    serverstate: &mut ServerState,
) -> Result<BinaryShare, ProtocolError>
where
    T: CommonSetupMessage,
    R: Relay,
{
    let arith_values = [
        time1.hour,
        time2.hour,
        time1.minute,
        time2.minute,
        time1.second,
        time2.second,
    ];
    let bin_values = run_batch_arithmetic_to_boolean(
        setup,
        mpc_encryption,
        tag_offset_counter,
        relay,
        &arith_values,
        serverstate,
    )
    .await?;
    let hour1_p = bin_values[0];
    let hour2_p = bin_values[1];
    let min1_p = bin_values[2];
    let min2_p = bin_values[3];
    let sec1_p = bin_values[4];
    let sec2_p = bin_values[5];

    // Hour, Minute, Second comparison
    let compare_a_values = [hour1_p, min1_p, sec1_p];
    let compare_b_values = [hour2_p, min2_p, sec2_p];
    let compare_ge_values = run_batch_compare_ge(
        setup,
        mpc_encryption,
        tag_offset_counter,
        relay,
        &compare_a_values,
        &compare_b_values,
        serverstate,
    )
    .await?;
    let res_hour_ge_p = compare_ge_values[0];
    let res_min_ge_p = compare_ge_values[1];
    let res_sec_ge_p = compare_ge_values[2];

    let res_hour_eq_p = run_compare_eq(
        setup,
        mpc_encryption,
        tag_offset_counter,
        relay,
        &hour1_p,
        &hour2_p,
        serverstate,
    )
    .await?;

    let res_min_eq_p = run_compare_eq(
        setup,
        mpc_encryption,
        tag_offset_counter,
        relay,
        &min1_p,
        &min2_p,
        serverstate,
    )
    .await?;

    let not_hour_eq_p = res_hour_eq_p.not();
    let not_min_eq_p = res_min_eq_p.not();

    let mul_a_values = [res_min_eq_p, not_min_eq_p];
    let mul_b_values = [res_sec_ge_p, res_min_ge_p];
    let mul_res_values = run_batch_and_binary_shares(
        setup,
        mpc_encryption,
        tag_offset_counter,
        relay,
        &mul_a_values,
        &mul_b_values,
        serverstate,
    )
    .await?;
    let temp1_share_p = mul_res_values[0];
    let temp2_share_p = mul_res_values[1];
    let min_out_p = temp1_share_p.xor(&temp2_share_p);

    let mul_a_values = [res_hour_ge_p, res_hour_eq_p];
    let mul_b_values = [not_hour_eq_p, min_out_p];
    let mul_res_values = run_batch_and_binary_shares(
        setup,
        mpc_encryption,
        tag_offset_counter,
        relay,
        &mul_a_values,
        &mul_b_values,
        serverstate,
    )
    .await?;
    let temp1_share_p = mul_res_values[0];
    let temp2_share_p = mul_res_values[1];
    let output = temp1_share_p.xor(&temp2_share_p);

    Ok(output)
}

#[allow(clippy::too_many_arguments)]
pub async fn run_multiplexer_timestamp<T, R>(
    setup: &T,
    mpc_encryption: &mut MPCEncryption,
    tag_offset_counter: &mut TagOffsetCounter,
    relay: &mut FilteredMsgRelay<R>,
    comp: &BinaryShare,
    time1: &TimeStamp,
    time2: &TimeStamp,
    serverstate: &mut ServerState,
) -> Result<TimeStamp, ProtocolError>
where
    T: CommonSetupMessage,
    R: Relay,
{
    let mut output: TimeStamp = TimeStamp::default();

    let arith_values = [
        time1.date,
        time2.date,
        time1.month,
        time2.month,
        time1.year,
        time2.year,
        time1.hour,
        time2.hour,
        time1.minute,
        time2.minute,
        time1.second,
        time2.second,
        time1.diff_hour,
        time2.diff_hour,
        time1.diff_minute,
        time2.diff_minute,
    ];
    let bin_values = run_batch_arithmetic_to_boolean(
        setup,
        mpc_encryption,
        tag_offset_counter,
        relay,
        &arith_values,
        serverstate,
    )
    .await?;

    let mut choice_values = Vec::new();
    for _ in 0..8 {
        choice_values.push(*comp);
    }
    let multiplexer_a_values = [
        bin_values[0],
        bin_values[2],
        bin_values[4],
        bin_values[6],
        bin_values[8],
        bin_values[10],
        bin_values[12],
        bin_values[14],
    ];
    let multiplexer_b_values = [
        bin_values[1],
        bin_values[3],
        bin_values[5],
        bin_values[7],
        bin_values[9],
        bin_values[11],
        bin_values[13],
        bin_values[15],
    ];

    let multiplexer_res_values = run_batch_multiplexer_array(
        setup,
        mpc_encryption,
        tag_offset_counter,
        relay,
        &choice_values,
        &multiplexer_a_values,
        &multiplexer_b_values,
        serverstate,
    )
    .await?;

    let arith_values = run_batch_boolean_to_arithmetic(
        setup,
        mpc_encryption,
        tag_offset_counter,
        relay,
        &multiplexer_res_values,
        serverstate,
    )
    .await?;

    output.date = arith_values[0];
    output.month = arith_values[1];
    output.year = arith_values[2];
    output.hour = arith_values[3];
    output.minute = arith_values[4];
    output.second = arith_values[5];
    output.diff_hour = arith_values[6];
    output.diff_minute = arith_values[7];
    output.plus = run_multiplexer_bit(
        setup,
        mpc_encryption,
        tag_offset_counter,
        relay,
        comp,
        &time1.plus,
        &time2.plus,
        serverstate,
    )
    .await?;

    Ok(output)
}

pub async fn run_eod_balances<T, R>(
    setup: &T,
    mpc_encryption: &mut MPCEncryption,
    tag_offset_counter: &mut TagOffsetCounter,
    relay: &mut FilteredMsgRelay<R>,
    month: usize,
    transactions: &[TransactionEntry],
    serverstate: &mut ServerState,
) -> Result<Vec<ArithmeticShare>, ProtocolError>
where
    T: CommonSetupMessage,
    R: Relay,
{
    let my_party_index = setup.participant_index();

    let num_transac = transactions.len();
    let default_month =
        BinaryArithmeticShare::from_constant(&FieldElement::from(month as u64), my_party_index);

    let n = transactions.len();

    // TODO fix it
    let days = [31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];

    let mut eod_balance_p: Vec<(BinaryArithmeticShare, TimeStamp)> = Vec::new();
    for _ in 0..days[month - 1] {
        eod_balance_p.push((BinaryArithmeticShare::ZERO, TimeStamp::default()));
    }

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

    let res_month_p_values = run_batch_compare_eq(
        setup,
        mpc_encryption,
        tag_offset_counter,
        relay,
        &month_p_values,
        &vec![default_month; n],
        serverstate,
    )
    .await?;

    let curr_bal_ar_p_values: Vec<ArithmeticShare> = transactions
        .iter()
        .map(|t| decimal_to_arithmetic(&t.curr_bal))
        .collect();
    let current_bal_p_values = run_batch_arithmetic_to_boolean(
        setup,
        mpc_encryption,
        tag_offset_counter,
        relay,
        &curr_bal_ar_p_values,
        serverstate,
    )
    .await?;

    let a_values: Vec<ArithmeticShare> = transactions.iter().map(|t| t.time_stamp.date).collect();
    let day_p_values = run_batch_arithmetic_to_boolean(
        setup,
        mpc_encryption,
        tag_offset_counter,
        relay,
        &a_values,
        serverstate,
    )
    .await?;

    for i in 0..num_transac {
        let res_month_p = res_month_p_values[i];
        let current_bal_p = current_bal_p_values[i];

        #[allow(clippy::needless_range_loop)]
        for j in 0..days[month - 1] {
            let default_day_p = BinaryArithmeticShare::from_constant(
                &FieldElement::from((j + 1) as u64),
                my_party_index,
            );
            let day_p = day_p_values[i];

            let res_day_p = run_compare_eq(
                setup,
                mpc_encryption,
                tag_offset_counter,
                relay,
                &day_p,
                &default_day_p,
                serverstate,
            )
            .await?;

            let compare_time_p = run_compare_time_ge(
                setup,
                mpc_encryption,
                tag_offset_counter,
                relay,
                &transactions[i].time_stamp,
                &eod_balance_p[j].1,
                serverstate,
            )
            .await?;

            let temp1_share_p = run_batch_and_binary_shares(
                setup,
                mpc_encryption,
                tag_offset_counter,
                relay,
                &[res_day_p],
                &[compare_time_p],
                serverstate,
            )
            .await?[0];

            let temp1_share_p = run_batch_and_binary_shares(
                setup,
                mpc_encryption,
                tag_offset_counter,
                relay,
                &[temp1_share_p],
                &[res_month_p],
                serverstate,
            )
            .await?[0];

            eod_balance_p[j].0 = run_multiplexer_array(
                setup,
                mpc_encryption,
                tag_offset_counter,
                relay,
                &temp1_share_p,
                &current_bal_p,
                &eod_balance_p[j].0,
                serverstate,
            )
            .await?;

            eod_balance_p[j].1 = run_multiplexer_timestamp(
                setup,
                mpc_encryption,
                tag_offset_counter,
                relay,
                &temp1_share_p,
                &transactions[i].time_stamp,
                &eod_balance_p[j].1,
                serverstate,
            )
            .await?;
        }
    }

    let mut b_values = Vec::new();
    #[allow(clippy::needless_range_loop)]
    for i in 0..days[month - 1] {
        b_values.push(eod_balance_p[i].0);
    }
    let eod_arith_balance = run_batch_boolean_to_arithmetic(
        setup,
        mpc_encryption,
        tag_offset_counter,
        relay,
        &b_values,
        serverstate,
    )
    .await?;

    Ok(eod_arith_balance)
}

// #[cfg(test)]
// mod tests {
//     use super::test_run_eod_balances;
//     use crate::process_plaintext_sh::TransactionEntry;
//     use crate::sample_transaction_entries::{TRANSAC_STR_P1, TRANSAC_STR_P2, TRANSAC_STR_P3};
//     use sl_compute::{
//         mpc::{common_randomness::test_run_get_serverstate, verify::test_run_verify},
//         proto::reconstruct_arith_to_float,
//     };
//
//     #[test]
//     fn test_eod_balances() {
//         let (mut serverstate_p1, mut serverstate_p2, mut serverstate_p3) =
//             test_run_get_serverstate();
//
//         let transac_p1: Vec<TransactionEntry> = serde_json::from_str(TRANSAC_STR_P1).unwrap();
//         let transac_p2: Vec<TransactionEntry> = serde_json::from_str(TRANSAC_STR_P2).unwrap();
//         let transac_p3: Vec<TransactionEntry> = serde_json::from_str(TRANSAC_STR_P3).unwrap();
//
//         let days = [31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
//
//         let month = 6;
//
//         let (output_p1, output_p2, output_p3) = test_run_eod_balances(
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
//         for i in 0..days[month - 1] {
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
