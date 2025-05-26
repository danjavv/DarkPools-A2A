use super::helper_function::{run_full_adder, run_parallel_prefix_adder, FAInput, FAOutput};
use crate::comparison::compare_ge_ec::{run_compare_ge_ec, run_compare_ge_long_ec};
use crate::constants::EC_FIELD_SIZE;
use crate::conversion::binary_ec_subtract::{run_binary_ec_long_subtract, run_binary_ec_subtract};
use crate::proto::convert_u256_to_bin;
use crate::transport::proto::FilteredMsgRelay;
use crate::transport::setup::common::MPCEncryption;
use crate::transport::setup::CommonSetupMessage;
use crate::transport::types::ProtocolError;
use crate::transport::utils::TagOffsetCounter;
use crate::types::{ArithmeticECShare, BinaryShare, BinaryStringShare, ServerState};
use crate::utility::helper::get_modulus;
use crate::utility::multiplexer::run_multiplexer_vec;
use sl_mpc_mate::coord::Relay;

fn a2b_ec_create_msg1(share: &ArithmeticECShare, party_index: usize) -> FAInput {
    let p = get_modulus();
    let sub = share.value1.sub_mod(&share.value2, &p);

    let binary_share1 = convert_u256_to_bin(sub);
    let binary_share2 = convert_u256_to_bin(share.value2);

    let binary_x1 = BinaryStringShare::from_constant(&binary_share2, 0);
    let binary_x2 = BinaryStringShare::zero(EC_FIELD_SIZE);
    let binary_x3 = BinaryStringShare::from_constant(&binary_share1, 1);

    match party_index {
        0 => FAInput {
            a: binary_x1,
            b: binary_x2,
            carry: binary_x3,
        },
        1 => FAInput {
            a: binary_x3,
            b: binary_x1,
            carry: binary_x2,
        },
        _ => FAInput {
            a: binary_x2,
            b: binary_x3,
            carry: binary_x1,
        },
    }
}

/// Implementation of Protocol 2.1 (A2B) from https://github.com/silence-laboratories/research-silent-compute/blob/main/paper/main.pdf.
pub async fn run_arithmetic_to_boolean_ec<T, R>(
    setup: &T,
    mpc_encryption: &mut MPCEncryption,
    tag_offset_counter: &mut TagOffsetCounter,
    relay: &mut FilteredMsgRelay<R>,
    share: &ArithmeticECShare,
    serverstate: &mut ServerState,
) -> Result<BinaryStringShare, ProtocolError>
where
    T: CommonSetupMessage,
    R: Relay,
{
    let my_party_id = setup.participant_index();

    let p = get_modulus();
    let pbin = convert_u256_to_bin(p);

    assert_eq!(pbin.length as usize, EC_FIELD_SIZE);
    let pbin_p = BinaryStringShare::from_constant(&pbin, my_party_id);
    let mut pbin_long_p = BinaryStringShare::from_constant(&pbin, my_party_id);
    pbin_long_p.push_binary_share(BinaryShare::ZERO);

    let binary_p = a2b_ec_create_msg1(share, my_party_id);

    let (carry, sum) = run_full_adder(
        setup,
        mpc_encryption,
        tag_offset_counter,
        relay,
        binary_p,
        serverstate,
    )
    .await?;

    let mut binary_fa_out = FAOutput { carry, sum };

    let mut c_p: BinaryStringShare = BinaryStringShare::zero(EC_FIELD_SIZE + 1);
    for i in (1..(EC_FIELD_SIZE + 1)).rev() {
        c_p.set_binary_share(i, &binary_fa_out.carry.get_binary_share(i - 1));
    }

    let comp_c1_p = run_compare_ge_long_ec(
        setup,
        mpc_encryption,
        tag_offset_counter,
        relay,
        &c_p,
        &pbin_long_p,
        serverstate,
    )
    .await?;

    let sub_c_1_p = run_binary_ec_long_subtract(
        setup,
        mpc_encryption,
        tag_offset_counter,
        relay,
        &c_p,
        serverstate,
    )
    .await?;

    let c_1_p = run_multiplexer_vec(
        setup,
        mpc_encryption,
        tag_offset_counter,
        relay,
        &comp_c1_p,
        &sub_c_1_p,
        &c_p,
        serverstate,
    )
    .await?;

    let comp_c2_p = run_compare_ge_long_ec(
        setup,
        mpc_encryption,
        tag_offset_counter,
        relay,
        &c_1_p,
        &pbin_long_p,
        serverstate,
    )
    .await?;

    let sub_c_2_p = run_binary_ec_long_subtract(
        setup,
        mpc_encryption,
        tag_offset_counter,
        relay,
        &c_1_p,
        serverstate,
    )
    .await?;

    let c_2_p = run_multiplexer_vec(
        setup,
        mpc_encryption,
        tag_offset_counter,
        relay,
        &comp_c2_p,
        &sub_c_2_p,
        &c_1_p,
        serverstate,
    )
    .await?;

    let comp_s_p = run_compare_ge_ec(
        setup,
        mpc_encryption,
        tag_offset_counter,
        relay,
        &binary_fa_out.sum,
        &pbin_p,
        serverstate,
    )
    .await?;

    let sub_s_p = run_binary_ec_subtract(
        setup,
        mpc_encryption,
        tag_offset_counter,
        relay,
        &binary_fa_out.sum,
        serverstate,
    )
    .await?;

    let news_p = run_multiplexer_vec(
        setup,
        mpc_encryption,
        tag_offset_counter,
        relay,
        &comp_s_p,
        &sub_s_p,
        &binary_fa_out.sum,
        serverstate,
    )
    .await?;

    for i in 0..EC_FIELD_SIZE {
        let temp_c_p = c_2_p.get_binary_share(i);
        binary_fa_out.carry.set_binary_share(i, &temp_c_p);

        let temp_s_p = news_p.get_binary_share(i);
        binary_fa_out.sum.set_binary_share(i, &temp_s_p);
    }

    let (sum_p1, g_n) = run_parallel_prefix_adder(
        setup,
        mpc_encryption,
        tag_offset_counter,
        relay,
        &binary_fa_out.carry,
        &binary_fa_out.sum,
        serverstate,
    )
    .await?;

    let mut long_sum_p1: BinaryStringShare = BinaryStringShare::with_capacity(EC_FIELD_SIZE + 1);
    for i in 0..EC_FIELD_SIZE {
        let temp1 = sum_p1.get_binary_share(i);
        long_sum_p1.push(temp1.value1, temp1.value2);
    }
    long_sum_p1.push_binary_share(g_n);

    let comp_o_p = run_compare_ge_long_ec(
        setup,
        mpc_encryption,
        tag_offset_counter,
        relay,
        &long_sum_p1,
        &pbin_long_p,
        serverstate,
    )
    .await?;

    let sub_o_p = run_binary_ec_long_subtract(
        setup,
        mpc_encryption,
        tag_offset_counter,
        relay,
        &long_sum_p1,
        serverstate,
    )
    .await?;

    let outtemp_p = run_multiplexer_vec(
        setup,
        mpc_encryption,
        tag_offset_counter,
        relay,
        &comp_o_p,
        &sub_o_p,
        &long_sum_p1,
        serverstate,
    )
    .await?;

    let mut out_p: BinaryStringShare = BinaryStringShare::with_capacity(EC_FIELD_SIZE);
    for i in 0..EC_FIELD_SIZE {
        let temp1 = outtemp_p.get_binary_share(i);
        out_p.push(temp1.value1, temp1.value2);
    }

    Ok(out_p)
}

// #[cfg(test)]
// mod tests {
//     use crypto_bigint::U256;
//
//     use super::test_run_a_to_b_ec;
//
//     use crate::constants::EC_FIELD_SIZE;
//
//     use crate::conversion::ec_to_a::multiply_mod;
//     use crate::mpc::common_randomness::test_run_get_serverstate;
//     use crate::mpc::verify::test_run_verify;
//     use crate::proto::{convert_bin_to_u256, reconstruct_binary_share};
//     use crate::types::{ArithmeticECShare, BinaryString};
//     use crate::utility::helper::{convert_str_to_u256, get_modulus};
//
//     #[test]
//     pub fn test_ec_arith_to_b() {
//         let p = get_modulus();
//         let x = p.sub_mod(&U256::from(2u8), &p);
//
//         let share_p1 = ArithmeticECShare {
//             value1: multiply_mod(x, U256::from(2u8)),
//             value2: x,
//         };
//
//         let share_p2 = ArithmeticECShare {
//             value1: multiply_mod(x, U256::from(2u8)),
//             value2: x,
//         };
//         let share_p3 = ArithmeticECShare {
//             value1: multiply_mod(x, U256::from(2u8)),
//             value2: x,
//         };
//
//         let (mut serverstate_p1, mut serverstate_p2, mut serverstate_p3) =
//             test_run_get_serverstate();
//
//         let (out_p1, out_p2, out_p3) = test_run_a_to_b_ec(
//             &share_p1,
//             &share_p2,
//             &share_p3,
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
//         let mut out: BinaryString = BinaryString::with_capacity(EC_FIELD_SIZE);
//         for i in 0..EC_FIELD_SIZE {
//             out.push(reconstruct_binary_share(
//                 out_p1.get_binary_share(i),
//                 out_p2.get_binary_share(i),
//                 out_p3.get_binary_share(i),
//                 &mut serverstate_p1,
//                 &mut serverstate_p2,
//                 &mut serverstate_p3,
//             ));
//         }
//         let result = convert_bin_to_u256(out);
//         let required_result =
//             convert_str_to_u256("7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFE7");
//
//         assert_eq!(required_result, result)
//     }
// }
