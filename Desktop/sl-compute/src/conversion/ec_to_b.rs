use crate::conversion::ec_arith_to_b::run_arithmetic_to_boolean_ec;
use crate::conversion::ec_to_a::run_ec_to_a;
use crate::transport::proto::FilteredMsgRelay;
use crate::transport::setup::common::MPCEncryption;
use crate::transport::setup::CommonSetupMessage;
use crate::transport::types::ProtocolError;
use crate::transport::utils::TagOffsetCounter;
use crate::types::ArithmeticECShare;
use crate::types::{BinaryStringShare, ServerState};
use sl_mpc_mate::coord::Relay;

/// Implementation of Protocol 2.4 (EC2B) from https://github.com/silence-laboratories/research-silent-compute/blob/main/paper/main.pdf.
pub async fn run_ec_to_b<T, R>(
    setup: &T,
    mpc_encryption: &mut MPCEncryption,
    tag_offset_counter: &mut TagOffsetCounter,
    relay: &mut FilteredMsgRelay<R>,
    points: &[ArithmeticECShare],
    serverstate: &mut ServerState,
) -> Result<(BinaryStringShare, BinaryStringShare), ProtocolError>
where
    T: CommonSetupMessage,
    R: Relay,
{
    let mut store_mult_triples_p1: Vec<Vec<ArithmeticECShare>> = Vec::new();
    let mult_a_p1: Vec<ArithmeticECShare> = Vec::new();
    let mult_b_p1: Vec<ArithmeticECShare> = Vec::new();
    let mult_c_p1: Vec<ArithmeticECShare> = Vec::new();
    store_mult_triples_p1.push(mult_a_p1);
    store_mult_triples_p1.push(mult_b_p1);
    store_mult_triples_p1.push(mult_c_p1);

    let (res_x_p, res_y_p) = run_ec_to_a(
        setup,
        mpc_encryption,
        tag_offset_counter,
        relay,
        points,
        &mut store_mult_triples_p1,
        serverstate,
    )
    .await?;

    // TODO implement verification
    // verification_ec(
    //     &mut serverstate_p1.common_randomness,
    //     &mut serverstate_p2.common_randomness,
    //     &mut serverstate_p3.common_randomness,
    //     &mut store_mult_triples_p1,
    //     &mut store_mult_triples_p2,
    //     &mut store_mult_triples_p3,
    // );

    let binx_p = run_arithmetic_to_boolean_ec(
        setup,
        mpc_encryption,
        tag_offset_counter,
        relay,
        &res_x_p,
        serverstate,
    )
    .await?;

    let biny_p = run_arithmetic_to_boolean_ec(
        setup,
        mpc_encryption,
        tag_offset_counter,
        relay,
        &res_y_p,
        serverstate,
    )
    .await?;

    Ok((binx_p, biny_p))
}

// #[cfg(test)]
// mod tests {
//     use crypto_bigint::U256;
//
//     use crate::constants::EC_FIELD_SIZE;
//     use crate::mpc::common_randomness::test_run_get_serverstate;
//     use crate::mpc::verify::test_run_verify;
//     use crate::proto::{convert_bin_to_u256, get_default_ec_share, reconstruct_binary_share};
//     use crate::types::{ArithmeticECShare, BinaryString};
//
//     use super::test_run_ec_to_b;
//
//     #[test]
//     pub fn test_ec_to_b() {
//         let (mut serverstate_p1, mut serverstate_p2, mut serverstate_p3) =
//             test_run_get_serverstate();
//
//         // Sample A1
//         let x1 = U256::from(5u8);
//         let y1 = U256::from(10u8);
//
//         // Sample A2
//         let x2 = U256::from(10u8);
//         let y2 = U256::from(40u8);
//
//         // Sample A3
//         let x3 = U256::from(20u8);
//         let y3 = U256::from(30u8);
//
//         let x1_p1 = get_default_ec_share(x1, 1);
//         let x1_p2 = get_default_ec_share(x1, 2);
//         let x1_p3 = get_default_ec_share(x1, 3);
//
//         let y1_p1 = get_default_ec_share(y1, 1);
//         let y1_p2 = get_default_ec_share(y1, 2);
//         let y1_p3 = get_default_ec_share(y1, 3);
//
//         let x2_p1 = get_default_ec_share(x2, 1);
//         let x2_p2 = get_default_ec_share(x2, 2);
//         let x2_p3 = get_default_ec_share(x2, 3);
//
//         let y2_p1 = get_default_ec_share(y2, 1);
//         let y2_p2 = get_default_ec_share(y2, 2);
//         let y2_p3 = get_default_ec_share(y2, 3);
//
//         let x3_p1 = get_default_ec_share(x3, 1);
//         let x3_p2 = get_default_ec_share(x3, 2);
//         let x3_p3 = get_default_ec_share(x3, 3);
//
//         let y3_p1 = get_default_ec_share(y3, 1);
//         let y3_p2 = get_default_ec_share(y3, 2);
//         let y3_p3 = get_default_ec_share(y3, 3);
//
//         let point_p1: Vec<ArithmeticECShare> = vec![x1_p1, x2_p1, x3_p1, y1_p1, y2_p1, y3_p1];
//         let point_p2: Vec<ArithmeticECShare> = vec![x1_p2, x2_p2, x3_p2, y1_p2, y2_p2, y3_p2];
//         let point_p3: Vec<ArithmeticECShare> = vec![x1_p3, x2_p3, x3_p3, y1_p3, y2_p3, y3_p3];
//
//         let (binx_p1, binx_p2, binx_p3, biny_p1, biny_p2, biny_p3) = test_run_ec_to_b(
//             &point_p1,
//             &point_p2,
//             &point_p3,
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
//         let mut out_x: BinaryString = BinaryString::with_capacity(EC_FIELD_SIZE);
//         let mut out_y: BinaryString = BinaryString::with_capacity(EC_FIELD_SIZE);
//         for i in 0..EC_FIELD_SIZE {
//             out_x.push(reconstruct_binary_share(
//                 binx_p1.get_binary_share(i),
//                 binx_p2.get_binary_share(i),
//                 binx_p3.get_binary_share(i),
//                 &mut serverstate_p1,
//                 &mut serverstate_p2,
//                 &mut serverstate_p3,
//             ));
//             out_y.push(reconstruct_binary_share(
//                 biny_p1.get_binary_share(i),
//                 biny_p2.get_binary_share(i),
//                 biny_p3.get_binary_share(i),
//                 &mut serverstate_p1,
//                 &mut serverstate_p2,
//                 &mut serverstate_p3,
//             ));
//         }
//         let outar_x = convert_bin_to_u256(out_x);
//         let outar_y = convert_bin_to_u256(out_y);
//
//         let required_x =
//             U256::from_be_hex("0000000000000000000000000000000000000000000000000000000000004817");
//         let required_y =
//             U256::from_be_hex("000000000000000000000000000000000000000000000000000000000026417A");
//
//         assert_eq!(outar_x, required_x);
//         assert_eq!(outar_y, required_y);
//     }
// }
