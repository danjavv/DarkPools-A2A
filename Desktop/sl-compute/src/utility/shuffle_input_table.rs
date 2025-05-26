use super::split_and_pad::SerializedInputTable;
use crate::transport::proto::FilteredMsgRelay;
use crate::transport::setup::common::MPCEncryption;
use crate::transport::setup::CommonSetupMessage;
use crate::transport::types::ProtocolError;
#[cfg(any(test, feature = "test-support"))]
use crate::transport::utils::Seed;
use crate::transport::utils::TagOffsetCounter;

use crate::types::{BinaryArithmeticShare, ServerState};
use crate::{
    constants::FIELD_SIZE,
    proto::{get_default_bin_share_from_bin_string, split},
    types::{BinaryString, BinaryStringShare},
    utility::{
        helper::random_permutation,
        shuffle_sort::{multiply_gf2_l, reshare_from_generate_msg},
    },
};
use sl_mpc_mate::coord::Relay;

pub struct ShufTableMacMsg1 {
    pub mac: Vec<Vec<BinaryStringShare>>,
}

pub fn shuf_table_create_mac_msg1(
    x: &[Vec<BinaryStringShare>],
    alpha: &[BinaryStringShare],
    n_table_columns: usize,
) -> (ShufTableMacMsg1, ShufTableMacMsg1, ShufTableMacMsg1) {
    let mut share_alpha_1 = vec![BinaryString::with_capacity(FIELD_SIZE); n_table_columns];
    let mut share_alpha_2 = vec![BinaryString::with_capacity(FIELD_SIZE); n_table_columns];

    for j in 0..n_table_columns {
        for i in 0..FIELD_SIZE {
            share_alpha_1[j]
                .push(alpha[j].get_binary_share(i).value1 ^ alpha[j].get_binary_share(i).value2);
            share_alpha_2[j].push(alpha[j].get_binary_share(i).value2);
        }
    }

    let length = x.len();

    let mut share_p1: Vec<Vec<BinaryStringShare>> = Vec::with_capacity(length);
    let mut share_p2: Vec<Vec<BinaryStringShare>> = Vec::with_capacity(length);
    let mut share_p3: Vec<Vec<BinaryStringShare>> = Vec::with_capacity(length);

    for x_i in x {
        let mut t1: Vec<BinaryStringShare> = Vec::with_capacity(n_table_columns);
        let mut t2: Vec<BinaryStringShare> = Vec::with_capacity(n_table_columns);
        let mut t3: Vec<BinaryStringShare> = Vec::with_capacity(n_table_columns);

        for k in 0..n_table_columns {
            let mut share_x_1 = BinaryString::with_capacity(FIELD_SIZE);
            let mut share_x_2 = BinaryString::with_capacity(FIELD_SIZE);

            let mut result: BinaryString = BinaryString::with_capacity(FIELD_SIZE);

            for j in 0..FIELD_SIZE {
                share_x_1
                    .push(x_i[k].get_binary_share(j).value1 ^ x_i[k].get_binary_share(j).value2);
                share_x_2.push(x_i[k].get_binary_share(j).value2);
            }

            let z_i_1 = multiply_gf2_l(&share_alpha_2[k], &share_x_2);
            let z_i_2 = multiply_gf2_l(&share_alpha_1[k], &share_x_2);
            let z_i_3 = multiply_gf2_l(&share_alpha_2[k], &share_x_1);

            for j in 0..FIELD_SIZE {
                result.push(z_i_1[j] ^ z_i_2[j] ^ z_i_3[j]);
            }

            let (temp1, temp2, temp3) = get_default_bin_share_from_bin_string(&result);

            t1.push(temp1);
            t2.push(temp2);
            t3.push(temp3);
        }
        share_p1.push(t1);
        share_p2.push(t2);
        share_p3.push(t3);
    }
    (
        ShufTableMacMsg1 { mac: share_p1 },
        ShufTableMacMsg1 { mac: share_p2 },
        ShufTableMacMsg1 { mac: share_p3 },
    )
}

pub fn shuf_table_apply_permutation(
    arr: &[Vec<BinaryString>],
    perm: &[usize],
) -> Vec<Vec<BinaryString>> {
    if arr.len() != perm.len() {
        panic!("Permutation length must match the array length.");
    }
    let mut permuted_vec = vec![arr[0].clone(); arr.len()];
    for (i, &p) in perm.iter().enumerate() {
        permuted_vec[i].clone_from(&arr[p]);
    }
    permuted_vec
}

/// Implementation of Protocol 3.14 (Shuffle) from https://github.com/silence-laboratories/research-silent-compute/blob/main/paper/main.pdf for a vector of inputs.
pub fn test_run_shuffle_serialized_table(
    ser_table_p1: &[Vec<BinaryStringShare>],
    ser_table_p2: &[Vec<BinaryStringShare>],
    ser_table_p3: &[Vec<BinaryStringShare>],
    serverstate_p1: &mut ServerState,
    serverstate_p2: &mut ServerState,
    serverstate_p3: &mut ServerState,
) -> (
    SerializedInputTable,
    SerializedInputTable,
    SerializedInputTable,
) {
    let n_table_columns = ser_table_p1[0].len();
    let n_table_entries = ser_table_p1.len();

    // Generate a random alpha value for the MAC
    let mut alpha_p1: Vec<BinaryStringShare> = Vec::with_capacity(n_table_columns);
    let mut alpha_p2: Vec<BinaryStringShare> = Vec::with_capacity(n_table_columns);
    let mut alpha_p3: Vec<BinaryStringShare> = Vec::with_capacity(n_table_columns);

    let mut zero: BinaryStringShare = BinaryStringShare::with_capacity(FIELD_SIZE);
    for _ in 0..FIELD_SIZE {
        zero.push(false, false);
    }

    for _ in 0..n_table_columns {
        alpha_p1.push(zero.clone());
        alpha_p2.push(zero.clone());
        alpha_p3.push(zero.clone());
    }

    for j in 0..FIELD_SIZE {
        for alpha_p1_j in alpha_p1.iter_mut().take(n_table_columns) {
            let rand_p1 = serverstate_p1.common_randomness.random_bit();
            alpha_p1_j.set(j, rand_p1[0], rand_p1[1]);
        }

        for alpha_p2_j in alpha_p2.iter_mut().take(n_table_columns) {
            let rand_p2 = serverstate_p2.common_randomness.random_bit();
            alpha_p2_j.set(j, rand_p2[0], rand_p2[1]);
        }

        for alpha_p3_j in alpha_p3.iter_mut().take(n_table_columns) {
            let rand_p3 = serverstate_p3.common_randomness.random_bit();
            alpha_p3_j.set(j, rand_p3[0], rand_p3[1]);
        }
    }

    // Compute the MAC on the secret-shared input table
    let (z1_p1, z1_p2, z1_p3) =
        shuf_table_create_mac_msg1(ser_table_p1, &alpha_p1, n_table_columns);
    let (z2_p1, z2_p2, z2_p3) =
        shuf_table_create_mac_msg1(ser_table_p2, &alpha_p2, n_table_columns);
    let (z3_p1, z3_p2, z3_p3) =
        shuf_table_create_mac_msg1(ser_table_p3, &alpha_p3, n_table_columns);

    let mut z_p1: Vec<Vec<BinaryStringShare>> = Vec::new();
    let mut z_p2: Vec<Vec<BinaryStringShare>> = Vec::new();
    let mut z_p3: Vec<Vec<BinaryStringShare>> = Vec::new();

    for i in 0..n_table_entries {
        let (mut t1, mut t2, mut t3) = (vec![], vec![], vec![]);
        for k in 0..n_table_columns {
            let mut temp_p1: BinaryStringShare = BinaryStringShare::with_capacity(2 * FIELD_SIZE);
            let mut temp_p2: BinaryStringShare = BinaryStringShare::with_capacity(2 * FIELD_SIZE);
            let mut temp_p3: BinaryStringShare = BinaryStringShare::with_capacity(2 * FIELD_SIZE);

            for _ in 0..(2 * FIELD_SIZE) {
                temp_p1.push(false, false);
                temp_p2.push(false, false);
                temp_p3.push(false, false);
            }

            for j in 0..FIELD_SIZE {
                let temp1 = ser_table_p1[i][k].get_binary_share(j);
                temp_p1.set(j, temp1.value1, temp1.value2);
                temp_p1.set(
                    FIELD_SIZE + j,
                    z1_p1.mac[i][k].get_binary_share(j).value1
                        ^ z2_p1.mac[i][k].get_binary_share(j).value1
                        ^ z3_p1.mac[i][k].get_binary_share(j).value1,
                    z1_p1.mac[i][k].get_binary_share(j).value2
                        ^ z2_p1.mac[i][k].get_binary_share(j).value2
                        ^ z3_p1.mac[i][k].get_binary_share(j).value2,
                );

                let temp2 = ser_table_p2[i][k].get_binary_share(j);
                temp_p2.set(j, temp2.value1, temp2.value2);
                temp_p2.set(
                    FIELD_SIZE + j,
                    z1_p2.mac[i][k].get_binary_share(j).value1
                        ^ z2_p2.mac[i][k].get_binary_share(j).value1
                        ^ z3_p2.mac[i][k].get_binary_share(j).value1,
                    z1_p2.mac[i][k].get_binary_share(j).value2
                        ^ z2_p2.mac[i][k].get_binary_share(j).value2
                        ^ z3_p2.mac[i][k].get_binary_share(j).value2,
                );

                let temp3 = ser_table_p3[i][k].get_binary_share(j);
                temp_p3.set(j, temp3.value1, temp3.value2);
                temp_p3.set(
                    FIELD_SIZE + j,
                    z1_p3.mac[i][k].get_binary_share(j).value1
                        ^ z2_p3.mac[i][k].get_binary_share(j).value1
                        ^ z3_p3.mac[i][k].get_binary_share(j).value1,
                    z1_p3.mac[i][k].get_binary_share(j).value2
                        ^ z2_p3.mac[i][k].get_binary_share(j).value2
                        ^ z3_p3.mac[i][k].get_binary_share(j).value2,
                );
            }
            t1.push(temp_p1);
            t2.push(temp_p2);
            t3.push(temp_p3);
        }
        z_p1.push(t1);
        z_p2.push(t2);
        z_p3.push(t3);
    }

    // 2 party shuffle with party 1 and party 2
    let mut reshare_z_p1: Vec<Vec<BinaryString>> = Vec::new();
    let mut reshare_z_p2: Vec<Vec<BinaryString>> = Vec::new();

    for i in 0..n_table_entries {
        let (mut temp_share_z_p1, mut temp_share_z_p2) = (vec![], vec![]);
        for k in 0..n_table_columns {
            let (rs_z_p1, _send_2_p1) = reshare_from_generate_msg(
                z_p1[i][k].clone(),
                &mut serverstate_p1.common_randomness,
            );
            let (send_1_p2, rs_z_p2) = reshare_from_generate_msg(
                z_p2[i][k].clone(),
                &mut serverstate_p2.common_randomness,
            );
            let (_send_1_p3, send_2_p3) = reshare_from_generate_msg(
                z_p3[i][k].clone(),
                &mut serverstate_p3.common_randomness,
            );

            let mut share_z_p1: BinaryString = BinaryString::with_capacity(2 * FIELD_SIZE);
            for j in 0..(2 * FIELD_SIZE) {
                share_z_p1.push(
                    rs_z_p1.data.get_binary_share(j).value1
                        ^ send_1_p2.data.get_binary_share(j).value2,
                );
            }
            temp_share_z_p1.push(share_z_p1);

            let mut share_z_p2: BinaryString = BinaryString::with_capacity(2 * FIELD_SIZE);
            for j in 0..(2 * FIELD_SIZE) {
                share_z_p2.push(
                    rs_z_p2.data.get_binary_share(j).value1
                        ^ send_2_p3.data.get_binary_share(j).value2,
                );
            }
            temp_share_z_p2.push(share_z_p2);
        }
        reshare_z_p1.push(temp_share_z_p1);
        reshare_z_p2.push(temp_share_z_p2);
    }

    let p1_random_permutation = random_permutation(n_table_entries);
    let p2_random_permutation = p1_random_permutation.clone();

    let shuffled_z1_p1 = shuf_table_apply_permutation(&reshare_z_p1, &p1_random_permutation);
    let shuffled_z2_p2 = shuf_table_apply_permutation(&reshare_z_p2, &p2_random_permutation);

    let mut z_perm1_p1: Vec<Vec<BinaryStringShare>> = Vec::new();
    let mut z_perm1_p2: Vec<Vec<BinaryStringShare>> = Vec::new();
    let mut z_perm1_p3: Vec<Vec<BinaryStringShare>> = Vec::new();

    for i in 0..n_table_entries {
        let mut t1: Vec<BinaryStringShare> = Vec::new();
        let mut t2: Vec<BinaryStringShare> = Vec::new();
        let mut t3: Vec<BinaryStringShare> = Vec::new();

        for k in 0..n_table_columns {
            let (share_z1_p1, share_z1_p2, share_z1_p3) =
                get_default_bin_share_from_bin_string(&shuffled_z1_p1[i][k].clone());
            let (share_z2_p1, share_z2_p2, share_z2_p3) =
                get_default_bin_share_from_bin_string(&shuffled_z2_p2[i][k].clone());

            let mut temp_p1: BinaryStringShare = BinaryStringShare::with_capacity(2 * FIELD_SIZE);
            let mut temp_p2: BinaryStringShare = BinaryStringShare::with_capacity(2 * FIELD_SIZE);
            let mut temp_p3: BinaryStringShare = BinaryStringShare::with_capacity(2 * FIELD_SIZE);

            for _ in 0..(2 * FIELD_SIZE) {
                temp_p1.push(false, false);
                temp_p2.push(false, false);
                temp_p3.push(false, false);
            }

            for j in 0..(2 * FIELD_SIZE) {
                temp_p1.set(
                    j,
                    share_z1_p1.get_binary_share(j).value1 ^ share_z2_p1.get_binary_share(j).value1,
                    share_z1_p1.get_binary_share(j).value2 ^ share_z2_p1.get_binary_share(j).value2,
                );
                temp_p2.set(
                    j,
                    share_z1_p2.get_binary_share(j).value1 ^ share_z2_p2.get_binary_share(j).value1,
                    share_z1_p2.get_binary_share(j).value2 ^ share_z2_p2.get_binary_share(j).value2,
                );
                temp_p3.set(
                    j,
                    share_z1_p3.get_binary_share(j).value1 ^ share_z2_p3.get_binary_share(j).value1,
                    share_z1_p3.get_binary_share(j).value2 ^ share_z2_p3.get_binary_share(j).value2,
                );
            }
            t1.push(temp_p1);
            t2.push(temp_p2);
            t3.push(temp_p3);
        }
        z_perm1_p1.push(t1);
        z_perm1_p2.push(t2);
        z_perm1_p3.push(t3);
    }

    let mut x_a_p1: Vec<Vec<BinaryStringShare>> = Vec::new();
    let mut x_a_p2: Vec<Vec<BinaryStringShare>> = Vec::new();
    let mut x_a_p3: Vec<Vec<BinaryStringShare>> = Vec::new();

    let mut mac_a_p1: Vec<Vec<BinaryStringShare>> = Vec::new();
    let mut mac_a_p2: Vec<Vec<BinaryStringShare>> = Vec::new();
    let mut mac_a_p3: Vec<Vec<BinaryStringShare>> = Vec::new();

    // split the shuffled value to message and MAC
    for i in 0..n_table_entries {
        let mut tx1: Vec<BinaryStringShare> = Vec::new();
        let mut tx2: Vec<BinaryStringShare> = Vec::new();
        let mut tx3: Vec<BinaryStringShare> = Vec::new();

        let mut tm1: Vec<BinaryStringShare> = Vec::new();
        let mut tm2: Vec<BinaryStringShare> = Vec::new();
        let mut tm3: Vec<BinaryStringShare> = Vec::new();

        for k in 0..n_table_columns {
            let (temp1_p1, temp2_p1) = split(z_perm1_p1[i][k].clone());
            let (temp1_p2, temp2_p2) = split(z_perm1_p2[i][k].clone());
            let (temp1_p3, temp2_p3) = split(z_perm1_p3[i][k].clone());
            tx1.push(temp1_p1);
            tm1.push(temp2_p1);

            tx2.push(temp1_p2);
            tm2.push(temp2_p2);

            tx3.push(temp1_p3);
            tm3.push(temp2_p3);
        }
        x_a_p1.push(tx1);
        mac_a_p1.push(tm1);

        x_a_p2.push(tx2);
        mac_a_p2.push(tm2);

        x_a_p3.push(tx3);
        mac_a_p3.push(tm3);
    }

    // Verify the MAC
    let (y1_p1, y1_p2, y1_p3) = shuf_table_create_mac_msg1(&x_a_p1, &alpha_p1, n_table_columns);
    let (y2_p1, y2_p2, y2_p3) = shuf_table_create_mac_msg1(&x_a_p2, &alpha_p2, n_table_columns);
    let (y3_p1, y3_p2, y3_p3) = shuf_table_create_mac_msg1(&x_a_p3, &alpha_p3, n_table_columns);

    let mut y_p1: Vec<Vec<BinaryStringShare>> = Vec::new();
    let mut y_p2: Vec<Vec<BinaryStringShare>> = Vec::new();
    let mut y_p3: Vec<Vec<BinaryStringShare>> = Vec::new();

    for i in 0..n_table_entries {
        let (mut t1, mut t2, mut t3) = (vec![], vec![], vec![]);
        for k in 0..n_table_columns {
            let mut temp_p1: BinaryStringShare = BinaryStringShare::with_capacity(FIELD_SIZE);
            let mut temp_p2: BinaryStringShare = BinaryStringShare::with_capacity(FIELD_SIZE);
            let mut temp_p3: BinaryStringShare = BinaryStringShare::with_capacity(FIELD_SIZE);

            for j in 0..FIELD_SIZE {
                temp_p1.push(
                    y1_p1.mac[i][k].get_binary_share(j).value1
                        ^ y2_p1.mac[i][k].get_binary_share(j).value1
                        ^ y3_p1.mac[i][k].get_binary_share(j).value1,
                    y1_p1.mac[i][k].get_binary_share(j).value2
                        ^ y2_p1.mac[i][k].get_binary_share(j).value2
                        ^ y3_p1.mac[i][k].get_binary_share(j).value2,
                );
                temp_p2.push(
                    y1_p2.mac[i][k].get_binary_share(j).value1
                        ^ y2_p2.mac[i][k].get_binary_share(j).value1
                        ^ y3_p2.mac[i][k].get_binary_share(j).value1,
                    y1_p2.mac[i][k].get_binary_share(j).value2
                        ^ y2_p2.mac[i][k].get_binary_share(j).value2
                        ^ y3_p2.mac[i][k].get_binary_share(j).value2,
                );
                temp_p3.push(
                    y1_p3.mac[i][k].get_binary_share(j).value1
                        ^ y2_p3.mac[i][k].get_binary_share(j).value1
                        ^ y3_p3.mac[i][k].get_binary_share(j).value1,
                    y1_p3.mac[i][k].get_binary_share(j).value2
                        ^ y2_p3.mac[i][k].get_binary_share(j).value2
                        ^ y3_p3.mac[i][k].get_binary_share(j).value2,
                );
            }
            t1.push(temp_p1);
            t2.push(temp_p2);
            t3.push(temp_p3);
        }
        y_p1.push(t1);
        y_p2.push(t2);
        y_p3.push(t3);
    }

    // Subtract mac
    let mut v_p1: Vec<Vec<BinaryStringShare>> = Vec::new();
    let mut v_p2: Vec<Vec<BinaryStringShare>> = Vec::new();
    let mut v_p3: Vec<Vec<BinaryStringShare>> = Vec::new();

    for i in 0..n_table_entries {
        let (mut t1, mut t2, mut t3) = (vec![], vec![], vec![]);
        for k in 0..n_table_columns {
            let mut temp_p1: BinaryStringShare = BinaryStringShare::with_capacity(FIELD_SIZE);
            let mut temp_p2: BinaryStringShare = BinaryStringShare::with_capacity(FIELD_SIZE);
            let mut temp_p3: BinaryStringShare = BinaryStringShare::with_capacity(FIELD_SIZE);

            for j in 0..FIELD_SIZE {
                temp_p1.push(
                    y_p1[i][k].get_binary_share(j).value1
                        ^ mac_a_p1[i][k].get_binary_share(j).value1,
                    y_p1[i][k].get_binary_share(j).value2
                        ^ mac_a_p1[i][k].get_binary_share(j).value2,
                );
                temp_p2.push(
                    y_p2[i][k].get_binary_share(j).value1
                        ^ mac_a_p2[i][k].get_binary_share(j).value1,
                    y_p2[i][k].get_binary_share(j).value2
                        ^ mac_a_p2[i][k].get_binary_share(j).value2,
                );
                temp_p3.push(
                    y_p3[i][k].get_binary_share(j).value1
                        ^ mac_a_p3[i][k].get_binary_share(j).value1,
                    y_p3[i][k].get_binary_share(j).value2
                        ^ mac_a_p3[i][k].get_binary_share(j).value2,
                );
            }
            t1.push(temp_p1);
            t2.push(temp_p2);
            t3.push(temp_p3);
        }
        v_p1.push(t1);
        v_p2.push(t2);
        v_p3.push(t3);
    }

    // Check if all the opened values is equal to 0
    for i in 0..n_table_entries {
        for k in 0..n_table_columns {
            for j in 0..FIELD_SIZE {
                assert!(
                    !(v_p1[i][k].get_binary_share(j).value1
                        ^ v_p2[i][k].get_binary_share(j).value2)
                );
                assert!(
                    !(v_p2[i][k].get_binary_share(j).value1
                        ^ v_p3[i][k].get_binary_share(j).value2)
                );
                assert!(
                    !(v_p3[i][k].get_binary_share(j).value1
                        ^ v_p1[i][k].get_binary_share(j).value2)
                );
            }
        }
    }

    // 2 party shuffle with party 2 and party 3
    let mut reshare2_z_p2: Vec<Vec<BinaryString>> = Vec::new();
    let mut reshare2_z_p3: Vec<Vec<BinaryString>> = Vec::new();

    for i in 0..n_table_entries {
        let (mut temp_share_z_p3, mut temp_share_z_p2) = (vec![], vec![]);
        for k in 0..n_table_columns {
            let (_send_1_p1, send_2_p1) = reshare_from_generate_msg(
                z_perm1_p1[i][k].clone(),
                &mut serverstate_p1.common_randomness,
            );
            let (rs_z_p2, _send_2_p2) = reshare_from_generate_msg(
                z_perm1_p2[i][k].clone(),
                &mut serverstate_p2.common_randomness,
            );
            let (send_1_p3, rs_z_p3) = reshare_from_generate_msg(
                z_perm1_p3[i][k].clone(),
                &mut serverstate_p3.common_randomness,
            );

            let mut share_z_p2: BinaryString = BinaryString::with_capacity(2 * FIELD_SIZE);
            for j in 0..(2 * FIELD_SIZE) {
                share_z_p2.push(
                    rs_z_p2.data.get_binary_share(j).value1
                        ^ send_1_p3.data.get_binary_share(j).value2,
                );
            }
            temp_share_z_p2.push(share_z_p2);

            let mut share_z_p3: BinaryString = BinaryString::with_capacity(2 * FIELD_SIZE);
            for j in 0..(2 * FIELD_SIZE) {
                share_z_p3.push(
                    rs_z_p3.data.get_binary_share(j).value1
                        ^ send_2_p1.data.get_binary_share(j).value2,
                );
            }
            temp_share_z_p3.push(share_z_p3);
        }
        reshare2_z_p2.push(temp_share_z_p2);
        reshare2_z_p3.push(temp_share_z_p3);
    }

    let p2_random_permutation = random_permutation(n_table_entries);
    let p3_random_permutation = p2_random_permutation.clone();

    let shuffled_z1_p2 = shuf_table_apply_permutation(&reshare2_z_p2, &p2_random_permutation);
    let shuffled_z2_p3 = shuf_table_apply_permutation(&reshare2_z_p3, &p3_random_permutation);

    let mut z_perm2_p1: Vec<Vec<BinaryStringShare>> = Vec::new();
    let mut z_perm2_p2: Vec<Vec<BinaryStringShare>> = Vec::new();
    let mut z_perm2_p3: Vec<Vec<BinaryStringShare>> = Vec::new();

    for i in 0..n_table_entries {
        let mut t1: Vec<BinaryStringShare> = Vec::new();
        let mut t2: Vec<BinaryStringShare> = Vec::new();
        let mut t3: Vec<BinaryStringShare> = Vec::new();

        for k in 0..n_table_columns {
            let (share_z1_p1, share_z1_p2, share_z1_p3) =
                get_default_bin_share_from_bin_string(&shuffled_z1_p2[i][k].clone());
            let (share_z2_p1, share_z2_p2, share_z2_p3) =
                get_default_bin_share_from_bin_string(&shuffled_z2_p3[i][k].clone());

            let mut temp_p1: BinaryStringShare = BinaryStringShare::with_capacity(2 * FIELD_SIZE);
            let mut temp_p2: BinaryStringShare = BinaryStringShare::with_capacity(2 * FIELD_SIZE);
            let mut temp_p3: BinaryStringShare = BinaryStringShare::with_capacity(2 * FIELD_SIZE);

            for j in 0..(2 * FIELD_SIZE) {
                temp_p1.push(
                    share_z1_p1.get_binary_share(j).value1 ^ share_z2_p1.get_binary_share(j).value1,
                    share_z1_p1.get_binary_share(j).value2 ^ share_z2_p1.get_binary_share(j).value2,
                );
                temp_p2.push(
                    share_z1_p2.get_binary_share(j).value1 ^ share_z2_p2.get_binary_share(j).value1,
                    share_z1_p2.get_binary_share(j).value2 ^ share_z2_p2.get_binary_share(j).value2,
                );
                temp_p3.push(
                    share_z1_p3.get_binary_share(j).value1 ^ share_z2_p3.get_binary_share(j).value1,
                    share_z1_p3.get_binary_share(j).value2 ^ share_z2_p3.get_binary_share(j).value2,
                );
            }
            t1.push(temp_p1);
            t2.push(temp_p2);
            t3.push(temp_p3);
        }
        z_perm2_p1.push(t1);
        z_perm2_p2.push(t2);
        z_perm2_p3.push(t3);
    }

    let mut x_b_p1: Vec<Vec<BinaryStringShare>> = Vec::new();
    let mut x_b_p2: Vec<Vec<BinaryStringShare>> = Vec::new();
    let mut x_b_p3: Vec<Vec<BinaryStringShare>> = Vec::new();

    let mut mac_b_p1: Vec<Vec<BinaryStringShare>> = Vec::new();
    let mut mac_b_p2: Vec<Vec<BinaryStringShare>> = Vec::new();
    let mut mac_b_p3: Vec<Vec<BinaryStringShare>> = Vec::new();

    for i in 0..n_table_entries {
        let (mut tx1, mut tx2, mut tx3) = (vec![], vec![], vec![]);
        let (mut tm1, mut tm2, mut tm3) = (vec![], vec![], vec![]);
        for k in 0..n_table_columns {
            let (temp1_p1, temp2_p1) = split(z_perm2_p1[i][k].clone());
            let (temp1_p2, temp2_p2) = split(z_perm2_p2[i][k].clone());
            let (temp1_p3, temp2_p3) = split(z_perm2_p3[i][k].clone());
            tx1.push(temp1_p1);
            tm1.push(temp2_p1);

            tx2.push(temp1_p2);
            tm2.push(temp2_p2);

            tx3.push(temp1_p3);
            tm3.push(temp2_p3);
        }

        x_b_p1.push(tx1);
        mac_b_p1.push(tm1);

        x_b_p2.push(tx2);
        mac_b_p2.push(tm2);

        x_b_p3.push(tx3);
        mac_b_p3.push(tm3);
    }

    // Verify the MAC
    let (y1_p1, y1_p2, y1_p3) = shuf_table_create_mac_msg1(&x_b_p1, &alpha_p1, n_table_columns);
    let (y2_p1, y2_p2, y2_p3) = shuf_table_create_mac_msg1(&x_b_p2, &alpha_p2, n_table_columns);
    let (y3_p1, y3_p2, y3_p3) = shuf_table_create_mac_msg1(&x_b_p3, &alpha_p3, n_table_columns);

    let mut y_2_p1: Vec<Vec<BinaryStringShare>> = Vec::new();
    let mut y_2_p2: Vec<Vec<BinaryStringShare>> = Vec::new();
    let mut y_2_p3: Vec<Vec<BinaryStringShare>> = Vec::new();

    for i in 0..n_table_entries {
        let mut t1: Vec<BinaryStringShare> = Vec::new();
        let mut t2: Vec<BinaryStringShare> = Vec::new();
        let mut t3: Vec<BinaryStringShare> = Vec::new();

        for k in 0..n_table_columns {
            let mut temp_p1: BinaryStringShare = BinaryStringShare::with_capacity(FIELD_SIZE);
            let mut temp_p2: BinaryStringShare = BinaryStringShare::with_capacity(FIELD_SIZE);
            let mut temp_p3: BinaryStringShare = BinaryStringShare::with_capacity(FIELD_SIZE);

            for j in 0..FIELD_SIZE {
                temp_p1.push(
                    y1_p1.mac[i][k].get_binary_share(j).value1
                        ^ y2_p1.mac[i][k].get_binary_share(j).value1
                        ^ y3_p1.mac[i][k].get_binary_share(j).value1,
                    y1_p1.mac[i][k].get_binary_share(j).value2
                        ^ y2_p1.mac[i][k].get_binary_share(j).value2
                        ^ y3_p1.mac[i][k].get_binary_share(j).value2,
                );
                temp_p2.push(
                    y1_p2.mac[i][k].get_binary_share(j).value1
                        ^ y2_p2.mac[i][k].get_binary_share(j).value1
                        ^ y3_p2.mac[i][k].get_binary_share(j).value1,
                    y1_p2.mac[i][k].get_binary_share(j).value2
                        ^ y2_p2.mac[i][k].get_binary_share(j).value2
                        ^ y3_p2.mac[i][k].get_binary_share(j).value2,
                );
                temp_p3.push(
                    y1_p3.mac[i][k].get_binary_share(j).value1
                        ^ y2_p3.mac[i][k].get_binary_share(j).value1
                        ^ y3_p3.mac[i][k].get_binary_share(j).value1,
                    y1_p3.mac[i][k].get_binary_share(j).value2
                        ^ y2_p3.mac[i][k].get_binary_share(j).value2
                        ^ y3_p3.mac[i][k].get_binary_share(j).value2,
                );
            }
            t1.push(temp_p1);
            t2.push(temp_p2);
            t3.push(temp_p3);
        }
        y_2_p1.push(t1);
        y_2_p2.push(t2);
        y_2_p3.push(t3);
    }

    // Subtract mac
    let mut v2_p1: Vec<Vec<BinaryStringShare>> = Vec::new();
    let mut v2_p2: Vec<Vec<BinaryStringShare>> = Vec::new();
    let mut v2_p3: Vec<Vec<BinaryStringShare>> = Vec::new();

    for i in 0..n_table_entries {
        let (mut t1, mut t2, mut t3) = (vec![], vec![], vec![]);
        for k in 0..n_table_columns {
            let mut temp_p1: BinaryStringShare = BinaryStringShare::with_capacity(FIELD_SIZE);
            let mut temp_p2: BinaryStringShare = BinaryStringShare::with_capacity(FIELD_SIZE);
            let mut temp_p3: BinaryStringShare = BinaryStringShare::with_capacity(FIELD_SIZE);

            for j in 0..FIELD_SIZE {
                temp_p1.push(
                    y_2_p1[i][k].get_binary_share(j).value1
                        ^ mac_b_p1[i][k].get_binary_share(j).value1,
                    y_2_p1[i][k].get_binary_share(j).value2
                        ^ mac_b_p1[i][k].get_binary_share(j).value2,
                );
                temp_p2.push(
                    y_2_p2[i][k].get_binary_share(j).value1
                        ^ mac_b_p2[i][k].get_binary_share(j).value1,
                    y_2_p2[i][k].get_binary_share(j).value2
                        ^ mac_b_p2[i][k].get_binary_share(j).value2,
                );
                temp_p3.push(
                    y_2_p3[i][k].get_binary_share(j).value1
                        ^ mac_b_p3[i][k].get_binary_share(j).value1,
                    y_2_p3[i][k].get_binary_share(j).value2
                        ^ mac_b_p3[i][k].get_binary_share(j).value2,
                );
            }
            t1.push(temp_p1);
            t2.push(temp_p2);
            t3.push(temp_p3);
        }
        v2_p1.push(t1);
        v2_p2.push(t2);
        v2_p3.push(t3);
    }

    // Check if all the opened values is equal to 0
    for i in 0..n_table_entries {
        for k in 0..n_table_columns {
            for j in 0..FIELD_SIZE {
                assert!(
                    !(v2_p1[i][k].get_binary_share(j).value1
                        ^ v2_p2[i][k].get_binary_share(j).value2)
                );
                assert!(
                    !(v2_p2[i][k].get_binary_share(j).value1
                        ^ v2_p3[i][k].get_binary_share(j).value2)
                );
                assert!(
                    !(v2_p3[i][k].get_binary_share(j).value1
                        ^ v2_p1[i][k].get_binary_share(j).value2)
                );
            }
        }
    }

    // 2 party shuffle with party 3 and party 1
    let mut reshare3_z_p3: Vec<Vec<BinaryString>> = Vec::new();
    let mut reshare3_z_p1: Vec<Vec<BinaryString>> = Vec::new();

    for i in 0..n_table_entries {
        let (mut temp_share_z_p3, mut temp_share_z_p1) = (vec![], vec![]);
        for k in 0..n_table_columns {
            let (send_3_p1, rs_z_p1) = reshare_from_generate_msg(
                z_perm2_p1[i][k].clone(),
                &mut serverstate_p1.common_randomness,
            );
            let (_send_3_p2, send_1_p2) = reshare_from_generate_msg(
                z_perm2_p2[i][k].clone(),
                &mut serverstate_p2.common_randomness,
            );
            let (rs_z_p3, _send_1_p3) = reshare_from_generate_msg(
                z_perm2_p3[i][k].clone(),
                &mut serverstate_p3.common_randomness,
            );

            let mut share_z_p1: BinaryString = BinaryString::with_capacity(2 * FIELD_SIZE);
            for j in 0..(2 * FIELD_SIZE) {
                share_z_p1.push(
                    rs_z_p1.data.get_binary_share(j).value1
                        ^ send_1_p2.data.get_binary_share(j).value2,
                );
            }
            temp_share_z_p1.push(share_z_p1);

            let mut share_z_p3: BinaryString = BinaryString::with_capacity(2 * FIELD_SIZE);
            for j in 0..(2 * FIELD_SIZE) {
                share_z_p3.push(
                    rs_z_p3.data.get_binary_share(j).value1
                        ^ send_3_p1.data.get_binary_share(j).value2,
                );
            }
            temp_share_z_p3.push(share_z_p3);
        }
        reshare3_z_p3.push(temp_share_z_p3);
        reshare3_z_p1.push(temp_share_z_p1);
    }

    let p3_random_permutation = random_permutation(n_table_entries);
    let p1_random_permutation = p3_random_permutation.clone();

    let shuffled_z1_p3 = shuf_table_apply_permutation(&reshare3_z_p3, &p3_random_permutation);
    let shuffled_z2_p1 = shuf_table_apply_permutation(&reshare3_z_p1, &p1_random_permutation);

    let mut z_perm3_p1: Vec<Vec<BinaryStringShare>> = Vec::new();
    let mut z_perm3_p2: Vec<Vec<BinaryStringShare>> = Vec::new();
    let mut z_perm3_p3: Vec<Vec<BinaryStringShare>> = Vec::new();

    for i in 0..n_table_entries {
        let mut t1: Vec<BinaryStringShare> = Vec::new();
        let mut t2: Vec<BinaryStringShare> = Vec::new();
        let mut t3: Vec<BinaryStringShare> = Vec::new();

        for k in 0..n_table_columns {
            let (share_z1_p1, share_z1_p2, share_z1_p3) =
                get_default_bin_share_from_bin_string(&shuffled_z1_p3[i][k].clone());
            let (share_z2_p1, share_z2_p2, share_z2_p3) =
                get_default_bin_share_from_bin_string(&shuffled_z2_p1[i][k].clone());

            let mut temp_p1: BinaryStringShare = BinaryStringShare::with_capacity(FIELD_SIZE);
            let mut temp_p2: BinaryStringShare = BinaryStringShare::with_capacity(FIELD_SIZE);
            let mut temp_p3: BinaryStringShare = BinaryStringShare::with_capacity(FIELD_SIZE);

            for j in 0..(2 * FIELD_SIZE) {
                temp_p1.push(
                    share_z1_p1.get_binary_share(j).value1 ^ share_z2_p1.get_binary_share(j).value1,
                    share_z1_p1.get_binary_share(j).value2 ^ share_z2_p1.get_binary_share(j).value2,
                );
                temp_p2.push(
                    share_z1_p2.get_binary_share(j).value1 ^ share_z2_p2.get_binary_share(j).value1,
                    share_z1_p2.get_binary_share(j).value2 ^ share_z2_p2.get_binary_share(j).value2,
                );
                temp_p3.push(
                    share_z1_p3.get_binary_share(j).value1 ^ share_z2_p3.get_binary_share(j).value1,
                    share_z1_p3.get_binary_share(j).value2 ^ share_z2_p3.get_binary_share(j).value2,
                );
            }
            t1.push(temp_p1);
            t2.push(temp_p2);
            t3.push(temp_p3);
        }
        z_perm3_p1.push(t1);
        z_perm3_p2.push(t2);
        z_perm3_p3.push(t3);
    }

    let mut x_c_p1: Vec<Vec<BinaryStringShare>> = Vec::new();
    let mut x_c_p2: Vec<Vec<BinaryStringShare>> = Vec::new();
    let mut x_c_p3: Vec<Vec<BinaryStringShare>> = Vec::new();

    let mut mac_c_p1: Vec<Vec<BinaryStringShare>> = Vec::new();
    let mut mac_c_p2: Vec<Vec<BinaryStringShare>> = Vec::new();
    let mut mac_c_p3: Vec<Vec<BinaryStringShare>> = Vec::new();

    for i in 0..n_table_entries {
        let (mut tx1, mut tx2, mut tx3) = (vec![], vec![], vec![]);
        let (mut tm1, mut tm2, mut tm3) = (vec![], vec![], vec![]);
        for k in 0..n_table_columns {
            let (temp1_p1, temp2_p1) = split(z_perm3_p1[i][k].clone());
            let (temp1_p2, temp2_p2) = split(z_perm3_p2[i][k].clone());
            let (temp1_p3, temp2_p3) = split(z_perm3_p3[i][k].clone());
            tx1.push(temp1_p1);
            tm1.push(temp2_p1);

            tx2.push(temp1_p2);
            tm2.push(temp2_p2);

            tx3.push(temp1_p3);
            tm3.push(temp2_p3);
        }

        x_c_p1.push(tx1);
        mac_c_p1.push(tm1);

        x_c_p2.push(tx2);
        mac_c_p2.push(tm2);

        x_c_p3.push(tx3);
        mac_c_p3.push(tm3);
    }

    // Verify the MAC
    let (y1_p1, y1_p2, y1_p3) = shuf_table_create_mac_msg1(&x_c_p1, &alpha_p1, n_table_columns);
    let (y2_p1, y2_p2, y2_p3) = shuf_table_create_mac_msg1(&x_c_p2, &alpha_p2, n_table_columns);
    let (y3_p1, y3_p2, y3_p3) = shuf_table_create_mac_msg1(&x_c_p3, &alpha_p3, n_table_columns);

    let mut y_3_p1: Vec<Vec<BinaryStringShare>> = Vec::new();
    let mut y_3_p2: Vec<Vec<BinaryStringShare>> = Vec::new();
    let mut y_3_p3: Vec<Vec<BinaryStringShare>> = Vec::new();

    for i in 0..n_table_entries {
        let mut t1: Vec<BinaryStringShare> = Vec::new();
        let mut t2: Vec<BinaryStringShare> = Vec::new();
        let mut t3: Vec<BinaryStringShare> = Vec::new();

        for k in 0..n_table_columns {
            let mut temp_p1: BinaryStringShare = BinaryStringShare::with_capacity(FIELD_SIZE);
            let mut temp_p2: BinaryStringShare = BinaryStringShare::with_capacity(FIELD_SIZE);
            let mut temp_p3: BinaryStringShare = BinaryStringShare::with_capacity(FIELD_SIZE);

            for j in 0..FIELD_SIZE {
                temp_p1.push(
                    y1_p1.mac[i][k].get_binary_share(j).value1
                        ^ y2_p1.mac[i][k].get_binary_share(j).value1
                        ^ y3_p1.mac[i][k].get_binary_share(j).value1,
                    y1_p1.mac[i][k].get_binary_share(j).value2
                        ^ y2_p1.mac[i][k].get_binary_share(j).value2
                        ^ y3_p1.mac[i][k].get_binary_share(j).value2,
                );
                temp_p2.push(
                    y1_p2.mac[i][k].get_binary_share(j).value1
                        ^ y2_p2.mac[i][k].get_binary_share(j).value1
                        ^ y3_p2.mac[i][k].get_binary_share(j).value1,
                    y1_p2.mac[i][k].get_binary_share(j).value2
                        ^ y2_p2.mac[i][k].get_binary_share(j).value2
                        ^ y3_p2.mac[i][k].get_binary_share(j).value2,
                );
                temp_p3.push(
                    y1_p3.mac[i][k].get_binary_share(j).value1
                        ^ y2_p3.mac[i][k].get_binary_share(j).value1
                        ^ y3_p3.mac[i][k].get_binary_share(j).value1,
                    y1_p3.mac[i][k].get_binary_share(j).value2
                        ^ y2_p3.mac[i][k].get_binary_share(j).value2
                        ^ y3_p3.mac[i][k].get_binary_share(j).value2,
                );
            }
            t1.push(temp_p1);
            t2.push(temp_p2);
            t3.push(temp_p3);
        }
        y_3_p1.push(t1);
        y_3_p2.push(t2);
        y_3_p3.push(t3);
    }

    // Subtract mac
    let mut v3_p1: Vec<Vec<BinaryStringShare>> = Vec::new();
    let mut v3_p2: Vec<Vec<BinaryStringShare>> = Vec::new();
    let mut v3_p3: Vec<Vec<BinaryStringShare>> = Vec::new();
    for i in 0..n_table_entries {
        let mut t1: Vec<BinaryStringShare> = Vec::new();
        let mut t2: Vec<BinaryStringShare> = Vec::new();
        let mut t3: Vec<BinaryStringShare> = Vec::new();

        for k in 0..n_table_columns {
            let mut temp_p1: BinaryStringShare = BinaryStringShare::with_capacity(FIELD_SIZE);
            let mut temp_p2: BinaryStringShare = BinaryStringShare::with_capacity(FIELD_SIZE);
            let mut temp_p3: BinaryStringShare = BinaryStringShare::with_capacity(FIELD_SIZE);

            for j in 0..FIELD_SIZE {
                temp_p1.push(
                    y_3_p1[i][k].get_binary_share(j).value1
                        ^ mac_c_p1[i][k].get_binary_share(j).value1,
                    y_3_p1[i][k].get_binary_share(j).value2
                        ^ mac_c_p1[i][k].get_binary_share(j).value2,
                );
                temp_p2.push(
                    y_3_p2[i][k].get_binary_share(j).value1
                        ^ mac_c_p2[i][k].get_binary_share(j).value1,
                    y_3_p2[i][k].get_binary_share(j).value2
                        ^ mac_c_p2[i][k].get_binary_share(j).value2,
                );
                temp_p3.push(
                    y_3_p3[i][k].get_binary_share(j).value1
                        ^ mac_c_p3[i][k].get_binary_share(j).value1,
                    y_3_p3[i][k].get_binary_share(j).value2
                        ^ mac_c_p3[i][k].get_binary_share(j).value2,
                );
            }
            t1.push(temp_p1);
            t2.push(temp_p2);
            t3.push(temp_p3);
        }
        v3_p1.push(t1);
        v3_p2.push(t2);
        v3_p3.push(t3);
    }

    // Check if all the opened values is equal to 0
    for i in 0..n_table_entries {
        for k in 0..n_table_columns {
            for j in 0..FIELD_SIZE {
                assert!(
                    !(v3_p1[i][k].get_binary_share(j).value1
                        ^ v3_p2[i][k].get_binary_share(j).value2)
                );
                assert!(
                    !(v3_p2[i][k].get_binary_share(j).value1
                        ^ v3_p3[i][k].get_binary_share(j).value2)
                );
                assert!(
                    !(v3_p3[i][k].get_binary_share(j).value1
                        ^ v3_p1[i][k].get_binary_share(j).value2)
                );
            }
        }
    }

    (
        SerializedInputTable { ser_table: x_c_p1 },
        SerializedInputTable { ser_table: x_c_p2 },
        SerializedInputTable { ser_table: x_c_p3 },
    )
}

/// Implementation of Protocol 3.14 (Shuffle) from https://github.com/silence-laboratories/research-silent-compute/blob/main/paper/main.pdf for a vector of inputs.
pub async fn run_shuffle_serialized_table<T, R>(
    _setup: &T,
    _mpc_encryption: &mut MPCEncryption,
    _tag_offset_counter: &mut TagOffsetCounter,
    _relay: &mut FilteredMsgRelay<R>,
    ser_table_p: &[Vec<BinaryArithmeticShare>],
    _serverstate: &mut ServerState,
) -> Result<Vec<Vec<BinaryArithmeticShare>>, ProtocolError>
where
    T: CommonSetupMessage,
    R: Relay,
{
    // let n_table_columns = ser_table_p[0].len();
    // let n_table_entries = ser_table_p.len();
    //
    // // Generate a random alpha value for the MAC
    // let mut alpha_p: Vec<BinaryStringShare> = Vec::with_capacity(n_table_columns);
    //
    // let mut zero: BinaryStringShare = BinaryStringShare::with_capacity(FIELD_SIZE);
    // for _ in 0..FIELD_SIZE {
    //     zero.push(false, false);
    // }
    //
    // for _ in 0..n_table_columns {
    //     alpha_p.push(zero.clone());
    // }
    //
    // for j in 0..FIELD_SIZE {
    //     for alpha_p1_j in alpha_p.iter_mut().take(n_table_columns) {
    //         let rand_p1 = generate_rand_bool(&mut serverstate.common_randomness);
    //         alpha_p1_j.set(j, rand_p1[0], rand_p1[1]);
    //     }
    // }
    //
    // // Compute the MAC on the secret-shared input table
    // let (z1_p1, z1_p2, z1_p3) =
    //     shuf_table_create_mac_msg1(ser_table_p, &alpha_p, n_table_columns);
    // // let (z2_p1, z2_p2, z2_p3) =
    // //     shuf_table_create_mac_msg1(ser_table_p2, &alpha_p2, n_table_columns);
    // // let (z3_p1, z3_p2, z3_p3) =
    // //     shuf_table_create_mac_msg1(ser_table_p3, &alpha_p3, n_table_columns);
    //
    // let mut z_p: Vec<Vec<BinaryStringShare>> = Vec::new();
    //
    // for i in 0..n_table_entries {
    //     let mut t = vec![];
    //     for k in 0..n_table_columns {
    //         let mut temp_p: BinaryStringShare = BinaryStringShare::with_capacity(2 * FIELD_SIZE);
    //
    //         for _ in 0..(2 * FIELD_SIZE) {
    //             temp_p.push(false, false);
    //         }
    //
    //         for j in 0..FIELD_SIZE {
    //             let temp1 = ser_table_p[i][k].get_binary_share(j);
    //             temp_p.set(j, temp1.value1, temp1.value2);
    //             temp_p.set(
    //                 FIELD_SIZE + j,
    //                 z1_p1.mac[i][k].get_binary_share(j).value1
    //                     ^ z2_p1.mac[i][k].get_binary_share(j).value1
    //                     ^ z3_p1.mac[i][k].get_binary_share(j).value1,
    //                 z1_p1.mac[i][k].get_binary_share(j).value2
    //                     ^ z2_p1.mac[i][k].get_binary_share(j).value2
    //                     ^ z3_p1.mac[i][k].get_binary_share(j).value2,
    //             );
    //         }
    //         t.push(temp_p);
    //     }
    //     z_p.push(t);
    // }
    //
    // // 2 party shuffle with party 1 and party 2
    // let mut reshare_z_p1: Vec<Vec<BinaryString>> = Vec::new();
    // let mut reshare_z_p2: Vec<Vec<BinaryString>> = Vec::new();
    //
    // for i in 0..n_table_entries {
    //     let (mut temp_share_z_p1, mut temp_share_z_p2) = (vec![], vec![]);
    //     for k in 0..n_table_columns {
    //         let (rs_z_p1, _send_2_p1) = reshare_from_generate_msg(
    //             z_p[i][k].clone(),
    //             &mut serverstate.common_randomness,
    //         );
    //         // let (send_1_p2, rs_z_p2) = reshare_from_generate_msg(
    //         //     z_p2[i][k].clone(),
    //         //     &mut serverstate_p2.common_randomness,
    //         // );
    //         // let (_send_1_p3, send_2_p3) = reshare_from_generate_msg(
    //         //     z_p3[i][k].clone(),
    //         //     &mut serverstate_p3.common_randomness,
    //         // );
    //
    //         let mut share_z_p1: BinaryString = BinaryString::with_capacity(2 * FIELD_SIZE);
    //         for j in 0..(2 * FIELD_SIZE) {
    //             share_z_p1.push(
    //                 rs_z_p1.data.get_binary_share(j).value1
    //                     ^ send_1_p2.data.get_binary_share(j).value2,
    //             );
    //         }
    //         temp_share_z_p1.push(share_z_p1);
    //
    //         let mut share_z_p2: BinaryString = BinaryString::with_capacity(2 * FIELD_SIZE);
    //         for j in 0..(2 * FIELD_SIZE) {
    //             share_z_p2.push(
    //                 rs_z_p2.data.get_binary_share(j).value1
    //                     ^ send_2_p3.data.get_binary_share(j).value2,
    //             );
    //         }
    //         temp_share_z_p2.push(share_z_p2);
    //     }
    //     reshare_z_p1.push(temp_share_z_p1);
    //     reshare_z_p2.push(temp_share_z_p2);
    // }
    //
    // let p1_random_permutation = random_permutation(n_table_entries);
    // let p2_random_permutation = p1_random_permutation.clone();
    //
    // let shuffled_z1_p1 = shuf_table_apply_permutation(&reshare_z_p1, &p1_random_permutation);
    // let shuffled_z2_p2 = shuf_table_apply_permutation(&reshare_z_p2, &p2_random_permutation);
    //
    // let mut z_perm1_p1: Vec<Vec<BinaryStringShare>> = Vec::new();
    // let mut z_perm1_p2: Vec<Vec<BinaryStringShare>> = Vec::new();
    // let mut z_perm1_p3: Vec<Vec<BinaryStringShare>> = Vec::new();
    //
    // for i in 0..n_table_entries {
    //     let mut t1: Vec<BinaryStringShare> = Vec::new();
    //     let mut t2: Vec<BinaryStringShare> = Vec::new();
    //     let mut t3: Vec<BinaryStringShare> = Vec::new();
    //
    //     for k in 0..n_table_columns {
    //         let (share_z1_p1, share_z1_p2, share_z1_p3) =
    //             get_default_bin_share_from_bin_string(&shuffled_z1_p1[i][k].clone());
    //         let (share_z2_p1, share_z2_p2, share_z2_p3) =
    //             get_default_bin_share_from_bin_string(&shuffled_z2_p2[i][k].clone());
    //
    //         let mut temp_p1: BinaryStringShare = BinaryStringShare::with_capacity(2 * FIELD_SIZE);
    //         let mut temp_p2: BinaryStringShare = BinaryStringShare::with_capacity(2 * FIELD_SIZE);
    //         let mut temp_p3: BinaryStringShare = BinaryStringShare::with_capacity(2 * FIELD_SIZE);
    //
    //         for _ in 0..(2 * FIELD_SIZE) {
    //             temp_p1.push(false, false);
    //             temp_p2.push(false, false);
    //             temp_p3.push(false, false);
    //         }
    //
    //         for j in 0..(2 * FIELD_SIZE) {
    //             temp_p1.set(
    //                 j,
    //                 share_z1_p1.get_binary_share(j).value1 ^ share_z2_p1.get_binary_share(j).value1,
    //                 share_z1_p1.get_binary_share(j).value2 ^ share_z2_p1.get_binary_share(j).value2,
    //             );
    //             temp_p2.set(
    //                 j,
    //                 share_z1_p2.get_binary_share(j).value1 ^ share_z2_p2.get_binary_share(j).value1,
    //                 share_z1_p2.get_binary_share(j).value2 ^ share_z2_p2.get_binary_share(j).value2,
    //             );
    //             temp_p3.set(
    //                 j,
    //                 share_z1_p3.get_binary_share(j).value1 ^ share_z2_p3.get_binary_share(j).value1,
    //                 share_z1_p3.get_binary_share(j).value2 ^ share_z2_p3.get_binary_share(j).value2,
    //             );
    //         }
    //         t1.push(temp_p1);
    //         t2.push(temp_p2);
    //         t3.push(temp_p3);
    //     }
    //     z_perm1_p1.push(t1);
    //     z_perm1_p2.push(t2);
    //     z_perm1_p3.push(t3);
    // }
    //
    // let mut x_a_p1: Vec<Vec<BinaryStringShare>> = Vec::new();
    // let mut x_a_p2: Vec<Vec<BinaryStringShare>> = Vec::new();
    // let mut x_a_p3: Vec<Vec<BinaryStringShare>> = Vec::new();
    //
    // let mut mac_a_p1: Vec<Vec<BinaryStringShare>> = Vec::new();
    // let mut mac_a_p2: Vec<Vec<BinaryStringShare>> = Vec::new();
    // let mut mac_a_p3: Vec<Vec<BinaryStringShare>> = Vec::new();
    //
    // // split the shuffled value to message and MAC
    // for i in 0..n_table_entries {
    //     let mut tx1: Vec<BinaryStringShare> = Vec::new();
    //     let mut tx2: Vec<BinaryStringShare> = Vec::new();
    //     let mut tx3: Vec<BinaryStringShare> = Vec::new();
    //
    //     let mut tm1: Vec<BinaryStringShare> = Vec::new();
    //     let mut tm2: Vec<BinaryStringShare> = Vec::new();
    //     let mut tm3: Vec<BinaryStringShare> = Vec::new();
    //
    //     for k in 0..n_table_columns {
    //         let (temp1_p1, temp2_p1) = split(z_perm1_p1[i][k].clone());
    //         let (temp1_p2, temp2_p2) = split(z_perm1_p2[i][k].clone());
    //         let (temp1_p3, temp2_p3) = split(z_perm1_p3[i][k].clone());
    //         tx1.push(temp1_p1);
    //         tm1.push(temp2_p1);
    //
    //         tx2.push(temp1_p2);
    //         tm2.push(temp2_p2);
    //
    //         tx3.push(temp1_p3);
    //         tm3.push(temp2_p3);
    //     }
    //     x_a_p1.push(tx1);
    //     mac_a_p1.push(tm1);
    //
    //     x_a_p2.push(tx2);
    //     mac_a_p2.push(tm2);
    //
    //     x_a_p3.push(tx3);
    //     mac_a_p3.push(tm3);
    // }
    //
    // // Verify the MAC
    // let (y1_p1, y1_p2, y1_p3) = shuf_table_create_mac_msg1(&x_a_p1, &alpha_p1, n_table_columns);
    // let (y2_p1, y2_p2, y2_p3) = shuf_table_create_mac_msg1(&x_a_p2, &alpha_p2, n_table_columns);
    // let (y3_p1, y3_p2, y3_p3) = shuf_table_create_mac_msg1(&x_a_p3, &alpha_p3, n_table_columns);
    //
    // let mut y_p1: Vec<Vec<BinaryStringShare>> = Vec::new();
    // let mut y_p2: Vec<Vec<BinaryStringShare>> = Vec::new();
    // let mut y_p3: Vec<Vec<BinaryStringShare>> = Vec::new();
    //
    // for i in 0..n_table_entries {
    //     let (mut t1, mut t2, mut t3) = (vec![], vec![], vec![]);
    //     for k in 0..n_table_columns {
    //         let mut temp_p1: BinaryStringShare = BinaryStringShare::with_capacity(FIELD_SIZE);
    //         let mut temp_p2: BinaryStringShare = BinaryStringShare::with_capacity(FIELD_SIZE);
    //         let mut temp_p3: BinaryStringShare = BinaryStringShare::with_capacity(FIELD_SIZE);
    //
    //         for j in 0..FIELD_SIZE {
    //             temp_p1.push(
    //                 y1_p1.mac[i][k].get_binary_share(j).value1
    //                     ^ y2_p1.mac[i][k].get_binary_share(j).value1
    //                     ^ y3_p1.mac[i][k].get_binary_share(j).value1,
    //                 y1_p1.mac[i][k].get_binary_share(j).value2
    //                     ^ y2_p1.mac[i][k].get_binary_share(j).value2
    //                     ^ y3_p1.mac[i][k].get_binary_share(j).value2,
    //             );
    //             temp_p2.push(
    //                 y1_p2.mac[i][k].get_binary_share(j).value1
    //                     ^ y2_p2.mac[i][k].get_binary_share(j).value1
    //                     ^ y3_p2.mac[i][k].get_binary_share(j).value1,
    //                 y1_p2.mac[i][k].get_binary_share(j).value2
    //                     ^ y2_p2.mac[i][k].get_binary_share(j).value2
    //                     ^ y3_p2.mac[i][k].get_binary_share(j).value2,
    //             );
    //             temp_p3.push(
    //                 y1_p3.mac[i][k].get_binary_share(j).value1
    //                     ^ y2_p3.mac[i][k].get_binary_share(j).value1
    //                     ^ y3_p3.mac[i][k].get_binary_share(j).value1,
    //                 y1_p3.mac[i][k].get_binary_share(j).value2
    //                     ^ y2_p3.mac[i][k].get_binary_share(j).value2
    //                     ^ y3_p3.mac[i][k].get_binary_share(j).value2,
    //             );
    //         }
    //         t1.push(temp_p1);
    //         t2.push(temp_p2);
    //         t3.push(temp_p3);
    //     }
    //     y_p1.push(t1);
    //     y_p2.push(t2);
    //     y_p3.push(t3);
    // }
    //
    // // Subtract mac
    // let mut v_p1: Vec<Vec<BinaryStringShare>> = Vec::new();
    // let mut v_p2: Vec<Vec<BinaryStringShare>> = Vec::new();
    // let mut v_p3: Vec<Vec<BinaryStringShare>> = Vec::new();
    //
    // for i in 0..n_table_entries {
    //     let (mut t1, mut t2, mut t3) = (vec![], vec![], vec![]);
    //     for k in 0..n_table_columns {
    //         let mut temp_p1: BinaryStringShare = BinaryStringShare::with_capacity(FIELD_SIZE);
    //         let mut temp_p2: BinaryStringShare = BinaryStringShare::with_capacity(FIELD_SIZE);
    //         let mut temp_p3: BinaryStringShare = BinaryStringShare::with_capacity(FIELD_SIZE);
    //
    //         for j in 0..FIELD_SIZE {
    //             temp_p1.push(
    //                 y_p1[i][k].get_binary_share(j).value1
    //                     ^ mac_a_p1[i][k].get_binary_share(j).value1,
    //                 y_p1[i][k].get_binary_share(j).value2
    //                     ^ mac_a_p1[i][k].get_binary_share(j).value2,
    //             );
    //             temp_p2.push(
    //                 y_p2[i][k].get_binary_share(j).value1
    //                     ^ mac_a_p2[i][k].get_binary_share(j).value1,
    //                 y_p2[i][k].get_binary_share(j).value2
    //                     ^ mac_a_p2[i][k].get_binary_share(j).value2,
    //             );
    //             temp_p3.push(
    //                 y_p3[i][k].get_binary_share(j).value1
    //                     ^ mac_a_p3[i][k].get_binary_share(j).value1,
    //                 y_p3[i][k].get_binary_share(j).value2
    //                     ^ mac_a_p3[i][k].get_binary_share(j).value2,
    //             );
    //         }
    //         t1.push(temp_p1);
    //         t2.push(temp_p2);
    //         t3.push(temp_p3);
    //     }
    //     v_p1.push(t1);
    //     v_p2.push(t2);
    //     v_p3.push(t3);
    // }
    //
    // // Check if all the opened values is equal to 0
    // for i in 0..n_table_entries {
    //     for k in 0..n_table_columns {
    //         for j in 0..FIELD_SIZE {
    //             assert!(
    //                 !(v_p1[i][k].get_binary_share(j).value1
    //                     ^ v_p2[i][k].get_binary_share(j).value2)
    //             );
    //             assert!(
    //                 !(v_p2[i][k].get_binary_share(j).value1
    //                     ^ v_p3[i][k].get_binary_share(j).value2)
    //             );
    //             assert!(
    //                 !(v_p3[i][k].get_binary_share(j).value1
    //                     ^ v_p1[i][k].get_binary_share(j).value2)
    //             );
    //         }
    //     }
    // }
    //
    // // 2 party shuffle with party 2 and party 3
    // let mut reshare2_z_p2: Vec<Vec<BinaryString>> = Vec::new();
    // let mut reshare2_z_p3: Vec<Vec<BinaryString>> = Vec::new();
    //
    // for i in 0..n_table_entries {
    //     let (mut temp_share_z_p3, mut temp_share_z_p2) = (vec![], vec![]);
    //     for k in 0..n_table_columns {
    //         let (_send_1_p1, send_2_p1) = reshare_from_generate_msg(
    //             z_perm1_p1[i][k].clone(),
    //             &mut serverstate_p1.common_randomness,
    //         );
    //         let (rs_z_p2, _send_2_p2) = reshare_from_generate_msg(
    //             z_perm1_p2[i][k].clone(),
    //             &mut serverstate_p2.common_randomness,
    //         );
    //         let (send_1_p3, rs_z_p3) = reshare_from_generate_msg(
    //             z_perm1_p3[i][k].clone(),
    //             &mut serverstate_p3.common_randomness,
    //         );
    //
    //         let mut share_z_p2: BinaryString = BinaryString::with_capacity(2 * FIELD_SIZE);
    //         for j in 0..(2 * FIELD_SIZE) {
    //             share_z_p2.push(
    //                 rs_z_p2.data.get_binary_share(j).value1
    //                     ^ send_1_p3.data.get_binary_share(j).value2,
    //             );
    //         }
    //         temp_share_z_p2.push(share_z_p2);
    //
    //         let mut share_z_p3: BinaryString = BinaryString::with_capacity(2 * FIELD_SIZE);
    //         for j in 0..(2 * FIELD_SIZE) {
    //             share_z_p3.push(
    //                 rs_z_p3.data.get_binary_share(j).value1
    //                     ^ send_2_p1.data.get_binary_share(j).value2,
    //             );
    //         }
    //         temp_share_z_p3.push(share_z_p3);
    //     }
    //     reshare2_z_p2.push(temp_share_z_p2);
    //     reshare2_z_p3.push(temp_share_z_p3);
    // }
    //
    // let p2_random_permutation = random_permutation(n_table_entries);
    // let p3_random_permutation = p2_random_permutation.clone();
    //
    // let shuffled_z1_p2 = shuf_table_apply_permutation(&reshare2_z_p2, &p2_random_permutation);
    // let shuffled_z2_p3 = shuf_table_apply_permutation(&reshare2_z_p3, &p3_random_permutation);
    //
    // let mut z_perm2_p1: Vec<Vec<BinaryStringShare>> = Vec::new();
    // let mut z_perm2_p2: Vec<Vec<BinaryStringShare>> = Vec::new();
    // let mut z_perm2_p3: Vec<Vec<BinaryStringShare>> = Vec::new();
    //
    // for i in 0..n_table_entries {
    //     let mut t1: Vec<BinaryStringShare> = Vec::new();
    //     let mut t2: Vec<BinaryStringShare> = Vec::new();
    //     let mut t3: Vec<BinaryStringShare> = Vec::new();
    //
    //     for k in 0..n_table_columns {
    //         let (share_z1_p1, share_z1_p2, share_z1_p3) =
    //             get_default_bin_share_from_bin_string(&shuffled_z1_p2[i][k].clone());
    //         let (share_z2_p1, share_z2_p2, share_z2_p3) =
    //             get_default_bin_share_from_bin_string(&shuffled_z2_p3[i][k].clone());
    //
    //         let mut temp_p1: BinaryStringShare = BinaryStringShare::with_capacity(2 * FIELD_SIZE);
    //         let mut temp_p2: BinaryStringShare = BinaryStringShare::with_capacity(2 * FIELD_SIZE);
    //         let mut temp_p3: BinaryStringShare = BinaryStringShare::with_capacity(2 * FIELD_SIZE);
    //
    //         for j in 0..(2 * FIELD_SIZE) {
    //             temp_p1.push(
    //                 share_z1_p1.get_binary_share(j).value1 ^ share_z2_p1.get_binary_share(j).value1,
    //                 share_z1_p1.get_binary_share(j).value2 ^ share_z2_p1.get_binary_share(j).value2,
    //             );
    //             temp_p2.push(
    //                 share_z1_p2.get_binary_share(j).value1 ^ share_z2_p2.get_binary_share(j).value1,
    //                 share_z1_p2.get_binary_share(j).value2 ^ share_z2_p2.get_binary_share(j).value2,
    //             );
    //             temp_p3.push(
    //                 share_z1_p3.get_binary_share(j).value1 ^ share_z2_p3.get_binary_share(j).value1,
    //                 share_z1_p3.get_binary_share(j).value2 ^ share_z2_p3.get_binary_share(j).value2,
    //             );
    //         }
    //         t1.push(temp_p1);
    //         t2.push(temp_p2);
    //         t3.push(temp_p3);
    //     }
    //     z_perm2_p1.push(t1);
    //     z_perm2_p2.push(t2);
    //     z_perm2_p3.push(t3);
    // }
    //
    // let mut x_b_p1: Vec<Vec<BinaryStringShare>> = Vec::new();
    // let mut x_b_p2: Vec<Vec<BinaryStringShare>> = Vec::new();
    // let mut x_b_p3: Vec<Vec<BinaryStringShare>> = Vec::new();
    //
    // let mut mac_b_p1: Vec<Vec<BinaryStringShare>> = Vec::new();
    // let mut mac_b_p2: Vec<Vec<BinaryStringShare>> = Vec::new();
    // let mut mac_b_p3: Vec<Vec<BinaryStringShare>> = Vec::new();
    //
    // for i in 0..n_table_entries {
    //     let (mut tx1, mut tx2, mut tx3) = (vec![], vec![], vec![]);
    //     let (mut tm1, mut tm2, mut tm3) = (vec![], vec![], vec![]);
    //     for k in 0..n_table_columns {
    //         let (temp1_p1, temp2_p1) = split(z_perm2_p1[i][k].clone());
    //         let (temp1_p2, temp2_p2) = split(z_perm2_p2[i][k].clone());
    //         let (temp1_p3, temp2_p3) = split(z_perm2_p3[i][k].clone());
    //         tx1.push(temp1_p1);
    //         tm1.push(temp2_p1);
    //
    //         tx2.push(temp1_p2);
    //         tm2.push(temp2_p2);
    //
    //         tx3.push(temp1_p3);
    //         tm3.push(temp2_p3);
    //     }
    //
    //     x_b_p1.push(tx1);
    //     mac_b_p1.push(tm1);
    //
    //     x_b_p2.push(tx2);
    //     mac_b_p2.push(tm2);
    //
    //     x_b_p3.push(tx3);
    //     mac_b_p3.push(tm3);
    // }
    //
    // // Verify the MAC
    // let (y1_p1, y1_p2, y1_p3) = shuf_table_create_mac_msg1(&x_b_p1, &alpha_p1, n_table_columns);
    // let (y2_p1, y2_p2, y2_p3) = shuf_table_create_mac_msg1(&x_b_p2, &alpha_p2, n_table_columns);
    // let (y3_p1, y3_p2, y3_p3) = shuf_table_create_mac_msg1(&x_b_p3, &alpha_p3, n_table_columns);
    //
    // let mut y_2_p1: Vec<Vec<BinaryStringShare>> = Vec::new();
    // let mut y_2_p2: Vec<Vec<BinaryStringShare>> = Vec::new();
    // let mut y_2_p3: Vec<Vec<BinaryStringShare>> = Vec::new();
    //
    // for i in 0..n_table_entries {
    //     let mut t1: Vec<BinaryStringShare> = Vec::new();
    //     let mut t2: Vec<BinaryStringShare> = Vec::new();
    //     let mut t3: Vec<BinaryStringShare> = Vec::new();
    //
    //     for k in 0..n_table_columns {
    //         let mut temp_p1: BinaryStringShare = BinaryStringShare::with_capacity(FIELD_SIZE);
    //         let mut temp_p2: BinaryStringShare = BinaryStringShare::with_capacity(FIELD_SIZE);
    //         let mut temp_p3: BinaryStringShare = BinaryStringShare::with_capacity(FIELD_SIZE);
    //
    //         for j in 0..FIELD_SIZE {
    //             temp_p1.push(
    //                 y1_p1.mac[i][k].get_binary_share(j).value1
    //                     ^ y2_p1.mac[i][k].get_binary_share(j).value1
    //                     ^ y3_p1.mac[i][k].get_binary_share(j).value1,
    //                 y1_p1.mac[i][k].get_binary_share(j).value2
    //                     ^ y2_p1.mac[i][k].get_binary_share(j).value2
    //                     ^ y3_p1.mac[i][k].get_binary_share(j).value2,
    //             );
    //             temp_p2.push(
    //                 y1_p2.mac[i][k].get_binary_share(j).value1
    //                     ^ y2_p2.mac[i][k].get_binary_share(j).value1
    //                     ^ y3_p2.mac[i][k].get_binary_share(j).value1,
    //                 y1_p2.mac[i][k].get_binary_share(j).value2
    //                     ^ y2_p2.mac[i][k].get_binary_share(j).value2
    //                     ^ y3_p2.mac[i][k].get_binary_share(j).value2,
    //             );
    //             temp_p3.push(
    //                 y1_p3.mac[i][k].get_binary_share(j).value1
    //                     ^ y2_p3.mac[i][k].get_binary_share(j).value1
    //                     ^ y3_p3.mac[i][k].get_binary_share(j).value1,
    //                 y1_p3.mac[i][k].get_binary_share(j).value2
    //                     ^ y2_p3.mac[i][k].get_binary_share(j).value2
    //                     ^ y3_p3.mac[i][k].get_binary_share(j).value2,
    //             );
    //         }
    //         t1.push(temp_p1);
    //         t2.push(temp_p2);
    //         t3.push(temp_p3);
    //     }
    //     y_2_p1.push(t1);
    //     y_2_p2.push(t2);
    //     y_2_p3.push(t3);
    // }
    //
    // // Subtract mac
    // let mut v2_p1: Vec<Vec<BinaryStringShare>> = Vec::new();
    // let mut v2_p2: Vec<Vec<BinaryStringShare>> = Vec::new();
    // let mut v2_p3: Vec<Vec<BinaryStringShare>> = Vec::new();
    //
    // for i in 0..n_table_entries {
    //     let (mut t1, mut t2, mut t3) = (vec![], vec![], vec![]);
    //     for k in 0..n_table_columns {
    //         let mut temp_p1: BinaryStringShare = BinaryStringShare::with_capacity(FIELD_SIZE);
    //         let mut temp_p2: BinaryStringShare = BinaryStringShare::with_capacity(FIELD_SIZE);
    //         let mut temp_p3: BinaryStringShare = BinaryStringShare::with_capacity(FIELD_SIZE);
    //
    //         for j in 0..FIELD_SIZE {
    //             temp_p1.push(
    //                 y_2_p1[i][k].get_binary_share(j).value1
    //                     ^ mac_b_p1[i][k].get_binary_share(j).value1,
    //                 y_2_p1[i][k].get_binary_share(j).value2
    //                     ^ mac_b_p1[i][k].get_binary_share(j).value2,
    //             );
    //             temp_p2.push(
    //                 y_2_p2[i][k].get_binary_share(j).value1
    //                     ^ mac_b_p2[i][k].get_binary_share(j).value1,
    //                 y_2_p2[i][k].get_binary_share(j).value2
    //                     ^ mac_b_p2[i][k].get_binary_share(j).value2,
    //             );
    //             temp_p3.push(
    //                 y_2_p3[i][k].get_binary_share(j).value1
    //                     ^ mac_b_p3[i][k].get_binary_share(j).value1,
    //                 y_2_p3[i][k].get_binary_share(j).value2
    //                     ^ mac_b_p3[i][k].get_binary_share(j).value2,
    //             );
    //         }
    //         t1.push(temp_p1);
    //         t2.push(temp_p2);
    //         t3.push(temp_p3);
    //     }
    //     v2_p1.push(t1);
    //     v2_p2.push(t2);
    //     v2_p3.push(t3);
    // }
    //
    // // Check if all the opened values is equal to 0
    // for i in 0..n_table_entries {
    //     for k in 0..n_table_columns {
    //         for j in 0..FIELD_SIZE {
    //             assert!(
    //                 !(v2_p1[i][k].get_binary_share(j).value1
    //                     ^ v2_p2[i][k].get_binary_share(j).value2)
    //             );
    //             assert!(
    //                 !(v2_p2[i][k].get_binary_share(j).value1
    //                     ^ v2_p3[i][k].get_binary_share(j).value2)
    //             );
    //             assert!(
    //                 !(v2_p3[i][k].get_binary_share(j).value1
    //                     ^ v2_p1[i][k].get_binary_share(j).value2)
    //             );
    //         }
    //     }
    // }
    //
    // // 2 party shuffle with party 3 and party 1
    // let mut reshare3_z_p3: Vec<Vec<BinaryString>> = Vec::new();
    // let mut reshare3_z_p1: Vec<Vec<BinaryString>> = Vec::new();
    //
    // for i in 0..n_table_entries {
    //     let (mut temp_share_z_p3, mut temp_share_z_p1) = (vec![], vec![]);
    //     for k in 0..n_table_columns {
    //         let (send_3_p1, rs_z_p1) = reshare_from_generate_msg(
    //             z_perm2_p1[i][k].clone(),
    //             &mut serverstate_p1.common_randomness,
    //         );
    //         let (_send_3_p2, send_1_p2) = reshare_from_generate_msg(
    //             z_perm2_p2[i][k].clone(),
    //             &mut serverstate_p2.common_randomness,
    //         );
    //         let (rs_z_p3, _send_1_p3) = reshare_from_generate_msg(
    //             z_perm2_p3[i][k].clone(),
    //             &mut serverstate_p3.common_randomness,
    //         );
    //
    //         let mut share_z_p1: BinaryString = BinaryString::with_capacity(2 * FIELD_SIZE);
    //         for j in 0..(2 * FIELD_SIZE) {
    //             share_z_p1.push(
    //                 rs_z_p1.data.get_binary_share(j).value1
    //                     ^ send_1_p2.data.get_binary_share(j).value2,
    //             );
    //         }
    //         temp_share_z_p1.push(share_z_p1);
    //
    //         let mut share_z_p3: BinaryString = BinaryString::with_capacity(2 * FIELD_SIZE);
    //         for j in 0..(2 * FIELD_SIZE) {
    //             share_z_p3.push(
    //                 rs_z_p3.data.get_binary_share(j).value1
    //                     ^ send_3_p1.data.get_binary_share(j).value2,
    //             );
    //         }
    //         temp_share_z_p3.push(share_z_p3);
    //     }
    //     reshare3_z_p3.push(temp_share_z_p3);
    //     reshare3_z_p1.push(temp_share_z_p1);
    // }
    //
    // let p3_random_permutation = random_permutation(n_table_entries);
    // let p1_random_permutation = p3_random_permutation.clone();
    //
    // let shuffled_z1_p3 = shuf_table_apply_permutation(&reshare3_z_p3, &p3_random_permutation);
    // let shuffled_z2_p1 = shuf_table_apply_permutation(&reshare3_z_p1, &p1_random_permutation);
    //
    // let mut z_perm3_p1: Vec<Vec<BinaryStringShare>> = Vec::new();
    // let mut z_perm3_p2: Vec<Vec<BinaryStringShare>> = Vec::new();
    // let mut z_perm3_p3: Vec<Vec<BinaryStringShare>> = Vec::new();
    //
    // for i in 0..n_table_entries {
    //     let mut t1: Vec<BinaryStringShare> = Vec::new();
    //     let mut t2: Vec<BinaryStringShare> = Vec::new();
    //     let mut t3: Vec<BinaryStringShare> = Vec::new();
    //
    //     for k in 0..n_table_columns {
    //         let (share_z1_p1, share_z1_p2, share_z1_p3) =
    //             get_default_bin_share_from_bin_string(&shuffled_z1_p3[i][k].clone());
    //         let (share_z2_p1, share_z2_p2, share_z2_p3) =
    //             get_default_bin_share_from_bin_string(&shuffled_z2_p1[i][k].clone());
    //
    //         let mut temp_p1: BinaryStringShare = BinaryStringShare::with_capacity(FIELD_SIZE);
    //         let mut temp_p2: BinaryStringShare = BinaryStringShare::with_capacity(FIELD_SIZE);
    //         let mut temp_p3: BinaryStringShare = BinaryStringShare::with_capacity(FIELD_SIZE);
    //
    //         for j in 0..(2 * FIELD_SIZE) {
    //             temp_p1.push(
    //                 share_z1_p1.get_binary_share(j).value1 ^ share_z2_p1.get_binary_share(j).value1,
    //                 share_z1_p1.get_binary_share(j).value2 ^ share_z2_p1.get_binary_share(j).value2,
    //             );
    //             temp_p2.push(
    //                 share_z1_p2.get_binary_share(j).value1 ^ share_z2_p2.get_binary_share(j).value1,
    //                 share_z1_p2.get_binary_share(j).value2 ^ share_z2_p2.get_binary_share(j).value2,
    //             );
    //             temp_p3.push(
    //                 share_z1_p3.get_binary_share(j).value1 ^ share_z2_p3.get_binary_share(j).value1,
    //                 share_z1_p3.get_binary_share(j).value2 ^ share_z2_p3.get_binary_share(j).value2,
    //             );
    //         }
    //         t1.push(temp_p1);
    //         t2.push(temp_p2);
    //         t3.push(temp_p3);
    //     }
    //     z_perm3_p1.push(t1);
    //     z_perm3_p2.push(t2);
    //     z_perm3_p3.push(t3);
    // }
    //
    // let mut x_c_p1: Vec<Vec<BinaryStringShare>> = Vec::new();
    // let mut x_c_p2: Vec<Vec<BinaryStringShare>> = Vec::new();
    // let mut x_c_p3: Vec<Vec<BinaryStringShare>> = Vec::new();
    //
    // let mut mac_c_p1: Vec<Vec<BinaryStringShare>> = Vec::new();
    // let mut mac_c_p2: Vec<Vec<BinaryStringShare>> = Vec::new();
    // let mut mac_c_p3: Vec<Vec<BinaryStringShare>> = Vec::new();
    //
    // for i in 0..n_table_entries {
    //     let (mut tx1, mut tx2, mut tx3) = (vec![], vec![], vec![]);
    //     let (mut tm1, mut tm2, mut tm3) = (vec![], vec![], vec![]);
    //     for k in 0..n_table_columns {
    //         let (temp1_p1, temp2_p1) = split(z_perm3_p1[i][k].clone());
    //         let (temp1_p2, temp2_p2) = split(z_perm3_p2[i][k].clone());
    //         let (temp1_p3, temp2_p3) = split(z_perm3_p3[i][k].clone());
    //         tx1.push(temp1_p1);
    //         tm1.push(temp2_p1);
    //
    //         tx2.push(temp1_p2);
    //         tm2.push(temp2_p2);
    //
    //         tx3.push(temp1_p3);
    //         tm3.push(temp2_p3);
    //     }
    //
    //     x_c_p1.push(tx1);
    //     mac_c_p1.push(tm1);
    //
    //     x_c_p2.push(tx2);
    //     mac_c_p2.push(tm2);
    //
    //     x_c_p3.push(tx3);
    //     mac_c_p3.push(tm3);
    // }
    //
    // // Verify the MAC
    // let (y1_p1, y1_p2, y1_p3) = shuf_table_create_mac_msg1(&x_c_p1, &alpha_p1, n_table_columns);
    // let (y2_p1, y2_p2, y2_p3) = shuf_table_create_mac_msg1(&x_c_p2, &alpha_p2, n_table_columns);
    // let (y3_p1, y3_p2, y3_p3) = shuf_table_create_mac_msg1(&x_c_p3, &alpha_p3, n_table_columns);
    //
    // let mut y_3_p1: Vec<Vec<BinaryStringShare>> = Vec::new();
    // let mut y_3_p2: Vec<Vec<BinaryStringShare>> = Vec::new();
    // let mut y_3_p3: Vec<Vec<BinaryStringShare>> = Vec::new();
    //
    // for i in 0..n_table_entries {
    //     let mut t1: Vec<BinaryStringShare> = Vec::new();
    //     let mut t2: Vec<BinaryStringShare> = Vec::new();
    //     let mut t3: Vec<BinaryStringShare> = Vec::new();
    //
    //     for k in 0..n_table_columns {
    //         let mut temp_p1: BinaryStringShare = BinaryStringShare::with_capacity(FIELD_SIZE);
    //         let mut temp_p2: BinaryStringShare = BinaryStringShare::with_capacity(FIELD_SIZE);
    //         let mut temp_p3: BinaryStringShare = BinaryStringShare::with_capacity(FIELD_SIZE);
    //
    //         for j in 0..FIELD_SIZE {
    //             temp_p1.push(
    //                 y1_p1.mac[i][k].get_binary_share(j).value1
    //                     ^ y2_p1.mac[i][k].get_binary_share(j).value1
    //                     ^ y3_p1.mac[i][k].get_binary_share(j).value1,
    //                 y1_p1.mac[i][k].get_binary_share(j).value2
    //                     ^ y2_p1.mac[i][k].get_binary_share(j).value2
    //                     ^ y3_p1.mac[i][k].get_binary_share(j).value2,
    //             );
    //             temp_p2.push(
    //                 y1_p2.mac[i][k].get_binary_share(j).value1
    //                     ^ y2_p2.mac[i][k].get_binary_share(j).value1
    //                     ^ y3_p2.mac[i][k].get_binary_share(j).value1,
    //                 y1_p2.mac[i][k].get_binary_share(j).value2
    //                     ^ y2_p2.mac[i][k].get_binary_share(j).value2
    //                     ^ y3_p2.mac[i][k].get_binary_share(j).value2,
    //             );
    //             temp_p3.push(
    //                 y1_p3.mac[i][k].get_binary_share(j).value1
    //                     ^ y2_p3.mac[i][k].get_binary_share(j).value1
    //                     ^ y3_p3.mac[i][k].get_binary_share(j).value1,
    //                 y1_p3.mac[i][k].get_binary_share(j).value2
    //                     ^ y2_p3.mac[i][k].get_binary_share(j).value2
    //                     ^ y3_p3.mac[i][k].get_binary_share(j).value2,
    //             );
    //         }
    //         t1.push(temp_p1);
    //         t2.push(temp_p2);
    //         t3.push(temp_p3);
    //     }
    //     y_3_p1.push(t1);
    //     y_3_p2.push(t2);
    //     y_3_p3.push(t3);
    // }
    //
    // // Subtract mac
    // let mut v3_p1: Vec<Vec<BinaryStringShare>> = Vec::new();
    // let mut v3_p2: Vec<Vec<BinaryStringShare>> = Vec::new();
    // let mut v3_p3: Vec<Vec<BinaryStringShare>> = Vec::new();
    // for i in 0..n_table_entries {
    //     let mut t1: Vec<BinaryStringShare> = Vec::new();
    //     let mut t2: Vec<BinaryStringShare> = Vec::new();
    //     let mut t3: Vec<BinaryStringShare> = Vec::new();
    //
    //     for k in 0..n_table_columns {
    //         let mut temp_p1: BinaryStringShare = BinaryStringShare::with_capacity(FIELD_SIZE);
    //         let mut temp_p2: BinaryStringShare = BinaryStringShare::with_capacity(FIELD_SIZE);
    //         let mut temp_p3: BinaryStringShare = BinaryStringShare::with_capacity(FIELD_SIZE);
    //
    //         for j in 0..FIELD_SIZE {
    //             temp_p1.push(
    //                 y_3_p1[i][k].get_binary_share(j).value1
    //                     ^ mac_c_p1[i][k].get_binary_share(j).value1,
    //                 y_3_p1[i][k].get_binary_share(j).value2
    //                     ^ mac_c_p1[i][k].get_binary_share(j).value2,
    //             );
    //             temp_p2.push(
    //                 y_3_p2[i][k].get_binary_share(j).value1
    //                     ^ mac_c_p2[i][k].get_binary_share(j).value1,
    //                 y_3_p2[i][k].get_binary_share(j).value2
    //                     ^ mac_c_p2[i][k].get_binary_share(j).value2,
    //             );
    //             temp_p3.push(
    //                 y_3_p3[i][k].get_binary_share(j).value1
    //                     ^ mac_c_p3[i][k].get_binary_share(j).value1,
    //                 y_3_p3[i][k].get_binary_share(j).value2
    //                     ^ mac_c_p3[i][k].get_binary_share(j).value2,
    //             );
    //         }
    //         t1.push(temp_p1);
    //         t2.push(temp_p2);
    //         t3.push(temp_p3);
    //     }
    //     v3_p1.push(t1);
    //     v3_p2.push(t2);
    //     v3_p3.push(t3);
    // }
    //
    // // Check if all the opened values is equal to 0
    // for i in 0..n_table_entries {
    //     for k in 0..n_table_columns {
    //         for j in 0..FIELD_SIZE {
    //             assert!(
    //                 !(v3_p1[i][k].get_binary_share(j).value1
    //                     ^ v3_p2[i][k].get_binary_share(j).value2)
    //             );
    //             assert!(
    //                 !(v3_p2[i][k].get_binary_share(j).value1
    //                     ^ v3_p3[i][k].get_binary_share(j).value2)
    //             );
    //             assert!(
    //                 !(v3_p3[i][k].get_binary_share(j).value1
    //                     ^ v3_p1[i][k].get_binary_share(j).value2)
    //             );
    //         }
    //     }
    // }
    //
    // (
    //     SerializedInputTable { ser_table: x_c_p1 },
    //     SerializedInputTable { ser_table: x_c_p2 },
    //     SerializedInputTable { ser_table: x_c_p3 },
    // )

    // todo!();
    Ok(ser_table_p.to_vec())
}

/// Test shuffle_serialized protocol
#[cfg(any(test, feature = "test-support"))]
async fn test_shuffle_serialized_protocol<T, R>(
    setup: T,
    seed: Seed,
    params: Vec<Vec<BinaryArithmeticShare>>,
    relay: R,
) -> Result<(usize, Vec<Vec<BinaryArithmeticShare>>), ProtocolError>
where
    T: CommonSetupMessage,
    R: Relay,
{
    use crate::mpc::common_randomness::run_common_randomness;
    use crate::transport::init::run_init;
    use merlin::Transcript;
    use sl_mpc_mate::coord::SinkExt;

    let mut relay = FilteredMsgRelay::new(relay);
    // let abort_msg = create_abort_message(&setup);
    // relay.ask_messages(&setup, ABORT_MESSAGE_TAG, false).await?;

    let mut init_seed = [0u8; 32];
    let mut common_randomness_seed = [0u8; 32];
    let mut transcript = Transcript::new(b"test");
    transcript.append_message(b"seed", &seed);
    transcript.challenge_bytes(b"init-seed", &mut init_seed);
    transcript.challenge_bytes(b"common-randomness-seed", &mut common_randomness_seed);

    let (_sid, mut mpc_encryption) = run_init(&setup, init_seed, &mut relay).await?;

    let common_randomness = run_common_randomness(
        &setup,
        common_randomness_seed,
        &mut mpc_encryption,
        &mut relay,
    )
    .await?;

    let mut serverstate = ServerState::new(common_randomness);

    let mut tag_offset_counter = TagOffsetCounter::new();

    let result = run_shuffle_serialized_table(
        &setup,
        &mut mpc_encryption,
        &mut tag_offset_counter,
        &mut relay,
        &params,
        &mut serverstate,
    )
    .await;

    let _ = relay.close().await;

    match result {
        Ok(v) => Ok((setup.participant_index(), v)),
        Err(e) => Err(e),
    }
}

#[cfg(test)]
mod tests {
    use super::test_shuffle_serialized_protocol;
    use crate::transport::test_utils::setup_mpc;
    use crate::types::BinaryArithmeticShare;
    use sl_mpc_mate::coord::{MessageRelayService, Relay};
    use tokio::task::JoinSet;

    async fn _sim<S, R>(
        coord: S,
        sim_params: &[Vec<Vec<BinaryArithmeticShare>>; 3],
    ) -> Vec<Vec<Vec<BinaryArithmeticShare>>>
    where
        S: MessageRelayService<MessageRelay = R>,
        R: Relay + Send + 'static,
    {
        let parties = setup_mpc(None, sim_params);

        let mut jset = JoinSet::new();
        for (setup, seed, params) in parties {
            let relay = coord.connect().await.unwrap();

            jset.spawn(test_shuffle_serialized_protocol(setup, seed, params, relay));
        }

        let mut results = vec![];
        while let Some(fini) = jset.join_next().await {
            let fini = fini.unwrap();

            if let Err(ref err) = fini {
                println!("error {}", err);
            }

            let res = fini.unwrap();
            results.push(res);
        }

        results.sort_by_key(|r| r.0);
        results.into_iter().map(|r| r.1).collect()
    }

    // #[test]
    // fn test_shuffle_serialized_table() {
    //     let (mut serverstate_p1, mut serverstate_p2, mut serverstate_p3) =
    //         test_run_get_serverstate();
    //
    //     let input = "hello hi wow";
    //
    //     let share_p1 = get_byte_str_share(input, 1);
    //     let share_p2 = get_byte_str_share(input, 2);
    //     let share_p3 = get_byte_str_share(input, 3);
    //
    //     let input_table_p1 = InputTable::new(&share_p1, 1);
    //     let input_table_p2 = InputTable::new(&share_p2, 2);
    //     let input_table_p3 = InputTable::new(&share_p3, 3);
    //
    //     let (ser_table_p1, ser_table_p2, ser_table_p3) = test_run_serialize_input_table(
    //         &input_table_p1,
    //         &input_table_p2,
    //         &input_table_p3,
    //         &mut serverstate_p1,
    //         &mut serverstate_p2,
    //         &mut serverstate_p3,
    //     );
    //
    //     let (inp_ser_table_p1, inp_ser_table_p2, inp_ser_table_p3) = (
    //         ser_table_p1.ser_table.clone(),
    //         ser_table_p2.ser_table.clone(),
    //         ser_table_p3.ser_table.clone(),
    //     );
    //
    //     let (out_p1, out_p2, out_p3) = test_run_shuffle_serialized_table(
    //         &ser_table_p1.ser_table,
    //         &ser_table_p2.ser_table,
    //         &ser_table_p3.ser_table,
    //         &mut serverstate_p1,
    //         &mut serverstate_p2,
    //         &mut serverstate_p3,
    //     );
    //
    //     // test_run_verify(
    //     //     &mut serverstate_p1,
    //     //     &mut serverstate_p2,
    //     //     &mut serverstate_p3,
    //     // );
    //
    //     let mut asert = true;
    //
    //     for i in 0..inp_ser_table_p1.len() {
    //         let mut found = false;
    //         let mut ival = Vec::new();
    //         for j in 0..ser_table_p1.ser_table[i].len() {
    //             ival.push(reconstruct_binary_string_share(
    //                 &inp_ser_table_p1[i][j],
    //                 &inp_ser_table_p2[i][j],
    //                 &inp_ser_table_p3[i][j],
    //                 &mut serverstate_p1,
    //                 &mut serverstate_p2,
    //                 &mut serverstate_p3,
    //             ));
    //         }
    //         for j in 0..inp_ser_table_p1.len() {
    //             let mut jval = Vec::new();
    //             for k in 0..ser_table_p1.ser_table[j].len() {
    //                 jval.push(reconstruct_binary_string_share(
    //                     &out_p1.ser_table[j][k],
    //                     &out_p2.ser_table[j][k],
    //                     &out_p3.ser_table[j][k],
    //                     &mut serverstate_p1,
    //                     &mut serverstate_p2,
    //                     &mut serverstate_p3,
    //                 ));
    //             }
    //             if ival == jval {
    //                 found |= true;
    //             }
    //         }
    //
    //         asert &= found;
    //     }
    //
    //     assert!(asert)
    // }
}
