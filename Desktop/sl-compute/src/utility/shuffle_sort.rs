use crate::proto::{get_default_bin_share_from_bin_string, split};

use crate::mpc::common_randomness::CommonRandomness;
use crate::transport::proto::FilteredMsgRelay;
use crate::transport::setup::common::MPCEncryption;
use crate::transport::setup::CommonSetupMessage;
use crate::transport::types::ProtocolError;
#[cfg(any(test, feature = "test-support"))]
use crate::transport::utils::Seed;
use crate::transport::utils::TagOffsetCounter;
use crate::types::{BinaryString, BinaryStringShare};
use crate::utility::helper::random_permutation;
use crypto_bigint::U256;
use sl_mpc_mate::coord::Relay;

pub struct RFMsgSend {
    pub data: BinaryStringShare,
}

pub fn reshare_from_generate_msg(
    x: BinaryStringShare,
    randomness: &mut CommonRandomness,
) -> (RFMsgSend, RFMsgSend) {
    let mut x_i: BinaryStringShare = BinaryStringShare::new();
    for _ in 0..x.length {
        x_i.push(false, false);
    }
    for i in 0..(x_i.length as usize) {
        let rand = randomness.random_bit();
        x_i.set(i, rand[0], rand[1]);
    }

    let mut x_j: BinaryStringShare = BinaryStringShare::new();
    for _ in 0..x.length {
        x_j.push(false, false);
    }
    for i in 0..(x_j.length as usize) {
        x_j.set(
            i,
            x.get_binary_share(i).value1 ^ x_i.get_binary_share(i).value1,
            x.get_binary_share(i).value2 ^ x_i.get_binary_share(i).value2,
        );
    }

    (RFMsgSend { data: x_i }, RFMsgSend { data: x_j })
}

pub fn apply_permutation(arr: &[BinaryString], perm: &[usize]) -> Vec<BinaryString> {
    if arr.len() != perm.len() {
        panic!("Permutation length must match the array length.");
    }
    let mut permuted_vec = vec![arr[0].clone(); arr.len()];
    for (i, &p) in perm.iter().enumerate() {
        permuted_vec[i].clone_from(&arr[p]);
    }
    permuted_vec
}

pub fn get_irreducible_poly(l: usize) -> U256 {
    match l {
        64 => U256::from(0b1000000000000000000000000000000000000000000000000000000000011101u64),
        128 => U256::from(0b10000000000000000000000000000000000000000000000000000000000000111u128),
        256 => {
            U256::from_le_hex("0002000000000000000400000000000002000000000000000000000000000000")
        }
        _ => panic!("Irreducible polynomial for GF(2^{}) is not defined.", l),
    }
}

pub fn multiply_gf2_l(a: &BinaryString, b: &BinaryString) -> Vec<bool> {
    let mut result = U256::ZERO;
    let mut a_value = U256::ZERO;
    let mut b_value = U256::ZERO;

    for i in 0..(a.length as usize) {
        let bit = a.get(i);
        if bit {
            a_value = a_value.wrapping_add(&(U256::ONE << i));
        }
    }
    for i in 0..(b.length as usize) {
        let bit = b.get(i);
        if bit {
            b_value = b_value.wrapping_add(&(U256::ONE << i));
        }
    }

    let l = a.length as usize;

    let irreducible_poly = get_irreducible_poly(l);

    for _ in 0..l {
        if b_value & U256::ONE != U256::ZERO {
            result ^= &a_value;
        }

        let carry = a_value >> (l - 1);
        a_value <<= 1;
        if carry != U256::ZERO {
            a_value ^= &irreducible_poly;
        }
        b_value >>= 1;
    }

    let mut output = vec![false; l];
    for (i, output_i) in output.iter_mut().enumerate().take(l) {
        *output_i = ((result >> i) & U256::ONE) != U256::ZERO;
    }

    output.to_vec()
}

pub fn create_mac_msg1(
    x: Vec<BinaryStringShare>,
    alpha: BinaryStringShare,
) -> (
    Vec<BinaryStringShare>,
    Vec<BinaryStringShare>,
    Vec<BinaryStringShare>,
) {
    let l = x[0].length as usize;

    let mut share_alpha_1: BinaryString = BinaryString::with_capacity(l);
    let mut share_alpha_2: BinaryString = BinaryString::with_capacity(l);

    for i in 0..l {
        share_alpha_1.push(alpha.get_binary_share(i).value1 ^ alpha.get_binary_share(i).value2);
        share_alpha_2.push(alpha.get_binary_share(i).value2);
    }

    let mut share_p1: Vec<BinaryStringShare> = Vec::new();
    let mut share_p2: Vec<BinaryStringShare> = Vec::new();
    let mut share_p3: Vec<BinaryStringShare> = Vec::new();

    for x_i in &x {
        let mut share_x_1: BinaryString = BinaryString::with_capacity(l);
        let mut share_x_2: BinaryString = BinaryString::with_capacity(l);

        let mut result: BinaryString = BinaryString::with_capacity(l);

        for j in 0..l {
            share_x_1.push(x_i.get_binary_share(j).value1 ^ x_i.get_binary_share(j).value2);
            share_x_2.push(x_i.get_binary_share(j).value2);
        }

        let z_i_1 = multiply_gf2_l(&share_alpha_2, &share_x_2);
        let z_i_2 = multiply_gf2_l(&share_alpha_1, &share_x_2);
        let z_i_3 = multiply_gf2_l(&share_alpha_2, &share_x_1);

        for j in 0..l {
            result.push(z_i_1[j] ^ z_i_2[j] ^ z_i_3[j]);
        }

        let (temp1, temp2, temp3) = get_default_bin_share_from_bin_string(&result);

        share_p1.push(temp1);
        share_p2.push(temp2);
        share_p3.push(temp3);
    }
    (share_p1, share_p2, share_p3)
}

/// Implementation of Protocol 3.14 (Shuffle) from https://github.com/silence-laboratories/research-silent-compute/blob/main/paper/main.pdf.
pub fn test_run_shuffle(
    l: usize,
    x_p1: Vec<BinaryStringShare>,
    x_p2: Vec<BinaryStringShare>,
    x_p3: Vec<BinaryStringShare>,
    randomness_p1: &mut CommonRandomness,
    randomness_p2: &mut CommonRandomness,
    randomness_p3: &mut CommonRandomness,
) -> (
    Vec<BinaryStringShare>,
    Vec<BinaryStringShare>,
    Vec<BinaryStringShare>,
) {
    let n = x_p1.len();

    // Generate a random alpha value for the MAC
    let mut alpha_p1: BinaryStringShare = BinaryStringShare::with_capacity(l);
    let mut alpha_p2: BinaryStringShare = BinaryStringShare::with_capacity(l);
    let mut alpha_p3: BinaryStringShare = BinaryStringShare::with_capacity(l);

    for _ in 0..l {
        let rand_p1 = randomness_p1.random_bit();
        alpha_p1.push(rand_p1[0], rand_p1[1]);
    }

    for _ in 0..l {
        let rand_p2 = randomness_p2.random_bit();
        alpha_p2.push(rand_p2[0], rand_p2[1]);
    }

    for _ in 0..l {
        let rand_p3 = randomness_p3.random_bit();
        alpha_p3.push(rand_p3[0], rand_p3[1]);
    }

    // Compute the MAC on the secret-shared test vector
    let (z1_p1, z1_p2, z1_p3) = create_mac_msg1(x_p1.clone(), alpha_p1.clone());
    let (z2_p1, z2_p2, z2_p3) = create_mac_msg1(x_p2.clone(), alpha_p2.clone());
    let (z3_p1, z3_p2, z3_p3) = create_mac_msg1(x_p3.clone(), alpha_p3.clone());

    let mut z_p1: Vec<BinaryStringShare> = Vec::new();
    let mut z_p2: Vec<BinaryStringShare> = Vec::new();
    let mut z_p3: Vec<BinaryStringShare> = Vec::new();

    for i in 0..n {
        let mut temp_p1: BinaryStringShare = BinaryStringShare::new();
        let mut temp_p2: BinaryStringShare = BinaryStringShare::new();
        let mut temp_p3: BinaryStringShare = BinaryStringShare::new();
        for _ in 0..(2 * l) {
            temp_p1.push(false, false);
            temp_p2.push(false, false);
            temp_p3.push(false, false);
        }

        for j in 0..l {
            temp_p1.set(
                j,
                x_p1[i].get_binary_share(j).value1,
                x_p1[i].get_binary_share(j).value2,
            );
            temp_p1.set(
                l + j,
                z1_p1[i].get_binary_share(j).value1
                    ^ z2_p1[i].get_binary_share(j).value1
                    ^ z3_p1[i].get_binary_share(j).value1,
                z1_p1[i].get_binary_share(j).value2
                    ^ z2_p1[i].get_binary_share(j).value2
                    ^ z3_p1[i].get_binary_share(j).value2,
            );

            temp_p2.set(
                j,
                x_p2[i].get_binary_share(j).value1,
                x_p2[i].get_binary_share(j).value2,
            );
            temp_p2.set(
                l + j,
                z1_p2[i].get_binary_share(j).value1
                    ^ z2_p2[i].get_binary_share(j).value1
                    ^ z3_p2[i].get_binary_share(j).value1,
                z1_p2[i].get_binary_share(j).value2
                    ^ z2_p2[i].get_binary_share(j).value2
                    ^ z3_p2[i].get_binary_share(j).value2,
            );

            temp_p3.set(
                j,
                x_p3[i].get_binary_share(j).value1,
                x_p3[i].get_binary_share(j).value2,
            );
            temp_p3.set(
                l + j,
                z1_p3[i].get_binary_share(j).value1
                    ^ z2_p3[i].get_binary_share(j).value1
                    ^ z3_p3[i].get_binary_share(j).value1,
                z1_p3[i].get_binary_share(j).value2
                    ^ z2_p3[i].get_binary_share(j).value2
                    ^ z3_p3[i].get_binary_share(j).value2,
            );
        }
        z_p1.push(temp_p1);
        z_p2.push(temp_p2);
        z_p3.push(temp_p3);
    }

    // 2 party shuffle with party 1 and party 2
    let mut reshare_z_p1 = Vec::new();
    let mut reshare_z_p2 = Vec::new();

    for i in 0..n {
        let (rs_z_p1, _send_2_p1) = reshare_from_generate_msg(z_p1[i].clone(), randomness_p1);
        let (send_1_p2, rs_z_p2) = reshare_from_generate_msg(z_p2[i].clone(), randomness_p2);
        let (_send_1_p3, send_2_p3) = reshare_from_generate_msg(z_p3[i].clone(), randomness_p3);

        let mut share_z_p1: BinaryString = BinaryString::with_capacity(2 * l);
        for j in 0..(2 * l) {
            share_z_p1.push(
                rs_z_p1.data.get_binary_share(j).value1 ^ send_1_p2.data.get_binary_share(j).value2,
            );
        }
        reshare_z_p1.push(share_z_p1);

        let mut share_z_p2: BinaryString = BinaryString::with_capacity(2 * l);
        for j in 0..(2 * l) {
            share_z_p2.push(
                rs_z_p2.data.get_binary_share(j).value1 ^ send_2_p3.data.get_binary_share(j).value2,
            );
        }
        reshare_z_p2.push(share_z_p2);
    }

    let p1_random_permutation = random_permutation(n);
    let p2_random_permutation = p1_random_permutation.clone();

    let shuffled_z1_p1 = apply_permutation(&reshare_z_p1, &p1_random_permutation);
    let shuffled_z2_p2 = apply_permutation(&reshare_z_p2, &p2_random_permutation);

    let mut z_perm1_p1: Vec<BinaryStringShare> = Vec::new();
    let mut z_perm1_p2: Vec<BinaryStringShare> = Vec::new();
    let mut z_perm1_p3: Vec<BinaryStringShare> = Vec::new();

    for i in 0..n {
        let (share_z1_p1, share_z1_p2, share_z1_p3) =
            get_default_bin_share_from_bin_string(&shuffled_z1_p1[i].clone());
        let (share_z2_p1, share_z2_p2, share_z2_p3) =
            get_default_bin_share_from_bin_string(&shuffled_z2_p2[i].clone());

        let mut temp_p1: BinaryStringShare = BinaryStringShare::new();
        let mut temp_p2: BinaryStringShare = BinaryStringShare::new();
        let mut temp_p3: BinaryStringShare = BinaryStringShare::new();

        for j in 0..(2 * l) {
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

        z_perm1_p1.push(temp_p1);
        z_perm1_p2.push(temp_p2);
        z_perm1_p3.push(temp_p3);
    }

    let mut x_a_p1: Vec<BinaryStringShare> = Vec::new();
    let mut x_a_p2: Vec<BinaryStringShare> = Vec::new();
    let mut x_a_p3: Vec<BinaryStringShare> = Vec::new();

    let mut mac_a_p1: Vec<BinaryStringShare> = Vec::new();
    let mut mac_a_p2: Vec<BinaryStringShare> = Vec::new();
    let mut mac_a_p3: Vec<BinaryStringShare> = Vec::new();

    // Split the shuffled value to message and MAC
    for i in 0..n {
        let (temp1_p1, temp2_p1) = split(z_perm1_p1[i].clone());
        let (temp1_p2, temp2_p2) = split(z_perm1_p2[i].clone());
        let (temp1_p3, temp2_p3) = split(z_perm1_p3[i].clone());

        x_a_p1.push(temp1_p1);
        mac_a_p1.push(temp2_p1);

        x_a_p2.push(temp1_p2);
        mac_a_p2.push(temp2_p2);

        x_a_p3.push(temp1_p3);
        mac_a_p3.push(temp2_p3);
    }

    // Verify the MAC
    let (y1_p1, y1_p2, y1_p3) = create_mac_msg1(x_a_p1, alpha_p1.clone());
    let (y2_p1, y2_p2, y2_p3) = create_mac_msg1(x_a_p2, alpha_p2.clone());
    let (y3_p1, y3_p2, y3_p3) = create_mac_msg1(x_a_p3, alpha_p3.clone());

    let mut y_p1: Vec<BinaryStringShare> = Vec::new();
    let mut y_p2: Vec<BinaryStringShare> = Vec::new();
    let mut y_p3: Vec<BinaryStringShare> = Vec::new();

    for i in 0..n {
        let mut temp_p1: BinaryStringShare = BinaryStringShare::new();
        let mut temp_p2: BinaryStringShare = BinaryStringShare::new();
        let mut temp_p3: BinaryStringShare = BinaryStringShare::new();

        for j in 0..l {
            temp_p1.push(
                y1_p1[i].get_binary_share(j).value1
                    ^ y2_p1[i].get_binary_share(j).value1
                    ^ y3_p1[i].get_binary_share(j).value1,
                y1_p1[i].get_binary_share(j).value2
                    ^ y2_p1[i].get_binary_share(j).value2
                    ^ y3_p1[i].get_binary_share(j).value2,
            );
            temp_p2.push(
                y1_p2[i].get_binary_share(j).value1
                    ^ y2_p2[i].get_binary_share(j).value1
                    ^ y3_p2[i].get_binary_share(j).value1,
                y1_p2[i].get_binary_share(j).value2
                    ^ y2_p2[i].get_binary_share(j).value2
                    ^ y3_p2[i].get_binary_share(j).value2,
            );
            temp_p3.push(
                y1_p3[i].get_binary_share(j).value1
                    ^ y2_p3[i].get_binary_share(j).value1
                    ^ y3_p3[i].get_binary_share(j).value1,
                y1_p3[i].get_binary_share(j).value2
                    ^ y2_p3[i].get_binary_share(j).value2
                    ^ y3_p3[i].get_binary_share(j).value2,
            );
        }

        y_p1.push(temp_p1);
        y_p2.push(temp_p2);
        y_p3.push(temp_p3);
    }

    // Subtract mac
    let mut v_p1: Vec<BinaryStringShare> = Vec::new();
    let mut v_p2: Vec<BinaryStringShare> = Vec::new();
    let mut v_p3: Vec<BinaryStringShare> = Vec::new();

    for i in 0..n {
        let mut temp_p1: BinaryStringShare = BinaryStringShare::new();
        let mut temp_p2: BinaryStringShare = BinaryStringShare::new();
        let mut temp_p3: BinaryStringShare = BinaryStringShare::new();

        for j in 0..l {
            temp_p1.push(
                y_p1[i].get_binary_share(j).value1 ^ mac_a_p1[i].get_binary_share(j).value1,
                y_p1[i].get_binary_share(j).value2 ^ mac_a_p1[i].get_binary_share(j).value2,
            );
            temp_p2.push(
                y_p2[i].get_binary_share(j).value1 ^ mac_a_p2[i].get_binary_share(j).value1,
                y_p2[i].get_binary_share(j).value2 ^ mac_a_p2[i].get_binary_share(j).value2,
            );
            temp_p3.push(
                y_p3[i].get_binary_share(j).value1 ^ mac_a_p3[i].get_binary_share(j).value1,
                y_p3[i].get_binary_share(j).value2 ^ mac_a_p3[i].get_binary_share(j).value2,
            );
        }
        v_p1.push(temp_p1);
        v_p2.push(temp_p2);
        v_p3.push(temp_p3);
    }

    // Check if all the opened values is equal to 0
    for i in 0..n {
        for j in 0..l {
            assert!(!(v_p1[i].get_binary_share(j).value1 ^ v_p2[i].get_binary_share(j).value2));
            assert!(!(v_p2[i].get_binary_share(j).value1 ^ v_p3[i].get_binary_share(j).value2));
            assert!(!(v_p3[i].get_binary_share(j).value1 ^ v_p1[i].get_binary_share(j).value2));
        }
    }

    // 2 party shuffle with party 2 and party 3
    let mut reshare2_z_p2 = Vec::new();
    let mut reshare2_z_p3 = Vec::new();

    for i in 0..n {
        let (_send_1_p1, send_2_p1) =
            reshare_from_generate_msg(z_perm1_p1[i].clone(), randomness_p1);
        let (rs_z_p2, _send_2_p2) = reshare_from_generate_msg(z_perm1_p2[i].clone(), randomness_p2);
        let (send_1_p3, rs_z_p3) = reshare_from_generate_msg(z_perm1_p3[i].clone(), randomness_p3);

        let mut share_z_p2: BinaryString = BinaryString::with_capacity(2 * l);
        for j in 0..(2 * l) {
            share_z_p2.push(
                rs_z_p2.data.get_binary_share(j).value1 ^ send_1_p3.data.get_binary_share(j).value2,
            );
        }
        reshare2_z_p2.push(share_z_p2);

        let mut share_z_p3: BinaryString = BinaryString::with_capacity(2 * l);
        for j in 0..(2 * l) {
            share_z_p3.push(
                rs_z_p3.data.get_binary_share(j).value1 ^ send_2_p1.data.get_binary_share(j).value2,
            );
        }
        reshare2_z_p3.push(share_z_p3);
    }

    let p2_random_permutation = random_permutation(n);
    let p3_random_permutation = p2_random_permutation.clone();

    let shuffled_z1_p2 = apply_permutation(&reshare2_z_p2, &p2_random_permutation);
    let shuffled_z2_p3 = apply_permutation(&reshare2_z_p3, &p3_random_permutation);

    let mut z_perm2_p1: Vec<BinaryStringShare> = Vec::new();
    let mut z_perm2_p2: Vec<BinaryStringShare> = Vec::new();
    let mut z_perm2_p3: Vec<BinaryStringShare> = Vec::new();

    for i in 0..n {
        let (share_z1_p1, share_z1_p2, share_z1_p3) =
            get_default_bin_share_from_bin_string(&shuffled_z1_p2[i].clone());
        let (share_z2_p1, share_z2_p2, share_z2_p3) =
            get_default_bin_share_from_bin_string(&shuffled_z2_p3[i].clone());

        let mut temp_p1: BinaryStringShare = BinaryStringShare::new();
        let mut temp_p2: BinaryStringShare = BinaryStringShare::new();
        let mut temp_p3: BinaryStringShare = BinaryStringShare::new();

        for j in 0..(2 * l) {
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

        z_perm2_p1.push(temp_p1);
        z_perm2_p2.push(temp_p2);
        z_perm2_p3.push(temp_p3);
    }

    let mut x_b_p1 = Vec::new();
    let mut x_b_p2 = Vec::new();
    let mut x_b_p3 = Vec::new();

    let mut mac_b_p1 = Vec::new();
    let mut mac_b_p2 = Vec::new();
    let mut mac_b_p3 = Vec::new();

    for i in 0..n {
        let (temp1_p1, temp2_p1) = split(z_perm2_p1[i].clone());
        let (temp1_p2, temp2_p2) = split(z_perm2_p2[i].clone());
        let (temp1_p3, temp2_p3) = split(z_perm2_p3[i].clone());

        x_b_p1.push(temp1_p1);
        mac_b_p1.push(temp2_p1);

        x_b_p2.push(temp1_p2);
        mac_b_p2.push(temp2_p2);

        x_b_p3.push(temp1_p3);
        mac_b_p3.push(temp2_p3);
    }

    // Verify the MAC
    let (y1_p1, y1_p2, y1_p3) = create_mac_msg1(x_b_p1, alpha_p1.clone());
    let (y2_p1, y2_p2, y2_p3) = create_mac_msg1(x_b_p2, alpha_p2.clone());
    let (y3_p1, y3_p2, y3_p3) = create_mac_msg1(x_b_p3, alpha_p3.clone());

    let mut y_2_p1: Vec<BinaryStringShare> = Vec::new();
    let mut y_2_p2: Vec<BinaryStringShare> = Vec::new();
    let mut y_2_p3: Vec<BinaryStringShare> = Vec::new();

    for i in 0..n {
        let mut temp_p1: BinaryStringShare = BinaryStringShare::new();
        let mut temp_p2: BinaryStringShare = BinaryStringShare::new();
        let mut temp_p3: BinaryStringShare = BinaryStringShare::new();

        for j in 0..l {
            temp_p1.push(
                y1_p1[i].get_binary_share(j).value1
                    ^ y2_p1[i].get_binary_share(j).value1
                    ^ y3_p1[i].get_binary_share(j).value1,
                y1_p1[i].get_binary_share(j).value2
                    ^ y2_p1[i].get_binary_share(j).value2
                    ^ y3_p1[i].get_binary_share(j).value2,
            );
            temp_p2.push(
                y1_p2[i].get_binary_share(j).value1
                    ^ y2_p2[i].get_binary_share(j).value1
                    ^ y3_p2[i].get_binary_share(j).value1,
                y1_p2[i].get_binary_share(j).value2
                    ^ y2_p2[i].get_binary_share(j).value2
                    ^ y3_p2[i].get_binary_share(j).value2,
            );
            temp_p3.push(
                y1_p3[i].get_binary_share(j).value1
                    ^ y2_p3[i].get_binary_share(j).value1
                    ^ y3_p3[i].get_binary_share(j).value1,
                y1_p3[i].get_binary_share(j).value2
                    ^ y2_p3[i].get_binary_share(j).value2
                    ^ y3_p3[i].get_binary_share(j).value2,
            );
        }
        y_2_p1.push(temp_p1);
        y_2_p2.push(temp_p2);
        y_2_p3.push(temp_p3);
    }

    // Subtract mac
    let mut v2_p1: Vec<BinaryStringShare> = Vec::new();
    let mut v2_p2: Vec<BinaryStringShare> = Vec::new();
    let mut v2_p3: Vec<BinaryStringShare> = Vec::new();

    for i in 0..n {
        let mut temp_p1: BinaryStringShare = BinaryStringShare::new();
        let mut temp_p2: BinaryStringShare = BinaryStringShare::new();
        let mut temp_p3: BinaryStringShare = BinaryStringShare::new();

        for j in 0..l {
            temp_p1.push(
                y_2_p1[i].get_binary_share(j).value1 ^ mac_b_p1[i].get_binary_share(j).value1,
                y_2_p1[i].get_binary_share(j).value2 ^ mac_b_p1[i].get_binary_share(j).value2,
            );
            temp_p2.push(
                y_2_p2[i].get_binary_share(j).value1 ^ mac_b_p2[i].get_binary_share(j).value1,
                y_2_p2[i].get_binary_share(j).value2 ^ mac_b_p2[i].get_binary_share(j).value2,
            );
            temp_p3.push(
                y_2_p3[i].get_binary_share(j).value1 ^ mac_b_p3[i].get_binary_share(j).value1,
                y_2_p3[i].get_binary_share(j).value2 ^ mac_b_p3[i].get_binary_share(j).value2,
            );
        }
        v2_p1.push(temp_p1);
        v2_p2.push(temp_p2);
        v2_p3.push(temp_p3);
    }

    // Check if all the opened values is equal to 0
    for i in 0..n {
        for j in 0..l {
            assert!(!(v2_p1[i].get_binary_share(j).value1 ^ v2_p2[i].get_binary_share(j).value2));
            assert!(!(v2_p2[i].get_binary_share(j).value1 ^ v2_p3[i].get_binary_share(j).value2));
            assert!(!(v2_p3[i].get_binary_share(j).value1 ^ v2_p1[i].get_binary_share(j).value2));
        }
    }

    // 2 party shuffle with party 3 and party 1
    let mut reshare3_z_p3 = Vec::new();
    let mut reshare3_z_p1 = Vec::new();

    for i in 0..n {
        let (send_3_p1, rs_z_p1) = reshare_from_generate_msg(z_perm2_p1[i].clone(), randomness_p1);
        let (_send_3_p2, send_1_p2) =
            reshare_from_generate_msg(z_perm2_p2[i].clone(), randomness_p2);
        let (rs_z_p3, _send_1_p3) = reshare_from_generate_msg(z_perm2_p3[i].clone(), randomness_p3);

        let mut share_z_p1: BinaryString = BinaryString::with_capacity(2 * l);
        for j in 0..(2 * l) {
            share_z_p1.push(
                rs_z_p1.data.get_binary_share(j).value1 ^ send_1_p2.data.get_binary_share(j).value2,
            );
        }
        reshare3_z_p1.push(share_z_p1);

        let mut share_z_p3: BinaryString = BinaryString::with_capacity(2 * l);
        for j in 0..(2 * l) {
            share_z_p3.push(
                rs_z_p3.data.get_binary_share(j).value1 ^ send_3_p1.data.get_binary_share(j).value2,
            );
        }
        reshare3_z_p3.push(share_z_p3);
    }

    let p3_random_permutation = random_permutation(n);
    let p1_random_permutation = p3_random_permutation.clone();

    let shuffled_z1_p3 = apply_permutation(&reshare3_z_p3, &p3_random_permutation);
    let shuffled_z2_p1 = apply_permutation(&reshare3_z_p1, &p1_random_permutation);

    let mut z_perm3_p1: Vec<BinaryStringShare> = Vec::new();
    let mut z_perm3_p2: Vec<BinaryStringShare> = Vec::new();
    let mut z_perm3_p3: Vec<BinaryStringShare> = Vec::new();

    for i in 0..n {
        let (share_z1_p1, share_z1_p2, share_z1_p3) =
            get_default_bin_share_from_bin_string(&shuffled_z1_p3[i].clone());
        let (share_z2_p1, share_z2_p2, share_z2_p3) =
            get_default_bin_share_from_bin_string(&shuffled_z2_p1[i].clone());

        let mut temp_p1: BinaryStringShare = BinaryStringShare::new();
        let mut temp_p2: BinaryStringShare = BinaryStringShare::new();
        let mut temp_p3: BinaryStringShare = BinaryStringShare::new();

        for j in 0..(2 * l) {
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

        z_perm3_p1.push(temp_p1);
        z_perm3_p2.push(temp_p2);
        z_perm3_p3.push(temp_p3);
    }

    let mut x_c_p1 = Vec::new();
    let mut x_c_p2 = Vec::new();
    let mut x_c_p3 = Vec::new();

    let mut mac_c_p1 = Vec::new();
    let mut mac_c_p2 = Vec::new();
    let mut mac_c_p3 = Vec::new();

    for i in 0..n {
        let (temp1_p1, temp2_p1) = split(z_perm3_p1[i].clone());
        let (temp1_p2, temp2_p2) = split(z_perm3_p2[i].clone());
        let (temp1_p3, temp2_p3) = split(z_perm3_p3[i].clone());

        x_c_p1.push(temp1_p1);
        mac_c_p1.push(temp2_p1);

        x_c_p2.push(temp1_p2);
        mac_c_p2.push(temp2_p2);

        x_c_p3.push(temp1_p3);
        mac_c_p3.push(temp2_p3);
    }

    // Verify the MAC
    let (y1_p1, y1_p2, y1_p3) = create_mac_msg1(x_c_p1.clone(), alpha_p1.clone());
    let (y2_p1, y2_p2, y2_p3) = create_mac_msg1(x_c_p2.clone(), alpha_p2.clone());
    let (y3_p1, y3_p2, y3_p3) = create_mac_msg1(x_c_p3.clone(), alpha_p3.clone());

    let mut y_3_p1: Vec<BinaryStringShare> = Vec::new();
    let mut y_3_p2: Vec<BinaryStringShare> = Vec::new();
    let mut y_3_p3: Vec<BinaryStringShare> = Vec::new();

    for i in 0..n {
        let mut temp_p1: BinaryStringShare = BinaryStringShare::new();
        let mut temp_p2: BinaryStringShare = BinaryStringShare::new();
        let mut temp_p3: BinaryStringShare = BinaryStringShare::new();

        for j in 0..l {
            temp_p1.push(
                y1_p1[i].get_binary_share(j).value1
                    ^ y2_p1[i].get_binary_share(j).value1
                    ^ y3_p1[i].get_binary_share(j).value1,
                y1_p1[i].get_binary_share(j).value2
                    ^ y2_p1[i].get_binary_share(j).value2
                    ^ y3_p1[i].get_binary_share(j).value2,
            );
            temp_p2.push(
                y1_p2[i].get_binary_share(j).value1
                    ^ y2_p2[i].get_binary_share(j).value1
                    ^ y3_p2[i].get_binary_share(j).value1,
                y1_p2[i].get_binary_share(j).value2
                    ^ y2_p2[i].get_binary_share(j).value2
                    ^ y3_p2[i].get_binary_share(j).value2,
            );
            temp_p3.push(
                y1_p3[i].get_binary_share(j).value1
                    ^ y2_p3[i].get_binary_share(j).value1
                    ^ y3_p3[i].get_binary_share(j).value1,
                y1_p3[i].get_binary_share(j).value2
                    ^ y2_p3[i].get_binary_share(j).value2
                    ^ y3_p3[i].get_binary_share(j).value2,
            );
        }
        y_3_p1.push(temp_p1);
        y_3_p2.push(temp_p2);
        y_3_p3.push(temp_p3);
    }

    // Subtract mac
    let mut v3_p1: Vec<BinaryStringShare> = Vec::new();
    let mut v3_p2: Vec<BinaryStringShare> = Vec::new();
    let mut v3_p3: Vec<BinaryStringShare> = Vec::new();
    for i in 0..n {
        let mut temp_p1: BinaryStringShare = BinaryStringShare::new();
        let mut temp_p2: BinaryStringShare = BinaryStringShare::new();
        let mut temp_p3: BinaryStringShare = BinaryStringShare::new();

        for j in 0..l {
            temp_p1.push(
                y_3_p1[i].get_binary_share(j).value1 ^ mac_c_p1[i].get_binary_share(j).value1,
                y_3_p1[i].get_binary_share(j).value2 ^ mac_c_p1[i].get_binary_share(j).value2,
            );
            temp_p2.push(
                y_3_p2[i].get_binary_share(j).value1 ^ mac_c_p2[i].get_binary_share(j).value1,
                y_3_p2[i].get_binary_share(j).value2 ^ mac_c_p2[i].get_binary_share(j).value2,
            );
            temp_p3.push(
                y_3_p3[i].get_binary_share(j).value1 ^ mac_c_p3[i].get_binary_share(j).value1,
                y_3_p3[i].get_binary_share(j).value2 ^ mac_c_p3[i].get_binary_share(j).value2,
            );
        }
        v3_p1.push(temp_p1);
        v3_p2.push(temp_p2);
        v3_p3.push(temp_p3);
    }

    // Check if all the opened values is equal to 0
    for i in 0..n {
        for j in 0..l {
            assert!(!(v3_p1[i].get_binary_share(j).value1 ^ v3_p2[i].get_binary_share(j).value2));
            assert!(!(v3_p2[i].get_binary_share(j).value1 ^ v3_p3[i].get_binary_share(j).value2));
            assert!(!(v3_p3[i].get_binary_share(j).value1 ^ v3_p1[i].get_binary_share(j).value2));
        }
    }

    (x_c_p1, x_c_p2, x_c_p3)
}

/// Implementation of Protocol 3.14 (Shuffle) from https://github.com/silence-laboratories/research-silent-compute/blob/main/paper/main.pdf.
pub async fn run_shuffle<T, R>(
    _setup: &T,
    _mpc_encryption: &mut MPCEncryption,
    _tag_offset_counter: &mut TagOffsetCounter,
    _relay: &mut FilteredMsgRelay<R>,
    _l: usize,
    _x_p: &[BinaryStringShare],
    _randomness: &mut CommonRandomness,
) -> Result<Vec<BinaryStringShare>, ProtocolError>
where
    T: CommonSetupMessage,
    R: Relay,
{
    todo!();
}

/// Test shuffle protocol
#[cfg(any(test, feature = "test-support"))]
async fn test_shuffle_protocol<T, R>(
    setup: T,
    seed: Seed,
    params: (usize, Vec<BinaryStringShare>),
    relay: R,
) -> Result<(usize, Vec<BinaryStringShare>), ProtocolError>
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

    let mut common_randomness = run_common_randomness(
        &setup,
        common_randomness_seed,
        &mut mpc_encryption,
        &mut relay,
    )
    .await?;

    let mut tag_offset_counter = TagOffsetCounter::new();

    let l = params.0;
    let x_p = params.1;
    let result = run_shuffle(
        &setup,
        &mut mpc_encryption,
        &mut tag_offset_counter,
        &mut relay,
        l,
        &x_p,
        &mut common_randomness,
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
    use super::{test_run_shuffle, test_shuffle_protocol};
    use crate::mpc::common_randomness::test_run_get_serverstate;
    use crate::proto::{
        convert_arith_to_bin, convert_bin_to_arith, get_default_bin_share_from_bin_string,
        reconstruct_binary_string_share,
    };
    use crate::transport::test_utils::setup_mpc;
    use crate::types::{BinaryStringShare, FieldElement};
    use sl_mpc_mate::coord::{MessageRelayService, Relay};
    use tokio::task::JoinSet;

    async fn _sim<S, R>(
        coord: S,
        sim_params: &[(usize, Vec<BinaryStringShare>); 3],
    ) -> Vec<Vec<BinaryStringShare>>
    where
        S: MessageRelayService<MessageRelay = R>,
        R: Relay + Send + 'static,
    {
        let parties = setup_mpc(None, sim_params);

        let mut jset = JoinSet::new();
        for (setup, seed, params) in parties {
            let relay = coord.connect().await.unwrap();

            jset.spawn(test_shuffle_protocol(setup, seed, params, relay));
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

    #[test]
    pub fn test_shuffle_sort() {
        // Random test array to be shuffled
        let test_array = vec![
            FieldElement::from(1u64),
            FieldElement::from(2u64),
            FieldElement::from(3u64),
            FieldElement::from(4u64),
            FieldElement::from(5u64),
            FieldElement::from(6u64),
            FieldElement::from(7u64),
            FieldElement::from(8u64),
            FieldElement::from(9u64),
            FieldElement::from(10u64),
        ];
        let n = test_array.len();

        // Generate binary sharings of the test array
        let mut x_p1 = Vec::new();
        let mut x_p2 = Vec::new();
        let mut x_p3 = Vec::new();

        let bit_length = 64;

        for test_array_i in test_array.iter().take(n) {
            let (temp1, temp2, temp3) = get_default_bin_share_from_bin_string(
                &convert_arith_to_bin(bit_length, test_array_i),
            );
            x_p1.push(temp1);
            x_p2.push(temp2);
            x_p3.push(temp3);
        }

        let (mut serverstate_p1, mut serverstate_p2, mut serverstate_p3) =
            test_run_get_serverstate();

        let (shuffled_p1, shuffled_p2, shuffled_p3) = test_run_shuffle(
            bit_length,
            x_p1.clone(),
            x_p2.clone(),
            x_p3.clone(),
            &mut serverstate_p1.common_randomness,
            &mut serverstate_p2.common_randomness,
            &mut serverstate_p3.common_randomness,
        );

        // test_run_verify(
        //     &mut serverstate_p1,
        //     &mut serverstate_p2,
        //     &mut serverstate_p3,
        // );

        let mut result: Vec<FieldElement> = Vec::new();

        for i in 0..shuffled_p1.len() {
            result.push(convert_bin_to_arith(reconstruct_binary_string_share(
                &shuffled_p1[i],
                &shuffled_p2[i],
                &shuffled_p3[i],
            )));
        }
        result.sort();

        assert_eq!(result, test_array)
    }
}
