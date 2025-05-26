use crate::constants::MUL_EC_SHARES_MSG;
use crate::mpc::common_randomness::CommonRandomness;
use crate::mpc::open_protocol::run_open_arith_ec;
use crate::transport::proto::{FilteredMsgRelay, Wrap};
use crate::transport::setup::common::MPCEncryption;
use crate::transport::setup::CommonSetupMessage;
use crate::transport::types::ProtocolError;
#[cfg(any(test, feature = "test-support"))]
use crate::transport::utils::Seed;
use crate::transport::utils::{receive_from_parties, send_to_party, TagOffsetCounter};
use crate::types::ServerState;
use crate::{
    proto::get_default_ec_share,
    types::ArithmeticECShare,
    utility::helper::{get_modulus, get_modulus_u512},
};
use crypto_bigint::{Encoding, NonZero, U256};
use sl_mpc_mate::coord::Relay;
use sl_mpc_mate::message::MessageTag;

pub fn multiply_mod(a: U256, b: U256) -> U256 {
    let product = a.mul(&b);
    let p = get_modulus_u512();
    let modulus = product.rem(&NonZero::new(p).expect("Modulus p should not be zero."));
    let bytes = modulus.to_be_bytes();
    U256::from_be_bytes(bytes[32..].try_into().expect("Slice should be 32 bytes"))
}

pub fn generate_rand_ec_arith(randomness: &mut CommonRandomness) -> ArithmeticECShare {
    let mut output: ArithmeticECShare = ArithmeticECShare {
        value1: U256::ZERO,
        value2: U256::ZERO,
    };

    let (random_prev, random_next) = randomness.random_32_bytes();

    let p = get_modulus();

    output.value1 = output
        .value1
        .add_mod(&U256::from_be_slice(&random_prev), &p);
    output.value1 = output
        .value1
        .add_mod(&U256::from_be_slice(&random_next), &p);

    output.value2 = output
        .value2
        .add_mod(&U256::from_be_slice(&random_next), &p);

    output
}

pub fn subtract(a: ArithmeticECShare, b: ArithmeticECShare) -> ArithmeticECShare {
    let mut output: ArithmeticECShare = ArithmeticECShare {
        value1: U256::ZERO,
        value2: U256::ZERO,
    };

    let p = get_modulus();

    output.value1 = a.value1.sub_mod(&b.value1, &p);
    output.value2 = a.value2.sub_mod(&b.value2, &p);

    output
}

pub fn add(a: ArithmeticECShare, b: ArithmeticECShare) -> ArithmeticECShare {
    let mut output: ArithmeticECShare = ArithmeticECShare {
        value1: U256::ZERO,
        value2: U256::ZERO,
    };
    let p = get_modulus();

    output.value1 = a.value1.add_mod(&b.value1, &p);
    output.value2 = a.value2.add_mod(&b.value2, &p);

    output
}

pub fn multiply_ec(
    a: ArithmeticECShare,
    b: ArithmeticECShare,
) -> (ArithmeticECShare, ArithmeticECShare, ArithmeticECShare) {
    let p = get_modulus();

    let a_share1 = a.value1.sub_mod(&a.value2, &p);
    let b_share1 = b.value1.sub_mod(&b.value2, &p);

    let z = (multiply_mod(a.value2, b.value2).add_mod(&multiply_mod(a_share1, b.value2), &p))
        .add_mod(&multiply_mod(b_share1, a.value2), &p);

    let z_p1 = get_default_ec_share(z, 1);
    let z_p2 = get_default_ec_share(z, 2);
    let z_p3 = get_default_ec_share(z, 3);

    (z_p1, z_p2, z_p3)
}

pub fn inverse_mod(a: &U256) -> U256 {
    let p = get_modulus();
    let (inv, _choice) = a.inv_mod(&p);

    inv
}

/// mul_ec_shares
pub async fn run_mul_ec_shares<T, R>(
    setup: &T,
    mpc_encryption: &mut MPCEncryption,
    tag_offset_counter: &mut TagOffsetCounter,
    relay: &mut FilteredMsgRelay<R>,
    a: &ArithmeticECShare,
    b: &ArithmeticECShare,
    store_mult_triples: &mut [Vec<ArithmeticECShare>],
) -> Result<ArithmeticECShare, ProtocolError>
where
    T: CommonSetupMessage,
    R: Relay,
{
    let party_index = setup.participant_index();
    // p2p messages all to all
    let msg_tag = MessageTag::tag1(MUL_EC_SHARES_MSG, tag_offset_counter.next_value());
    relay.ask_messages(setup, msg_tag, true).await?;

    let (share_z1_p1, share_z1_p2, share_z1_p3) = multiply_ec(a.to_owned(), b.to_owned());
    let msg_size = share_z1_p1.external_size();

    let mult_p = match party_index {
        0 => {
            // party_1 sends share_z1_p2 to party_2
            send_to_party(setup, mpc_encryption, msg_tag, share_z1_p2, 1, relay).await?;
            // party_1 sends share_z1_p3 to party_3
            send_to_party(setup, mpc_encryption, msg_tag, share_z1_p3, 2, relay).await?;
            // party_1 receives points from party_2 and party_3
            let values: Vec<ArithmeticECShare> =
                receive_from_parties(setup, mpc_encryption, msg_tag, msg_size, vec![1, 2], relay)
                    .await?;

            add(add(share_z1_p1, values[0].clone()), values[1].clone())
        }
        1 => {
            // party_2 sends share_z1_p1 to party_1
            send_to_party(setup, mpc_encryption, msg_tag, share_z1_p1, 0, relay).await?;
            // party_2 sends share_z1_p3 to party_3
            send_to_party(setup, mpc_encryption, msg_tag, share_z1_p3, 2, relay).await?;
            // party_2 receives points from party_1 and party_3
            let values: Vec<ArithmeticECShare> =
                receive_from_parties(setup, mpc_encryption, msg_tag, msg_size, vec![0, 2], relay)
                    .await?;

            add(add(values[0].clone(), share_z1_p2), values[1].clone())
        }
        _ => {
            // party_3 sends share_z1_p1 to party_1
            send_to_party(setup, mpc_encryption, msg_tag, share_z1_p1, 0, relay).await?;
            // party_3 sends share_z1_p2 to party_2
            send_to_party(setup, mpc_encryption, msg_tag, share_z1_p2, 1, relay).await?;
            // party_3 receives points from party_1 and party_2
            let values: Vec<ArithmeticECShare> =
                receive_from_parties(setup, mpc_encryption, msg_tag, msg_size, vec![0, 1], relay)
                    .await?;

            add(add(values[0].clone(), values[1].clone()), share_z1_p3)
        }
    };

    store_mult_triples[0].push(a.to_owned());
    store_mult_triples[1].push(b.to_owned());
    store_mult_triples[2].push(mult_p.clone());

    Ok(mult_p)
}

/// Adds two point shares A1(x1, y1) + A2(x2, y2)
pub async fn run_ec_addition<T, R>(
    setup: &T,
    mpc_encryption: &mut MPCEncryption,
    tag_offset_counter: &mut TagOffsetCounter,
    relay: &mut FilteredMsgRelay<R>,
    points: &[ArithmeticECShare],
    store_mult_triples: &mut [Vec<ArithmeticECShare>],
    serverstate: &mut ServerState,
) -> Result<(ArithmeticECShare, ArithmeticECShare), ProtocolError>
where
    T: CommonSetupMessage,
    R: Relay,
{
    let x1_p = points[0].clone();
    let x2_p = points[1].clone();
    let y1_p = points[2].clone();
    let y2_p = points[3].clone();

    // Compute A1 + A2
    let slope_num_p = subtract(y2_p.clone(), y1_p.clone());
    let slope_den_p = subtract(x2_p.clone(), x1_p.clone());

    // Random value r
    let r1_p1 = generate_rand_ec_arith(&mut serverstate.common_randomness);

    let inv_x_p = run_mul_ec_shares(
        setup,
        mpc_encryption,
        tag_offset_counter,
        relay,
        &slope_den_p,
        &r1_p1,
        store_mult_triples,
    )
    .await?;

    // Open inv_x and take inverse of it
    let mult_r_p1 = run_open_arith_ec(
        setup,
        mpc_encryption,
        tag_offset_counter,
        relay,
        &inv_x_p,
        serverstate,
    )
    .await?;

    let inverse_p1 = inverse_mod(&mult_r_p1);

    // Multiply r with a constant
    let mut int_output_p1: ArithmeticECShare = ArithmeticECShare {
        value1: U256::ZERO,
        value2: U256::ZERO,
    };

    int_output_p1.value1 = multiply_mod(r1_p1.value1, inverse_p1);
    int_output_p1.value2 = multiply_mod(r1_p1.value2, inverse_p1);

    // Mulitply inv and slope num
    let m_p1 = run_mul_ec_shares(
        setup,
        mpc_encryption,
        tag_offset_counter,
        relay,
        &int_output_p1,
        &slope_num_p,
        store_mult_triples,
    )
    .await?;

    // Compute x3
    let m_sq_p1 = run_mul_ec_shares(
        setup,
        mpc_encryption,
        tag_offset_counter,
        relay,
        &m_p1,
        &m_p1,
        store_mult_triples,
    )
    .await?;

    let int_x3_p1 = subtract(subtract(m_sq_p1, x1_p.clone()), x2_p.clone());

    // Compute y3
    let inter_p1 = subtract(x1_p.clone(), int_x3_p1.clone());

    let int_p1 = run_mul_ec_shares(
        setup,
        mpc_encryption,
        tag_offset_counter,
        relay,
        &m_p1,
        &inter_p1,
        store_mult_triples,
    )
    .await?;

    let int_y3_p1 = subtract(int_p1, y1_p.clone());

    Ok((int_x3_p1, int_y3_p1))
}

/// Implementation of Protocol 2.3 (EC2A) from https://github.com/silence-laboratories/research-silent-compute/blob/main/paper/main.pdf.
pub async fn run_ec_to_a<T, R>(
    setup: &T,
    mpc_encryption: &mut MPCEncryption,
    tag_offset_counter: &mut TagOffsetCounter,
    relay: &mut FilteredMsgRelay<R>,
    points: &[ArithmeticECShare],
    store_mult_triples: &mut [Vec<ArithmeticECShare>],
    serverstate: &mut ServerState,
) -> Result<(ArithmeticECShare, ArithmeticECShare), ProtocolError>
where
    T: CommonSetupMessage,
    R: Relay,
{
    // Extract the points from each party
    let (x1_p1, x2_p1, x3_p1, y1_p1, y2_p1, y3_p1) = (
        points[0].clone(),
        points[1].clone(),
        points[2].clone(),
        points[3].clone(),
        points[4].clone(),
        points[5].clone(),
    );

    // Set up the points for the first test
    let points1_p = [x1_p1, x2_p1, y1_p1, y2_p1];

    // Run the first EC addition
    let (tempx_p, tempy_p) = run_ec_addition(
        setup,
        mpc_encryption,
        tag_offset_counter,
        relay,
        &points1_p,
        store_mult_triples,
        serverstate,
    )
    .await?;

    // Set up the points for the second test
    let points2_p = [tempx_p, x3_p1, tempy_p, y3_p1];

    // Run the second EC addition
    let (resx_p, resy_p) = run_ec_addition(
        setup,
        mpc_encryption,
        tag_offset_counter,
        relay,
        &points2_p,
        store_mult_triples,
        serverstate,
    )
    .await?;

    // Return the results
    Ok((resx_p, resy_p))
}

pub fn verification_ec(
    randomness_p1: &mut CommonRandomness,
    randomness_p2: &mut CommonRandomness,
    randomness_p3: &mut CommonRandomness,
    store_mult_triples_p1: &mut [Vec<ArithmeticECShare>],
    store_mult_triples_p2: &mut [Vec<ArithmeticECShare>],
    store_mult_triples_p3: &mut [Vec<ArithmeticECShare>],
) {
    let p = get_modulus();

    // Generate a random alpha
    let alpha_p1 = generate_rand_ec_arith(randomness_p1);
    let alpha_p2 = generate_rand_ec_arith(randomness_p2);
    let alpha_p3 = generate_rand_ec_arith(randomness_p3);

    // Generate random triples for verification
    let mut triples_p1: Vec<Vec<ArithmeticECShare>> = Vec::new();
    let a_p1: Vec<ArithmeticECShare> = Vec::new();
    let b_p1: Vec<ArithmeticECShare> = Vec::new();
    let c_p1: Vec<ArithmeticECShare> = Vec::new();
    triples_p1.push(a_p1);
    triples_p1.push(b_p1);
    triples_p1.push(c_p1);

    let mut triples_p2: Vec<Vec<ArithmeticECShare>> = Vec::new();
    let a_p2: Vec<ArithmeticECShare> = Vec::new();
    let b_p2: Vec<ArithmeticECShare> = Vec::new();
    let c_p2: Vec<ArithmeticECShare> = Vec::new();
    triples_p2.push(a_p2);
    triples_p2.push(b_p2);
    triples_p2.push(c_p2);

    let mut triples_p3: Vec<Vec<ArithmeticECShare>> = Vec::new();
    let a_p3: Vec<ArithmeticECShare> = Vec::new();
    let b_p3: Vec<ArithmeticECShare> = Vec::new();
    let c_p3: Vec<ArithmeticECShare> = Vec::new();
    triples_p3.push(a_p3);
    triples_p3.push(b_p3);
    triples_p3.push(c_p3);

    for _ in 0..8 {
        let rand_a_p1 = generate_rand_ec_arith(randomness_p1);
        let rand_a_p2 = generate_rand_ec_arith(randomness_p2);
        let rand_a_p3 = generate_rand_ec_arith(randomness_p3);

        let rand_b_p1 = generate_rand_ec_arith(randomness_p1);
        let rand_b_p2 = generate_rand_ec_arith(randomness_p2);
        let rand_b_p3 = generate_rand_ec_arith(randomness_p3);

        let (share_c1_p1, share_c1_p2, share_c1_p3) =
            multiply_ec(rand_a_p1.clone(), rand_b_p1.clone());
        let (share_c2_p1, share_c2_p2, share_c2_p3) =
            multiply_ec(rand_a_p2.clone(), rand_b_p2.clone());
        let (share_c3_p1, share_c3_p2, share_c3_p3) =
            multiply_ec(rand_a_p3.clone(), rand_b_p3.clone());

        let rand_c_p1 = add(add(share_c1_p1, share_c2_p1), share_c3_p1);
        let rand_c_p2 = add(add(share_c1_p2, share_c2_p2), share_c3_p2);
        let rand_c_p3 = add(add(share_c1_p3, share_c2_p3), share_c3_p3);

        triples_p1[0].push(rand_a_p1);
        triples_p2[0].push(rand_a_p2);
        triples_p3[0].push(rand_a_p3);

        triples_p1[1].push(rand_b_p1);
        triples_p2[1].push(rand_b_p2);
        triples_p3[1].push(rand_b_p3);

        triples_p1[2].push(rand_c_p1);
        triples_p2[2].push(rand_c_p2);
        triples_p3[2].push(rand_c_p3);
    }

    let mut gamma_p1: Vec<ArithmeticECShare> = Vec::new();
    let mut gamma_p2: Vec<ArithmeticECShare> = Vec::new();
    let mut gamma_p3: Vec<ArithmeticECShare> = Vec::new();

    let mut sigma_p1: Vec<ArithmeticECShare> = Vec::new();
    let mut sigma_p2: Vec<ArithmeticECShare> = Vec::new();
    let mut sigma_p3: Vec<ArithmeticECShare> = Vec::new();

    let mut zalpha_p1: Vec<ArithmeticECShare> = Vec::new();
    let mut zalpha_p2: Vec<ArithmeticECShare> = Vec::new();
    let mut zalpha_p3: Vec<ArithmeticECShare> = Vec::new();

    let mut asigma_p1: Vec<ArithmeticECShare> = Vec::new();
    let mut asigma_p2: Vec<ArithmeticECShare> = Vec::new();
    let mut asigma_p3: Vec<ArithmeticECShare> = Vec::new();

    let mut ygamma_p1: Vec<ArithmeticECShare> = Vec::new();
    let mut ygamma_p2: Vec<ArithmeticECShare> = Vec::new();
    let mut ygamma_p3: Vec<ArithmeticECShare> = Vec::new();

    let mut psi_p1: Vec<U256> = Vec::new();
    let mut psi_p2: Vec<U256> = Vec::new();
    let mut psi_p3: Vec<U256> = Vec::new();

    // Steps 2 to 7 of the protocol 3.6
    for i in 0..8 {
        let x_p1 = store_mult_triples_p1[0][i].clone();
        let y_p1 = store_mult_triples_p1[1][i].clone();
        let z_p1 = store_mult_triples_p1[2][i].clone();
        let a_p1 = triples_p1[0][i].clone();
        let b_p1 = triples_p1[1][i].clone();

        let x_p2 = store_mult_triples_p2[0][i].clone();
        let y_p2 = store_mult_triples_p2[1][i].clone();
        let z_p2 = store_mult_triples_p2[2][i].clone();
        let a_p2 = triples_p2[0][i].clone();
        let b_p2 = triples_p2[1][i].clone();

        let x_p3 = store_mult_triples_p3[0][i].clone();
        let y_p3 = store_mult_triples_p3[1][i].clone();
        let z_p3 = store_mult_triples_p3[2][i].clone();
        let a_p3 = triples_p3[0][i].clone();
        let b_p3 = triples_p3[1][i].clone();

        let (share_xalpha1_p1, share_xalpha1_p2, share_xalpha1_p3) =
            multiply_ec(alpha_p1.clone(), x_p1.clone());
        let (share_xalpha2_p1, share_xalpha2_p2, share_xalpha2_p3) =
            multiply_ec(alpha_p2.clone(), x_p2.clone());
        let (share_xalpha3_p1, share_xalpha3_p2, share_xalpha3_p3) =
            multiply_ec(alpha_p3.clone(), x_p3.clone());

        let temp_gamma_p1 = add(
            add(add(share_xalpha1_p1, share_xalpha2_p1), share_xalpha3_p1),
            a_p1.clone(),
        );
        let temp_gamma_p2 = add(
            add(add(share_xalpha1_p2, share_xalpha2_p2), share_xalpha3_p2),
            a_p2.clone(),
        );
        let temp_gamma_p3 = add(
            add(add(share_xalpha1_p3, share_xalpha2_p3), share_xalpha3_p3),
            a_p3.clone(),
        );

        gamma_p1.push(temp_gamma_p1.clone());
        gamma_p2.push(temp_gamma_p2.clone());
        gamma_p3.push(temp_gamma_p3.clone());

        let temp_sigma_p1 = add(y_p1.clone(), b_p1);
        let temp_sigma_p2 = add(y_p2.clone(), b_p2);
        let temp_sigma_p3 = add(y_p3.clone(), b_p3);

        sigma_p1.push(temp_sigma_p1.clone());
        sigma_p2.push(temp_sigma_p2.clone());
        sigma_p3.push(temp_sigma_p3.clone());

        let (share_zalpha1_p1, share_zalpha1_p2, share_zalpha1_p3) =
            multiply_ec(z_p1, alpha_p1.clone());
        let (share_zalpha2_p1, share_zalpha2_p2, share_zalpha2_p3) =
            multiply_ec(z_p2, alpha_p2.clone());
        let (share_zalpha3_p1, share_zalpha3_p2, share_zalpha3_p3) =
            multiply_ec(z_p3, alpha_p3.clone());

        let temp_zalpha_p1 = add(add(share_zalpha1_p1, share_zalpha2_p1), share_zalpha3_p1);
        let temp_zalpha_p2 = add(add(share_zalpha1_p2, share_zalpha2_p2), share_zalpha3_p2);
        let temp_zalpha_p3 = add(add(share_zalpha1_p3, share_zalpha2_p3), share_zalpha3_p3);

        zalpha_p1.push(temp_zalpha_p1);
        zalpha_p2.push(temp_zalpha_p2);
        zalpha_p3.push(temp_zalpha_p3);

        let (share_asigma1_p1, share_asigma1_p2, share_asigma1_p3) =
            multiply_ec(a_p1, temp_sigma_p1);
        let (share_asigma2_p1, share_asigma2_p2, share_asigma2_p3) =
            multiply_ec(a_p2, temp_sigma_p2);
        let (share_asigma3_p1, share_asigma3_p2, share_asigma3_p3) =
            multiply_ec(a_p3, temp_sigma_p3);

        let temp_asigma_p1 = add(add(share_asigma1_p1, share_asigma2_p1), share_asigma3_p1);
        let temp_asigma_p2 = add(add(share_asigma1_p2, share_asigma2_p2), share_asigma3_p2);
        let temp_asigma_p3 = add(add(share_asigma1_p3, share_asigma2_p3), share_asigma3_p3);

        asigma_p1.push(temp_asigma_p1);
        asigma_p2.push(temp_asigma_p2);
        asigma_p3.push(temp_asigma_p3);

        let (share_ygamma1_p1, share_ygamma1_p2, share_ygamma1_p3) =
            multiply_ec(y_p1, temp_gamma_p1);
        let (share_ygamma2_p1, share_ygamma2_p2, share_ygamma2_p3) =
            multiply_ec(y_p2, temp_gamma_p2);
        let (share_ygamma3_p1, share_ygamma3_p2, share_ygamma3_p3) =
            multiply_ec(y_p3, temp_gamma_p3);

        let temp_ygamma_p1 = add(add(share_ygamma1_p1, share_ygamma2_p1), share_ygamma3_p1);
        let temp_ygamma_p2 = add(add(share_ygamma1_p2, share_ygamma2_p2), share_ygamma3_p2);
        let temp_ygamma_p3 = add(add(share_ygamma1_p3, share_ygamma2_p3), share_ygamma3_p3);

        ygamma_p1.push(temp_ygamma_p1);
        ygamma_p2.push(temp_ygamma_p2);
        ygamma_p3.push(temp_ygamma_p3);

        // Generate shares of psi
        let rand_psi_p1 = generate_rand_ec_arith(randomness_p1);
        let rand_psi_p2 = generate_rand_ec_arith(randomness_p2);
        let rand_psi_p3 = generate_rand_ec_arith(randomness_p3);

        // Open psi and store
        psi_p1.push(rand_psi_p1.value1.add_mod(&rand_psi_p2.value2, &p));
        psi_p2.push(rand_psi_p2.value1.add_mod(&rand_psi_p3.value2, &p));
        psi_p3.push(rand_psi_p3.value1.add_mod(&rand_psi_p1.value2, &p));
    }

    // Open alpha
    let open_alpha_p1 = alpha_p1.value1.add_mod(&alpha_p2.value2, &p);
    let open_alpha_p2 = alpha_p2.value1.add_mod(&alpha_p3.value2, &p);
    let open_alpha_p3 = alpha_p3.value1.add_mod(&alpha_p1.value2, &p);

    let mut v_p1: Vec<ArithmeticECShare> = Vec::new();
    let mut v_p2: Vec<ArithmeticECShare> = Vec::new();
    let mut v_p3: Vec<ArithmeticECShare> = Vec::new();

    // Step 9 of protocol 3.6
    for i in 0..8 {
        let temp1_p1 = multiply_mod(open_alpha_p1, psi_p1[i]);
        let mut multx_p1 = store_mult_triples_p1[0][i].clone();

        let temp1_p2 = multiply_mod(open_alpha_p2, psi_p2[i]);
        let mut multx_p2 = store_mult_triples_p2[0][i].clone();

        let temp1_p3 = multiply_mod(open_alpha_p3, psi_p3[i]);
        let mut multx_p3 = store_mult_triples_p3[0][i].clone();

        multx_p1.value1 = multiply_mod(multx_p1.value1, temp1_p1);
        multx_p1.value2 = multiply_mod(multx_p1.value2, temp1_p1);
        let term1_p1 = add(zalpha_p1[i].clone(), multx_p1);
        let c_p1 = triples_p1[2][i].clone();

        multx_p2.value1 = multiply_mod(multx_p2.value1, temp1_p2);
        multx_p2.value2 = multiply_mod(multx_p2.value2, temp1_p2);
        let term1_p2 = add(zalpha_p2[i].clone(), multx_p2);
        let c_p2 = triples_p2[2][i].clone();

        multx_p3.value1 = multiply_mod(multx_p3.value1, temp1_p3);
        multx_p3.value2 = multiply_mod(multx_p3.value2, temp1_p3);
        let term1_p3 = add(zalpha_p3[i].clone(), multx_p3);
        let c_p3 = triples_p3[2][i].clone();

        let term2_p1 = subtract(term1_p1, c_p1);
        let term2_p2 = subtract(term1_p2, c_p2);
        let term2_p3 = subtract(term1_p3, c_p3);

        let term3_p1 = add(term2_p1, asigma_p1[i].clone());
        let term3_p2 = add(term2_p2, asigma_p2[i].clone());
        let term3_p3 = add(term2_p3, asigma_p3[i].clone());

        let mut term4_p1 = triples_p1[0][i].clone();
        term4_p1.value1 = multiply_mod(term4_p1.value1, psi_p1[i]);
        term4_p1.value2 = multiply_mod(term4_p1.value2, psi_p1[i]);

        let mut term4_p2 = triples_p2[0][i].clone();
        term4_p2.value1 = multiply_mod(term4_p2.value1, psi_p2[i]);
        term4_p2.value2 = multiply_mod(term4_p2.value2, psi_p2[i]);

        let mut term4_p3 = triples_p3[0][i].clone();
        term4_p3.value1 = multiply_mod(term4_p3.value1, psi_p3[i]);
        term4_p3.value2 = multiply_mod(term4_p3.value2, psi_p3[i]);

        let term5_p1 = add(term3_p1, term4_p1);
        let term5_p2 = add(term3_p2, term4_p2);
        let term5_p3 = add(term3_p3, term4_p3);

        let mut term6_p1 = gamma_p1[i].clone();
        term6_p1.value1 = multiply_mod(term6_p1.value1, psi_p1[i]);
        term6_p1.value2 = multiply_mod(term6_p1.value2, psi_p1[i]);

        let mut term6_p2 = gamma_p2[i].clone();
        term6_p2.value1 = multiply_mod(term6_p2.value1, psi_p2[i]);
        term6_p2.value2 = multiply_mod(term6_p2.value2, psi_p2[i]);

        let mut term6_p3 = gamma_p3[i].clone();
        term6_p3.value1 = multiply_mod(term6_p3.value1, psi_p3[i]);
        term6_p3.value2 = multiply_mod(term6_p3.value2, psi_p3[i]);

        let term7_p1 = add(term6_p1, ygamma_p1[i].clone());
        let term7_p2 = add(term6_p2, ygamma_p2[i].clone());
        let term7_p3 = add(term6_p3, ygamma_p3[i].clone());

        let temp_p1 = subtract(term5_p1, term7_p1);
        let temp_p2 = subtract(term5_p2, term7_p2);
        let temp_p3 = subtract(term5_p3, term7_p3);

        v_p1.push(temp_p1);
        v_p2.push(temp_p2);
        v_p3.push(temp_p3);
    }

    let mut random_elem_p1: Vec<U256> = Vec::new();
    let mut random_elem_p2: Vec<U256> = Vec::new();
    let mut random_elem_p3: Vec<U256> = Vec::new();

    for _ in 0..8 {
        // Generate shares of p
        let rand_p_p1 = generate_rand_ec_arith(randomness_p1);
        let rand_p_p2 = generate_rand_ec_arith(randomness_p2);
        let rand_p_p3 = generate_rand_ec_arith(randomness_p3);

        // Open p and store
        random_elem_p1.push(rand_p_p1.value1.add_mod(&rand_p_p2.value2, &p));
        random_elem_p2.push(rand_p_p2.value1.add_mod(&rand_p_p3.value2, &p));
        random_elem_p3.push(rand_p_p3.value1.add_mod(&rand_p_p1.value2, &p));
    }

    let mut share_v_p1: ArithmeticECShare = ArithmeticECShare {
        value1: U256::ZERO,
        value2: U256::ZERO,
    };
    let mut share_v_p2: ArithmeticECShare = ArithmeticECShare {
        value1: U256::ZERO,
        value2: U256::ZERO,
    };
    let mut share_v_p3: ArithmeticECShare = ArithmeticECShare {
        value1: U256::ZERO,
        value2: U256::ZERO,
    };

    for i in 0..8 {
        let mut temp_p1 = v_p1[i].clone();
        temp_p1.value1 = multiply_mod(temp_p1.value1, random_elem_p1[i]);
        temp_p1.value2 = multiply_mod(temp_p1.value2, random_elem_p1[i]);

        let mut temp_p2 = v_p2[i].clone();
        temp_p2.value1 = multiply_mod(temp_p2.value1, random_elem_p2[i]);
        temp_p2.value2 = multiply_mod(temp_p2.value2, random_elem_p2[i]);

        let mut temp_p3 = v_p3[i].clone();
        temp_p3.value1 = multiply_mod(temp_p3.value1, random_elem_p3[i]);
        temp_p3.value2 = multiply_mod(temp_p3.value2, random_elem_p3[i]);

        share_v_p1 = add(share_v_p1, temp_p1);
        share_v_p2 = add(share_v_p2, temp_p2);
        share_v_p3 = add(share_v_p3, temp_p3);
    }

    // Generate shares of r
    let r_p1 = generate_rand_ec_arith(randomness_p1);
    let r_p2 = generate_rand_ec_arith(randomness_p2);
    let r_p3 = generate_rand_ec_arith(randomness_p3);

    let (share_w1_p1, share_w1_p2, share_w1_p3) = multiply_ec(r_p1, share_v_p1);
    let (share_w2_p1, share_w2_p2, share_w2_p3) = multiply_ec(r_p2, share_v_p2);
    let (share_w3_p1, share_w3_p2, share_w3_p3) = multiply_ec(r_p3, share_v_p3);

    let w_p1 = add(add(share_w1_p1, share_w2_p1), share_w3_p1);
    let w_p2 = add(add(share_w1_p2, share_w2_p2), share_w3_p2);
    let w_p3 = add(add(share_w1_p3, share_w2_p3), share_w3_p3);

    // Open w
    let open_w_p1 = w_p1.value1.add_mod(&w_p2.value2, &p);
    let open_w_p2 = w_p2.value1.add_mod(&w_p3.value2, &p);
    let open_w_p3 = w_p3.value1.add_mod(&w_p1.value2, &p);

    assert!(open_w_p1 == U256::ZERO);
    assert!(open_w_p2 == U256::ZERO);
    assert!(open_w_p3 == U256::ZERO);
}

/// Test EC to A protocol
#[cfg(any(test, feature = "test-support"))]
async fn test_ec_to_a_protocol<T, R>(
    setup: T,
    seed: Seed,
    params: [ArithmeticECShare; 6],
    relay: R,
) -> Result<(usize, (ArithmeticECShare, ArithmeticECShare)), ProtocolError>
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

    let mut serverstate = ServerState::new(common_randomness);

    let mut store_mult_triples_p = Vec::new();
    let mult_a_p1: Vec<ArithmeticECShare> = Vec::new();
    let mult_b_p1: Vec<ArithmeticECShare> = Vec::new();
    let mult_c_p1: Vec<ArithmeticECShare> = Vec::new();
    store_mult_triples_p.push(mult_a_p1);
    store_mult_triples_p.push(mult_b_p1);
    store_mult_triples_p.push(mult_c_p1);

    let mut tag_offset_counter = TagOffsetCounter::new();

    let result = run_ec_to_a(
        &setup,
        &mut mpc_encryption,
        &mut tag_offset_counter,
        &mut relay,
        &params,
        &mut store_mult_triples_p,
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
    use crate::conversion::ec_to_a::test_ec_to_a_protocol;
    use crate::proto::{get_default_ec_share, reconstruct_ec_share};
    use crate::transport::test_utils::setup_mpc;
    use crate::types::ArithmeticECShare;
    use crypto_bigint::U256;
    use sl_mpc_mate::coord::{MessageRelayService, Relay, SimpleMessageRelay};
    use tokio::task::JoinSet;

    async fn sim<S, R>(
        coord: S,
        sim_params: &[[ArithmeticECShare; 6]; 3],
    ) -> Vec<(ArithmeticECShare, ArithmeticECShare)>
    where
        S: MessageRelayService<MessageRelay = R>,
        R: Relay + Send + 'static,
    {
        let parties = setup_mpc(None, sim_params);

        let mut jset = JoinSet::new();
        for (setup, seed, params) in parties {
            let relay = coord.connect().await.unwrap();

            jset.spawn(test_ec_to_a_protocol(setup, seed, params, relay));
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

    #[tokio::test(flavor = "multi_thread")]
    async fn test_ec_to_a_i() {
        // Sample A1
        let x1 = U256::from(5u8);
        let y1 = U256::from(10u8);

        // Sample A2
        let x2 = U256::from(10u8);
        let y2 = U256::from(40u8);

        // Sample A3
        let x3 = U256::from(20u8);
        let y3 = U256::from(30u8);

        let x1_p1 = get_default_ec_share(x1, 1);
        let x1_p2 = get_default_ec_share(x1, 2);
        let x1_p3 = get_default_ec_share(x1, 3);

        let y1_p1 = get_default_ec_share(y1, 1);
        let y1_p2 = get_default_ec_share(y1, 2);
        let y1_p3 = get_default_ec_share(y1, 3);

        let x2_p1 = get_default_ec_share(x2, 1);
        let x2_p2 = get_default_ec_share(x2, 2);
        let x2_p3 = get_default_ec_share(x2, 3);

        let y2_p1 = get_default_ec_share(y2, 1);
        let y2_p2 = get_default_ec_share(y2, 2);
        let y2_p3 = get_default_ec_share(y2, 3);

        let x3_p1 = get_default_ec_share(x3, 1);
        let x3_p2 = get_default_ec_share(x3, 2);
        let x3_p3 = get_default_ec_share(x3, 3);

        let y3_p1 = get_default_ec_share(y3, 1);
        let y3_p2 = get_default_ec_share(y3, 2);
        let y3_p3 = get_default_ec_share(y3, 3);

        let points_p1 = [x1_p1, x2_p1, x3_p1, y1_p1, y2_p1, y3_p1];
        let points_p2 = [x1_p2, x2_p2, x3_p2, y1_p2, y2_p2, y3_p2];
        let points_p3 = [x1_p3, x2_p3, x3_p3, y1_p3, y2_p3, y3_p3];

        let params = [points_p1, points_p2, points_p3];

        let results = sim(SimpleMessageRelay::new(), &params).await;
        assert_eq!(results.len(), 3);

        let res_p1 = results[0].clone();
        let res_p2 = results[1].clone();
        let res_p3 = results[2].clone();

        let out_x = reconstruct_ec_share(res_p1.0, res_p2.0, res_p3.0);
        let out_y = reconstruct_ec_share(res_p1.1, res_p2.1, res_p3.1);

        let required_x =
            U256::from_be_hex("0000000000000000000000000000000000000000000000000000000000004817");
        let required_y =
            U256::from_be_hex("000000000000000000000000000000000000000000000000000000000026417A");

        assert_eq!(required_x, out_x);
        assert_eq!(required_y, out_y);
    }
}
