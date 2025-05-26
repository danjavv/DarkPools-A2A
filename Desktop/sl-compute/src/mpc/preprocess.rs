use crate::constants::{B, C, L, M, N, OPEN_MSG, VERIFY_ARRAY_OF_BITS_MSG, X};
use crate::mpc::multiply_binary_shares::run_and_with_error;
use crate::mpc::open_protocol::{run_open_for_gen_triples, run_output_without_verification};
use crate::transport::proto::FilteredMsgRelay;
use crate::transport::setup::common::MPCEncryption;
use crate::transport::setup::CommonSetupMessage;
use crate::transport::types::ProtocolError;
use crate::transport::types::ProtocolError::VerificationError;
use crate::transport::utils::{p2p_send_to_next_receive_from_prev, TagOffsetCounter};
use crate::types::{BinaryString, BinaryStringShare, ServerState};
use aead::rand_core::{CryptoRng, RngCore, SeedableRng};
use crypto_bigint::subtle::ConstantTimeEq;
use rand::Rng;
use rand_chacha::ChaCha20Rng;
use sha2::{Digest, Sha256};
use sl_mpc_mate::coord::Relay;
use sl_mpc_mate::message::MessageTag;

/// Seed for our RNG
pub type Seed = <ChaCha20Rng as SeedableRng>::Seed;

/// Implementation of VerifyArrayOfBits Protocol 2.4.4
pub async fn run_verify_array_of_bits<T, R>(
    setup: &T,
    mpc_encryption: &mut MPCEncryption,
    tag_offset_counter: &mut TagOffsetCounter,
    relay: &mut FilteredMsgRelay<R>,
    x: &BinaryString,
) -> Result<(), ProtocolError>
where
    T: CommonSetupMessage,
    R: Relay,
{
    let tag_offset = tag_offset_counter.next_value();
    relay
        .ask_messages(
            setup,
            MessageTag::tag1(VERIFY_ARRAY_OF_BITS_MSG, tag_offset),
            true,
        )
        .await?;

    let mut hasher = Sha256::new();
    hasher.update(&x.value);
    let y: [u8; 32] = hasher.finalize().into();

    let y_from_prev = p2p_send_to_next_receive_from_prev(
        setup,
        mpc_encryption,
        MessageTag::tag1(VERIFY_ARRAY_OF_BITS_MSG, tag_offset),
        y,
        relay,
    )
    .await?;

    if y.ct_ne(&y_from_prev).into() {
        return Err(VerificationError);
    }

    Ok(())
}

/// Implementation of Coin(s) Protocol 2.6.1.
pub async fn run_coin<T, R>(
    setup: &T,
    mpc_encryption: &mut MPCEncryption,
    tag_offset_counter: &mut TagOffsetCounter,
    relay: &mut FilteredMsgRelay<R>,
    s: usize,
    serverstate: &mut ServerState,
) -> Result<BinaryString, ProtocolError>
where
    T: CommonSetupMessage,
    R: Relay,
{
    let random_bits = serverstate.common_randomness.random_binary_string_share(s);

    let output_values = run_output_without_verification(
        setup,
        mpc_encryption,
        tag_offset_counter,
        relay,
        random_bits,
    )
    .await?;

    run_verify_array_of_bits(
        setup,
        mpc_encryption,
        tag_offset_counter,
        relay,
        &output_values,
    )
    .await?;

    Ok(output_values)
}

/// Implementation of Perm Protocol 2.6.2.
pub fn permute_indexes<const N: usize, R>(mut d: [usize; N], rng: &mut R) -> [usize; N]
where
    R: CryptoRng + RngCore,
{
    let m = d.len();
    for j in 0..m {
        let index = rng.gen_range(j..m);
        d.swap(j, index);
    }
    d
}

/// Implementation of GeneratingValidTriples Protocol 2.6.3.
/// Generates N mult triples
/// 8 messages
pub async fn run_gen_valid_triples<T, R>(
    setup: &T,
    mpc_encryption: &mut MPCEncryption,
    tag_offset_counter: &mut TagOffsetCounter,
    relay: &mut FilteredMsgRelay<R>,
    serverstate: &mut ServerState,
) -> Result<(BinaryStringShare, BinaryStringShare, BinaryStringShare), ProtocolError>
where
    T: CommonSetupMessage,
    R: Relay,
{
    let a = serverstate.common_randomness.random_binary_string_share(M);
    let b = serverstate.common_randomness.random_binary_string_share(M);
    let c = run_and_with_error(
        setup,
        mpc_encryption,
        tag_offset_counter,
        relay,
        &a,
        &b,
        serverstate,
    )
    .await?;

    // TODO 3 messages can combine into 2 messages
    // 3.(a)
    let pre_seed = run_coin(
        setup,
        mpc_encryption,
        tag_offset_counter,
        relay,
        256,
        serverstate,
    )
    .await?;
    let seed = pre_seed.value.try_into().unwrap();
    let mut rng = ChaCha20Rng::from_seed(seed);

    // 3.(d) Parties run Perm(D_{k,j}) for each k = 2,...,B and j = 1,...,L
    let array_x: [usize; X] = core::array::from_fn(|i| i);
    let array_l: [usize; L] = core::array::from_fn(|i| i);
    let mut permute_sub_sub_arrays: Vec<[usize; X]> = Vec::with_capacity(L * (B - 1));
    for _ in 0..(B - 1) {
        for _ in 0..L {
            permute_sub_sub_arrays.push(permute_indexes(array_x, &mut rng));
        }
    }

    // 3.(e) Parties run Perm(L_{k,j}) for each k = 2,...,B
    let mut permute_sub_arrays: Vec<[usize; L]> = Vec::with_capacity(B - 1);
    for _ in 0..(B - 1) {
        permute_sub_arrays.push(permute_indexes(array_l, &mut rng));
    }

    // 3.(f) for each k = 2,...,B and j = 1,...,L
    // parties run triple verification with opening
    // for each of the first C triples in D_{k.j}
    let mut a_to_open = BinaryStringShare::with_capacity(C * L * (B - 1));
    let mut b_to_open = BinaryStringShare::with_capacity(C * L * (B - 1));
    let mut c_to_open = BinaryStringShare::with_capacity(C * L * (B - 1));
    for k in 0..(B - 1) {
        // j in Perm(0..L)
        for j in permute_sub_arrays[k] {
            let offset = (k + 1) * N + k * L * C + X * j;
            for i in 0..C {
                let sub_sub_index = permute_sub_sub_arrays[k * j][i];
                let index = offset + sub_sub_index;
                a_to_open.push_binary_share(a.get_binary_share(index));
                b_to_open.push_binary_share(b.get_binary_share(index));
                c_to_open.push_binary_share(c.get_binary_share(index));
            }
        }
    }
    // 2 messages
    run_triple_verification_with_opening(
        setup,
        mpc_encryption,
        tag_offset_counter,
        relay,
        &a_to_open,
        &b_to_open,
        &c_to_open,
        serverstate,
    )
    .await?;

    let (a1, a) = a.split(N);
    let (b1, b) = b.split(N);
    let (c1, c) = c.split(N);

    // we set B = 2 so this loop only runs once
    for k in 0..(B - 1) {
        let mut a_k = BinaryStringShare::with_capacity(N);
        let mut b_k = BinaryStringShare::with_capacity(N);
        let mut c_k = BinaryStringShare::with_capacity(N);
        // j in Perm(0..L)
        for j in permute_sub_arrays[k] {
            let offset = k * (N + L * C) + X * j;
            for i in C..X {
                let sub_sub_index = permute_sub_sub_arrays[k * j][i];
                let index = offset + sub_sub_index;
                a_k.push_binary_share(a.get_binary_share(index));
                b_k.push_binary_share(b.get_binary_share(index));
                c_k.push_binary_share(c.get_binary_share(index));
            }
        }

        // 3 messages
        run_triple_verification_without_opening(
            setup,
            mpc_encryption,
            tag_offset_counter,
            relay,
            &a1,
            &b1,
            &c1,
            &a_k,
            &b_k,
            &c_k,
            serverstate,
        )
        .await?;
    }

    Ok((a1, b1, c1))
}

/// Implementation of TripleVerificationWithOpening Protocol 2.6.4.
pub async fn run_triple_verification_with_opening<T, R>(
    setup: &T,
    mpc_encryption: &mut MPCEncryption,
    tag_offset_counter: &mut TagOffsetCounter,
    relay: &mut FilteredMsgRelay<R>,
    x: &BinaryStringShare,
    y: &BinaryStringShare,
    z: &BinaryStringShare,
    serverstate: &mut ServerState,
) -> Result<(), ProtocolError>
where
    T: CommonSetupMessage,
    R: Relay,
{
    let l = x.length as usize;
    assert_eq!(l % 8, 0);
    assert_eq!(y.length as usize, l);
    assert_eq!(z.length as usize, l);

    let mut c = x.clone();
    c.append(y);
    c.append(z);
    let res = run_open_for_gen_triples(
        setup,
        mpc_encryption,
        tag_offset_counter,
        relay,
        &c,
        serverstate,
    )
    .await?;
    let (x_open, y_open) = res.split(l);
    let (y_open, z_open) = y_open.split(l);

    if z_open != x_open.and(&y_open) {
        return Err(VerificationError);
    }
    Ok(())
}

fn h_function(l: u64, value: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(l.to_le_bytes());
    hasher.update(value);
    hasher.finalize().into()
}

/// Implementation of TripleVerificationWithoutOpening Protocol 2.6.5.
pub async fn run_triple_verification_without_opening<T, R>(
    setup: &T,
    mpc_encryption: &mut MPCEncryption,
    tag_offset_counter: &mut TagOffsetCounter,
    relay: &mut FilteredMsgRelay<R>,
    x: &BinaryStringShare,
    y: &BinaryStringShare,
    z: &BinaryStringShare,
    a: &BinaryStringShare,
    b: &BinaryStringShare,
    c: &BinaryStringShare,
    serverstate: &mut ServerState,
) -> Result<(), ProtocolError>
where
    T: CommonSetupMessage,
    R: Relay,
{
    let l = x.length as usize;
    assert_eq!(l % 8, 0);
    assert_eq!(y.length as usize, l);
    assert_eq!(z.length as usize, l);
    assert_eq!(a.length as usize, l);
    assert_eq!(b.length as usize, l);
    assert_eq!(c.length as usize, l);

    let tag_offset = tag_offset_counter.next_value();
    relay
        .ask_messages(setup, MessageTag::tag1(OPEN_MSG, tag_offset), true)
        .await?;

    let mut rho = a.xor(x);
    let sigma = b.xor(y);

    rho.append(&sigma);
    let res = run_open_for_gen_triples(
        setup,
        mpc_encryption,
        tag_offset_counter,
        relay,
        &rho,
        serverstate,
    )
    .await?;

    let (rho_open, sigma_open) = res.split(l);

    let mut share = c.xor(z);
    share = share.xor(&x.and_scalar(&sigma_open));
    share = share.xor(&y.and_scalar(&rho_open));
    share = share.xor_scalar(&rho_open.and(&sigma_open));

    let tau = h_function(share.length, &share.value1);
    let gamma = h_function(share.length, &share.value2);

    let tau_from_prev = p2p_send_to_next_receive_from_prev(
        setup,
        mpc_encryption,
        MessageTag::tag1(OPEN_MSG, tag_offset),
        tau,
        relay,
    )
    .await?;

    if tau_from_prev != gamma {
        return Err(VerificationError);
    }
    Ok(())
}

/// Implementation of BatchVerificationWithoutOpening Protocol 2.6.6.
pub async fn run_batch_verification_without_opening<T, R>(
    setup: &T,
    mpc_encryption: &mut MPCEncryption,
    tag_offset_counter: &mut TagOffsetCounter,
    relay: &mut FilteredMsgRelay<R>,
    x: &BinaryStringShare,
    y: &BinaryStringShare,
    z: &BinaryStringShare,
    serverstate: &mut ServerState,
) -> Result<(), ProtocolError>
where
    T: CommonSetupMessage,
    R: Relay,
{
    // expect the length to be a multiple of 8
    let l = x.length as usize;
    assert_eq!(l % 8, 0);
    assert_eq!(y.length as usize, l);
    assert_eq!(z.length as usize, l);

    if l > N {
        let mut v_a = BinaryStringShare::new();
        let mut v_b = BinaryStringShare::new();
        let mut v_c = BinaryStringShare::new();

        let count = l.div_ceil(N);
        for _ in 0..count {
            let (a, b, c) = run_gen_valid_triples(
                setup,
                mpc_encryption,
                tag_offset_counter,
                relay,
                serverstate,
            )
            .await?;

            v_a.append(&a);
            v_b.append(&b);
            v_c.append(&c);
        }

        let (v_a, _) = v_a.split(l);
        let (v_b, _) = v_b.split(l);
        let (v_c, _) = v_c.split(l);

        run_triple_verification_without_opening(
            setup,
            mpc_encryption,
            tag_offset_counter,
            relay,
            x,
            y,
            z,
            &v_a,
            &v_b,
            &v_c,
            serverstate,
        )
        .await?;
    } else {
        // Step 1
        if serverstate.ver.0.length == 0 {
            // create ver and rep
            serverstate.ver = run_gen_valid_triples(
                setup,
                mpc_encryption,
                tag_offset_counter,
                relay,
                serverstate,
            )
            .await?;

            serverstate.rep = run_gen_valid_triples(
                setup,
                mpc_encryption,
                tag_offset_counter,
                relay,
                serverstate,
            )
            .await?;
        }

        // // Step 2
        // // parties call Coin(/kappa)
        // // 2 messages
        // // TODO precompute common seed for RNG
        // let pre_seed = run_coin(
        //     setup,
        //     mpc_encryption,
        //     tag_offset_counter,
        //     relay,
        //     256,
        //     serverstate,
        // ).await?;
        // let seed = pre_seed.value.try_into().unwrap();
        // let mut rng = ChaCha20Rng::from_seed(seed);

        let (v_a, mut new_ver_a) = serverstate.ver.0.split(l);
        let (v_b, mut new_ver_b) = serverstate.ver.1.split(l);
        let (v_c, mut new_ver_c) = serverstate.ver.2.split(l);

        let len_rep = serverstate.rep.0.length as usize;
        if len_rep < l {
            let append_len = l - len_rep;
            new_ver_a.append(&serverstate.rep.0);
            new_ver_b.append(&serverstate.rep.1);
            new_ver_c.append(&serverstate.rep.2);

            // 8 messages
            serverstate.rep = run_gen_valid_triples(
                setup,
                mpc_encryption,
                tag_offset_counter,
                relay,
                serverstate,
            )
            .await?;

            let (r_a, new_rep_a) = serverstate.rep.0.split(append_len);
            let (r_b, new_rep_b) = serverstate.rep.1.split(append_len);
            let (r_c, new_rep_c) = serverstate.rep.2.split(append_len);

            new_ver_a.append(&r_a);
            new_ver_b.append(&r_b);
            new_ver_c.append(&r_c);

            serverstate.ver = (new_ver_a, new_ver_b, new_ver_c);
            serverstate.rep = (new_rep_a, new_rep_b, new_rep_c);
        } else {
            let (r_a, new_rep_a) = serverstate.rep.0.split(l);
            let (r_b, new_rep_b) = serverstate.rep.1.split(l);
            let (r_c, new_rep_c) = serverstate.rep.2.split(l);

            new_ver_a.append(&r_a);
            new_ver_b.append(&r_b);
            new_ver_c.append(&r_c);

            serverstate.ver = (new_ver_a, new_ver_b, new_ver_c);
            serverstate.rep = (new_rep_a, new_rep_b, new_rep_c);
        }

        // Step 3 - Batch Verification
        // 3 messages
        run_triple_verification_without_opening(
            setup,
            mpc_encryption,
            tag_offset_counter,
            relay,
            x,
            y,
            z,
            &v_a,
            &v_b,
            &v_c,
            serverstate,
        )
        .await?;
    }

    Ok(())
}
