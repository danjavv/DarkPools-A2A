use crate::constants::{FIELD_SIZE_BYTES, OPEN_TO_MSG};
use crate::mpc::common_randomness::CommonRandomness;
use crate::transport::proto::{FilteredMsgRelay, Wrap};
use crate::transport::setup::common::MPCEncryption;
use crate::transport::setup::CommonSetupMessage;
use crate::transport::types::ProtocolError;
use crate::transport::utils::{receive_from_parties, send_to_party, TagOffsetCounter};
use crate::types::{BinaryArithmeticShare, FieldElement};
use aead::rand_core::{CryptoRng, RngCore};
use crypto_bigint::Encoding;
use rand::Rng;
use sl_mpc_mate::coord::Relay;
use sl_mpc_mate::message::MessageTag;
use std::cmp::PartialEq;

#[derive(Clone, Debug, Copy, PartialEq)]
pub struct GaloisElement(pub(crate) [u8; FIELD_SIZE_BYTES]);

impl GaloisElement {
    /// ZERO GaloisElement
    pub const ZERO: GaloisElement = GaloisElement([0u8; FIELD_SIZE_BYTES]);

    pub fn add(self, other: &GaloisElement) -> GaloisElement {
        let mut res = self.0;
        #[allow(clippy::needless_range_loop)]
        for i in 0..FIELD_SIZE_BYTES {
            res[i] ^= other.0[i];
        }
        GaloisElement(res)
    }

    /// Multiplies `a` and `b` in the finite field of order 2^64
    /// modulo the irreducible polynomial f(x) = x^64 + x^4 + x^3 + x^2 + 1
    ///
    /// https://link.springer.com/book/10.1007/b97644
    /// multiplication part: Algorithm 2.34, "Right-to-left comb method for polynomial multiplication"
    /// reduction part: variant of the idea of Figure 2.9
    pub(crate) fn mul_gf(self, b_data: &GaloisElement) -> GaloisElement {
        const W: usize = 8;
        const T: usize = FIELD_SIZE_BYTES;

        let mut c = [0u8; T * 2];
        let mut b = [0u8; T + 1];

        let a = self.0;
        b[..T].copy_from_slice(&b_data.0);

        for k in 0..W {
            for j in 0..T {
                // let mask = if (a[j] >> k) & 0x01 == 1 { 0xFF } else { 0x00 };
                let mask = -(((a[j] >> k) & 0x01) as i8) as u8;
                for i in 0..T + 1 {
                    c[j + i] ^= b[i] & mask;
                }
            }

            for i in (1..=T).rev() {
                b[i] = (b[i] << 1) | (b[i - 1] >> 7);
            }
            b[0] <<= 1
        }

        for i in (T..=2 * T - 1).rev() {
            c[i - 8] ^= c[i];
            c[i - 8] ^= c[i] << 2;
            c[i - 7] ^= c[i] >> 6;
            c[i - 8] ^= c[i] << 3;
            c[i - 7] ^= c[i] >> 5;
            c[i - 8] ^= c[i] << 4;
            c[i - 7] ^= c[i] >> 4;
        }

        GaloisElement(c[..T].try_into().unwrap())
    }
}

#[derive(Clone, Debug, Copy)]
pub struct GaloisShare {
    pub(crate) value1: GaloisElement,
    pub(crate) value2: GaloisElement,
}

impl GaloisShare {
    /// ZERO GaloisShare
    pub const ZERO: GaloisShare = GaloisShare {
        value1: GaloisElement::ZERO,
        value2: GaloisElement::ZERO,
    };

    pub fn new(
        x1: GaloisElement,
        x2: GaloisElement,
        x3: GaloisElement,
        party_index: usize,
    ) -> Self {
        match party_index {
            0 => GaloisShare {
                value1: x3,
                value2: x1,
            },
            1 => GaloisShare {
                value1: x1,
                value2: x2,
            },
            _ => GaloisShare {
                value1: x2,
                value2: x3,
            },
        }
    }

    /// Returns random share
    pub fn galois_rand(common_randomness: &mut CommonRandomness) -> Self {
        let (value1, value2) = common_randomness.random_8_bytes();
        GaloisShare {
            value1: GaloisElement(value1),
            value2: GaloisElement(value2),
        }
    }

    /// Returns default party share for value
    pub fn from_constant(value: &FieldElement, party_index: usize) -> Self {
        let v: [u8; FIELD_SIZE_BYTES] = value.to_le_bytes();
        match party_index {
            0 => GaloisShare {
                value1: GaloisElement::ZERO,
                value2: GaloisElement(v),
            },
            1 => GaloisShare {
                value1: GaloisElement(v),
                value2: GaloisElement::ZERO,
            },
            _ => GaloisShare::ZERO,
        }
    }

    pub fn from_bit_arr(v: &BinaryArithmeticShare) -> Self {
        let mut value1 = v.value1;
        #[allow(clippy::needless_range_loop)]
        for i in 0..FIELD_SIZE_BYTES {
            value1[i] ^= v.value2[i];
        }
        GaloisShare {
            value1: GaloisElement(value1),
            value2: GaloisElement(v.value2),
        }
    }

    pub fn to_bit_arr(self) -> BinaryArithmeticShare {
        let mut value1 = self.value1.0;
        #[allow(clippy::needless_range_loop)]
        for i in 0..FIELD_SIZE_BYTES {
            value1[i] ^= self.value2.0[i];
        }
        BinaryArithmeticShare {
            value1,
            value2: self.value2.0,
        }
    }

    /// Add other GaloisShare to self and return new GaloisShare
    pub fn add_share(&self, &other: &GaloisShare) -> Self {
        GaloisShare {
            value1: self.value1.add(&other.value1),
            value2: self.value2.add(&other.value2),
        }
    }

    /// Multiply self by constant and return new GaloisShare
    pub fn mul_const(&self, c: &FieldElement) -> Self {
        let c: [u8; FIELD_SIZE_BYTES] = c.to_le_bytes();
        GaloisShare {
            value1: self.value1.mul_gf(&GaloisElement(c)),
            value2: self.value2.mul_gf(&GaloisElement(c)),
        }
    }

    /// calculate r value for multiplication
    pub fn mul_local(&self, &other: &GaloisShare) -> GaloisElement {
        let a = self.value1.mul_gf(&other.value1);
        let b = self.value1.mul_gf(&other.value2);
        let c = self.value2.mul_gf(&other.value1);
        a.add(&b).add(&c)
    }
}

/// Run InputGaloisFrom(x, P_i) protocol
pub async fn run_send_input_galois_from<T, R, G>(
    setup: &T,
    mpc_encryption: &mut MPCEncryption,
    open_tag: MessageTag,
    relay: &mut FilteredMsgRelay<R>,
    x: &GaloisElement,
    rng: &mut G,
) -> Result<GaloisShare, ProtocolError>
where
    T: CommonSetupMessage,
    R: Relay,
    G: CryptoRng + RngCore,
{
    let my_party_index = setup.participant_index();
    let prev_party_index = setup.prev_party_index();
    let next_party_index = setup.next_party_index();

    let x1: [u8; FIELD_SIZE_BYTES] = rng.gen();
    let x2: [u8; FIELD_SIZE_BYTES] = rng.gen();
    let x1 = GaloisElement(x1);
    let x2 = GaloisElement(x2);
    let x3 = x.add(&x1).add(&x2);

    let share_to_prev = GaloisShare::new(x1, x2, x3, prev_party_index);
    let share_to_next = GaloisShare::new(x1, x2, x3, next_party_index);

    // let tag_offset = tag_offset_counter.next_value();
    // let open_tag = MessageTag::tag1(OPEN_TO_MSG, tag_offset);

    // send to P_{i-1}
    send_to_party(
        setup,
        mpc_encryption,
        open_tag,
        share_to_prev,
        prev_party_index,
        relay,
    )
    .await?;

    // send to P_{i+1}
    send_to_party(
        setup,
        mpc_encryption,
        open_tag,
        share_to_next,
        next_party_index,
        relay,
    )
    .await?;

    let my_share = GaloisShare::new(x1, x2, x3, my_party_index);
    Ok(my_share)
}

/// Run InputGaloisFrom(x, P_i) protocol
pub async fn run_receive_input_galois_from<T, R>(
    setup: &T,
    mpc_encryption: &mut MPCEncryption,
    open_tag: MessageTag,
    check_tag: MessageTag,
    relay: &mut FilteredMsgRelay<R>,
    from_party_index: usize,
) -> Result<GaloisShare, ProtocolError>
where
    T: CommonSetupMessage,
    R: Relay,
{
    let my_party_index = setup.participant_index();
    assert_ne!(from_party_index, my_party_index);

    let prev_party_index = setup.prev_party_index();
    let next_party_index = setup.next_party_index();

    // party receives open_value from from_party_index
    let share_from_party: GaloisShare = receive_from_parties(
        setup,
        mpc_encryption,
        open_tag,
        GaloisShare::ZERO.external_size(),
        vec![from_party_index],
        relay,
    )
    .await?[0];

    if prev_party_index == from_party_index {
        // party receives open_value from next_party_index
        let check_value: Vec<GaloisElement> = receive_from_parties(
            setup,
            mpc_encryption,
            check_tag,
            GaloisElement::ZERO.external_size(),
            vec![next_party_index],
            relay,
        )
        .await?;

        if check_value[0] != share_from_party.value2 {
            return Err(ProtocolError::VerificationError);
        }
    } else {
        // send to prev party
        send_to_party(
            setup,
            mpc_encryption,
            check_tag,
            share_from_party.value1,
            prev_party_index,
            relay,
        )
        .await?;
    }

    Ok(share_from_party)
}

/// Run InputGaloisFrom all parties protocol
pub async fn run_input_galois_from_all<T, R, G>(
    setup: &T,
    mpc_encryption: &mut MPCEncryption,
    tag_offset_counter: &mut TagOffsetCounter,
    relay: &mut FilteredMsgRelay<R>,
    x: &GaloisElement,
    rng: &mut G,
) -> Result<(GaloisShare, GaloisShare, GaloisShare), ProtocolError>
where
    T: CommonSetupMessage,
    R: Relay,
    G: CryptoRng + RngCore,
{
    let my_party_index = setup.participant_index();
    let prev_party_index = setup.prev_party_index();
    let next_party_index = setup.next_party_index();

    let x1 = GaloisElement(rng.gen());
    let x2 = GaloisElement(rng.gen());
    let x3 = x.add(&x1).add(&x2);

    let my_share = GaloisShare::new(x1, x2, x3, my_party_index);
    let share_to_prev = GaloisShare::new(x1, x2, x3, prev_party_index);
    let share_to_next = GaloisShare::new(x1, x2, x3, next_party_index);

    let tag_offset = tag_offset_counter.next_value();
    let open_tag_1 = MessageTag::tag1(OPEN_TO_MSG, tag_offset);
    relay.ask_messages(setup, open_tag_1, true).await?;

    // send to P_{i-1}
    send_to_party(
        setup,
        mpc_encryption,
        open_tag_1,
        share_to_prev,
        prev_party_index,
        relay,
    )
    .await?;

    // send to P_{i+1}
    send_to_party(
        setup,
        mpc_encryption,
        open_tag_1,
        share_to_next,
        next_party_index,
        relay,
    )
    .await?;

    let share_from_parties: Vec<GaloisShare> = receive_from_parties(
        setup,
        mpc_encryption,
        open_tag_1,
        GaloisShare::ZERO.external_size(),
        vec![prev_party_index, next_party_index],
        relay,
    )
    .await?;
    let (share_from_prev, share_from_next) = match my_party_index {
        0 => (share_from_parties[1], share_from_parties[0]),
        1 => (share_from_parties[0], share_from_parties[1]),
        _ => (share_from_parties[1], share_from_parties[0]),
    };

    let tag_offset = tag_offset_counter.next_value();
    let open_tag_2 = MessageTag::tag1(OPEN_TO_MSG, tag_offset);
    relay.ask_messages(setup, open_tag_2, true).await?;

    // send to P_{i-1}
    send_to_party(
        setup,
        mpc_encryption,
        open_tag_2,
        share_from_next.value1,
        prev_party_index,
        relay,
    )
    .await?;

    // receive from P_{i+1}
    let share_from_parties: Vec<GaloisElement> = receive_from_parties(
        setup,
        mpc_encryption,
        open_tag_2,
        GaloisElement::ZERO.external_size(),
        vec![next_party_index],
        relay,
    )
    .await?;
    let check_from_next = share_from_parties[0];
    if check_from_next != share_from_prev.value2 {
        return Err(ProtocolError::VerificationError);
    }

    let (s0, s1, s2) = match my_party_index {
        0 => (my_share, share_from_next, share_from_prev),
        1 => (share_from_prev, my_share, share_from_next),
        _ => (share_from_next, share_from_prev, my_share),
    };

    Ok((s0, s1, s2))
}

/// Run batch InputGaloisFrom(x, P_i) protocol
pub async fn run_batch_send_input_galois_from<T, R, G>(
    setup: &T,
    mpc_encryption: &mut MPCEncryption,
    open_tag: MessageTag,
    relay: &mut FilteredMsgRelay<R>,
    x_values: &[GaloisElement],
    rng: &mut G,
) -> Result<Vec<GaloisShare>, ProtocolError>
where
    T: CommonSetupMessage,
    R: Relay,
    G: CryptoRng + RngCore,
{
    let my_party_index = setup.participant_index();
    let prev_party_index = setup.prev_party_index();
    let next_party_index = setup.next_party_index();

    let mut shares_to_prev = Vec::new();
    let mut shares_to_next = Vec::new();
    let mut my_shares = Vec::new();
    for x in x_values {
        let x1 = GaloisElement(rng.gen());
        let x2 = GaloisElement(rng.gen());
        let x3 = x.add(&x1).add(&x2);

        let share_to_prev = GaloisShare::new(x1, x2, x3, prev_party_index);
        let share_to_next = GaloisShare::new(x1, x2, x3, next_party_index);

        shares_to_prev.push(share_to_prev);
        shares_to_next.push(share_to_next);

        let my_share = GaloisShare::new(x1, x2, x3, my_party_index);
        my_shares.push(my_share);
    }

    // send to P_{i-1}
    send_to_party(
        setup,
        mpc_encryption,
        open_tag,
        shares_to_prev,
        prev_party_index,
        relay,
    )
    .await?;

    // send to P_{i+1}
    send_to_party(
        setup,
        mpc_encryption,
        open_tag,
        shares_to_next,
        next_party_index,
        relay,
    )
    .await?;

    Ok(my_shares)
}

/// Run batch InputGaloisFrom(x, P_i) protocol
pub async fn run_batch_receive_input_galois_from<T, R>(
    setup: &T,
    mpc_encryption: &mut MPCEncryption,
    open_tag: MessageTag,
    check_tag: MessageTag,
    relay: &mut FilteredMsgRelay<R>,
    from_party_index: usize,
    n: usize,
) -> Result<Vec<GaloisShare>, ProtocolError>
where
    T: CommonSetupMessage,
    R: Relay,
{
    let my_party_index = setup.participant_index();
    assert_ne!(from_party_index, my_party_index);

    let prev_party_index = setup.prev_party_index();
    let next_party_index = setup.next_party_index();

    // party receives open_value from from_party_index
    let t = vec![GaloisShare::ZERO; n];
    let shares_from_party: Vec<Vec<GaloisShare>> = receive_from_parties(
        setup,
        mpc_encryption,
        open_tag,
        t.external_size(),
        vec![from_party_index],
        relay,
    )
    .await?;
    let shares_from_party = shares_from_party[0].clone();

    if prev_party_index == from_party_index {
        // party receives open_value from next_party_index
        let check_values: Vec<Vec<GaloisElement>> = receive_from_parties(
            setup,
            mpc_encryption,
            check_tag,
            GaloisElement::ZERO.external_size() * n,
            vec![next_party_index],
            relay,
        )
        .await?;

        for (&check_value, share_from_party) in check_values[0].iter().zip(shares_from_party.iter())
        {
            if check_value != share_from_party.value2 {
                return Err(ProtocolError::VerificationError);
            }
        }
    } else {
        let check_values = shares_from_party
            .iter()
            .map(|s| s.value1)
            .collect::<Vec<_>>();
        // send to prev party
        send_to_party(
            setup,
            mpc_encryption,
            check_tag,
            check_values,
            prev_party_index,
            relay,
        )
        .await?;
    }

    Ok(shares_from_party)
}

/// Run OutputGalois protocol
pub async fn run_output_galois<T, R>(
    setup: &T,
    mpc_encryption: &mut MPCEncryption,
    tag_offset_counter: &mut TagOffsetCounter,
    relay: &mut FilteredMsgRelay<R>,
    share: &GaloisShare,
) -> Result<GaloisElement, ProtocolError>
where
    T: CommonSetupMessage,
    R: Relay,
{
    let prev_party_index = setup.prev_party_index();
    let next_party_index = setup.next_party_index();

    let open_tag = MessageTag::tag1(OPEN_TO_MSG, tag_offset_counter.next_value());
    relay.ask_messages(setup, open_tag, true).await?;

    // send value1 to P_{i+1}
    send_to_party(
        setup,
        mpc_encryption,
        open_tag,
        share.value1,
        next_party_index,
        relay,
    )
    .await?;
    // send value2 to P_{i-1}
    send_to_party(
        setup,
        mpc_encryption,
        open_tag,
        share.value2,
        prev_party_index,
        relay,
    )
    .await?;

    // party receives values from P_{i-1} and P_{i+1}
    let values: Vec<GaloisElement> = receive_from_parties(
        setup,
        mpc_encryption,
        open_tag,
        GaloisElement::ZERO.external_size(),
        vec![prev_party_index, next_party_index],
        relay,
    )
    .await?;

    if values[0] != values[1] {
        return Err(ProtocolError::VerificationError);
    }

    let x = share.value1.add(&share.value2).add(&values[0]);

    Ok(x)
}

/// Run send OutputGaloisTo protocol
pub async fn run_send_output_galois_to<T, R>(
    setup: &T,
    mpc_encryption: &mut MPCEncryption,
    open_tag: MessageTag,
    relay: &mut FilteredMsgRelay<R>,
    share: GaloisShare,
    to_party_index: usize,
) -> Result<(), ProtocolError>
where
    T: CommonSetupMessage,
    R: Relay,
{
    let my_party_index = setup.participant_index();
    assert_ne!(my_party_index, to_party_index);

    let next_party_index = setup.next_party_index();
    let value_to_send = if to_party_index == next_party_index {
        share.value1
    } else {
        share.value2
    };
    send_to_party(
        setup,
        mpc_encryption,
        open_tag,
        value_to_send,
        to_party_index,
        relay,
    )
    .await?;

    Ok(())
}

/// Run receive OutputGaloisTo protocol
pub async fn run_receive_output_galois_to<T, R>(
    setup: &T,
    mpc_encryption: &mut MPCEncryption,
    open_tag: MessageTag,
    relay: &mut FilteredMsgRelay<R>,
    share: GaloisShare,
) -> Result<GaloisElement, ProtocolError>
where
    T: CommonSetupMessage,
    R: Relay,
{
    let prev_party_index = setup.prev_party_index();
    let next_party_index = setup.next_party_index();

    // party receives values from P_{i-1} and P_{i+1}
    let values: Vec<GaloisElement> = receive_from_parties(
        setup,
        mpc_encryption,
        open_tag,
        GaloisElement::ZERO.external_size(),
        vec![prev_party_index, next_party_index],
        relay,
    )
    .await?;

    if values[0] != values[1] {
        return Err(ProtocolError::VerificationError);
    }

    let x = share.value1.add(&share.value2).add(&values[0]);

    Ok(x)
}

/// Run Galois Multiplication with Error protocol
pub async fn run_galois_multiplication_with_error<T, R, G>(
    setup: &T,
    mpc_encryption: &mut MPCEncryption,
    tag_offset_counter: &mut TagOffsetCounter,
    relay: &mut FilteredMsgRelay<R>,
    x: &GaloisShare,
    y: &GaloisShare,
    rng: &mut G,
) -> Result<GaloisShare, ProtocolError>
where
    T: CommonSetupMessage,
    R: Relay,
    G: CryptoRng + RngCore,
{
    let r = x.mul_local(y);
    let (s0, s1, s2) =
        run_input_galois_from_all(setup, mpc_encryption, tag_offset_counter, relay, &r, rng)
            .await?;
    Ok(s0.add_share(&s1).add_share(&s2))
}

/// Run map Galois Multiplication with Error protocol
pub async fn run_map_galois_multiplication_with_error<T, R, G>(
    setup: &T,
    mpc_encryption: &mut MPCEncryption,
    tag_offset_counter: &mut TagOffsetCounter,
    relay: &mut FilteredMsgRelay<R>,
    x_values: &[GaloisShare],
    y: &GaloisShare,
    rng: &mut G,
) -> Result<Vec<GaloisShare>, ProtocolError>
where
    T: CommonSetupMessage,
    R: Relay,
    G: CryptoRng + RngCore,
{
    let my_party_index = setup.participant_index();
    let prev_party_index = setup.prev_party_index();
    let next_party_index = setup.next_party_index();

    let r_values: Vec<GaloisElement> = x_values.iter().map(|x| x.mul_local(y)).collect();

    let open_tag_from_0 = MessageTag::tag1(OPEN_TO_MSG, tag_offset_counter.next_value());
    let open_tag_from_1 = MessageTag::tag1(OPEN_TO_MSG, tag_offset_counter.next_value());
    let open_tag_from_2 = MessageTag::tag1(OPEN_TO_MSG, tag_offset_counter.next_value());
    relay.ask_messages(setup, open_tag_from_0, true).await?;
    relay.ask_messages(setup, open_tag_from_1, true).await?;
    relay.ask_messages(setup, open_tag_from_2, true).await?;

    let check_tag = MessageTag::tag1(OPEN_TO_MSG, tag_offset_counter.next_value());
    relay.ask_messages(setup, check_tag, true).await?;

    let (prev_open_tag, my_open_tag, next_open_tag) = match my_party_index {
        0 => (open_tag_from_2, open_tag_from_0, open_tag_from_1),
        1 => (open_tag_from_0, open_tag_from_1, open_tag_from_2),
        _ => (open_tag_from_1, open_tag_from_2, open_tag_from_0),
    };

    let my_shares =
        run_batch_send_input_galois_from(setup, mpc_encryption, my_open_tag, relay, &r_values, rng)
            .await?;

    let next_shares = run_batch_receive_input_galois_from(
        setup,
        mpc_encryption,
        next_open_tag,
        check_tag,
        relay,
        next_party_index,
        my_shares.len(),
    )
    .await?;

    let prev_shares = run_batch_receive_input_galois_from(
        setup,
        mpc_encryption,
        prev_open_tag,
        check_tag,
        relay,
        prev_party_index,
        my_shares.len(),
    )
    .await?;

    let z_shares: Vec<GaloisShare> = my_shares
        .iter()
        .zip(prev_shares.iter())
        .zip(next_shares.iter())
        .map(|((my_share, prev_share), next_share)| {
            my_share.add_share(prev_share).add_share(next_share)
        })
        .collect();

    Ok(z_shares)
}

/// Run Galois Inner Product with Error protocol
pub async fn run_galois_inner_product_with_error<T, R, G>(
    setup: &T,
    mpc_encryption: &mut MPCEncryption,
    tag_offset_counter: &mut TagOffsetCounter,
    relay: &mut FilteredMsgRelay<R>,
    x_values: &[GaloisShare],
    y_values: &[GaloisShare],
    rng: &mut G,
) -> Result<GaloisShare, ProtocolError>
where
    T: CommonSetupMessage,
    R: Relay,
    G: CryptoRng + RngCore,
{
    assert_eq!(x_values.len(), y_values.len());

    let mut r_acc = GaloisElement::ZERO;
    for i in 0..x_values.len() {
        let r = x_values[i].mul_local(&y_values[i]);
        r_acc = r_acc.add(&r);
    }

    let (s0, s1, s2) = run_input_galois_from_all(
        setup,
        mpc_encryption,
        tag_offset_counter,
        relay,
        &r_acc,
        rng,
    )
    .await?;

    Ok(s0.add_share(&s1).add_share(&s2))
}

#[cfg(test)]
mod tests {
    use crate::galois_abb::GaloisElement;

    // Test based on fermat's little theorem
    #[test]
    fn test_mul_64() {
        for _ in 0..10 {
            let rand_num = GaloisElement(rand::random::<[u8; 8]>());
            let mut temp = rand_num.clone();

            for _ in 0..64 {
                temp = temp.mul_gf(&temp);
            }

            assert_eq!(temp, rand_num);
        }
    }
}
