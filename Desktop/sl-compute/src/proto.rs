use crate::types::{BinaryArithmeticShare, ByteShare};
use crate::{
    constants::{EC_FIELD_SIZE, FIELD_SIZE},
    types::{
        ArithmeticECShare, ArithmeticShare, BinaryShare, BinaryString, BinaryStringShare,
        DecimalShare, FieldElement,
    },
    utility::helper::get_modulus,
};
use crypto_bigint::{Encoding, U256};
use encoding_rs::ISO_8859_10;
use rust_decimal::Decimal;

pub fn convert_arith_to_bin(l: usize, input: &FieldElement) -> BinaryString {
    assert_eq!(l, FIELD_SIZE);
    BinaryString {
        length: FIELD_SIZE as u64,
        value: input.to_le_bytes().to_vec(),
    }
}

pub fn convert_bin_to_arith(input: BinaryString) -> FieldElement {
    assert_eq!(input.length, FIELD_SIZE as u64);
    FieldElement::from_le_slice(&input.value)
}

pub fn convert_u256_to_bin(input: U256) -> BinaryString {
    BinaryString {
        length: EC_FIELD_SIZE as u64,
        value: input.to_le_bytes().to_vec(),
    }
}

pub fn convert_bin_to_u256(input: BinaryString) -> U256 {
    assert_eq!(input.length as usize, EC_FIELD_SIZE);
    U256::from_le_slice(&input.value)
}

pub fn reconstruct_binary_string_share(
    share_p1: &BinaryStringShare,
    share_p2: &BinaryStringShare,
    share_p3: &BinaryStringShare,
) -> BinaryString {
    let len = share_p1.length as usize;
    let mut output: BinaryString = BinaryString::with_capacity(len);
    for i in 0..len {
        output.push(reconstruct_binary_share(
            share_p1.get_binary_share(i),
            share_p2.get_binary_share(i),
            share_p3.get_binary_share(i),
        ));
    }

    output
}

pub fn reconstruct_binary_arith_share(
    share_p1: &BinaryArithmeticShare,
    share_p2: &BinaryArithmeticShare,
    share_p3: &BinaryArithmeticShare,
) -> BinaryString {
    let share_p1 = share_p1.to_binary_string_share();
    let share_p2 = share_p2.to_binary_string_share();
    let share_p3 = share_p3.to_binary_string_share();

    let len = share_p1.length as usize;
    let mut output: BinaryString = BinaryString::with_capacity(len);
    for i in 0..len {
        output.push(reconstruct_binary_share(
            share_p1.get_binary_share(i),
            share_p2.get_binary_share(i),
            share_p3.get_binary_share(i),
        ));
    }

    output
}

pub fn reconstruct_binary_string_share_to_string(
    share_p1: Vec<BinaryStringShare>,
    share_p2: Vec<BinaryStringShare>,
    share_p3: Vec<BinaryStringShare>,
) -> String {
    let mut output = "".to_string();
    for j in 0..share_p1.len() {
        let mut out: BinaryString = BinaryString::with_capacity(8);
        for i in 0..8 {
            assert!(
                share_p1[j].get_binary_share(i).value1 ^ share_p2[j].get_binary_share(i).value1
                    == share_p3[j].get_binary_share(i).value1
            );
            assert!(
                share_p1[j].get_binary_share(i).value2 ^ share_p3[j].get_binary_share(i).value2
                    == share_p1[j].get_binary_share(i).value1
            );
            assert!(
                share_p2[j].get_binary_share(i).value2 ^ share_p1[j].get_binary_share(i).value2
                    == share_p2[j].get_binary_share(i).value1
            );
            assert!(
                share_p3[j].get_binary_share(i).value2 ^ share_p2[j].get_binary_share(i).value2
                    == share_p3[j].get_binary_share(i).value1
            );
            let temp =
                share_p1[j].get_binary_share(i).value2 ^ share_p3[j].get_binary_share(i).value1;
            out.push(temp);
        }
        output += &binary_string_to_char(out).unwrap().to_string();
    }
    output
}

pub fn reconstruct_byte_share_to_string(
    share_p1: Vec<ByteShare>,
    share_p2: Vec<ByteShare>,
    share_p3: Vec<ByteShare>,
) -> String {
    let mut output = "".to_string();
    for j in 0..share_p1.len() {
        let mut out: BinaryString = BinaryString::with_capacity(8);
        for i in 0..8 {
            assert!(
                share_p1[j].get_binary_share(i).value1 ^ share_p2[j].get_binary_share(i).value1
                    == share_p3[j].get_binary_share(i).value1
            );
            assert!(
                share_p1[j].get_binary_share(i).value2 ^ share_p3[j].get_binary_share(i).value2
                    == share_p1[j].get_binary_share(i).value1
            );
            assert!(
                share_p2[j].get_binary_share(i).value2 ^ share_p1[j].get_binary_share(i).value2
                    == share_p2[j].get_binary_share(i).value1
            );
            assert!(
                share_p3[j].get_binary_share(i).value2 ^ share_p2[j].get_binary_share(i).value2
                    == share_p3[j].get_binary_share(i).value1
            );
            let temp =
                share_p1[j].get_binary_share(i).value2 ^ share_p3[j].get_binary_share(i).value1;
            out.push(temp);
        }
        output += &binary_string_to_char(out).unwrap().to_string();
    }
    output
}

pub fn reconstruct_arith(
    share_p1: ArithmeticShare,
    _share_p2: ArithmeticShare,
    share_p3: ArithmeticShare,
) -> FieldElement {
    share_p1.reconstruct(&share_p3.open_value1())
}

pub fn test_run_reconstruct_arith(
    share_p1: ArithmeticShare,
    share_p2: ArithmeticShare,
    share_p3: ArithmeticShare,
) -> (FieldElement, FieldElement, FieldElement) {
    let output_p1 = share_p1.reconstruct(&share_p3.open_value1());
    let output_p2 = share_p2.reconstruct(&share_p1.open_value1());
    let output_p3 = share_p3.reconstruct(&share_p2.open_value1());

    assert_eq!(output_p1, output_p2);
    assert_eq!(output_p1, output_p3);

    (output_p1, output_p2, output_p3)
}

pub fn reconstruct_arith_to_float(
    share_p1: ArithmeticShare,
    _share_p2: ArithmeticShare,
    share_p3: ArithmeticShare,
) -> f64 {
    let (_, result) = share_p1.reconstruct_to_float(&share_p3.open_value1());
    result
}

pub fn test_run_reconstruct_arith_to_float(
    share_p1: ArithmeticShare,
    share_p2: ArithmeticShare,
    share_p3: ArithmeticShare,
) -> (f64, f64, f64) {
    let (_, result_p1) = share_p1.reconstruct_to_float(&share_p3.open_value1());
    let (_, result_p2) = share_p2.reconstruct_to_float(&share_p1.open_value1());
    let (_, result_p3) = share_p3.reconstruct_to_float(&share_p2.open_value1());

    assert_eq!(result_p1, result_p2);
    assert_eq!(result_p1, result_p3);

    (result_p1, result_p2, result_p3)
}

/// TODO rewrite this
pub fn reconstruct_decimal(
    share_p1: DecimalShare,
    _share_p2: DecimalShare,
    share_p3: DecimalShare,
) -> Decimal {
    let (bin_out_p1, result_p1) = share_p1.reconstruct_to_decimal(&share_p3.open_value1());
    result_p1
}

pub fn reconstruct_bin_string_share_to_byte(
    share_p1: BinaryStringShare,
    share_p2: BinaryStringShare,
    share_p3: BinaryStringShare,
) -> u8 {
    let mut out = [false; 8];
    for (i, out_i) in out.iter_mut().enumerate() {
        assert!(
            share_p1.get_binary_share(i).value1 ^ share_p2.get_binary_share(i).value1
                == share_p3.get_binary_share(i).value1
        );
        assert!(
            share_p1.get_binary_share(i).value2 ^ share_p3.get_binary_share(i).value2
                == share_p1.get_binary_share(i).value1
        );
        assert!(
            share_p2.get_binary_share(i).value2 ^ share_p1.get_binary_share(i).value2
                == share_p2.get_binary_share(i).value1
        );
        assert!(
            share_p3.get_binary_share(i).value2 ^ share_p2.get_binary_share(i).value2
                == share_p3.get_binary_share(i).value1
        );
        *out_i = share_p1.get_binary_share(i).value2 ^ share_p3.get_binary_share(i).value1;
    }
    let mut value = 0u8;

    for (i, &bit) in out.iter().enumerate() {
        if bit {
            value |= 1 << (7 - i);
        }
    }
    value
}

// TODO refactor it
pub fn test_run_reconstruct_bin_string_share_to_byte(
    share_p1: BinaryStringShare,
    share_p2: BinaryStringShare,
    share_p3: BinaryStringShare,
) -> (u8, u8, u8) {
    let mut out_p1 = [false; 8];
    let mut out_p2 = [false; 8];
    let mut out_p3 = [false; 8];
    for i in 0..8 {
        out_p1[i] = share_p1.get_binary_share(i).value2 ^ share_p3.get_binary_share(i).value1;
        out_p2[i] = share_p2.get_binary_share(i).value2 ^ share_p1.get_binary_share(i).value1;
        out_p3[i] = share_p3.get_binary_share(i).value2 ^ share_p2.get_binary_share(i).value1;
    }
    let mut value_p1 = 0u8;
    let mut value_p2 = 0u8;
    let mut value_p3 = 0u8;

    for i in 0..8 {
        if out_p1[i] {
            value_p1 |= 1 << (7 - i);
        }
        if out_p2[i] {
            value_p2 |= 1 << (7 - i);
        }
        if out_p3[i] {
            value_p3 |= 1 << (7 - i);
        }
    }
    (value_p1, value_p2, value_p3)
}

pub fn reconstruct_ec_share(
    share_p1: ArithmeticECShare,
    share_p2: ArithmeticECShare,
    share_p3: ArithmeticECShare,
) -> U256 {
    let p = get_modulus();

    let value1 = share_p1.value2.add_mod(&share_p3.value2, &p);
    assert_eq!(value1, share_p1.value1);

    let value2 = share_p2.value2.add_mod(&share_p1.value2, &p);
    assert_eq!(value2, share_p2.value1);

    let value3 = share_p3.value2.add_mod(&share_p2.value2, &p);
    assert_eq!(value3, share_p3.value1);

    share_p1.value2.add_mod(&share_p3.value1, &p)
}

pub fn reconstruct_binary_share(
    share_p1: BinaryShare,
    share_p2: BinaryShare,
    share_p3: BinaryShare,
) -> bool {
    assert!(share_p1.value1 ^ share_p2.value1 == share_p3.value1);
    assert!(share_p1.value2 ^ share_p3.value2 == share_p1.value1);
    assert!(share_p2.value2 ^ share_p1.value2 == share_p2.value1);
    assert!(share_p3.value2 ^ share_p2.value2 == share_p3.value1);

    share_p1.value2 ^ share_p3.value1
}

pub fn test_run_reconstruct_binary_share(
    share_p1: BinaryShare,
    share_p2: BinaryShare,
    share_p3: BinaryShare,
) -> (bool, bool, bool) {
    let output_p1 = share_p1.value2 ^ share_p3.value1;
    let output_p2 = share_p2.value2 ^ share_p1.value1;
    let output_p3 = share_p3.value2 ^ share_p2.value1;

    (output_p1, output_p2, output_p3)
}

pub fn u8_vec_to_binary_string(vec_u8: Vec<u8>) -> BinaryString {
    let mut output: BinaryString = BinaryString::with_capacity(vec_u8.len());
    for byte in vec_u8 {
        for i in (0..8).rev() {
            let bit = (byte >> i) & 1;
            output.push(bit != 0);
        }
    }

    output
}

pub fn binary_string_to_u8_vec(input: BinaryString) -> Vec<u8> {
    let mut vec_u8 = Vec::new();
    let mut byte = 0u8;

    for i in 0..(input.length as usize) {
        if input.get(i) {
            byte |= 1 << (7 - (i % 8));
        }
        if i % 8 == 7 {
            vec_u8.push(byte);
            byte = 0;
        }
    }
    if input.length % 8 != 0 {
        vec_u8.push(byte);
    }

    vec_u8
}

pub fn default_bytes_share(string: &str, party: usize) -> Vec<ByteShare> {
    let (encoded, _, _) = ISO_8859_10.encode(string);
    let vvec = u8_vec_to_binary_string(encoded.into_owned());
    let n = vvec.length as usize / 8;

    let mut output = Vec::with_capacity(n);
    for i in 0..n {
        let vvec_i = vvec.value[i];
        let byte_share = ByteShare::from_constant_u8(vvec_i, party);
        output.push(byte_share);
    }
    output
}

pub fn get_default_bin_share_from_bin_string(
    value: &BinaryString,
) -> (BinaryStringShare, BinaryStringShare, BinaryStringShare) {
    let len = value.length as usize;
    let mut output_p1 = BinaryStringShare::with_capacity(len);
    let mut output_p2 = BinaryStringShare::with_capacity(len);
    let mut output_p3 = BinaryStringShare::with_capacity(len);

    for i in 0..len {
        let value_i = value.get(i);
        output_p1.push(value_i, value_i);
        output_p2.push(value_i, false);
        output_p3.push(false, false);
    }

    (output_p1, output_p2, output_p3)
}

pub fn get_default_ec_share(value: U256, party: usize) -> ArithmeticECShare {
    let p = get_modulus();

    if party == 1 {
        return ArithmeticECShare {
            value1: value.sub_mod(&U256::from(1u32), &p),
            value2: value.sub_mod(&U256::from(2u32), &p),
        };
    } else if party == 2 {
        return ArithmeticECShare {
            value1: value.sub_mod(&U256::from(1u32), &p),
            value2: U256::from(1u32),
        };
    } else if party == 3 {
        return ArithmeticECShare {
            value1: U256::from(2u32),
            value2: U256::from(1u32),
        };
    }
    ArithmeticECShare {
        value1: U256::ZERO,
        value2: U256::ZERO,
    }
}

pub fn binary_string_share_to_byte_shares(shares: &BinaryStringShare) -> Option<Vec<ByteShare>> {
    let n_shares = shares.length as usize;
    if n_shares % 8 != 0 {
        println!("Size not consistent");
        return None;
    }

    let mut byteshares = Vec::new();
    let values_1 = &shares.value1;
    let values_2 = &shares.value2;
    for (v1, v2) in values_1.iter().zip(values_2.iter()) {
        byteshares.push(ByteShare {
            value1: *v1,
            value2: *v2,
        });
    }

    Some(byteshares)
}

pub fn split(value: BinaryStringShare) -> (BinaryStringShare, BinaryStringShare) {
    let n = value.length as usize;
    let size = n / 2;

    let mut x_1: BinaryStringShare = BinaryStringShare::with_capacity(size);
    let mut x_2: BinaryStringShare = BinaryStringShare::with_capacity(size);

    for i in 0..size {
        x_1.push(
            value.get_binary_share(i).value1,
            value.get_binary_share(i).value2,
        );
        x_2.push(
            value.get_binary_share(size + i).value1,
            value.get_binary_share(size + i).value2,
        );
    }

    (x_1, x_2)
}

fn binary_string_to_char(input: BinaryString) -> Option<char> {
    let mut value = 0u8;

    for i in 0..(input.length as usize) {
        if input.get(i) {
            value |= 1 << (7 - i);
        }
    }
    char::from_u32(value as u32)
}
