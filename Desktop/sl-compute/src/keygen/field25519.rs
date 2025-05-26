#![allow(unused_parens)]
#![allow(non_snake_case)]

// The current implementation of Edwards point operations relies on a third-party library that may not meet production security standards.
// A review and potential upgrade of this implementation is recommended before deployment.

use base64::prelude::BASE64_STANDARD;
use base64::Engine;
use core::cmp::{Eq, PartialEq};
use core::ops::{Add, Mul, Sub};
use curve25519_dalek::edwards::CompressedEdwardsY;
use elliptic_curve::subtle::{Choice, ConditionallySelectable, ConstantTimeEq};

type Fiat25519U1 = u8;
type Fiat25519I1 = i8;
type Fiat25519I2 = i8;

fn fiat_25519_addcarryx_u51(
    out1: &mut u64,
    out2: &mut Fiat25519U1,
    arg1: Fiat25519U1,
    arg2: u64,
    arg3: u64,
) {
    let x1: u64 = (((arg1 as u64).wrapping_add(arg2)).wrapping_add(arg3));
    let x2: u64 = (x1 & 0x7ffffffffffff);
    let x3: Fiat25519U1 = ((x1 >> 51) as Fiat25519U1);
    *out1 = x2;
    *out2 = x3;
}

fn fiat_25519_subborrowx_u51(
    out1: &mut u64,
    out2: &mut Fiat25519U1,
    arg1: Fiat25519U1,
    arg2: u64,
    arg3: u64,
) {
    let x1: i64 = ((((((arg2 as i128).wrapping_sub(arg1 as i128)) as i64) as i128)
        .wrapping_sub(arg3 as i128)) as i64);
    let x2: Fiat25519I1 = ((x1 >> 51) as Fiat25519I1);
    let x3: u64 = (((x1 as i128) & 0x7ffffffffffff_i128) as u64);
    *out1 = x3;
    *out2 = ((0x0_i8.wrapping_sub(x2 as Fiat25519I2)) as Fiat25519U1);
}

fn fiat_25519_cmovznz_u64(out1: &mut u64, arg1: Fiat25519U1, arg2: u64, arg3: u64) {
    let x1: Fiat25519U1 = (!(!arg1));
    let x2: u64 = (((((0x0_i8.wrapping_sub(x1 as Fiat25519I2)) as Fiat25519I1) as i128)
        & 0xffffffffffffffff_i128) as u64);
    let x3: u64 = ((x2 & arg3) | ((!x2) & arg2));
    *out1 = x3;
}

fn fiat_25519_carry_mul(out1: &mut [u64; 5], arg1: &[u64; 5], arg2: &[u64; 5]) {
    let x1: u128 = (((arg1[4]) as u128).wrapping_mul(((arg2[4]).wrapping_mul(0x13)) as u128));
    let x2: u128 = (((arg1[4]) as u128).wrapping_mul(((arg2[3]).wrapping_mul(0x13)) as u128));
    let x3: u128 = (((arg1[4]) as u128).wrapping_mul(((arg2[2]).wrapping_mul(0x13)) as u128));
    let x4: u128 = (((arg1[4]) as u128).wrapping_mul(((arg2[1]).wrapping_mul(0x13)) as u128));
    let x5: u128 = (((arg1[3]) as u128).wrapping_mul(((arg2[4]).wrapping_mul(0x13)) as u128));
    let x6: u128 = (((arg1[3]) as u128).wrapping_mul(((arg2[3]).wrapping_mul(0x13)) as u128));
    let x7: u128 = (((arg1[3]) as u128).wrapping_mul(((arg2[2]).wrapping_mul(0x13)) as u128));
    let x8: u128 = (((arg1[2]) as u128).wrapping_mul(((arg2[4]).wrapping_mul(0x13)) as u128));
    let x9: u128 = (((arg1[2]) as u128).wrapping_mul(((arg2[3]).wrapping_mul(0x13)) as u128));
    let x10: u128 = (((arg1[1]) as u128).wrapping_mul(((arg2[4]).wrapping_mul(0x13)) as u128));
    let x11: u128 = (((arg1[4]) as u128).wrapping_mul(arg2[0] as u128));
    let x12: u128 = (((arg1[3]) as u128).wrapping_mul((arg2[1]) as u128));
    let x13: u128 = (((arg1[3]) as u128).wrapping_mul((arg2[0]) as u128));
    let x14: u128 = (((arg1[2]) as u128).wrapping_mul((arg2[2]) as u128));
    let x15: u128 = (((arg1[2]) as u128).wrapping_mul((arg2[1]) as u128));
    let x16: u128 = (((arg1[2]) as u128).wrapping_mul((arg2[0]) as u128));
    let x17: u128 = (((arg1[1]) as u128).wrapping_mul((arg2[3]) as u128));
    let x18: u128 = (((arg1[1]) as u128).wrapping_mul((arg2[2]) as u128));
    let x19: u128 = (((arg1[1]) as u128).wrapping_mul((arg2[1]) as u128));
    let x20: u128 = (((arg1[1]) as u128).wrapping_mul((arg2[0]) as u128));
    let x21: u128 = (((arg1[0]) as u128).wrapping_mul((arg2[4]) as u128));
    let x22: u128 = (((arg1[0]) as u128).wrapping_mul((arg2[3]) as u128));
    let x23: u128 = (((arg1[0]) as u128).wrapping_mul((arg2[2]) as u128));
    let x24: u128 = (((arg1[0]) as u128).wrapping_mul((arg2[1]) as u128));
    let x25: u128 = (((arg1[0]) as u128).wrapping_mul((arg2[0]) as u128));
    let x26: u128 = (x25.wrapping_add(x10.wrapping_add(x9.wrapping_add(x7.wrapping_add(x4)))));
    let x27: u64 = ((x26 >> 51) as u64);
    let x28: u64 = ((x26 & 0x7ffffffffffff_u128) as u64);
    let x29: u128 = (x21.wrapping_add(x17.wrapping_add(x14.wrapping_add(x12.wrapping_add(x11)))));
    let x30: u128 = (x22.wrapping_add(x18.wrapping_add(x15.wrapping_add(x13.wrapping_add(x1)))));
    let x31: u128 = (x23.wrapping_add(x19.wrapping_add(x16.wrapping_add(x5.wrapping_add(x2)))));
    let x32: u128 = (x24.wrapping_add(x20.wrapping_add(x8.wrapping_add(x6.wrapping_add(x3)))));
    let x33: u128 = ((x27 as u128).wrapping_add(x32));
    let x34: u64 = ((x33 >> 51) as u64);
    let x35: u64 = ((x33 & 0x7ffffffffffff_u128) as u64);
    let x36: u128 = ((x34 as u128).wrapping_add(x31));
    let x37: u64 = ((x36 >> 51) as u64);
    let x38: u64 = ((x36 & 0x7ffffffffffff_u128) as u64);
    let x39: u128 = ((x37 as u128).wrapping_add(x30));
    let x40: u64 = ((x39 >> 51) as u64);
    let x41: u64 = ((x39 & 0x7ffffffffffff_u128) as u64);
    let x42: u128 = ((x40 as u128).wrapping_add(x29));
    let x43: u64 = ((x42 >> 51) as u64);
    let x44: u64 = ((x42 & 0x7ffffffffffff_u128) as u64);
    let x45: u64 = (x43.wrapping_mul(0x13));
    let x46: u64 = (x28.wrapping_add(x45));
    let x47: u64 = (x46 >> 51);
    let x48: u64 = (x46 & 0x7ffffffffffff);
    let x49: u64 = (x47.wrapping_add(x35));
    let x50: Fiat25519U1 = ((x49 >> 51) as Fiat25519U1);
    let x51: u64 = (x49 & 0x7ffffffffffff);
    let x52: u64 = ((x50 as u64).wrapping_add(x38));
    out1[0] = x48;
    out1[1] = x51;
    out1[2] = x52;
    out1[3] = x41;
    out1[4] = x44;
}

fn fiat_25519_carry_square(out1: &mut [u64; 5], arg1: &[u64; 5]) {
    let x1: u64 = ((arg1[4]).wrapping_mul(0x13));
    let x2: u64 = (x1.wrapping_mul(0x2));
    let x3: u64 = ((arg1[4]).wrapping_mul(0x2));
    let x4: u64 = ((arg1[3]).wrapping_mul(0x13));
    let x5: u64 = (x4.wrapping_mul(0x2));
    let x6: u64 = ((arg1[3]).wrapping_mul(0x2));
    let x7: u64 = ((arg1[2]).wrapping_mul(0x2));
    let x8: u64 = ((arg1[1]).wrapping_mul(0x2));
    let x9: u128 = (((arg1[4]) as u128).wrapping_mul(x1 as u128));
    let x10: u128 = (((arg1[3]) as u128).wrapping_mul(x2 as u128));
    let x11: u128 = (((arg1[3]) as u128).wrapping_mul(x4 as u128));
    let x12: u128 = (((arg1[2]) as u128).wrapping_mul(x2 as u128));
    let x13: u128 = (((arg1[2]) as u128).wrapping_mul(x5 as u128));
    let x14: u128 = (((arg1[2]) as u128).wrapping_mul(arg1[2] as u128));
    let x15: u128 = (((arg1[1]) as u128).wrapping_mul(x2 as u128));
    let x16: u128 = (((arg1[1]) as u128).wrapping_mul(x6 as u128));
    let x17: u128 = (((arg1[1]) as u128).wrapping_mul(x7 as u128));
    let x18: u128 = (((arg1[1]) as u128).wrapping_mul(arg1[1] as u128));
    let x19: u128 = (((arg1[0]) as u128).wrapping_mul(x3 as u128));
    let x20: u128 = (((arg1[0]) as u128).wrapping_mul(x6 as u128));
    let x21: u128 = (((arg1[0]) as u128).wrapping_mul(x7 as u128));
    let x22: u128 = (((arg1[0]) as u128).wrapping_mul(x8 as u128));
    let x23: u128 = (((arg1[0]) as u128).wrapping_mul(arg1[0] as u128));
    let x24: u128 = (x23.wrapping_add(x15.wrapping_add(x13)));
    let x25: u64 = ((x24 >> 51) as u64);
    let x26: u64 = ((x24 & 0x7ffffffffffff_u128) as u64);
    let x27: u128 = (x19.wrapping_add(x16.wrapping_add(x14)));
    let x28: u128 = (x20.wrapping_add(x17.wrapping_add(x9)));
    let x29: u128 = (x21.wrapping_add(x18.wrapping_add(x10)));
    let x30: u128 = (x22.wrapping_add(x12.wrapping_add(x11)));
    let x31: u128 = ((x25 as u128).wrapping_add(x30));
    let x32: u64 = ((x31 >> 51) as u64);
    let x33: u64 = ((x31 & 0x7ffffffffffff_u128) as u64);
    let x34: u128 = ((x32 as u128).wrapping_add(x29));
    let x35: u64 = ((x34 >> 51) as u64);
    let x36: u64 = ((x34 & 0x7ffffffffffff_u128) as u64);
    let x37: u128 = ((x35 as u128).wrapping_add(x28));
    let x38: u64 = ((x37 >> 51) as u64);
    let x39: u64 = ((x37 & 0x7ffffffffffff_u128) as u64);
    let x40: u128 = ((x38 as u128).wrapping_add(x27));
    let x41: u64 = ((x40 >> 51) as u64);
    let x42: u64 = ((x40 & 0x7ffffffffffff_u128) as u64);
    let x43: u64 = (x41.wrapping_mul(0x13));
    let x44: u64 = (x26.wrapping_add(x43));
    let x45: u64 = (x44 >> 51);
    let x46: u64 = (x44 & 0x7ffffffffffff);
    let x47: u64 = (x45.wrapping_add(x33));
    let x48: Fiat25519U1 = ((x47 >> 51) as Fiat25519U1);
    let x49: u64 = (x47 & 0x7ffffffffffff);
    let x50: u64 = ((x48 as u64).wrapping_add(x36));
    out1[0] = x46;
    out1[1] = x49;
    out1[2] = x50;
    out1[3] = x39;
    out1[4] = x42;
}

fn fiat_25519_carry(out1: &mut [u64; 5], arg1: &[u64; 5]) {
    let x1: u64 = (arg1[0]);
    let x2: u64 = ((x1 >> 51).wrapping_add(arg1[1]));
    let x3: u64 = ((x2 >> 51).wrapping_add(arg1[2]));
    let x4: u64 = ((x3 >> 51).wrapping_add(arg1[3]));
    let x5: u64 = ((x4 >> 51).wrapping_add(arg1[4]));
    let x6: u64 = ((x1 & 0x7ffffffffffff).wrapping_add((x5 >> 51).wrapping_mul(0x13)));
    let x7: u64 = ((((x6 >> 51) as Fiat25519U1) as u64).wrapping_add(x2 & 0x7ffffffffffff));
    let x8: u64 = (x6 & 0x7ffffffffffff);
    let x9: u64 = (x7 & 0x7ffffffffffff);
    let x10: u64 = ((((x7 >> 51) as Fiat25519U1) as u64).wrapping_add(x3 & 0x7ffffffffffff));
    let x11: u64 = (x4 & 0x7ffffffffffff);
    let x12: u64 = (x5 & 0x7ffffffffffff);
    out1[0] = x8;
    out1[1] = x9;
    out1[2] = x10;
    out1[3] = x11;
    out1[4] = x12;
}
fn fiat_25519_add(out1: &mut [u64; 5], arg1: &[u64; 5], arg2: &[u64; 5]) {
    let x1: u64 = ((arg1[0]).wrapping_add(arg2[0]));
    let x2: u64 = ((arg1[1]).wrapping_add(arg2[1]));
    let x3: u64 = ((arg1[2]).wrapping_add(arg2[2]));
    let x4: u64 = ((arg1[3]).wrapping_add(arg2[3]));
    let x5: u64 = ((arg1[4]).wrapping_add(arg2[4]));
    out1[0] = x1;
    out1[1] = x2;
    out1[2] = x3;
    out1[3] = x4;
    out1[4] = x5;
}

fn fiat_25519_sub(out1: &mut [u64; 5], arg1: &[u64; 5], arg2: &[u64; 5]) {
    let x1: u64 = ((0xfffffffffffdau64.wrapping_add(arg1[0])).wrapping_sub(arg2[0]));
    let x2: u64 = ((0xffffffffffffeu64.wrapping_add(arg1[1])).wrapping_sub(arg2[1]));
    let x3: u64 = ((0xffffffffffffeu64.wrapping_add(arg1[2])).wrapping_sub(arg2[2]));
    let x4: u64 = ((0xffffffffffffeu64.wrapping_add(arg1[3])).wrapping_sub(arg2[3]));
    let x5: u64 = ((0xffffffffffffeu64.wrapping_add(arg1[4])).wrapping_sub(arg2[4]));
    out1[0] = x1;
    out1[1] = x2;
    out1[2] = x3;
    out1[3] = x4;
    out1[4] = x5;
}

fn fiat_25519_opp(out1: &mut [u64; 5], arg1: &[u64; 5]) {
    let x1: u64 = (0xfffffffffffdau64.wrapping_sub(arg1[0]));
    let x2: u64 = (0xffffffffffffeu64.wrapping_sub(arg1[1]));
    let x3: u64 = (0xffffffffffffeu64.wrapping_sub(arg1[2]));
    let x4: u64 = (0xffffffffffffeu64.wrapping_sub(arg1[3]));
    let x5: u64 = (0xffffffffffffeu64.wrapping_sub(arg1[4]));
    out1[0] = x1;
    out1[1] = x2;
    out1[2] = x3;
    out1[3] = x4;
    out1[4] = x5;
}

fn fiat_25519_to_bytes(out1: &mut [u8; 32], arg1: &[u64; 5]) {
    let mut x1: u64 = 0;
    let mut x2: Fiat25519U1 = 0;
    fiat_25519_subborrowx_u51(&mut x1, &mut x2, 0x0, (arg1[0]), 0x7ffffffffffed);
    let mut x3: u64 = 0;
    let mut x4: Fiat25519U1 = 0;
    fiat_25519_subborrowx_u51(&mut x3, &mut x4, x2, (arg1[1]), 0x7ffffffffffff);
    let mut x5: u64 = 0;
    let mut x6: Fiat25519U1 = 0;
    fiat_25519_subborrowx_u51(&mut x5, &mut x6, x4, (arg1[2]), 0x7ffffffffffff);
    let mut x7: u64 = 0;
    let mut x8: Fiat25519U1 = 0;
    fiat_25519_subborrowx_u51(&mut x7, &mut x8, x6, (arg1[3]), 0x7ffffffffffff);
    let mut x9: u64 = 0;
    let mut x10: Fiat25519U1 = 0;
    fiat_25519_subborrowx_u51(&mut x9, &mut x10, x8, (arg1[4]), 0x7ffffffffffff);
    let mut x11: u64 = 0;
    fiat_25519_cmovznz_u64(&mut x11, x10, 0x0_u64, 0xffffffffffffffff);
    let mut x12: u64 = 0;
    let mut x13: Fiat25519U1 = 0;
    fiat_25519_addcarryx_u51(&mut x12, &mut x13, 0x0, x1, (x11 & 0x7ffffffffffed));
    let mut x14: u64 = 0;
    let mut x15: Fiat25519U1 = 0;
    fiat_25519_addcarryx_u51(&mut x14, &mut x15, x13, x3, (x11 & 0x7ffffffffffff));
    let mut x16: u64 = 0;
    let mut x17: Fiat25519U1 = 0;
    fiat_25519_addcarryx_u51(&mut x16, &mut x17, x15, x5, (x11 & 0x7ffffffffffff));
    let mut x18: u64 = 0;
    let mut x19: Fiat25519U1 = 0;
    fiat_25519_addcarryx_u51(&mut x18, &mut x19, x17, x7, (x11 & 0x7ffffffffffff));
    let mut x20: u64 = 0;
    let mut x21: Fiat25519U1 = 0;
    fiat_25519_addcarryx_u51(&mut x20, &mut x21, x19, x9, (x11 & 0x7ffffffffffff));
    let x22: u64 = (x20 << 4);
    let x23: u64 = (x18.wrapping_mul(0x2_u64));
    let x24: u64 = (x16 << 6);
    let x25: u64 = (x14 << 3);
    let x26: u8 = ((x12 & 0xff_u64) as u8);
    let x27: u64 = (x12 >> 8);
    let x28: u8 = ((x27 & 0xff_u64) as u8);
    let x29: u64 = (x27 >> 8);
    let x30: u8 = ((x29 & 0xff_u64) as u8);
    let x31: u64 = (x29 >> 8);
    let x32: u8 = ((x31 & 0xff_u64) as u8);
    let x33: u64 = (x31 >> 8);
    let x34: u8 = ((x33 & 0xff_u64) as u8);
    let x35: u64 = (x33 >> 8);
    let x36: u8 = ((x35 & 0xff_u64) as u8);
    let x37: u8 = ((x35 >> 8) as u8);
    let x38: u64 = (x25.wrapping_add(x37 as u64));
    let x39: u8 = ((x38 & 0xff_u64) as u8);
    let x40: u64 = (x38 >> 8);
    let x41: u8 = ((x40 & 0xff_u64) as u8);
    let x42: u64 = (x40 >> 8);
    let x43: u8 = ((x42 & 0xff_u64) as u8);
    let x44: u64 = (x42 >> 8);
    let x45: u8 = ((x44 & 0xff_u64) as u8);
    let x46: u64 = (x44 >> 8);
    let x47: u8 = ((x46 & 0xff_u64) as u8);
    let x48: u64 = (x46 >> 8);
    let x49: u8 = ((x48 & 0xff_u64) as u8);
    let x50: u8 = ((x48 >> 8) as u8);
    let x51: u64 = (x24.wrapping_add(x50 as u64));
    let x52: u8 = ((x51 & 0xff_u64) as u8);
    let x53: u64 = (x51 >> 8);
    let x54: u8 = ((x53 & 0xff_u64) as u8);
    let x55: u64 = (x53 >> 8);
    let x56: u8 = ((x55 & 0xff_u64) as u8);
    let x57: u64 = (x55 >> 8);
    let x58: u8 = ((x57 & 0xff_u64) as u8);
    let x59: u64 = (x57 >> 8);
    let x60: u8 = ((x59 & 0xff_u64) as u8);
    let x61: u64 = (x59 >> 8);
    let x62: u8 = ((x61 & 0xff_u64) as u8);
    let x63: u64 = (x61 >> 8);
    let x64: u8 = ((x63 & 0xff_u64) as u8);
    let x65: Fiat25519U1 = ((x63 >> 8) as Fiat25519U1);
    let x66: u64 = (x23.wrapping_add(x65 as u64));
    let x67: u8 = ((x66 & 0xff_u64) as u8);
    let x68: u64 = (x66 >> 8);
    let x69: u8 = ((x68 & 0xff_u64) as u8);
    let x70: u64 = (x68 >> 8);
    let x71: u8 = ((x70 & 0xff_u64) as u8);
    let x72: u64 = (x70 >> 8);
    let x73: u8 = ((x72 & 0xff_u64) as u8);
    let x74: u64 = (x72 >> 8);
    let x75: u8 = ((x74 & 0xff_u64) as u8);
    let x76: u64 = (x74 >> 8);
    let x77: u8 = ((x76 & 0xff_u64) as u8);
    let x78: u8 = ((x76 >> 8) as u8);
    let x79: u64 = (x22.wrapping_add(x78 as u64));
    let x80: u8 = ((x79 & 0xff_u64) as u8);
    let x81: u64 = (x79 >> 8);
    let x82: u8 = ((x81 & 0xff_u64) as u8);
    let x83: u64 = (x81 >> 8);
    let x84: u8 = ((x83 & 0xff_u64) as u8);
    let x85: u64 = (x83 >> 8);
    let x86: u8 = ((x85 & 0xff_u64) as u8);
    let x87: u64 = (x85 >> 8);
    let x88: u8 = ((x87 & 0xff_u64) as u8);
    let x89: u64 = (x87 >> 8);
    let x90: u8 = ((x89 & 0xff_u64) as u8);
    let x91: u8 = ((x89 >> 8) as u8);
    out1[0] = x26;
    out1[1] = x28;
    out1[2] = x30;
    out1[3] = x32;
    out1[4] = x34;
    out1[5] = x36;
    out1[6] = x39;
    out1[7] = x41;
    out1[8] = x43;
    out1[9] = x45;
    out1[10] = x47;
    out1[11] = x49;
    out1[12] = x52;
    out1[13] = x54;
    out1[14] = x56;
    out1[15] = x58;
    out1[16] = x60;
    out1[17] = x62;
    out1[18] = x64;
    out1[19] = x67;
    out1[20] = x69;
    out1[21] = x71;
    out1[22] = x73;
    out1[23] = x75;
    out1[24] = x77;
    out1[25] = x80;
    out1[26] = x82;
    out1[27] = x84;
    out1[28] = x86;
    out1[29] = x88;
    out1[30] = x90;
    out1[31] = x91;
}

#[derive(Clone, Default, Copy, Debug)]
struct Fe(pub [u64; 5]);

impl ConstantTimeEq for Fe {
    /// Test equality between two `FieldElement`s.  Since the
    /// internal representation is not canonical, the field elements
    /// are normalized to wire format before comparison.
    fn ct_eq(&self, other: &Fe) -> Choice {
        self.to_bytes().ct_eq(&other.to_bytes())
    }
}

impl ConditionallySelectable for Fe {
    fn conditional_select(a: &Fe, b: &Fe, choice: Choice) -> Fe {
        Fe([
            u64::conditional_select(&a.0[0], &b.0[0], choice),
            u64::conditional_select(&a.0[1], &b.0[1], choice),
            u64::conditional_select(&a.0[2], &b.0[2], choice),
            u64::conditional_select(&a.0[3], &b.0[3], choice),
            u64::conditional_select(&a.0[4], &b.0[4], choice),
        ])
    }

    fn conditional_assign(&mut self, other: &Fe, choice: Choice) {
        self.0[0].conditional_assign(&other.0[0], choice);
        self.0[1].conditional_assign(&other.0[1], choice);
        self.0[2].conditional_assign(&other.0[2], choice);
        self.0[3].conditional_assign(&other.0[3], choice);
        self.0[4].conditional_assign(&other.0[4], choice);
    }
}

impl PartialEq for Fe {
    fn eq(&self, other: &Fe) -> bool {
        let &Fe(self_elems) = self;
        let &Fe(other_elems) = other;
        self_elems == other_elems
    }
}
impl Eq for Fe {}

static FE_ONE: Fe = Fe([1, 0, 0, 0, 0]);

static FE_SQRTM1: Fe = Fe([
    1718705420411056,
    234908883556509,
    2233514472574048,
    2117202627021982,
    765476049583133,
]);
static FE_D: Fe = Fe([
    929955233495203,
    466365720129213,
    1662059464998953,
    2033849074728123,
    1442794654840575,
]);
static _FE_D2: Fe = Fe([
    1859910466990425,
    932731440258426,
    1072319116312658,
    1815898335770999,
    633789495995903,
]);

static FE_A: Fe = Fe([486662, 0, 0, 0, 0]);

static FE_A_DIV_3: Fe = Fe([
    750599938057297,
    1501199875790165,
    750599937895082,
    1501199875790165,
    750599937895082,
]);

static FE_C: Fe = Fe([
    557817479725543,
    1643290402203250,
    16226468853936,
    1304118542701054,
    1985241807451647,
]);

fn load_8u(s: &[u8]) -> u64 {
    (s[0] as u64)
        | ((s[1] as u64) << 8)
        | ((s[2] as u64) << 16)
        | ((s[3] as u64) << 24)
        | ((s[4] as u64) << 32)
        | ((s[5] as u64) << 40)
        | ((s[6] as u64) << 48)
        | ((s[7] as u64) << 56)
}

impl Add for Fe {
    type Output = Fe;

    fn add(self, _rhs: Fe) -> Fe {
        let Fe(f) = self;
        let Fe(g) = _rhs;
        let mut h = Fe::default();
        fiat_25519_add(&mut h.0, &f, &g);
        h
    }
}

impl Sub for Fe {
    type Output = Fe;

    fn sub(self, _rhs: Fe) -> Fe {
        let Fe(f) = self;
        let Fe(g) = _rhs;
        let mut h = Fe::default();
        fiat_25519_sub(&mut h.0, &f, &g);
        h.carry()
    }
}

impl Mul for Fe {
    type Output = Fe;

    fn mul(self, _rhs: Fe) -> Fe {
        let Fe(f) = self;
        let Fe(g) = _rhs;
        let mut h = Fe::default();
        fiat_25519_carry_mul(&mut h.0, &f, &g);
        h
    }
}

impl Fe {
    fn from_bytes(s: &[u8]) -> Fe {
        if s.len() != 32 {
            panic!("Invalid compressed length")
        }
        let mut h = Fe::default();
        let mask = 0x7ffffffffffff;
        h.0[0] = load_8u(&s[0..]) & mask;
        h.0[1] = (load_8u(&s[6..]) >> 3) & mask;
        h.0[2] = (load_8u(&s[12..]) >> 6) & mask;
        h.0[3] = (load_8u(&s[19..]) >> 1) & mask;
        h.0[4] = (load_8u(&s[24..]) >> 12) & mask;
        h
    }

    #[allow(clippy::wrong_self_convention)]
    fn to_bytes(&self) -> [u8; 32] {
        let &Fe(es) = &self.carry();
        let mut s_ = [0u8; 32];
        fiat_25519_to_bytes(&mut s_, &es);
        s_
    }

    fn carry(&self) -> Fe {
        let mut h = Fe::default();
        fiat_25519_carry(&mut h.0, &self.0);
        h
    }

    fn square(&self) -> Fe {
        let &Fe(f) = &self;
        let mut h = Fe::default();
        fiat_25519_carry_square(&mut h.0, f);
        h
    }

    #[allow(clippy::let_and_return)]
    fn invert(&self) -> Fe {
        let z1 = *self;
        let z2 = z1.square();
        let z8 = z2.square().square();
        let z9 = z1 * z8;
        let z11 = z2 * z9;
        let z22 = z11.square();
        let z_5_0 = z9 * z22;
        let z_10_5 = (0..5).fold(z_5_0, |z_5_n, _| z_5_n.square());
        let z_10_0 = z_10_5 * z_5_0;
        let z_20_10 = (0..10).fold(z_10_0, |x, _| x.square());
        let z_20_0 = z_20_10 * z_10_0;
        let z_40_20 = (0..20).fold(z_20_0, |x, _| x.square());
        let z_40_0 = z_40_20 * z_20_0;
        let z_50_10 = (0..10).fold(z_40_0, |x, _| x.square());
        let z_50_0 = z_50_10 * z_10_0;
        let z_100_50 = (0..50).fold(z_50_0, |x, _| x.square());
        let z_100_0 = z_100_50 * z_50_0;
        let z_200_100 = (0..100).fold(z_100_0, |x, _| x.square());
        let z_200_0 = z_200_100 * z_100_0;
        let z_250_50 = (0..50).fold(z_200_0, |x, _| x.square());
        let z_250_0 = z_250_50 * z_50_0;
        let z_255_5 = (0..5).fold(z_250_0, |x, _| x.square());
        let z_255_21 = z_255_5 * z11;
        z_255_21
    }

    fn is_negative(&self) -> bool {
        (self.to_bytes()[0] & 1) != 0
    }

    fn neg(&self) -> Fe {
        let &Fe(f) = &self;
        let mut h = Fe::default();
        fiat_25519_opp(&mut h.0, f);
        h
    }

    #[allow(clippy::let_and_return)]
    fn pow25523(&self) -> Fe {
        let z2 = self.square();
        let z8 = (0..2).fold(z2, |x, _| x.square());
        let z9 = *self * z8;
        let z11 = z2 * z9;
        let z22 = z11.square();
        let z_5_0 = z9 * z22;
        let z_10_5 = (0..5).fold(z_5_0, |x, _| x.square());
        let z_10_0 = z_10_5 * z_5_0;
        let z_20_10 = (0..10).fold(z_10_0, |x, _| x.square());
        let z_20_0 = z_20_10 * z_10_0;
        let z_40_20 = (0..20).fold(z_20_0, |x, _| x.square());
        let z_40_0 = z_40_20 * z_20_0;
        let z_50_10 = (0..10).fold(z_40_0, |x, _| x.square());
        let z_50_0 = z_50_10 * z_10_0;
        let z_100_50 = (0..50).fold(z_50_0, |x, _| x.square());
        let z_100_0 = z_100_50 * z_50_0;
        let z_200_100 = (0..100).fold(z_100_0, |x, _| x.square());
        let z_200_0 = z_200_100 * z_100_0;
        let z_250_50 = (0..50).fold(z_200_0, |x, _| x.square());
        let z_250_0 = z_250_50 * z_50_0;
        let z_252_2 = (0..2).fold(z_250_0, |x, _| x.square());
        let z_252_3 = z_252_2 * *self;

        z_252_3
    }
}

/// Given `FieldElements` `u` and `v`, compute either `sqrt(u/v)`
/// or `sqrt(i*u/v)` in constant time.
///
/// This function always returns the nonnegative square root.
///
/// # Return
///
/// - `(Choice(1), +sqrt(u/v))  ` if `v` is nonzero and `u/v` is square;
/// - `(Choice(1), zero)        ` if `u` is zero;
/// - `(Choice(0), zero)        ` if `v` is zero and `u` is nonzero;
/// - `(Choice(0), +sqrt(i*u/v))` if `u/v` is nonsquare (so `i*u/v` is square).
///
fn sqrt_ratio_i(u: Fe, v: Fe) -> (Choice, Fe) {
    // Using the same trick as in ed25519 decoding, we merge the
    // inversion, the square root, and the square test as follows.
    //
    // To compute sqrt(α), we can compute β = α^((p+3)/8).
    // Then β^2 = ±α, so multiplying β by sqrt(-1) if necessary
    // gives sqrt(α).
    //
    // To compute 1/sqrt(α), we observe that
    //    1/β = α^(p-1 - (p+3)/8) = α^((7p-11)/8)
    //                            = α^3 * (α^7)^((p-5)/8).
    //
    // We can therefore compute sqrt(u/v) = sqrt(u)/sqrt(v)
    // by first computing
    //    r = u^((p+3)/8) v^(p-1-(p+3)/8)
    //      = u u^((p-5)/8) v^3 (v^7)^((p-5)/8)
    //      = (uv^3) (uv^7)^((p-5)/8).
    //
    // If v is nonzero and u/v is square, then r^2 = ±u/v,
    //                                     so vr^2 = ±u.
    // If vr^2 =  u, then sqrt(u/v) = r.
    // If vr^2 = -u, then sqrt(u/v) = r*sqrt(-1).
    //
    // If v is zero, r is also zero.

    let v3 = v.square().mul(v);
    let v7 = v3.square().mul(v);
    let mut r = u.mul(v3).mul(u.mul(v7).pow25523());
    let check = v.mul(r.square());

    let i = FE_SQRTM1;

    let correct_sign_sqrt = check.ct_eq(&u);
    let flipped_sign_sqrt = check.ct_eq(&u.neg());
    let flipped_sign_sqrt_i = check.ct_eq(&(u.neg().mul(i)));

    let r_prime = FE_SQRTM1.mul(r);
    r.conditional_assign(&r_prime, flipped_sign_sqrt | flipped_sign_sqrt_i);

    // Choose the nonnegative square root.
    let r_is_negative = r.is_negative();
    // r.conditional_negate(r_is_negative);
    if r_is_negative {
        r = r.neg()
    }

    let was_nonzero_square = correct_sign_sqrt | flipped_sign_sqrt;

    (was_nonzero_square, r)
}

#[allow(dead_code)]
#[derive(Debug)]
pub struct EdwardsPointInternal {
    X: Fe,
    Y: Fe,
    Z: Fe,
    T: Fe,
}

pub struct EdCoordinates {
    pub x: [u8; 32],
    pub y: [u8; 32],
}

pub struct MnCoordinates {
    pub x: [u8; 32],
    pub y: [u8; 32],
}

pub struct WeiCoordinates {
    pub x: [u8; 32],
    pub y: [u8; 32],
}

impl WeiCoordinates {
    pub fn to_pem(&self) -> String {
        let pre = "308201313081ea06072a8648ce3d02013081de020101302b06072a8648ce3d010102207fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed304404202aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa984914a14404207b425ed097b425ed097b425ed097b425ed097b425ed097b4260b5e9c7710c8640441042aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaad245a20ae19a1b8a086b4e01edd2c7748d14c923d4d7e6d7c61b229e9c5a27eced3d902201000000000000000000000000000000014def9dea2f79cd65812631a5cf5d3ed020108034200";

        let mut bytes_payload = hex::decode(pre).unwrap();
        bytes_payload.push(4u8);
        bytes_payload.extend_from_slice(&self.x);
        bytes_payload.extend_from_slice(&self.y);

        let encoded = BASE64_STANDARD.encode(bytes_payload);

        let start = "-----BEGIN PUBLIC KEY-----".to_string();
        let end = "-----END PUBLIC KEY-----".to_string();

        start + &*encoded + &*end
    }

    pub fn to_ed_coordinates(&self) -> EdCoordinates {
        let mut x = self.x;
        let mut y = self.y;
        x.reverse();
        y.reverse();
        let x = Fe::from_bytes(&x);
        let y = Fe::from_bytes(&y);

        let three = FE_ONE.add(FE_ONE.add(FE_ONE));

        // ed_x = c * (3*x - A) / (3*y)
        let t = x.mul(three).sub(FE_A);
        let ed_x = FE_C.mul(t).mul(y.mul(three).invert());

        // ed_y = (3*x - A - 3) / (3*x - A + 3)
        let ed_y = t.sub(three).mul(t.add(three).invert());

        let mut x_bytes = ed_x.to_bytes();
        x_bytes.reverse();

        let mut y_bytes = ed_y.to_bytes();
        y_bytes.reverse();

        EdCoordinates {
            x: x_bytes,
            y: y_bytes,
        }
    }

    pub fn to_mn_coordinates(&self) -> MnCoordinates {
        let mut x = self.x;
        let mut y = self.x;
        x.reverse();
        y.reverse();
        let x = Fe::from_bytes(&x);
        let y = Fe::from_bytes(&y);

        let three = FE_ONE.add(FE_ONE.add(FE_ONE));

        let delta = FE_A.mul(three.invert());

        let ed_x = x.sub(delta);
        let ed_y = y;

        let mut x_bytes = ed_x.to_bytes();
        x_bytes.reverse();

        let mut y_bytes = ed_y.to_bytes();
        y_bytes.reverse();

        MnCoordinates {
            x: x_bytes,
            y: y_bytes,
        }
    }

    pub fn to_ed_compressed(&self) -> CompressedEdwardsY {
        let mut x = self.x;
        let mut y = self.y;
        x.reverse();
        y.reverse();
        let x = Fe::from_bytes(&x);
        let y = Fe::from_bytes(&y);

        let three = FE_ONE.add(FE_ONE.add(FE_ONE));

        // ed_x = c * (3*x - A) / (3*y)
        let t = x.mul(three).sub(FE_A);
        let ed_x = FE_C.mul(t).mul(y.mul(three).invert());

        // ed_y = (3*x - A - 3) / (3*x - A + 3)
        let ed_y = t.sub(three).mul(t.add(three).invert());

        let mut s: [u8; 32];
        s = ed_y.to_bytes();
        if ed_x.is_negative() {
            s[31] ^= 1 << 7;
        }

        CompressedEdwardsY(s)
    }
}

impl MnCoordinates {
    pub fn to_wei_coordinates(&self) -> WeiCoordinates {
        let mut x = self.x;
        let mut y = self.x;
        x.reverse();
        y.reverse();
        let x = Fe::from_bytes(&x);
        let y = Fe::from_bytes(&y);

        let three = FE_ONE.add(FE_ONE.add(FE_ONE));

        let delta = FE_A.mul(three.invert());

        let ed_x = x.add(delta);
        let ed_y = y;

        let mut x_bytes = ed_x.to_bytes();
        x_bytes.reverse();

        let mut y_bytes = ed_y.to_bytes();
        y_bytes.reverse();

        WeiCoordinates {
            x: x_bytes,
            y: y_bytes,
        }
    }
}

impl EdwardsPointInternal {
    fn step_1(repr: &CompressedEdwardsY) -> (Choice, Fe, Fe, Fe) {
        let Y = Fe::from_bytes(repr.as_bytes());
        let Z = FE_ONE;
        let YY = Y.square();
        let u = YY.sub(Z); // u =  y²-1
        let v = YY.mul(FE_D).add(Z); // v = dy²+1
        let (is_valid_y_coord, X) = sqrt_ratio_i(u, v);

        (is_valid_y_coord, X, Y, Z)
    }

    fn step_2(repr: &CompressedEdwardsY, X: Fe, Y: Fe, Z: Fe) -> EdwardsPointInternal {
        // sqrt_ratio_i() always returns the nonnegative square root,
        // so we negate according to the supplied sign bit.
        let compressed_sign_bit = repr.as_bytes()[31] >> 7;
        // X.conditional_negate(compressed_sign_bit);
        let mut new_x = X;
        if compressed_sign_bit == 1 {
            new_x = X.neg()
        }
        let T = new_x.mul(Y);

        EdwardsPointInternal { X: new_x, Y, Z, T }
    }

    pub fn from_compressed(repr: &CompressedEdwardsY) -> Option<Self> {
        let (is_valid_y_coord, x, y, z) = EdwardsPointInternal::step_1(repr);

        if is_valid_y_coord.into() {
            Some(EdwardsPointInternal::step_2(repr, x, y, z))
        } else {
            None
        }
    }

    #[allow(dead_code)]
    pub fn compress(&self) -> CompressedEdwardsY {
        let recip = self.Z.invert();
        let x = self.X * recip;
        let y = self.Y * recip;

        let mut s: [u8; 32];
        s = y.to_bytes();
        if x.is_negative() {
            s[31] ^= 1 << 7;
        }

        CompressedEdwardsY(s)
    }

    #[allow(dead_code)]
    pub fn to_ed_coordinates(&self) -> EdCoordinates {
        let recip = self.Z.invert();
        let x = self.X.mul(recip);
        let y = self.Y.mul(recip);
        let mut x = x.to_bytes();
        let mut y = y.to_bytes();
        x.reverse();
        y.reverse();
        EdCoordinates { x, y }
    }

    pub fn to_wei_coordinates(&self) -> WeiCoordinates {
        let recip = self.Z.invert();
        let x = self.X.mul(recip);
        let y = self.Y.mul(recip);

        // x' = (1 + y) / (1 - y) + A/3
        // t = (1 + y) / (1 - y)
        let t = FE_ONE.add(y).mul(FE_ONE.sub(y).invert());
        let x_prime = t.add(FE_A_DIV_3);
        let mut x_prime_bytes = x_prime.to_bytes();
        x_prime_bytes.reverse();

        // y' = c * (1 + y) / ((1 - y) * x)
        let y_prime = FE_C.mul(t).mul(x.invert());
        let mut y_prime_bytes = y_prime.to_bytes();
        y_prime_bytes.reverse();

        WeiCoordinates {
            x: x_prime_bytes,
            y: y_prime_bytes,
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::keygen::field25519::EdwardsPointInternal;
    use curve25519_dalek::Scalar;

    #[test]
    pub fn test() {
        use curve25519_dalek::EdwardsPoint;
        use elliptic_curve::Group;

        use rand::thread_rng;
        let mut rng = thread_rng();

        let generator = EdwardsPoint::generator();

        let ed_coordinates = EdwardsPointInternal::from_compressed(&generator.compress())
            .unwrap()
            .to_ed_coordinates();
        println!("base ed_x: {:?}", hex::encode(&ed_coordinates.x));
        println!("base ed_y: {:?}", hex::encode(&ed_coordinates.y));

        let wei_coordinates = EdwardsPointInternal::from_compressed(&generator.compress())
            .unwrap()
            .to_wei_coordinates();
        println!("base wei_x: {:?}", hex::encode(&wei_coordinates.x));
        println!("base wei_y: {:?}", hex::encode(&wei_coordinates.y));

        let expected_ed_coordinates = wei_coordinates.to_ed_coordinates();
        println!("base ed_x 2: {:?}", hex::encode(&expected_ed_coordinates.x));
        println!("base ed_y 2: {:?}", hex::encode(&expected_ed_coordinates.y));

        assert_eq!(ed_coordinates.x, expected_ed_coordinates.x);
        assert_eq!(ed_coordinates.y, expected_ed_coordinates.y);

        let scalar_bob = Scalar::random(&mut rng);
        let _pk_bob = generator * scalar_bob;

        let compressed_point = generator.compress();
        println!(
            "compressed: {:?}",
            hex::encode(&compressed_point.to_bytes())
        );

        let decompressed_point = compressed_point.decompress().unwrap();
        println!("decompressed 1: {:?}", decompressed_point);

        let point = EdwardsPointInternal::from_compressed(&compressed_point).unwrap();
        println!("decompressed 2: {:?}", point);

        let expected_compressed_point = point.to_wei_coordinates().to_ed_compressed();
        let expected_compressed_point2 = point.compress();

        assert_eq!(compressed_point, expected_compressed_point);
        assert_eq!(compressed_point, expected_compressed_point2);
    }
}
