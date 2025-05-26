// Copyright (c) Silence Laboratories Pte. Ltd. All Rights Reserved.
// This software is licensed under the Silence Laboratories License Agreement.

use crypto_bigint::{Encoding, U256};
use std::mem;
use x25519_dalek::PublicKey;

use sl_mpc_mate::ByteArray;

use crate::transport::setup::{ProtocolParticipant, ABORT_MESSAGE_TAG};

mod encrypted;
mod signed;
pub(crate) mod tags;

pub use encrypted::{EncryptedMessage, NonceCounter};
pub use signed::SignedMessage;
pub use tags::{FilteredMsgRelay, Round};

/// External representation of a point on a curve
pub type PointBytes = [u8; 33];

/// External Scalar representation
pub type ScalarBytes = [u8; 32]; // KAPPA_BYTES

use crate::constants::FIELD_SIZE_BYTES;

use crate::types::{ArithmeticECShare, Binary, BinaryArithmetic, BinaryString, FieldElement};

use crate::galois_abb::{GaloisElement, GaloisShare};
use crate::utility::threshold_dec::ThresholdDecMsg1;
pub use sl_mpc_mate::{
    coord::Relay,
    message::{MessageTag, MsgHdr},
};

/// Create an Abort Message.
pub fn create_abort_message<P>(setup: &P) -> Vec<u8>
where
    P: ProtocolParticipant,
{
    SignedMessage::<(), _>::new(
        &setup.msg_id(None, ABORT_MESSAGE_TAG),
        setup.message_ttl().as_secs() as _,
        0,
        0,
    )
    .sign(setup.signer())
}

/// Returns passed error if msg is a vaild abort message.
pub fn check_abort<P: ProtocolParticipant, E>(
    setup: &P,
    msg: &[u8],
    party_id: usize,
    err: impl FnOnce(usize) -> E,
) -> Result<(), E> {
    SignedMessage::<(), _>::verify(msg, setup.verifier(party_id))
        .map_or(Ok(()), |_| Err(err(party_id)))
}

/// A type with some external representation.
pub trait Wrap: Sized {
    /// Size of external representation in bytes
    fn external_size(&self) -> usize;

    /// Serialize a value into passed buffer
    fn write(&self, buffer: &mut [u8]);

    /// Deserialize value from given buffer
    fn read(buffer: &[u8]) -> Option<Self>;

    /// Encode a value into passed buffer and return remaining bytes.
    fn encode<'a>(&self, buf: &'a mut [u8]) -> &'a mut [u8] {
        let (buf, rest) = buf.split_at_mut(self.external_size());
        self.write(buf);
        rest
    }

    /// Decode a value from `input` buffer using `size` bytes.
    /// Return remaining bytes and decoded value.
    fn decode(input: &[u8], size: usize) -> Option<(&[u8], Self)> {
        if input.len() < size {
            return None;
        }
        let (input, rest) = input.split_at(size);
        Some((rest, Self::read(input)?))
    }
}

/// A type with fixed size of external representation.
pub trait FixedExternalSize: Sized {
    /// Size of an external representation of Self
    const SIZE: usize;
}

impl Wrap for () {
    fn external_size(&self) -> usize {
        0
    }

    fn write(&self, _buffer: &mut [u8]) {}

    fn read(_buffer: &[u8]) -> Option<Self> {
        Some(())
    }
}

impl FixedExternalSize for () {
    const SIZE: usize = 0;
}

impl<const N: usize> FixedExternalSize for ByteArray<N> {
    const SIZE: usize = N;
}

impl<const N: usize> Wrap for ByteArray<N> {
    fn external_size(&self) -> usize {
        self.len()
    }

    fn write(&self, buffer: &mut [u8]) {
        buffer.copy_from_slice(self);
    }

    fn read(buffer: &[u8]) -> Option<Self> {
        let mut value = Self::default();
        value.copy_from_slice(buffer);
        Some(value)
    }
}

impl<const N: usize> Wrap for [u8; N] {
    fn external_size(&self) -> usize {
        N
    }

    fn write(&self, buffer: &mut [u8]) {
        buffer.copy_from_slice(self);
    }

    fn read(buffer: &[u8]) -> Option<Self> {
        let mut value = [0u8; N];
        value.copy_from_slice(buffer);
        Some(value)
    }
}

impl Wrap for PublicKey {
    fn external_size(&self) -> usize {
        32
    }

    fn write(&self, buffer: &mut [u8]) {
        buffer.copy_from_slice(self.as_bytes());
    }

    fn read(buffer: &[u8]) -> Option<Self> {
        let mut value = [0u8; 32];
        value.copy_from_slice(buffer);
        Some(PublicKey::from(value))
    }
}

impl<T: Wrap + FixedExternalSize> Wrap for Vec<T> {
    fn external_size(&self) -> usize {
        self.len() * T::SIZE
    }

    fn write(&self, buffer: &mut [u8]) {
        for (v, b) in self.iter().zip(buffer.chunks_exact_mut(T::SIZE)) {
            v.write(b);
        }
    }

    fn read(buffer: &[u8]) -> Option<Self> {
        buffer
            .chunks_exact(T::SIZE)
            .map(T::read)
            .collect::<Option<Vec<T>>>()
    }
}

impl FixedExternalSize for u8 {
    const SIZE: usize = 1;
}

impl Wrap for u8 {
    fn external_size(&self) -> usize {
        1
    }

    fn write(&self, buffer: &mut [u8]) {
        buffer[0] = *self;
    }

    fn read(buffer: &[u8]) -> Option<Self> {
        Some(buffer[0])
    }
}

impl Wrap for u16 {
    fn external_size(&self) -> usize {
        2
    }

    fn write(&self, buffer: &mut [u8]) {
        buffer[..2].copy_from_slice(&self.to_le_bytes());
    }

    fn read(buffer: &[u8]) -> Option<Self> {
        Some(u16::from_le_bytes(buffer[..2].try_into().unwrap()))
    }
}

impl Wrap for u64 {
    fn external_size(&self) -> usize {
        8
    }

    fn write(&self, buffer: &mut [u8]) {
        buffer[..8].copy_from_slice(&self.to_le_bytes());
    }

    fn read(buffer: &[u8]) -> Option<Self> {
        Some(u64::from_le_bytes(buffer[..8].try_into().unwrap()))
    }
}

impl FixedExternalSize for FieldElement {
    const SIZE: usize = 8;
}

impl Wrap for FieldElement {
    fn external_size(&self) -> usize {
        8
    }

    fn write(&self, buffer: &mut [u8]) {
        buffer[..8].copy_from_slice(&self.to_le_bytes());
    }

    fn read(buffer: &[u8]) -> Option<Self> {
        Some(FieldElement::from_le_bytes(buffer[..8].try_into().unwrap()))
    }
}

impl Wrap for BinaryString {
    fn external_size(&self) -> usize {
        self.get_external_size()
    }

    fn write(&self, buffer: &mut [u8]) {
        let (l, v) = buffer.split_at_mut(mem::size_of::<u64>());
        self.length.write(l);
        v[..self.length_in_bytes()].copy_from_slice(&self.value);
    }

    fn read(buffer: &[u8]) -> Option<Self> {
        let (l, v) = buffer.split_at(mem::size_of::<u64>());
        let length = u64::read(l)?;
        let value = v
            .chunks_exact(1)
            .map(u8::read)
            .collect::<Option<Vec<u8>>>()?;

        Some(BinaryString { length, value })
    }
}

impl FixedExternalSize for BinaryArithmetic {
    const SIZE: usize = FIELD_SIZE_BYTES;
}

impl Wrap for BinaryArithmetic {
    fn external_size(&self) -> usize {
        self.get_external_size()
    }

    fn write(&self, buffer: &mut [u8]) {
        self.value.write(buffer);
    }

    fn read(buffer: &[u8]) -> Option<Self> {
        let mut value = [0u8; FIELD_SIZE_BYTES];
        value.copy_from_slice(buffer);
        Some(BinaryArithmetic { value })
    }
}

impl FixedExternalSize for Binary {
    const SIZE: usize = 1;
}

impl Wrap for Binary {
    fn external_size(&self) -> usize {
        1
    }

    fn write(&self, buffer: &mut [u8]) {
        buffer[0] = *self as u8;
    }

    fn read(buffer: &[u8]) -> Option<Self> {
        Some(buffer[0] == 1)
    }
}

impl Wrap for U256 {
    fn external_size(&self) -> usize {
        32
    }

    fn write(&self, buffer: &mut [u8]) {
        buffer.copy_from_slice(&self.to_be_bytes())
    }

    fn read(buffer: &[u8]) -> Option<Self> {
        Some(U256::from_be_slice(buffer))
    }
}

impl Wrap for ArithmeticECShare {
    fn external_size(&self) -> usize {
        64
    }

    fn write(&self, buffer: &mut [u8]) {
        let (p1, p2) = buffer.split_at_mut(32);
        p1.copy_from_slice(&self.value1.to_be_bytes());
        p2.copy_from_slice(&self.value2.to_be_bytes());
    }

    fn read(buffer: &[u8]) -> Option<Self> {
        let length = buffer.len();
        let (p1, p2) = buffer.split_at(length / 2);

        let value1 = U256::from_be_slice(p1);
        let value2 = U256::from_be_slice(p2);

        Some(ArithmeticECShare { value1, value2 })
    }
}

impl Wrap for ThresholdDecMsg1 {
    fn external_size(&self) -> usize {
        self.x.external_size() + self.y.external_size()
    }

    fn write(&self, buffer: &mut [u8]) {
        let (p1, p2) = buffer.split_at_mut(self.x.external_size());
        self.x.write(p1);
        self.y.write(p2);
    }

    fn read(buffer: &[u8]) -> Option<Self> {
        let length = buffer.len();
        let (p1, p2) = buffer.split_at(length / 2);

        let x = ArithmeticECShare::read(p1)?;
        let y = ArithmeticECShare::read(p2)?;

        Some(ThresholdDecMsg1 { x, y })
    }
}

impl FixedExternalSize for GaloisElement {
    const SIZE: usize = FIELD_SIZE_BYTES;
}

impl Wrap for GaloisElement {
    fn external_size(&self) -> usize {
        FIELD_SIZE_BYTES
    }

    fn write(&self, buffer: &mut [u8]) {
        self.0.write(buffer);
    }

    fn read(buffer: &[u8]) -> Option<Self> {
        let mut value = [0u8; FIELD_SIZE_BYTES];
        value.copy_from_slice(buffer);
        Some(GaloisElement(value))
    }
}

impl FixedExternalSize for GaloisShare {
    const SIZE: usize = FIELD_SIZE_BYTES * 2;
}

impl Wrap for GaloisShare {
    fn external_size(&self) -> usize {
        FIELD_SIZE_BYTES * 2
    }

    fn write(&self, buffer: &mut [u8]) {
        let (p1, p2) = buffer.split_at_mut(FIELD_SIZE_BYTES);
        p1.copy_from_slice(&self.value1.0);
        p2.copy_from_slice(&self.value2.0);
    }

    fn read(buffer: &[u8]) -> Option<Self> {
        let length = buffer.len();
        let (p1, p2) = buffer.split_at(length / 2);

        let mut value1 = [0u8; FIELD_SIZE_BYTES];
        let mut value2 = [0u8; FIELD_SIZE_BYTES];
        value1.copy_from_slice(p1);
        value2.copy_from_slice(p2);

        Some(GaloisShare {
            value1: GaloisElement(value1),
            value2: GaloisElement(value2),
        })
    }
}
