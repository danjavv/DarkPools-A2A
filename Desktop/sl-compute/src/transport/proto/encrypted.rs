// Copyright (c) Silence Laboratories Pte. Ltd. All Rights Reserved.
// This software is licensed under the Silence Laboratories License Agreement.

use std::marker::PhantomData;

use aead::{
    consts::U10,
    generic_array::{typenum::Unsigned, GenericArray},
    AeadCore, AeadInPlace, KeyInit, Nonce, Tag,
};
use bytemuck::{AnyBitPattern, NoUninit};
use chacha20::hchacha;
use chacha20poly1305::ChaCha20Poly1305;
use sha2::{Digest, Sha256};
use x25519_dalek::{PublicKey, ReusableSecret};
use zeroize::Zeroizing;

use sl_mpc_mate::message::*;

type Aead = ChaCha20Poly1305;

const TAG_SIZE: usize = <Aead as AeadCore>::TagSize::USIZE;
const NONCE_SIZE: usize = <Aead as AeadCore>::NonceSize::USIZE;

/// Counter to create a unique nonce.
#[derive(Default)]
pub struct NonceCounter(u32);

impl NonceCounter {
    /// New counter initialized by 0.
    pub fn new() -> Self {
        Self(0)
    }

    /// Increment counter.
    pub fn next_nonce(&mut self) -> Self {
        self.0 = self.0.wrapping_add(1);
        Self(self.0)
    }

    /// Consume counter and create a nonce. This way we can't create
    /// two equal nonces from the same counter.
    ///
    /// This is private method and should be called from encrypt() to
    /// avoid using generated nonce more than once.
    pub fn nonce(self) -> Nonce<Aead> {
        let mut nonce = Nonce::<Aead>::default();
        nonce[..4].copy_from_slice(&self.0.to_le_bytes());

        nonce
    }
}

/// A wrapper for a message of type T with support for inplace
/// encryption/decryption with additional data.
///
/// Format of enrypted message:
///
/// [ msg-hdr | additional-data | payload | trailer | tag + nonce ]
///
/// `payload | trailer` are encrypted.
///
/// `trailer` is variable-sized part of message
///
/// `payload` is external prepresentation of `T`
///
pub struct EncryptedMessage<T> {
    buffer: Vec<u8>,
    additional_data: usize, // size of additional-data
    marker: PhantomData<T>,
}

impl<T: AnyBitPattern + NoUninit> EncryptedMessage<T> {
    const T_SIZE: usize = core::mem::size_of::<T>();
    const S_SIZE: usize = TAG_SIZE + NONCE_SIZE;

    /// Size of the whole message with additional data and trailer bytes.
    pub const fn size(ad: usize, trailer: usize) -> usize {
        MESSAGE_HEADER_SIZE + ad + Self::T_SIZE + trailer + Self::S_SIZE
    }

    /// Allocate a message with passed ID and TTL and additional
    /// trailer bytes.
    pub fn new(id: &MsgId, ttl: u32, flags: u16, trailer: usize) -> Self {
        let buffer = vec![0u8; Self::size(0, trailer)];

        Self::from_buffer(buffer, id, ttl, flags, 0, trailer)
    }

    /// Allocate a message with passed ID and TTL and additional data
    /// and trailer bytes.
    pub fn new_with_ad(
        id: &MsgId,
        ttl: u32,
        flags: u16,
        additional_data: usize,
        trailer: usize,
    ) -> Self {
        let buffer = vec![0u8; Self::size(additional_data, trailer)];

        Self::from_buffer(buffer, id, ttl, flags, additional_data, trailer)
    }

    /// Use existing buffer but make sure it has the right size.
    ///
    pub fn from_buffer(
        mut buffer: Vec<u8>,
        id: &MsgId,
        ttl: u32,
        flags: u16,
        additional_data: usize,
        trailer: usize,
    ) -> Self {
        buffer.resize(Self::size(additional_data, trailer), 0);

        if let Some(hdr) = buffer.first_chunk_mut::<MESSAGE_HEADER_SIZE>() {
            MsgHdr::encode(hdr, id, ttl, flags);
        }

        Self {
            buffer,
            additional_data,
            marker: PhantomData,
        }
    }

    /// Return a mutable references to message payload object, trailer
    /// and additional data byte slices.
    pub fn payload_with_ad(&mut self) -> (&mut T, &mut [u8], &mut [u8]) {
        let tag_offset = self.buffer.len() - Self::S_SIZE;

        // body = ad | payload | trailer
        let body = &mut self.buffer[MESSAGE_HEADER_SIZE..tag_offset];

        let (additional_data, msg_and_trailer) = body.split_at_mut(self.additional_data);

        let (msg, trailer) = msg_and_trailer.split_at_mut(Self::T_SIZE);

        (bytemuck::from_bytes_mut(msg), trailer, additional_data)
    }

    /// Return a mutable reference to message payload object and trailer byte slice.
    pub fn payload(&mut self) -> (&mut T, &mut [u8]) {
        let (msg, trailer, _) = self.payload_with_ad();

        (msg, trailer)
    }

    /// Encrypt message.
    pub fn encrypt(
        self,
        secret: &ReusableSecret,
        public_key: &PublicKey,
        counter: NonceCounter,
    ) -> Option<Vec<u8>> {
        let shared_secret = secret.diffie_hellman(public_key);

        if !shared_secret.was_contributory() {
            return None;
        }

        let key = Zeroizing::new(hchacha::<U10>(
            GenericArray::from_slice(shared_secret.as_bytes()),
            &GenericArray::default(),
        ));

        let key = Zeroizing::new(
            Sha256::new_with_prefix(public_key)
                .chain_update(key)
                .finalize(),
        );

        let cipher = Aead::new(&key);

        let mut buffer = self.buffer;

        let last = buffer.len() - Self::S_SIZE;
        let (msg, tail) = buffer.split_at_mut(last);

        let (data, plaintext) = msg.split_at_mut(MESSAGE_HEADER_SIZE + self.additional_data);

        let nonce = counter.nonce();
        let tag = cipher
            .encrypt_in_place_detached(&nonce, data, plaintext)
            .ok()?;

        tail[..TAG_SIZE].copy_from_slice(&tag);
        tail[TAG_SIZE..].copy_from_slice(&nonce);

        Some(buffer)
    }

    /// Decrypt message and return references to the payload, trailer
    /// and additional data bytes.
    pub fn decrypt_with_ad<'msg>(
        buffer: &'msg mut [u8],
        additional_data: usize,
        trailer: usize,
        secret: &ReusableSecret,
        public_key: &PublicKey,
    ) -> Option<(&'msg T, &'msg [u8], &'msg [u8])> {
        let shared_secret = secret.diffie_hellman(public_key);

        if !shared_secret.was_contributory() {
            return None;
        }

        let key = Zeroizing::new(hchacha::<U10>(
            GenericArray::from_slice(shared_secret.as_bytes()),
            &GenericArray::default(),
        ));

        let key = Zeroizing::new(
            Sha256::new_with_prefix(PublicKey::from(secret))
                .chain_update(key)
                .finalize(),
        );

        let cipher = Aead::new(&key);

        if buffer.len() != Self::size(additional_data, trailer) {
            return None;
        }

        let (data, body) = buffer.split_at_mut(MESSAGE_HEADER_SIZE + additional_data);

        let (ciphertext, tail) = body.split_at_mut(body.len() - Self::S_SIZE);

        let nonce = Nonce::<Aead>::from_slice(&tail[TAG_SIZE..]);
        let tag = Tag::<Aead>::from_slice(&tail[..TAG_SIZE]);

        cipher
            .decrypt_in_place_detached(nonce, data, ciphertext, tag)
            .ok()?;

        let (msg, trailer) = ciphertext.split_at_mut(Self::T_SIZE);

        Some((
            bytemuck::from_bytes_mut(msg),
            trailer,
            &data[MESSAGE_HEADER_SIZE..],
        ))
    }

    /// Decrypte message and return reference to the payload and trailer bytes.
    pub fn decrypt<'msg>(
        buffer: &'msg mut [u8],
        trailer: usize,
        secret: &ReusableSecret,
        public_key: &PublicKey,
    ) -> Option<(&'msg T, &'msg [u8])> {
        Self::decrypt_with_ad(buffer, 0, trailer, secret, public_key)
            .map(|(msg, trailer, _)| (msg, trailer))
    }
}
