// Copyright (c) Silence Laboratories Pte. Ltd. All Rights Reserved.
// This software is licensed under the Silence Laboratories License Agreement.

#![allow(missing_docs)]

use std::marker::PhantomData;
use std::time::Duration;

use signature::{SignatureEncoding, Signer, Verifier};

use sl_mpc_mate::message::InstanceId;
use x25519_dalek::{PublicKey, ReusableSecret};

const DEFAULT_TTL: u64 = 100; // smaller timeout might fail tests

use crate::transport::proto::NonceCounter;
use crate::transport::setup::{
    keys::{NoSignature, NoSigningKey, NoVerifyingKey},
    CommonSetupMessage, ProtocolParticipant,
};

/// MPCEncryption struct with public encryption keys, own decryption key and nonce counter
pub struct MPCEncryption {
    pub(crate) dec_key: ReusableSecret,
    pub(crate) enc_pub_keys: [PublicKey; 3],
    pub(crate) nonce_counter: NonceCounter,
}

#[derive(Clone)]
pub struct SetupMessage<SK = NoSigningKey, VK = NoVerifyingKey, MS = NoSignature> {
    n: usize,
    party_id: usize,
    sk: SK,
    vk: Vec<VK>,
    inst: InstanceId,
    ttl: Duration,
    marker: PhantomData<MS>,
}

impl<SK, VK, MS> SetupMessage<SK, VK, MS> {
    pub fn new(inst: InstanceId, sk: SK, party_id: usize, vk: Vec<VK>) -> Self {
        Self {
            n: 3,
            party_id,
            sk,
            vk,
            inst,
            ttl: Duration::from_secs(DEFAULT_TTL),
            marker: PhantomData,
        }
    }

    pub fn with_ttl(mut self, ttl: Duration) -> Self {
        self.ttl = ttl;
        self
    }

    pub fn with_instance_id(mut self, inst: InstanceId) -> Self {
        self.inst = inst;
        self
    }
}

impl<SK, VK, MS> ProtocolParticipant for SetupMessage<SK, VK, MS>
where
    SK: Signer<MS>,
    MS: SignatureEncoding,
    VK: AsRef<[u8]> + Verifier<MS>,
{
    type MessageSignature = MS;
    type MessageSigner = SK;
    type MessageVerifier = VK;

    fn total_participants(&self) -> usize {
        self.n
    }

    fn participant_index(&self) -> usize {
        self.party_id
    }

    fn instance_id(&self) -> &InstanceId {
        &self.inst
    }

    fn message_ttl(&self) -> Duration {
        self.ttl
    }

    fn verifier(&self, index: usize) -> &Self::MessageVerifier {
        &self.vk[index]
    }

    fn signer(&self) -> &Self::MessageSigner {
        &self.sk
    }

    fn next_party_index(&self) -> usize {
        (self.party_id + 1) % 3
    }

    fn prev_party_index(&self) -> usize {
        if self.party_id == 0 {
            2
        } else {
            self.party_id - 1
        }
    }
}

impl<SK, VK, MS> CommonSetupMessage for SetupMessage<SK, VK, MS>
where
    SK: Signer<MS>,
    MS: SignatureEncoding,
    VK: AsRef<[u8]> + Verifier<MS>,
{
}
