// Copyright (c) Silence Laboratories Pte. Ltd. All Rights Reserved.
// This software is licensed under the Silence Laboratories License Agreement.

//!
//! Protocol setup message
//!

use std::time::Duration;

pub use signature::{SignatureEncoding, Signer, Verifier};

use sl_mpc_mate::message::{InstanceId, MessageTag, MsgId};

/// Tag for all setup messages
pub const SETUP_MESSAGE_TAG: MessageTag = MessageTag::tag(0);

/// Tag for all setup messages
pub const INIT_MSG_TAG: MessageTag = MessageTag::tag(1);

/// Tag of a broadcast message indicating that sender
/// won't participate in the protocol. The payload of
/// the message contains error code.
pub const ABORT_MESSAGE_TAG: MessageTag = MessageTag::tag(u64::MAX);

/// An iterator for parties in range 0..total except me.
pub struct AllOtherParties {
    total: usize,
    me: usize,
    curr: usize,
}

impl Iterator for AllOtherParties {
    type Item = usize;

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            let val = self.curr;

            if val >= self.total {
                return None;
            }

            self.curr += 1;

            if val != self.me {
                return Some(val);
            }
        }
    }
}

impl ExactSizeIterator for AllOtherParties {
    fn len(&self) -> usize {
        self.total - 1
    }
}

/// Type that provides a protocol participant details.
pub trait ProtocolParticipant {
    /// Type of a signature, added at end of all broadcast messages
    /// passed between participants.
    type MessageSignature: SignatureEncoding;

    /// Type to sign broadcast messages, some kind of SecretKey.
    type MessageSigner: Signer<Self::MessageSignature>;

    /// Type to verify signed message, a verifying key. AsRef<[u8]> is
    /// used to get external representation of the key to derive
    /// message ID.
    type MessageVerifier: Verifier<Self::MessageSignature> + AsRef<[u8]>;

    /// Return total number of participants of a distributed protocol.
    fn total_participants(&self) -> usize;

    /// Return a verifying key for a messages from a participant with
    /// given index.
    fn verifier(&self, index: usize) -> &Self::MessageVerifier;

    /// A signer to sign messages from the participant.
    fn signer(&self) -> &Self::MessageSigner;

    /// Return an index of the participant in a protocol.
    /// This is a value in range 0..self.total_participants()
    fn participant_index(&self) -> usize;

    /// Each execution of a distributed protocol requires
    /// a unique instance id to derive all IDs of messages.
    fn instance_id(&self) -> &InstanceId;

    /// Return message Time To Live.
    fn message_ttl(&self) -> Duration;

    /// Return reference to participant's own verifier
    fn participant_verifier(&self) -> &Self::MessageVerifier {
        self.verifier(self.participant_index())
    }

    /// Return iterator of all participant's indexes except own one.
    fn all_other_parties(&self) -> AllOtherParties {
        AllOtherParties {
            curr: 0,
            total: self.total_participants(),
            me: self.participant_index(),
        }
    }

    /// Generate ID of a message from this party to some other (or broadcast)
    /// if passed receiver is None.
    fn msg_id(&self, receiver: Option<usize>, tag: MessageTag) -> MsgId {
        self.msg_id_from(self.participant_index(), receiver, tag)
    }

    /// Generate ID of a message from given sender to a given
    /// receiver.  Receiver is designed by its index and is None for a
    /// broadcase message.
    fn msg_id_from(&self, sender: usize, receiver: Option<usize>, tag: MessageTag) -> MsgId {
        let receiver = receiver
            .map(|p| self.verifier(p))
            .map(AsRef::<[u8]>::as_ref);

        MsgId::new(
            self.instance_id(),
            self.verifier(sender).as_ref(),
            receiver.as_ref().map(AsRef::as_ref),
            tag,
        )
    }

    /// return next party_index
    fn next_party_index(&self) -> usize;

    /// return previous party_index
    fn prev_party_index(&self) -> usize;
}

/// A setup message for all sub-protocols
pub trait CommonSetupMessage: ProtocolParticipant {}

/// Setup for sub-protocols
pub mod common;

pub use keys::*;

mod keys;
