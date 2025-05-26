// Copyright (c) Silence Laboratories Pte. Ltd. All Rights Reserved.
// This software is licensed under the Silence Laboratories License Agreement.

#![allow(dead_code)]

use std::{
    collections::HashMap,
    ops::{Deref, DerefMut},
};

use crate::transport::setup::{ProtocolParticipant, ABORT_MESSAGE_TAG};
use sl_mpc_mate::coord::*;
use sl_mpc_mate::message::{MessageTag, MsgId};

/// Relay Errors
pub enum Error {
    Abort(u8),
    Recv,
    Send,
}

/// custom message relay
pub struct FilteredMsgRelay<R> {
    relay: R,
    in_buf: Vec<(Vec<u8>, usize, MessageTag)>,
    expected: HashMap<MsgId, (usize, MessageTag)>,
}

impl<R: Relay> FilteredMsgRelay<R> {
    /// Construct a FilteredMsgRelay by wrapping up a Relay object
    pub fn new(relay: R) -> Self {
        Self {
            relay,
            expected: HashMap::new(),
            in_buf: vec![],
        }
    }

    /// Mark message with ID as expected and associate pair (party-id,
    /// tag) with it.
    pub async fn expect_message(
        &mut self,
        id: MsgId,
        tag: MessageTag,
        party_id: usize,
        ttl: u32,
    ) -> Result<(), MessageSendError> {
        self.relay.ask(&id, ttl).await?;
        self.expected.insert(id, (party_id, tag));

        Ok(())
    }

    fn put_back(&mut self, msg: &[u8], tag: MessageTag, party_id: usize) {
        self.expected
            .insert(msg.try_into().unwrap(), (party_id, tag));
    }

    /// Receive an expected message with given tag, and return a
    /// party-id associated with it.
    pub async fn recv(&mut self, tag: MessageTag) -> Result<(Vec<u8>, usize, bool), Error> {
        // flush output message messages.
        self.relay.flush().await.map_err(|_| Error::Recv)?;

        if let Some(idx) = self.in_buf.iter().position(|ent| ent.2 == tag) {
            let (msg, p, _) = self.in_buf.swap_remove(idx);
            return Ok((msg, p, false));
        }

        loop {
            let msg = self.relay.next().await.ok_or(Error::Recv)?;

            if let Ok(id) = <&MsgId>::try_from(msg.as_slice()) {
                if let Some(&(p, t)) = self.expected.get(id) {
                    self.expected.remove(id);
                    match t {
                        ABORT_MESSAGE_TAG => {
                            return Ok((msg, p, true));
                        }

                        _ if t == tag => {
                            return Ok((msg, p, false));
                        }

                        _ => {
                            // some expected but not required right now message.
                            self.in_buf.push((msg, p, t));
                        }
                    }
                }
            }
        }
    }

    /// Add expected messages and Ask underlying message relay to
    /// receive them.
    pub async fn ask_messages<P: ProtocolParticipant>(
        &mut self,
        setup: &P,
        tag: MessageTag,
        p2p: bool,
    ) -> Result<(), MessageSendError> {
        let me = p2p.then_some(setup.participant_index());

        for p in setup.all_other_parties() {
            let msg_id = setup.msg_id_from(p, me, tag);
            self.expect_message(msg_id, tag, p, setup.message_ttl().as_secs() as _)
                .await?;
        }

        Ok(())
    }
}

impl<R> Deref for FilteredMsgRelay<R> {
    type Target = R;

    fn deref(&self) -> &Self::Target {
        &self.relay
    }
}

impl<R> DerefMut for FilteredMsgRelay<R> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.relay
    }
}

/// Structure to receive a round of messages
pub struct Round<'a, R> {
    tag: MessageTag,
    count: usize,
    pub(crate) relay: &'a mut FilteredMsgRelay<R>,
}

impl<'a, R: Relay> Round<'a, R> {
    /// Create a new round with a given number of messages to receive.
    pub fn new(count: usize, tag: MessageTag, relay: &'a mut FilteredMsgRelay<R>) -> Self {
        Self { count, tag, relay }
    }

    /// Receive next message in the round.
    /// On success returns Ok(Some(message, party_index, is_abort_flag)).
    /// At the end of the round it returns Ok(None).
    ///
    pub async fn recv(&mut self) -> Result<Option<(Vec<u8>, usize, bool)>, Error> {
        Ok(if self.count > 0 {
            let msg = self.relay.recv(self.tag).await;
            #[cfg(feature = "tracing")]
            if msg.is_err() {
                for (id, (p, t)) in &self.relay.expected {
                    if t == &self.tag {
                        tracing::debug!("waiting for {:X} {} {:?}", id, p, t);
                    }
                }
            }
            self.count -= 1;
            Some(msg?)
        } else {
            None
        })
    }

    /// It is possible to receive a invalid message with a correct ID.
    /// In this case, it have to put the message id back into
    /// relay.expected table and increment a counter of waiting
    /// messages in the round.
    pub fn put_back(&mut self, msg: &[u8], tag: MessageTag, party_id: usize) {
        self.relay.put_back(msg, tag, party_id);
        self.count += 1;

        // TODO Should we ASK it again?
    }
}
