use crate::transport::pairs::Pairs;
use crate::transport::proto::{
    check_abort, EncryptedMessage, FilteredMsgRelay, Round, SignedMessage, Wrap,
};
use crate::transport::setup::common::MPCEncryption;
use crate::transport::setup::{ProtocolParticipant, ABORT_MESSAGE_TAG};
use crate::transport::types::ProtocolError;
use aead::rand_core::SeedableRng;
use rand_chacha::ChaCha20Rng;
use sl_mpc_mate::coord::{Relay, SinkExt};
use sl_mpc_mate::message::MessageTag;
use zeroize::Zeroizing;

/// Seed for our RNG
pub type Seed = <ChaCha20Rng as SeedableRng>::Seed;

/// Counter for tag offset.
#[derive(Default)]
pub struct TagOffsetCounter(u32);

impl TagOffsetCounter {
    /// New counter initialized by 0.
    pub fn new() -> Self {
        Self(0)
    }

    /// Increment counter and return next value
    pub fn next_value(&mut self) -> u32 {
        self.0 = self.0.wrapping_add(1);
        self.0
    }
}

/// broadcast_2
pub async fn broadcast_2<P, R, T1, T2>(
    setup: &P,
    relay: &mut FilteredMsgRelay<R>,
    tag: MessageTag,
    msg: (T1, T2),
) -> Result<(Vec<T1>, Vec<T2>), ProtocolError>
where
    P: ProtocolParticipant,
    R: Relay,
    T1: Wrap,
    T2: Wrap,
{
    #[cfg(feature = "tracing")]
    tracing::debug!("enter broadcast {:?}", tag);

    let my_party_id = setup.participant_index() as u8;
    let sizes = [msg.0.external_size(), msg.1.external_size()];
    let trailer: usize = sizes.iter().sum();

    let buffer = {
        // Do not hold SignedMessage across an await point to avoid
        // forcing ProtocolParticipant::MessageSignature to be Send
        // in case if the future returned by run() have to be Send.
        let mut buffer = SignedMessage::<(), _>::new(
            &setup.msg_id(None, tag),
            setup.message_ttl().as_secs() as _,
            0,
            trailer,
        );

        let (_, mut out) = buffer.payload();

        out = msg.0.encode(out);
        msg.1.encode(out);

        buffer.sign(setup.signer())
    };

    relay.send(buffer).await?;

    let mut p0 = Pairs::new_with_item(my_party_id, msg.0);
    let mut p1 = Pairs::new_with_item(my_party_id, msg.1);

    let mut round = Round::new(setup.total_participants() - 1, tag, relay);

    while let Some((msg, party_id, is_abort)) = round.recv().await? {
        if is_abort {
            check_abort(setup, &msg, party_id, ProtocolError::AbortProtocol)?;
            round.put_back(&msg, ABORT_MESSAGE_TAG, party_id);
            continue;
        }

        let buf = match SignedMessage::<(), _>::verify_with_trailer(
            &msg,
            trailer,
            setup.verifier(party_id),
        ) {
            Some((_, msg)) => msg,
            None => {
                // We got message with a right ID but with broken signature.
                round.put_back(&msg, tag, party_id);
                continue;
            }
        };

        let (buf, v1) = T1::decode(buf, sizes[0]).ok_or(ProtocolError::InvalidMessage)?;
        let (_buf, v2) = T2::decode(buf, sizes[1]).ok_or(ProtocolError::InvalidMessage)?;

        p0.push(party_id as _, v1);
        p1.push(party_id as _, v2);
    }

    #[cfg(feature = "tracing")]
    tracing::debug!("leave broadcast {:?}", tag);

    Ok((p0.into(), p1.into()))
}

/// Party sends a message to next party and receives a message from previous party
pub async fn p2p_send_to_next_receive_from_prev<P, R, T>(
    setup: &P,
    mpc_encryption: &mut MPCEncryption,
    tag: MessageTag,
    msg: T,
    relay: &mut FilteredMsgRelay<R>,
) -> Result<T, ProtocolError>
where
    P: ProtocolParticipant,
    R: Relay,
    T: Wrap,
{
    let next_party_id = setup.next_party_index();
    let prev_party_id = setup.prev_party_index();
    let message_size = msg.external_size();
    let trailer: usize = message_size;

    let buffer = {
        let mut buffer = EncryptedMessage::<()>::new(
            &setup.msg_id(Some(next_party_id), tag),
            setup.message_ttl().as_secs() as _,
            0,
            trailer,
        );

        let (_, out) = buffer.payload();
        msg.encode(out);

        buffer
            .encrypt(
                &mpc_encryption.dec_key,
                &mpc_encryption.enc_pub_keys[next_party_id],
                mpc_encryption.nonce_counter.next_nonce(),
            )
            .ok_or(ProtocolError::SendMessage)?
    };

    relay.send(buffer).await?;

    let mut round = Round::new(1, tag, relay);
    while let Some((msg, party_id, is_abort)) = round.recv().await? {
        if is_abort {
            check_abort(setup, &msg, party_id, ProtocolError::AbortProtocol)?;
            round.put_back(&msg, ABORT_MESSAGE_TAG, party_id);
            continue;
        }

        // We got message with a right TAG but from not expected party.
        if party_id != prev_party_id {
            round.put_back(&msg, tag, party_id);
            continue;
        }

        let mut msg = Zeroizing::new(msg);

        let (_, trailer_payload) = match EncryptedMessage::<()>::decrypt(
            &mut msg,
            trailer,
            &mpc_encryption.dec_key,
            &mpc_encryption.enc_pub_keys[party_id],
        ) {
            Some(refs) => refs,
            _ => {
                round.put_back(&msg, tag, party_id);
                continue;
            }
        };

        let (_buf, v1) =
            T::decode(trailer_payload, message_size).ok_or(ProtocolError::InvalidMessage)?;
        return Ok(v1);
    }

    Err(ProtocolError::InvalidMessage)
}

/// Party sends a message to other party
pub async fn send_to_party<P, R, T>(
    setup: &P,
    mpc_encryption: &mut MPCEncryption,
    tag: MessageTag,
    msg: T,
    to_party: usize,
    relay: &mut FilteredMsgRelay<R>,
) -> Result<(), ProtocolError>
where
    P: ProtocolParticipant,
    R: Relay,
    T: Wrap,
{
    let trailer: usize = msg.external_size();
    let buffer = {
        let mut buffer = EncryptedMessage::<()>::new(
            &setup.msg_id(Some(to_party), tag),
            setup.message_ttl().as_secs() as _,
            0,
            trailer,
        );
        let (_, out) = buffer.payload();
        msg.encode(out);
        buffer
            .encrypt(
                &mpc_encryption.dec_key,
                &mpc_encryption.enc_pub_keys[to_party],
                mpc_encryption.nonce_counter.next_nonce(),
            )
            .ok_or(ProtocolError::SendMessage)?
    };
    relay.send(buffer).await?;

    Ok(())
}

/// Party receives a message from other party
pub async fn receive_from_parties<P, R, T>(
    setup: &P,
    mpc_encryption: &mut MPCEncryption,
    tag: MessageTag,
    message_size: usize,
    from_parties: Vec<usize>,
    relay: &mut FilteredMsgRelay<R>,
) -> Result<Vec<T>, ProtocolError>
where
    P: ProtocolParticipant,
    R: Relay,
    T: Wrap,
{
    let trailer: usize = message_size;

    let mut p0 = Pairs::new();

    let mut round = Round::new(from_parties.len(), tag, relay);
    while let Some((msg, party_id, is_abort)) = round.recv().await? {
        if is_abort {
            check_abort(setup, &msg, party_id, ProtocolError::AbortProtocol)?;
            round.put_back(&msg, ABORT_MESSAGE_TAG, party_id);
            continue;
        }

        // We got message with a right TAG but from not expected party.
        if !from_parties.contains(&party_id) {
            round.put_back(&msg, tag, party_id);
            continue;
        }

        let mut msg = Zeroizing::new(msg);

        let (_, trailer_payload) = match EncryptedMessage::<()>::decrypt(
            &mut msg,
            trailer,
            &mpc_encryption.dec_key,
            &mpc_encryption.enc_pub_keys[party_id],
        ) {
            Some(refs) => refs,
            _ => {
                round.put_back(&msg, tag, party_id);
                continue;
            }
        };

        let (_buf, v1) =
            T::decode(trailer_payload, message_size).ok_or(ProtocolError::InvalidMessage)?;

        p0.push(party_id, v1);
    }

    Ok(p0.into())
}
