use crate::transport::proto::tags::FilteredMsgRelay;
use crate::transport::proto::NonceCounter;
use crate::transport::setup::common::MPCEncryption;
#[cfg(any(test, feature = "test-support"))]
use crate::transport::setup::common::SetupMessage;
use crate::transport::setup::{CommonSetupMessage, INIT_MSG_TAG};
#[cfg(any(test, feature = "test-support"))]
use crate::transport::setup::{NoSigningKey, NoVerifyingKey};
#[cfg(any(test, feature = "test-support"))]
use crate::transport::setup::{ProtocolParticipant, ABORT_MESSAGE_TAG};
use crate::transport::types::ProtocolError;
use crate::transport::utils::{broadcast_2, Seed};
use aead::rand_core::SeedableRng;
use rand::Rng;
use rand_chacha::ChaCha20Rng;
use sha2::{Digest, Sha256};
use sl_mpc_mate::coord::Relay;
use sl_mpc_mate::SessionId;
use x25519_dalek::{PublicKey, ReusableSecret};

/// Test Init protocol
#[cfg(any(test, feature = "test-support"))]
async fn test_run_init<T, R>(
    setup: T,
    seed: Seed,
    relay: R,
) -> Result<([u8; 32], MPCEncryption), ProtocolError>
where
    T: CommonSetupMessage,
    R: Relay,
{
    use crate::transport::proto::create_abort_message;
    use sl_mpc_mate::coord::SinkExt;

    let mut relay = FilteredMsgRelay::new(relay);
    let abort_msg = create_abort_message(&setup);
    relay.ask_messages(&setup, ABORT_MESSAGE_TAG, false).await?;

    let result = run_init(&setup, seed, &mut relay).await;

    let result = match result {
        Ok(v) => Ok(v),
        Err(ProtocolError::AbortProtocol(p)) => Err(ProtocolError::AbortProtocol(p)),
        Err(ProtocolError::SendMessage) => Err(ProtocolError::SendMessage),
        Err(err) => {
            // ignore error of sending abort message
            let _ = relay.send(abort_msg).await;
            Err(err)
        }
    };

    let _ = relay.close().await;

    result
}

/// Execute Init protocol
pub async fn run_init<T, R>(
    setup: &T,
    seed: Seed,
    relay: &mut FilteredMsgRelay<R>,
) -> Result<([u8; 32], MPCEncryption), ProtocolError>
where
    T: CommonSetupMessage,
    R: Relay,
{
    let mut rng = ChaCha20Rng::from_seed(seed);
    let _nonce_counter = NonceCounter::new();

    let session_id = SessionId::new(rng.gen());
    let dec_key = ReusableSecret::random_from_rng(&mut rng);

    relay.ask_messages(setup, INIT_MSG_TAG, false).await?;

    let (sid_i_list, enc_pub_key_list) = broadcast_2(
        setup,
        relay,
        INIT_MSG_TAG,
        (session_id, PublicKey::from(&dec_key)),
    )
    .await?;

    let final_session_id = sid_i_list
        .iter()
        .fold(Sha256::new(), |hash, sid| hash.chain_update(sid))
        .finalize()
        .into();

    let mpc_encryption = MPCEncryption {
        dec_key,
        enc_pub_keys: <[PublicKey; 3]>::try_from(enc_pub_key_list).unwrap(),
        nonce_counter: NonceCounter::default(),
    };

    Ok((final_session_id, mpc_encryption))
}

/// Generate setup messages and seeds for Init parties.
#[cfg(any(test, feature = "test-support"))]
pub(crate) fn setup_init(instance: Option<[u8; 32]>) -> Vec<(SetupMessage, [u8; 32])> {
    use std::time::Duration;

    use sl_mpc_mate::message::InstanceId;

    let instance = instance.unwrap_or_else(rand::random);

    // a signing key for each party.
    let party_sk: Vec<NoSigningKey> = std::iter::repeat_with(|| NoSigningKey)
        .take(3usize)
        .collect();

    let party_vk: Vec<NoVerifyingKey> = party_sk
        .iter()
        .enumerate()
        .map(|(party_id, _)| NoVerifyingKey::new(party_id))
        .collect();

    party_sk
        .into_iter()
        .enumerate()
        .map(|(party_id, sk)| {
            SetupMessage::new(InstanceId::new(instance), sk, party_id, party_vk.clone())
                .with_ttl(Duration::from_secs(1000))
        })
        .map(|setup| {
            let mixin = [setup.participant_index() as u8 + 1];

            (
                setup,
                Sha256::new()
                    .chain_update(instance)
                    .chain_update(b"party-seed")
                    .chain_update(mixin)
                    .finalize()
                    .into(),
            )
        })
        .collect::<Vec<_>>()
}

#[cfg(test)]
mod tests {
    use super::*;
    use sl_mpc_mate::coord::{MessageRelayService, SimpleMessageRelay};

    use tokio::task::JoinSet;

    use crate::transport::setup::common::SetupMessage;

    async fn sim<S, R>(coord: S) -> Vec<([u8; 32], MPCEncryption)>
    where
        S: MessageRelayService<MessageRelay = R>,
        R: Relay + Send + 'static,
    {
        let parties = setup_init(None);
        sim_parties(parties, coord).await
    }

    async fn sim_parties<S, R>(
        parties: Vec<(SetupMessage, [u8; 32])>,
        coord: S,
    ) -> Vec<([u8; 32], MPCEncryption)>
    where
        S: MessageRelayService<MessageRelay = R>,
        R: Send + Relay + 'static,
    {
        let mut jset = JoinSet::new();
        for (setup, seed) in parties {
            let relay = coord.connect().await.unwrap();

            jset.spawn(test_run_init(setup, seed, relay));
        }

        let mut results = vec![];

        while let Some(fini) = jset.join_next().await {
            let fini = fini.unwrap();

            if let Err(ref err) = fini {
                println!("error {}", err);
            }

            let res = fini.unwrap();
            results.push(res);
        }

        results
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_init_protocol() {
        let results = sim(SimpleMessageRelay::new()).await;
        let (final_session_id, mpc_encryption) = &results[0];
        for item in results.iter() {
            assert_eq!(item.0, *final_session_id);
            assert_eq!(item.1.enc_pub_keys, mpc_encryption.enc_pub_keys);
        }
    }
}
