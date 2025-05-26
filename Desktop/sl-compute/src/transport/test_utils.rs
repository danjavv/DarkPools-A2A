use crate::transport::setup::common::SetupMessage;
use crate::transport::setup::{NoSigningKey, NoVerifyingKey};

/// Generate setup messages for MPC protocol
/// For tests
pub fn setup_mpc<P>(instance: Option<[u8; 32]>, params: &[P; 3]) -> Vec<(SetupMessage, [u8; 32], P)>
where
    P: Clone,
{
    use crate::transport::setup::ProtocolParticipant;
    use sha2::{Digest, Sha256};
    use sl_mpc_mate::message::InstanceId;
    use std::time::Duration;

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
        .zip(params.iter())
        .map(|(setup, share)| {
            let mixin = [setup.participant_index() as u8 + 1];

            (
                setup,
                Sha256::new()
                    .chain_update(instance)
                    .chain_update(b"party-seed")
                    .chain_update(mixin)
                    .finalize()
                    .into(),
                share.clone(),
            )
        })
        .collect::<Vec<_>>()
}
