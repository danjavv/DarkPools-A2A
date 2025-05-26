use crate::constants::COMMON_RAND_MSG;
#[cfg(any(test, feature = "test-support"))]
use crate::transport::init::run_init;
use crate::transport::proto::FilteredMsgRelay;
use crate::transport::setup::common::MPCEncryption;
use crate::transport::setup::CommonSetupMessage;
use crate::transport::types::ProtocolError;
use crate::transport::utils::{p2p_send_to_next_receive_from_prev, Seed};
use crate::types::BinaryStringShare;
use crate::types::ServerState;
use aead::rand_core::SeedableRng;
#[cfg(any(test, feature = "test-support"))]
use merlin::Transcript;
use rand::Rng;
use rand_chacha::ChaCha20Rng;
use sl_mpc_mate::coord::Relay;

#[derive(Clone, Debug)]
pub struct CommonRandomness {
    f1: ChaCha20Rng,
    f2: ChaCha20Rng,
}

impl CommonRandomness {
    /// New CommonRandomness
    pub fn new(key_prev: [u8; 32], key_next: [u8; 32]) -> Self {
        CommonRandomness {
            f1: ChaCha20Rng::from_seed(key_prev),
            f2: ChaCha20Rng::from_seed(key_next),
        }
    }

    /// Implementation of the Protocol 2.3.2. RandomZero()
    pub fn random_zero_bool(&mut self) -> bool {
        let rb: bool = self.f2.gen();
        let ra: bool = self.f1.gen();
        rb ^ ra
    }

    /// Implementation of the Protocol 2.3.3. RandomBit()
    pub fn random_bit(&mut self) -> [bool; 2] {
        let rb: bool = self.f2.gen();
        let ra: bool = self.f1.gen();
        [ra ^ rb, rb]
    }

    /// RandomZeroByte()
    pub fn random_zero_byte(&mut self) -> u8 {
        let rb: u8 = self.f2.gen();
        let ra: u8 = self.f1.gen();
        rb ^ ra
    }

    /// RandomByte()
    pub fn random_byte_share(&mut self) -> [u8; 2] {
        let rb: u8 = self.f2.gen();
        let ra: u8 = self.f1.gen();
        [ra ^ rb, rb]
    }

    /// Returns (random_prev: [u8; 8], random_next: [u8; 8])
    pub fn random_8_bytes(&mut self) -> ([u8; 8], [u8; 8]) {
        let ra: [u8; 8] = self.f1.gen();
        let rb: [u8; 8] = self.f2.gen();
        (ra, rb)
    }

    /// Returns (random_prev: [u8; 32], random_next: [u8; 32])
    pub fn random_32_bytes(&mut self) -> ([u8; 32], [u8; 32]) {
        let ra: [u8; 32] = self.f1.gen();
        let rb: [u8; 32] = self.f2.gen();
        (ra, rb)
    }

    pub fn random_binary_string_share(&mut self, l: usize) -> BinaryStringShare {
        let size_in_bytes = (l + 7) / 8;
        let mut value1 = Vec::with_capacity(size_in_bytes);
        let mut value2 = Vec::with_capacity(size_in_bytes);
        for _ in 0..size_in_bytes {
            let [v1, v2] = self.random_byte_share();
            value1.push(v1);
            value2.push(v2);
        }
        BinaryStringShare {
            length: l as u64,
            value1,
            value2,
        }
    }
}

/// Implementation of the Protocol 2.3.1.
pub async fn run_common_randomness<T, R>(
    setup: &T,
    seed: Seed,
    mpc_encryption: &mut MPCEncryption,
    relay: &mut FilteredMsgRelay<R>,
) -> Result<CommonRandomness, ProtocolError>
where
    T: CommonSetupMessage,
    R: Relay,
{
    relay.ask_messages(setup, COMMON_RAND_MSG, true).await?;

    let mut rng = ChaCha20Rng::from_seed(seed);
    let key_next: [u8; 32] = rng.gen();

    let key_prev =
        p2p_send_to_next_receive_from_prev(setup, mpc_encryption, COMMON_RAND_MSG, key_next, relay)
            .await?;

    if key_prev == key_next {
        return Err(ProtocolError::VerificationError);
    }

    Ok(CommonRandomness::new(key_prev, key_next))
}

/// Test CommonRandomness protocol
#[cfg(any(test, feature = "test-support"))]
async fn test_run_common_randomness<T, R>(
    setup: T,
    seed: Seed,
    relay: R,
) -> Result<(usize, CommonRandomness), ProtocolError>
where
    T: CommonSetupMessage,
    R: Relay,
{
    use sl_mpc_mate::coord::SinkExt;

    let mut relay = FilteredMsgRelay::new(relay);
    // let abort_msg = create_abort_message(&setup);
    // relay.ask_messages(&setup, ABORT_MESSAGE_TAG, false).await?;

    let mut init_seed = [0u8; 32];
    let mut common_randomness_seed = [0u8; 32];
    let mut transcript = Transcript::new(b"test");
    transcript.append_message(b"seed", &seed);
    transcript.challenge_bytes(b"init-seed", &mut init_seed);
    transcript.challenge_bytes(b"common-randomness-seed", &mut common_randomness_seed);

    let (_sid, mut mpc_encryption) = run_init(&setup, init_seed, &mut relay).await?;

    let result = run_common_randomness(
        &setup,
        common_randomness_seed,
        &mut mpc_encryption,
        &mut relay,
    )
    .await;

    let _ = relay.close().await;

    match result {
        Ok(v) => Ok((setup.participant_index(), v)),
        Err(e) => Err(e),
    }
}

pub fn test_run_get_serverstate() -> (ServerState, ServerState, ServerState) {
    let mut rng = ChaCha20Rng::from_seed([0u8; 32]);

    let k1 = rng.gen();
    let k2 = rng.gen();
    let k3 = rng.gen();

    let randomness_p1 = CommonRandomness::new(k3, k1);
    let randomness_p2 = CommonRandomness::new(k1, k2);
    let randomness_p3 = CommonRandomness::new(k2, k3);

    let serverstate_p1 = ServerState::new(randomness_p1);
    let serverstate_p2 = ServerState::new(randomness_p2);
    let serverstate_p3 = ServerState::new(randomness_p3);

    (serverstate_p1, serverstate_p2, serverstate_p3)
}

#[cfg(test)]
mod tests {
    use super::{test_run_common_randomness, CommonRandomness};
    use crate::transport::init::setup_init;
    use crate::transport::setup::common::SetupMessage;

    use sl_mpc_mate::coord::{MessageRelayService, Relay, SimpleMessageRelay};
    use tokio::task::JoinSet;

    async fn sim<S, R>(coord: S) -> Vec<CommonRandomness>
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
    ) -> Vec<CommonRandomness>
    where
        S: MessageRelayService<MessageRelay = R>,
        R: Send + Relay + 'static,
    {
        let mut jset = JoinSet::new();
        for (setup, seed) in parties {
            let relay = coord.connect().await.unwrap();

            jset.spawn(test_run_common_randomness(setup, seed, relay));
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

        results.sort_by_key(|r| r.0);
        results.into_iter().map(|r| r.1).collect()
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_common_randomness() {
        let results = sim(SimpleMessageRelay::new()).await;
        assert_eq!(results.len(), 3);

        let mut randomness_p1 = results[0].clone();
        let mut randomness_p2 = results[1].clone();
        let mut randomness_p3 = results[2].clone();

        let a1 = randomness_p1.random_zero_bool();
        let a2 = randomness_p2.random_zero_bool();
        let a3 = randomness_p3.random_zero_bool();
        assert_eq!(a1 ^ a2 ^ a3, false);

        let a1 = randomness_p1.random_zero_byte();
        let a2 = randomness_p2.random_zero_byte();
        let a3 = randomness_p3.random_zero_byte();
        assert_eq!(a1 ^ a2 ^ a3, 0u8);

        let [t1, s1] = randomness_p1.random_bit();
        let [t2, s2] = randomness_p2.random_bit();
        let [t3, s3] = randomness_p3.random_bit();
        assert_eq!(t1 ^ s2, t2 ^ s3);
        assert_eq!(t2 ^ s3, t3 ^ s1);

        let [t1, s1] = randomness_p1.random_byte_share();
        let [t2, s2] = randomness_p2.random_byte_share();
        let [t3, s3] = randomness_p3.random_byte_share();
        assert_eq!(t1 ^ s2, t2 ^ s3);
        assert_eq!(t2 ^ s3, t3 ^ s1);
    }
}
