#[cfg(any(test, feature = "test-support"))]
use crate::aes::aes_gcm::run_batch_aes_256_encryption;
use crate::mpc::preprocess::{run_batch_verification_without_opening, run_verify_array_of_bits};
use crate::transport::proto::FilteredMsgRelay;
use crate::transport::setup::common::MPCEncryption;
use crate::transport::setup::CommonSetupMessage;
use crate::transport::types::ProtocolError;
#[cfg(any(test, feature = "test-support"))]
use crate::transport::utils::Seed;
use crate::transport::utils::TagOffsetCounter;
use crate::types::{BinaryShare, BinaryString, BinaryStringShare};
use crate::types::{MultTripleStorage, ServerState};
use sl_mpc_mate::coord::Relay;

/// Implementation of Protocol 2.8.1 Verify()
pub async fn run_verify<T, R>(
    setup: &T,
    mpc_encryption: &mut MPCEncryption,
    tag_offset_counter: &mut TagOffsetCounter,
    relay: &mut FilteredMsgRelay<R>,
    serverstate: &mut ServerState,
) -> Result<(), ProtocolError>
where
    T: CommonSetupMessage,
    R: Relay,
{
    // VerifyArrayOfBits
    if serverstate.unverified_list.length > 0 {
        run_verify_array_of_bits(
            setup,
            mpc_encryption,
            tag_offset_counter,
            relay,
            &serverstate.unverified_list,
        )
        .await?;
        serverstate.unverified_list = BinaryString::new();
    }

    let triples_to_verify_p = &serverstate.and_triples;
    let n = triples_to_verify_p.len();
    if n > 0 {
        if (n % 8) != 0 {
            for _ in (n % 8)..8 {
                serverstate
                    .and_triples
                    .a
                    .push_binary_share(BinaryShare::ZERO);
                serverstate
                    .and_triples
                    .b
                    .push_binary_share(BinaryShare::ZERO);
                serverstate
                    .and_triples
                    .c
                    .push_binary_share(BinaryShare::ZERO);
            }
        }

        let mut x = BinaryStringShare::new();
        let mut y = BinaryStringShare::new();
        let mut z = BinaryStringShare::new();
        x.append(&serverstate.and_triples.a);
        y.append(&serverstate.and_triples.b);
        z.append(&serverstate.and_triples.c);

        serverstate.and_triples = MultTripleStorage::new();

        run_batch_verification_without_opening(
            setup,
            mpc_encryption,
            tag_offset_counter,
            relay,
            &x,
            &y,
            &z,
            serverstate,
        )
        .await?;
    }

    Ok(())
}

/// Test Verify protocol
#[cfg(any(test, feature = "test-support"))]
async fn test_verify_protocol<T, R>(setup: T, seed: Seed, relay: R) -> Result<(), ProtocolError>
where
    T: CommonSetupMessage,
    R: Relay,
{
    use crate::mpc::common_randomness::run_common_randomness;
    use crate::transport::init::run_init;
    use crate::types::BinaryStringShare;
    use merlin::Transcript;
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

    let common_randomness = run_common_randomness(
        &setup,
        common_randomness_seed,
        &mut mpc_encryption,
        &mut relay,
    )
    .await?;

    let mut serverstate = ServerState::new(common_randomness);

    let mut tag_offset_counter = TagOffsetCounter::new();

    let mut msgsh: BinaryStringShare = BinaryStringShare::with_capacity(128);
    let mut keysh: BinaryStringShare = BinaryStringShare::with_capacity(256);

    for _ in 0..128 {
        msgsh.push(false, false);
        keysh.push(false, false);
        keysh.push(false, false);
    }

    for _ in 0..500 {
        let _ = run_batch_aes_256_encryption(
            &setup,
            &mut mpc_encryption,
            &mut tag_offset_counter,
            &mut relay,
            &[msgsh.clone()],
            &keysh,
            &mut serverstate,
        )
        .await?[0];
    }

    run_verify(
        &setup,
        &mut mpc_encryption,
        &mut tag_offset_counter,
        &mut relay,
        &mut serverstate,
    )
    .await?;

    let _ = relay.close().await;

    Ok(())
}

#[cfg(test)]
mod tests {
    use crate::mpc::verify::test_verify_protocol;
    use crate::transport::test_utils::setup_mpc;
    use sl_mpc_mate::coord::{MessageRelayService, Relay, SimpleMessageRelay};
    use tokio::task::JoinSet;

    async fn sim<S, R>(coord: S)
    where
        S: MessageRelayService<MessageRelay = R>,
        R: Relay + Send + 'static,
    {
        let parties = setup_mpc(None, &[(); 3]);

        let mut jset = JoinSet::new();
        for (setup, seed, _params) in parties {
            let relay = coord.connect().await.unwrap();

            jset.spawn(test_verify_protocol(setup, seed, relay));
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
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_verify_i() {
        sim(SimpleMessageRelay::new()).await;
    }
}
