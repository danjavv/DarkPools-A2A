use crate::mpc::circuit_eval::run_circuit_eval_file;
use crate::mpc::verify::run_verify;
use crate::transport::proto::FilteredMsgRelay;
use crate::transport::setup::common::MPCEncryption;
use crate::transport::setup::CommonSetupMessage;
use crate::transport::types::ProtocolError;
#[cfg(any(test, feature = "test-support"))]
use crate::transport::utils::Seed;
use crate::transport::utils::TagOffsetCounter;
use crate::types::{BinaryShare, ServerState};
use crate::{
    constants::{SHA_BLOCK_LEN, SHA_CHAIN_LEN},
    types::{BinaryString, BinaryStringShare},
};
use sl_mpc_mate::coord::Relay;
use std::path::Path;

/// Secure SHA-256 function. Follows the standards in https://datatracker.ietf.org/doc/html/rfc2104.
/// Securely runs the sha-256 basic circuit file from https://nigelsmart.github.io/MPC-Circuits/ for the hash computation.
pub async fn run_sha_256<T, R>(
    setup: &T,
    mpc_encryption: &mut MPCEncryption,
    tag_offset_counter: &mut TagOffsetCounter,
    relay: &mut FilteredMsgRelay<R>,
    share_p: &BinaryStringShare,
    serverstate: &mut ServerState,
) -> Result<BinaryStringShare, ProtocolError>
where
    T: CommonSetupMessage,
    R: Relay,
{
    let party_index = setup.participant_index();
    // Initial chaining state
    let chaining_state_hex: [u32; 8] = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
        0x5be0cd19,
    ];

    let mut chaining_state: BinaryString = BinaryString::with_capacity(SHA_CHAIN_LEN);
    for id in 0..chaining_state_hex.len() {
        let value = chaining_state_hex[7 - id];
        let mut temp2 = Vec::new();
        for i in 0..32 {
            chaining_state.push((value >> i) & 1 == 1);
            temp2.push((value >> i) & 1 == 1);
        }
    }
    let mut chaining_state_p = BinaryStringShare::from_constant(&chaining_state, party_index);

    // Padding the input
    let one_p = BinaryShare::from_constant(true, party_index);

    let mut padded_p1 = share_p.clone();
    padded_p1.push(one_p.value1, one_p.value2);

    let original_length_bits = share_p.length as usize;
    let current_length_bits = padded_p1.length as usize;

    let k = (448 - (current_length_bits % 512) + 512) % 512;

    for _ in 0..k {
        padded_p1.push(false, false);
    }

    let length_bits = original_length_bits.to_be_bytes();
    for byte in length_bits.iter() {
        for i in (0..8).rev() {
            let value = (byte >> i) & 1u8 == 1u8;
            let value_p = BinaryShare::from_constant(value, party_index);
            padded_p1.push_binary_share(value_p);
        }
    }

    let count = padded_p1.length as usize / 512;
    for i in 0..count {
        let mut block_pad_p1 = BinaryStringShare::with_capacity(SHA_BLOCK_LEN);

        for j in 0..512 {
            block_pad_p1.push_binary_share(padded_p1.get_binary_share(i * 512 + j));
        }

        block_pad_p1.reverse();

        let path = Path::new(env!("OUT_DIR"))
            .join("sha256.txt")
            .into_os_string()
            .into_string()
            .unwrap();
        let current_chaining_state = run_circuit_eval_file(
            setup,
            mpc_encryption,
            tag_offset_counter,
            relay,
            &path,
            &[block_pad_p1, chaining_state_p],
            serverstate,
        )
        .await?;

        chaining_state_p = current_chaining_state[0].clone();
    }

    chaining_state_p.reverse();

    Ok(chaining_state_p)
}

/// Test SHA-256 protocol
#[cfg(any(test, feature = "test-support"))]
async fn test_sha_256_protocol<T, R>(
    setup: T,
    seed: Seed,
    params: BinaryStringShare,
    relay: R,
) -> Result<(usize, BinaryStringShare), ProtocolError>
where
    T: CommonSetupMessage,
    R: Relay,
{
    use crate::mpc::common_randomness::run_common_randomness;
    use crate::transport::init::run_init;
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

    let result = run_sha_256(
        &setup,
        &mut mpc_encryption,
        &mut tag_offset_counter,
        &mut relay,
        &params,
        &mut serverstate,
    )
    .await;

    run_verify(
        &setup,
        &mut mpc_encryption,
        &mut tag_offset_counter,
        &mut relay,
        &mut serverstate,
    )
    .await?;

    let _ = relay.close().await;

    match result {
        Ok(v) => Ok((setup.participant_index(), v)),
        Err(e) => Err(e),
    }
}

#[cfg(test)]
mod tests {
    use super::test_sha_256_protocol;
    use crate::proto::binary_string_to_u8_vec;
    use crate::transport::test_utils::setup_mpc;
    use crate::types::BinaryString;
    use crate::{
        constants::SHA_CHAIN_LEN, proto::reconstruct_binary_share, types::BinaryStringShare,
    };
    use sl_mpc_mate::coord::{MessageRelayService, Relay, SimpleMessageRelay};
    use tokio::task::JoinSet;

    async fn sim<S, R>(coord: S, sim_params: &[BinaryStringShare; 3]) -> Vec<BinaryStringShare>
    where
        S: MessageRelayService<MessageRelay = R>,
        R: Relay + Send + 'static,
    {
        let parties = setup_mpc(None, sim_params);

        let mut jset = JoinSet::new();
        for (setup, seed, params) in parties {
            let relay = coord.connect().await.unwrap();

            jset.spawn(test_sha_256_protocol(setup, seed, params, relay));
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
    async fn test_sha_256() {
        let mut input_p1: BinaryStringShare = BinaryStringShare::new();
        let mut input_p2: BinaryStringShare = BinaryStringShare::new();
        let mut input_p3: BinaryStringShare = BinaryStringShare::new();
        for _ in 0..256 {
            input_p1.push(false, false);
            input_p2.push(false, false);
            input_p3.push(false, false);
        }

        let expected =
            hex::decode("66687AADF862BD776C8FC18B8E9F8E20089714856EE233B3902A591D0D5F2925")
                .unwrap();

        let params = [input_p1, input_p2, input_p3];

        let results = sim(SimpleMessageRelay::new(), &params).await;
        assert_eq!(results.len(), 3);

        let output_share_p1 = results[0].clone();
        let output_share_p2 = results[1].clone();
        let output_share_p3 = results[2].clone();

        let mut out: BinaryString = BinaryString::with_capacity(SHA_CHAIN_LEN);
        for i in 0..SHA_CHAIN_LEN {
            out.push(reconstruct_binary_share(
                output_share_p1.get_binary_share(i),
                output_share_p2.get_binary_share(i),
                output_share_p3.get_binary_share(i),
            ));
        }
        let output = binary_string_to_u8_vec(out);
        assert_eq!(expected, output);
    }
}
