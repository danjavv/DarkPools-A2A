use crate::constants::BLOCK_SIZE;
use crate::mpc::circuit_eval::run_batch_circuit_eval_file;
use crate::transport::proto::FilteredMsgRelay;
use crate::transport::setup::common::MPCEncryption;
use crate::transport::setup::CommonSetupMessage;
use crate::transport::types::ProtocolError;
#[cfg(any(test, feature = "test-support"))]
use crate::transport::utils::Seed;
use crate::transport::utils::TagOffsetCounter;
use crate::types::FieldElement;
use crate::{
    constants::FIELD_SIZE,
    proto::{convert_arith_to_bin, u8_vec_to_binary_string},
    types::{BinaryStringShare, ServerState},
};
use sl_mpc_mate::coord::Relay;
use std::path::Path;

/// AES-256 Encryption. Securely runs the aes-256 basic circuit file from https://nigelsmart.github.io/MPC-Circuits/.
#[allow(clippy::needless_lifetimes)]
pub async fn run_batch_aes_256_encryption<T, R>(
    setup: &T,
    mpc_encryption: &mut MPCEncryption,
    tag_offset_counter: &mut TagOffsetCounter,
    relay: &mut FilteredMsgRelay<R>,
    messages: &[BinaryStringShare],
    key: &BinaryStringShare,
    server_state: &mut ServerState,
) -> Result<Vec<BinaryStringShare>, ProtocolError>
where
    T: CommonSetupMessage,
    R: Relay,
{
    let path = Path::new(env!("OUT_DIR"))
        .join("aes256.txt")
        .into_os_string()
        .into_string()
        .unwrap();

    let mut key_rev = key.clone();
    key_rev.reverse();

    let mut output_values = Vec::new();
    let mut input_values = Vec::new();
    for msg in messages {
        let mut msg_rev = msg.clone();
        msg_rev.reverse();

        input_values.push(vec![key_rev.clone(), msg_rev]);
    }

    let out_values = run_batch_circuit_eval_file(
        setup,
        mpc_encryption,
        tag_offset_counter,
        relay,
        &path,
        &input_values,
        server_state,
    )
    .await?;

    for out in out_values.iter() {
        let mut output_p: BinaryStringShare = BinaryStringShare::with_capacity(BLOCK_SIZE);
        for i in 0..128 {
            let temp1 = out[0].get_binary_share(127 - i);
            output_p.push(temp1.value1, temp1.value2);
        }
        output_values.push(output_p)
    }

    Ok(output_values)
}

/// AES-256 GCM mode. Follows the standards in https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38d.pdf.
/// TODO it is not a complete implementation of AES-GCM
#[allow(clippy::too_many_arguments)]
pub async fn run_aes_gcm<T, R>(
    setup: &T,
    mpc_encryption: &mut MPCEncryption,
    tag_offset_counter: &mut TagOffsetCounter,
    relay: &mut FilteredMsgRelay<R>,
    msgbyt: &[u8],
    key: BinaryStringShare,
    iv: BinaryStringShare,
    serverstate: &mut ServerState,
) -> Result<BinaryStringShare, ProtocolError>
where
    T: CommonSetupMessage,
    R: Relay,
{
    let msglen = msgbyt.len();
    let msgbool = u8_vec_to_binary_string(msgbyt.to_vec());

    let num_encryptions = msglen.div_ceil(16);

    let mut ivpltext_p1: BinaryStringShare = BinaryStringShare::zero(128);
    for i in 0..96 {
        ivpltext_p1.set_binary_share(i, &iv.get_binary_share(i));
    }

    let mut messages_to_aes = Vec::new();
    let mut count = 1;
    while count < (1usize << 32) && count <= num_encryptions {
        let countbin = convert_arith_to_bin(FIELD_SIZE, &FieldElement::from((count + 1) as u64));

        for i in 0..32 {
            ivpltext_p1.set(i + 96, false, countbin.get(31 - i));
        }

        messages_to_aes.push(ivpltext_p1.clone());
        count += 1;
    }

    let out_values = run_batch_aes_256_encryption(
        setup,
        mpc_encryption,
        tag_offset_counter,
        relay,
        &messages_to_aes,
        &key,
        serverstate,
    )
    .await?;

    let mut ciphertext_p1: BinaryStringShare = BinaryStringShare::new();
    let mut count = 1;
    for out in out_values.iter() {
        for i in 0..128 {
            if (count - 1) * 128 + i >= msglen * 8 {
                break;
            }
            ciphertext_p1.push(
                out.get_binary_share(i).value1,
                out.get_binary_share(i).value2 ^ msgbool.get((count - 1) * 128 + i),
            );
        }
        count += 1;
    }

    Ok(ciphertext_p1)
}

/// Test AES-GCM encryption protocol
#[cfg(any(test, feature = "test-support"))]
async fn test_aes_256_gcm_protocol<T, R>(
    setup: T,
    seed: Seed,
    params: (Vec<u8>, BinaryStringShare, BinaryStringShare),
    relay: R,
) -> Result<(usize, BinaryStringShare), ProtocolError>
where
    T: CommonSetupMessage,
    R: Relay,
{
    use crate::mpc::common_randomness::run_common_randomness;
    use crate::mpc::verify::run_verify;
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

    let msgbyt = params.0;
    let key = params.1;
    let iv = params.2;
    let result = run_aes_gcm(
        &setup,
        &mut mpc_encryption,
        &mut tag_offset_counter,
        &mut relay,
        &msgbyt,
        key,
        iv,
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
    use super::test_aes_256_gcm_protocol;
    use crate::proto::binary_string_to_u8_vec;
    use crate::transport::test_utils::setup_mpc;
    use crate::types::BinaryString;
    use crate::{
        proto::{reconstruct_binary_share, u8_vec_to_binary_string},
        types::BinaryStringShare,
    };
    use sl_mpc_mate::coord::{MessageRelayService, Relay, SimpleMessageRelay};
    use tokio::task::JoinSet;

    async fn sim<S, R>(
        coord: S,
        sim_params: &[(Vec<u8>, BinaryStringShare, BinaryStringShare); 3],
    ) -> Vec<BinaryStringShare>
    where
        S: MessageRelayService<MessageRelay = R>,
        R: Relay + Send + 'static,
    {
        let parties = setup_mpc(None, sim_params);

        let mut jset = JoinSet::new();
        for (setup, seed, params) in parties {
            let relay = coord.connect().await.unwrap();

            jset.spawn(test_aes_256_gcm_protocol(setup, seed, params, relay));
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
    async fn test_aes_256_gcm() {
        // Test Case 16
        // https://luca-giuzzi.unibs.it/corsi/Support/papers-cryptography/gcm-spec.pdf
        let key = hex::decode("feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308")
            .unwrap();
        let iv = hex::decode("cafebabefacedbaddecaf888").unwrap();
        let plain = hex::decode("d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39").unwrap();
        let ciphertext = hex::decode("522dc1f099567d07f47f37a32a84427d643a8cdcbfe5c0c97598a2bd2555d1aa8cb08e48590dbb3da7b08b1056828838c5f61e6393ba7a0abcc9f662").unwrap();

        let keybool = u8_vec_to_binary_string(key);
        let mut key_p1 = BinaryStringShare::with_capacity(256);
        let mut key_p2 = BinaryStringShare::with_capacity(256);
        let mut key_p3 = BinaryStringShare::with_capacity(256);
        for i in 0..256 {
            let keybool_i = keybool.get(i);
            key_p1.push(false, keybool_i);
            key_p2.push(false, keybool_i);
            key_p3.push(false, keybool_i);
        }

        let ivbool = u8_vec_to_binary_string(iv);
        let mut iv_p1 = BinaryStringShare::with_capacity(96);
        let mut iv_p2 = BinaryStringShare::with_capacity(96);
        let mut iv_p3 = BinaryStringShare::with_capacity(96);
        for i in 0..96 {
            let ivbool_i = ivbool.get(i);
            iv_p1.push(false, ivbool_i);
            iv_p2.push(false, ivbool_i);
            iv_p3.push(false, ivbool_i);
        }

        let params = [
            (plain.clone(), key_p1, iv_p1),
            (plain.clone(), key_p2, iv_p2),
            (plain.clone(), key_p3, iv_p3),
        ];

        let results = sim(SimpleMessageRelay::new(), &params).await;
        assert_eq!(results.len(), 3);

        let output_share_p1 = results[0].clone();
        let output_share_p2 = results[1].clone();
        let output_share_p3 = results[2].clone();

        let mut out: BinaryString = BinaryString::with_capacity(output_share_p1.length as usize);

        for i in 0..output_share_p1.length as usize {
            out.push(reconstruct_binary_share(
                output_share_p1.get_binary_share(i),
                output_share_p2.get_binary_share(i),
                output_share_p3.get_binary_share(i),
            ));
        }
        let output = binary_string_to_u8_vec(out);

        assert_eq!(ciphertext, output);
    }
}
