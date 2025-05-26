#[cfg(any(test, feature = "test-support"))]
use crate::constants::FIELD_SIZE;
#[cfg(any(test, feature = "test-support"))]
use crate::conversion::b_to_a::run_boolean_to_arithmetic;
#[cfg(any(test, feature = "test-support"))]
use crate::mpc::common_randomness::run_common_randomness;
use crate::mpc::multiply_binary_shares::run_batch_and_binary_shares;
#[cfg(any(test, feature = "test-support"))]
use crate::transport::init::run_init;
use crate::transport::proto::FilteredMsgRelay;
use crate::transport::setup::common::MPCEncryption;
use crate::transport::setup::CommonSetupMessage;
use crate::transport::types::ProtocolError;
#[cfg(any(test, feature = "test-support"))]
use crate::transport::utils::Seed;
use crate::transport::utils::TagOffsetCounter;
#[cfg(any(test, feature = "test-support"))]
use crate::types::{ArithmeticShare, BinaryArithmeticShare};
use crate::{
    mpc::circuit::{BooleanCircuit, Circuit, GateType},
    types::{BinaryStringShare, ServerState},
};
use sl_mpc_mate::coord::Relay;

/// Run CircuitEval protocol
pub async fn run_circuit_eval_file<T, R>(
    setup: &T,
    mpc_encryption: &mut MPCEncryption,
    tag_offset_counter: &mut TagOffsetCounter,
    relay: &mut FilteredMsgRelay<R>,
    circuit_file_name: &str,
    input: &[BinaryStringShare],
    serverstate: &mut ServerState,
) -> Result<Vec<BinaryStringShare>, ProtocolError>
where
    T: CommonSetupMessage,
    R: Relay,
{
    let mut circuit = BooleanCircuit::new();
    circuit.read_circuit_file(circuit_file_name);
    let topo_circuit = circuit.generate_topological_ordering();

    let mut wires: BinaryStringShare = BinaryStringShare::zero(circuit.wire_count + 1);

    for (i, input_wire_i) in circuit.input_wires.iter().enumerate() {
        for (j, input_wire_i_j) in input_wire_i.iter().enumerate() {
            wires.set_binary_share(*input_wire_i_j, &input[i].get_binary_share(j));
        }
    }

    for i in 0..=circuit.depth {
        let num_and = topo_circuit.interactive_gates[i].len();
        if num_and != 0 {
            let mut a_binary_shares = Vec::new();
            let mut b_binary_shares = Vec::new();
            for gate in topo_circuit.interactive_gates[i].iter() {
                if gate.gate_type != GateType::And {
                    panic!("Unknown gate!!!");
                }
                a_binary_shares.push(wires.get_binary_share(gate.input[0]));
                b_binary_shares.push(wires.get_binary_share(gate.input[1]));
            }
            let and_res_values = run_batch_and_binary_shares(
                setup,
                mpc_encryption,
                tag_offset_counter,
                relay,
                &a_binary_shares,
                &b_binary_shares,
                serverstate,
            )
            .await?;
            for (i, gate) in topo_circuit.interactive_gates[i].iter().enumerate() {
                wires.set_binary_share(gate.output, &and_res_values[i]);
            }
        }

        for gate in &topo_circuit.local_gates[i] {
            if gate.gate_type == GateType::Xor {
                let temp_p1 = wires
                    .get_binary_share(gate.input[0])
                    .xor(&wires.get_binary_share(gate.input[1]));
                wires.set_binary_share(gate.output, &temp_p1);
            } else if gate.gate_type == GateType::Inv {
                wires.set_binary_share(gate.output, &wires.get_binary_share(gate.input[0]).not());
            } else {
                panic!("Unknown Gate!!!");
            }
        }
    }

    let mut p1_output: Vec<BinaryStringShare> = Vec::new();
    for out in &circuit.output_wires {
        let mut temp_p1: BinaryStringShare = BinaryStringShare::new();
        for out_j in out {
            temp_p1.push(
                wires.get_binary_share(*out_j).value1,
                wires.get_binary_share(*out_j).value2,
            );
        }
        p1_output.push(temp_p1);
    }

    Ok(p1_output)
}

/// Run batch CircuitEval protocol
pub async fn run_batch_circuit_eval_file<T, R>(
    setup: &T,
    mpc_encryption: &mut MPCEncryption,
    tag_offset_counter: &mut TagOffsetCounter,
    relay: &mut FilteredMsgRelay<R>,
    circuit_file_name: &str,
    input_values: &[Vec<BinaryStringShare>],
    serverstate: &mut ServerState,
) -> Result<Vec<Vec<BinaryStringShare>>, ProtocolError>
where
    T: CommonSetupMessage,
    R: Relay,
{
    let n = input_values.len();
    let mut output_values = Vec::new();

    let mut circuit = BooleanCircuit::new();
    circuit.read_circuit_file(circuit_file_name);
    let topo_circuit = circuit.generate_topological_ordering();

    let mut wires_values = Vec::new();
    for _ in 0..n {
        let wires = BinaryStringShare::zero(circuit.wire_count + 1);
        wires_values.push(wires);
    }

    for k in 0..n {
        for (i, input_wire_i) in circuit.input_wires.iter().enumerate() {
            for (j, input_wire_i_j) in input_wire_i.iter().enumerate() {
                let input_value_bin_share = &input_values[k][i].get_binary_share(j);
                wires_values[k].set_binary_share(*input_wire_i_j, input_value_bin_share);
            }
        }
    }

    for i in 0..=circuit.depth {
        let num_and = topo_circuit.interactive_gates[i].len();
        if num_and != 0 {
            let mut a_binary_shares = Vec::new();
            let mut b_binary_shares = Vec::new();
            for wires in wires_values.iter_mut() {
                for gate in topo_circuit.interactive_gates[i].iter() {
                    if gate.gate_type != GateType::And {
                        panic!("Unknown gate!!!");
                    }
                    a_binary_shares.push(wires.get_binary_share(gate.input[0]));
                    b_binary_shares.push(wires.get_binary_share(gate.input[1]));
                }
            }
            let and_res_values = run_batch_and_binary_shares(
                setup,
                mpc_encryption,
                tag_offset_counter,
                relay,
                &a_binary_shares,
                &b_binary_shares,
                serverstate,
            )
            .await?;
            let mut offset = 0;
            for wires in wires_values.iter_mut() {
                for (i, gate) in topo_circuit.interactive_gates[i].iter().enumerate() {
                    wires.set_binary_share(gate.output, &and_res_values[i + offset]);
                }
                offset += topo_circuit.interactive_gates[i].len()
            }
        }

        for gate in &topo_circuit.local_gates[i] {
            for wires in wires_values.iter_mut() {
                if gate.gate_type == GateType::Xor {
                    let temp_p1 = wires
                        .get_binary_share(gate.input[0])
                        .xor(&wires.get_binary_share(gate.input[1]));
                    wires.set_binary_share(gate.output, &temp_p1);
                } else if gate.gate_type == GateType::Inv {
                    wires.set_binary_share(
                        gate.output,
                        &wires.get_binary_share(gate.input[0]).not(),
                    );
                } else {
                    panic!("Unknown Gate!!!");
                }
            }
        }
    }

    for wires in wires_values.iter_mut() {
        let mut p1_output: Vec<BinaryStringShare> = Vec::new();
        for out in &circuit.output_wires {
            let mut temp_p1: BinaryStringShare = BinaryStringShare::new();
            for out_j in out {
                temp_p1.push(
                    wires.get_binary_share(*out_j).value1,
                    wires.get_binary_share(*out_j).value2,
                );
            }
            p1_output.push(temp_p1);
        }
        output_values.push(p1_output);
    }

    Ok(output_values)
}

/// Test CircuitEval protocol
#[cfg(any(test, feature = "test-support"))]
async fn test_circuit_eval_file<T, R>(
    setup: T,
    seed: Seed,
    input_data: Vec<BinaryStringShare>,
    relay: R,
) -> Result<(usize, ArithmeticShare), ProtocolError>
where
    T: CommonSetupMessage,
    R: Relay,
{
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
    let filename = String::from("circuit/adder64.txt");
    let result = run_circuit_eval_file(
        &setup,
        &mut mpc_encryption,
        &mut tag_offset_counter,
        &mut relay,
        &filename,
        &input_data,
        &mut serverstate,
    )
    .await?;

    let mut p_sharr: BinaryStringShare = BinaryStringShare::with_capacity(FIELD_SIZE);
    for i in 0..FIELD_SIZE {
        let temp1 = result[0].get_binary_share(i);
        p_sharr.push(temp1.value1, temp1.value2);
    }

    let result = run_boolean_to_arithmetic(
        &setup,
        &mut mpc_encryption,
        &mut tag_offset_counter,
        &mut relay,
        &BinaryArithmeticShare::from_binary_string_share(&p_sharr),
        &mut serverstate,
    )
    .await;

    let _ = relay.close().await;

    match result {
        Ok(v) => Ok((setup.participant_index(), v)),
        Err(e) => Err(e),
    }
}

#[cfg(test)]
mod tests {
    use crate::mpc::circuit_eval::test_circuit_eval_file;
    use crate::transport::test_utils::setup_mpc;
    use crate::types::{ArithmeticShare, FieldElement};
    use crate::{
        constants::{FIELD_SIZE, FRACTION_LENGTH},
        proto::{convert_arith_to_bin, reconstruct_arith},
        types::BinaryStringShare,
    };
    use sl_mpc_mate::coord::{MessageRelayService, Relay, SimpleMessageRelay};
    use tokio::task::JoinSet;

    async fn sim<S, R>(
        coord: S,
        file_name: String,
        inputs: &[Vec<BinaryStringShare>; 3],
    ) -> Vec<ArithmeticShare>
    where
        S: MessageRelayService<MessageRelay = R>,
        R: Relay + Send + 'static,
    {
        let parties = setup_mpc(None, inputs);

        let mut jset = JoinSet::new();
        for (setup, seed, shares) in parties {
            let relay = coord.connect().await.unwrap();

            jset.spawn(test_circuit_eval_file(setup, seed, shares, relay));
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
    async fn test_circuit_eval_protocol() {
        let aval =
            FieldElement::from(23498u64).wrapping_mul(&FieldElement::from(1u64 << FRACTION_LENGTH));
        let bval = FieldElement::from(234958u64)
            .wrapping_mul(&FieldElement::from(1u64 << FRACTION_LENGTH));

        let mut inpsh = BinaryStringShare::zero(64);

        let mut input_p1: Vec<BinaryStringShare> = vec![inpsh.clone(); 2];
        let mut input_p2: Vec<BinaryStringShare> = vec![inpsh.clone(); 2];
        let mut input_p3: Vec<BinaryStringShare> = vec![inpsh.clone(); 2];

        let abin = convert_arith_to_bin(FIELD_SIZE, &aval);
        let bbin = convert_arith_to_bin(FIELD_SIZE, &bval);

        for i in 0..(abin.length as usize) {
            input_p1[0].set(i, false, abin.get(i));
            input_p2[0].set(i, false, abin.get(i));
            input_p3[0].set(i, false, abin.get(i));

            input_p1[1].set(i, false, bbin.get(i));
            input_p2[1].set(i, false, bbin.get(i));
            input_p3[1].set(i, false, bbin.get(i));
        }
        let filename = String::from("circuit/adder64.txt");
        let inputs = [input_p1, input_p2, input_p3];

        let results = sim(SimpleMessageRelay::new(), filename, &inputs).await;

        assert_eq!(results.len(), 3);
        let p1_output = &results[0];
        let p2_output = &results[1];
        let p3_output = &results[2];

        let required_output = FieldElement::from(258456u64);
        let output = reconstruct_arith(*p1_output, *p2_output, *p3_output);
        assert_eq!(required_output, output);
    }
}
