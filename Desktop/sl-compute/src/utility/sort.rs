use crate::transport::proto::FilteredMsgRelay;
use crate::transport::setup::common::MPCEncryption;
use crate::transport::setup::CommonSetupMessage;
use crate::transport::types::ProtocolError;
#[cfg(any(test, feature = "test-support"))]
use crate::transport::utils::Seed;
use crate::transport::utils::TagOffsetCounter;
use crate::types::{BinaryArithmeticShare, FieldElement, ServerState};
use crate::{
    constants::FIELD_SIZE,
    proto::{convert_arith_to_bin, get_default_bin_share_from_bin_string},
    types::BinaryStringShare,
    utility::shuffle_sort::test_run_shuffle,
};
use sl_mpc_mate::coord::Relay;

/// Implementation of Protocol 3.17 (QuickSort) from https://github.com/silence-laboratories/research-silent-compute/blob/main/paper/main.pdf.
pub fn test_run_quick_sort(
    ord: &str,
    w_p1: Vec<BinaryStringShare>,
    w_p2: Vec<BinaryStringShare>,
    w_p3: Vec<BinaryStringShare>,
    serverstate_p1: &mut ServerState,
    serverstate_p2: &mut ServerState,
    serverstate_p3: &mut ServerState,
) -> (
    Vec<BinaryStringShare>,
    Vec<BinaryStringShare>,
    Vec<BinaryStringShare>,
) {
    // assert!(w_p1.len() == w_p2.len() && w_p1.len() == w_p3.len());
    // let n = w_p1.len();
    //
    // if n <= 1 {
    //     return (w_p1, w_p2, w_p3);
    // }
    //
    // let pivot_p1 = w_p1[0].clone();
    // let pivot_p2 = w_p2[0].clone();
    // let pivot_p3 = w_p3[0].clone();
    //
    // let mut shared_comp_p1: BinaryStringShare = BinaryStringShare::new();
    // let mut shared_comp_p2: BinaryStringShare = BinaryStringShare::new();
    // let mut shared_comp_p3: BinaryStringShare = BinaryStringShare::new();
    //
    // if ord == "asc" {
    //     for i in 1..n {
    //         let (comp_out_p1, comp_out_p2, comp_out_p3) = test_run_compare_ge_sort(
    //             &mut CompareGeSortPartyInput {
    //                 abin: &pivot_p1,
    //                 bbin: &w_p1[i],
    //                 serverstate: serverstate_p1,
    //             },
    //             &mut CompareGeSortPartyInput {
    //                 abin: &pivot_p2,
    //                 bbin: &w_p2[i],
    //                 serverstate: serverstate_p2,
    //             },
    //             &mut CompareGeSortPartyInput {
    //                 abin: &pivot_p3,
    //                 bbin: &w_p3[i],
    //                 serverstate: serverstate_p3,
    //             },
    //         );
    //         shared_comp_p1.push(comp_out_p1.value1, comp_out_p1.value2);
    //         shared_comp_p2.push(comp_out_p2.value1, comp_out_p2.value2);
    //         shared_comp_p3.push(comp_out_p3.value1, comp_out_p3.value2);
    //     }
    // } else if ord == "dec" {
    //     for i in 1..n {
    //         let (comp_out_p1, comp_out_p2, comp_out_p3) = test_run_compare_le_sort(
    //             &mut CompareLeSortPartyInput {
    //                 abin: &pivot_p1,
    //                 bbin: &w_p1[i],
    //                 serverstate: serverstate_p1,
    //             },
    //             &mut CompareLeSortPartyInput {
    //                 abin: &pivot_p2,
    //                 bbin: &w_p2[i],
    //                 serverstate: serverstate_p2,
    //             },
    //             &mut CompareLeSortPartyInput {
    //                 abin: &pivot_p3,
    //                 bbin: &w_p3[i],
    //                 serverstate: serverstate_p3,
    //             },
    //         );
    //         shared_comp_p1.push(comp_out_p1.value1, comp_out_p1.value2);
    //         shared_comp_p2.push(comp_out_p2.value1, comp_out_p2.value2);
    //         shared_comp_p3.push(comp_out_p3.value1, comp_out_p3.value2);
    //     }
    // }
    //
    // let mut compare_p1: BinaryString = BinaryString::new();
    // let mut compare_p2: BinaryString = BinaryString::new();
    // let mut compare_p3: BinaryString = BinaryString::new();
    //
    // for i in 0..(n - 1) {
    //     compare_p1.push(
    //         shared_comp_p1.get_binary_share(i).value1 ^ shared_comp_p2.get_binary_share(i).value2,
    //     );
    //     compare_p3.push(
    //         shared_comp_p2.get_binary_share(i).value1 ^ shared_comp_p3.get_binary_share(i).value2,
    //     );
    //     compare_p2.push(
    //         shared_comp_p3.get_binary_share(i).value1 ^ shared_comp_p1.get_binary_share(i).value2,
    //     );
    // }
    //
    // let mut a_p1 = Vec::new();
    // let mut a_p2 = Vec::new();
    // let mut a_p3 = Vec::new();
    //
    // let mut b_p1 = Vec::new();
    // let mut b_p2 = Vec::new();
    // let mut b_p3 = Vec::new();
    //
    // for i in 0..(n - 1) {
    //     if compare_p1.get(i) {
    //         a_p1.push(w_p1[i + 1].clone());
    //     } else {
    //         b_p1.push(w_p1[i + 1].clone());
    //     }
    //
    //     if compare_p2.get(i) {
    //         a_p2.push(w_p2[i + 1].clone());
    //     } else {
    //         b_p2.push(w_p2[i + 1].clone());
    //     }
    //
    //     if compare_p3.get(i) {
    //         a_p3.push(w_p3[i + 1].clone());
    //     } else {
    //         b_p3.push(w_p3[i + 1].clone());
    //     }
    // }
    //
    // let (sorted_a_p1, sorted_a_p2, sorted_a_p3) = test_run_quick_sort(
    //     ord,
    //     a_p1,
    //     a_p2,
    //     a_p3,
    //     serverstate_p1,
    //     serverstate_p2,
    //     serverstate_p3,
    // );
    // let (sorted_b_p1, sorted_b_p2, sorted_b_p3) = test_run_quick_sort(
    //     ord,
    //     b_p1,
    //     b_p2,
    //     b_p3,
    //     serverstate_p1,
    //     serverstate_p2,
    //     serverstate_p3,
    // );
    //
    // let mut sorted_p1 = Vec::new();
    // let mut sorted_p2 = Vec::new();
    // let mut sorted_p3 = Vec::new();
    //
    // for i in 0..sorted_a_p1.len() {
    //     sorted_p1.push(sorted_a_p1[i].clone());
    //     sorted_p2.push(sorted_a_p2[i].clone());
    //     sorted_p3.push(sorted_a_p3[i].clone());
    // }
    //
    // sorted_p1.push(pivot_p1.clone());
    // sorted_p2.push(pivot_p2.clone());
    // sorted_p3.push(pivot_p3.clone());
    //
    // for i in 0..sorted_b_p1.len() {
    //     sorted_p1.push(sorted_b_p1[i].clone());
    //     sorted_p2.push(sorted_b_p2[i].clone());
    //     sorted_p3.push(sorted_b_p3[i].clone());
    // }
    //
    // (sorted_p1, sorted_p2, sorted_p3)

    todo!();
}

/// Implementation of Protocol 3.17 (QuickSort) from https://github.com/silence-laboratories/research-silent-compute/blob/main/paper/main.pdf.
/// for BinaryArithmeticShare type
pub async fn run_quick_sort<T, R>(
    setup: &T,
    mpc_encryption: &mut MPCEncryption,
    tag_offset_counter: &mut TagOffsetCounter,
    relay: &mut FilteredMsgRelay<R>,
    ord_asc: bool,
    w_p: &[BinaryArithmeticShare],
    _serverstate: &mut ServerState,
) -> Result<Vec<BinaryArithmeticShare>, ProtocolError>
where
    T: CommonSetupMessage,
    R: Relay,
{
    //
    //     let n = w_p.len();
    //
    //     if n <= 1 {
    //         return Ok(w_p.to_vec());
    //     }
    //
    //     let pivot_p = w_p[0].clone();
    //
    //     let mut shared_comp_p= BinaryArithmeticShare::ZERO;
    //
    //     if ord_asc {
    //         for i in 1..n {
    //             let (comp_out_p1, comp_out_p2, comp_out_p3) = test_run_compare_ge_sort(
    //                 &mut CompareGeSortPartyInput {
    //                     abin: &pivot_p1,
    //                     bbin: &w_p1[i],
    //                     serverstate: serverstate_p1,
    //                 },
    //                 &mut CompareGeSortPartyInput {
    //                     abin: &pivot_p2,
    //                     bbin: &w_p2[i],
    //                     serverstate: serverstate_p2,
    //                 },
    //                 &mut CompareGeSortPartyInput {
    //                     abin: &pivot_p3,
    //                     bbin: &w_p3[i],
    //                     serverstate: serverstate_p3,
    //                 },
    //             );
    //             shared_comp_p1.push(comp_out_p1.value1, comp_out_p1.value2);
    //             shared_comp_p2.push(comp_out_p2.value1, comp_out_p2.value2);
    //             shared_comp_p3.push(comp_out_p3.value1, comp_out_p3.value2);
    //         }
    //     } else {
    //         for i in 1..n {
    //             let (comp_out_p1, comp_out_p2, comp_out_p3) = test_run_compare_le_sort(
    //                 &mut CompareLeSortPartyInput {
    //                     abin: &pivot_p1,
    //                     bbin: &w_p1[i],
    //                     serverstate: serverstate_p1,
    //                 },
    //                 &mut CompareLeSortPartyInput {
    //                     abin: &pivot_p2,
    //                     bbin: &w_p2[i],
    //                     serverstate: serverstate_p2,
    //                 },
    //                 &mut CompareLeSortPartyInput {
    //                     abin: &pivot_p3,
    //                     bbin: &w_p3[i],
    //                     serverstate: serverstate_p3,
    //                 },
    //             );
    //             shared_comp_p1.push(comp_out_p1.value1, comp_out_p1.value2);
    //             shared_comp_p2.push(comp_out_p2.value1, comp_out_p2.value2);
    //             shared_comp_p3.push(comp_out_p3.value1, comp_out_p3.value2);
    //         }
    //     }
    //
    //     let mut compare_p1: BinaryString = BinaryString::new();
    //     let mut compare_p2: BinaryString = BinaryString::new();
    //     let mut compare_p3: BinaryString = BinaryString::new();
    //
    //     for i in 0..(n - 1) {
    //         compare_p1.push(
    //             shared_comp_p1.get_binary_share(i).value1 ^ shared_comp_p2.get_binary_share(i).value2,
    //         );
    //         compare_p3.push(
    //             shared_comp_p2.get_binary_share(i).value1 ^ shared_comp_p3.get_binary_share(i).value2,
    //         );
    //         compare_p2.push(
    //             shared_comp_p3.get_binary_share(i).value1 ^ shared_comp_p1.get_binary_share(i).value2,
    //         );
    //     }
    //
    //     let mut a_p1 = Vec::new();
    //     let mut a_p2 = Vec::new();
    //     let mut a_p3 = Vec::new();
    //
    //     let mut b_p1 = Vec::new();
    //     let mut b_p2 = Vec::new();
    //     let mut b_p3 = Vec::new();
    //
    //     for i in 0..(n - 1) {
    //         if compare_p1.get(i) {
    //             a_p1.push(w_p1[i + 1].clone());
    //         } else {
    //             b_p1.push(w_p1[i + 1].clone());
    //         }
    //
    //         if compare_p2.get(i) {
    //             a_p2.push(w_p2[i + 1].clone());
    //         } else {
    //             b_p2.push(w_p2[i + 1].clone());
    //         }
    //
    //         if compare_p3.get(i) {
    //             a_p3.push(w_p3[i + 1].clone());
    //         } else {
    //             b_p3.push(w_p3[i + 1].clone());
    //         }
    //     }
    //
    //     let (sorted_a_p1, sorted_a_p2, sorted_a_p3) = test_run_quick_sort(
    //         ord,
    //         a_p1,
    //         a_p2,
    //         a_p3,
    //         serverstate_p1,
    //         serverstate_p2,
    //         serverstate_p3,
    //     );
    //     let (sorted_b_p1, sorted_b_p2, sorted_b_p3) = test_run_quick_sort(
    //         ord,
    //         b_p1,
    //         b_p2,
    //         b_p3,
    //         serverstate_p1,
    //         serverstate_p2,
    //         serverstate_p3,
    //     );
    //
    //     let mut sorted_p1 = Vec::new();
    //     let mut sorted_p2 = Vec::new();
    //     let mut sorted_p3 = Vec::new();
    //
    //     for i in 0..sorted_a_p1.len() {
    //         sorted_p1.push(sorted_a_p1[i].clone());
    //         sorted_p2.push(sorted_a_p2[i].clone());
    //         sorted_p3.push(sorted_a_p3[i].clone());
    //     }
    //
    //     sorted_p1.push(pivot_p1.clone());
    //     sorted_p2.push(pivot_p2.clone());
    //     sorted_p3.push(pivot_p3.clone());
    //
    //     for i in 0..sorted_b_p1.len() {
    //         sorted_p1.push(sorted_b_p1[i].clone());
    //         sorted_p2.push(sorted_b_p2[i].clone());
    //         sorted_p3.push(sorted_b_p3[i].clone());
    //     }
    //
    //     (sorted_p1, sorted_p2, sorted_p3)
    //
    //
    //
    //     //todo!();
    Ok(w_p.to_vec())
}

/// Test quick_sort protocol
#[cfg(any(test, feature = "test-support"))]
async fn test_quick_sort_protocol<T, R>(
    setup: T,
    seed: Seed,
    params: (bool, Vec<BinaryArithmeticShare>),
    relay: R,
) -> Result<(usize, Vec<BinaryArithmeticShare>), ProtocolError>
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

    let ord = params.0;
    let w_p = params.1;
    let result = run_quick_sort(
        &setup,
        &mut mpc_encryption,
        &mut tag_offset_counter,
        &mut relay,
        ord,
        &w_p,
        &mut serverstate,
    )
    .await;

    let _ = relay.close().await;

    match result {
        Ok(v) => Ok((setup.participant_index(), v)),
        Err(e) => Err(e),
    }
}

pub struct StableSortPartyInput<'a> {
    pub key: &'a [BinaryStringShare],
    pub data: &'a [BinaryStringShare],
    pub serverstate: &'a mut ServerState,
}

pub struct StableSortPartyOutput {
    pub key: Vec<BinaryStringShare>,
    pub data: Vec<BinaryStringShare>,
}

/// Implementation of Protocol 3.16 (StableSort) from https://github.com/silence-laboratories/research-silent-compute/blob/main/paper/main.pdf.
pub fn test_run_stable_sort(
    ord: &str,
    input_p1: &mut StableSortPartyInput,
    input_p2: &mut StableSortPartyInput,
    input_p3: &mut StableSortPartyInput,
) -> (
    StableSortPartyOutput,
    StableSortPartyOutput,
    StableSortPartyOutput,
) {
    assert!(input_p1.key.len() == input_p2.key.len() && input_p1.key.len() == input_p3.key.len());
    let n = input_p1.key.len();
    let l = input_p1.key[0].length as usize;

    assert!(
        input_p1.data.len() == input_p2.data.len() && input_p1.data.len() == input_p3.data.len()
    );
    let t = input_p1.data[0].length as usize;

    let mut ind_p1 = Vec::new();
    let mut ind_p2 = Vec::new();
    let mut ind_p3 = Vec::new();

    for i in 0..n {
        if ord == "asc" {
            let (temp_p1, temp_p2, temp_p3) = get_default_bin_share_from_bin_string(
                &convert_arith_to_bin(FIELD_SIZE, &FieldElement::from(i as u64)),
            );
            ind_p1.push(temp_p1);
            ind_p2.push(temp_p2);
            ind_p3.push(temp_p3);
        } else if ord == "dec" {
            let (temp_p1, temp_p2, temp_p3) = get_default_bin_share_from_bin_string(
                &convert_arith_to_bin(FIELD_SIZE, &FieldElement::from((n - 1 - i) as u64)),
            );
            ind_p1.push(temp_p1);
            ind_p2.push(temp_p2);
            ind_p3.push(temp_p3);
        }
    }

    let mut unique_keys_p1 = Vec::new();
    let mut unique_keys_p2 = Vec::new();
    let mut unique_keys_p3 = Vec::new();

    for i in 0..n {
        let mut temp_p1: BinaryStringShare = BinaryStringShare::new();
        for j in 0..l {
            let temp = input_p1.key[i].get_binary_share(j);
            temp_p1.push(temp.value1, temp.value2);
        }
        for j in 0..(FIELD_SIZE) {
            let temp = ind_p1[i].get_binary_share(j);
            temp_p1.push(temp.value1, temp.value2);
        }
        unique_keys_p1.push(temp_p1);

        let mut temp_p2: BinaryStringShare = BinaryStringShare::new();
        for j in 0..l {
            let temp = input_p2.key[i].get_binary_share(j);
            temp_p2.push(temp.value1, temp.value2);
        }
        for j in 0..(FIELD_SIZE) {
            let temp = ind_p2[i].get_binary_share(j);
            temp_p2.push(temp.value1, temp.value2);
        }
        unique_keys_p2.push(temp_p2);

        let mut temp_p3: BinaryStringShare = BinaryStringShare::new();
        for j in 0..l {
            let temp = input_p3.key[i].get_binary_share(j);
            temp_p3.push(temp.value1, temp.value2);
        }
        for j in 0..(FIELD_SIZE) {
            let temp = ind_p3[i].get_binary_share(j);
            temp_p3.push(temp.value1, temp.value2);
        }
        unique_keys_p3.push(temp_p3);
    }

    let mut combined_keys_p1: Vec<BinaryStringShare> = Vec::new();
    let mut combined_keys_p2: Vec<BinaryStringShare> = Vec::new();
    let mut combined_keys_p3: Vec<BinaryStringShare> = Vec::new();

    let x = 256 - (l + FIELD_SIZE + t);
    for i in 0..n {
        let mut temp_p1: BinaryStringShare = BinaryStringShare::new();
        for _ in 0..x {
            temp_p1.push(false, false);
        }
        for j in 0..(l + FIELD_SIZE) {
            let temp = unique_keys_p1[i].get_binary_share(j);
            temp_p1.push(temp.value1, temp.value2);
        }
        for j in 0..t {
            let temp = input_p1.data[i].get_binary_share(j);
            temp_p1.push(temp.value1, temp.value2);
        }
        combined_keys_p1.push(temp_p1);

        let mut temp_p2: BinaryStringShare = BinaryStringShare::new();
        for _ in 0..x {
            temp_p2.push(false, false);
        }
        for j in 0..(l + FIELD_SIZE) {
            let temp = unique_keys_p2[i].get_binary_share(j);
            temp_p2.push(temp.value1, temp.value2);
        }
        for j in 0..t {
            let temp = input_p2.data[i].get_binary_share(j);
            temp_p2.push(temp.value1, temp.value2);
        }
        combined_keys_p2.push(temp_p2);

        let mut temp_p3: BinaryStringShare = BinaryStringShare::new();
        for _ in 0..x {
            temp_p3.push(false, false);
        }
        for j in 0..(l + FIELD_SIZE) {
            let temp = unique_keys_p3[i].get_binary_share(j);
            temp_p3.push(temp.value1, temp.value2);
        }
        for j in 0..t {
            let temp = input_p3.data[i].get_binary_share(j);
            temp_p3.push(temp.value1, temp.value2);
        }
        combined_keys_p3.push(temp_p3);
    }

    let (permuted_p1, permuted_p2, permuted_p3) = test_run_shuffle(
        4 * FIELD_SIZE,
        combined_keys_p1,
        combined_keys_p2,
        combined_keys_p3,
        &mut input_p1.serverstate.common_randomness,
        &mut input_p2.serverstate.common_randomness,
        &mut input_p3.serverstate.common_randomness,
    );

    let (sorted_p1, sorted_p2, sorted_p3) = test_run_quick_sort(
        ord,
        permuted_p1,
        permuted_p2,
        permuted_p3,
        input_p1.serverstate,
        input_p2.serverstate,
        input_p3.serverstate,
    );

    let mut sorted_keys_p1 = Vec::new();
    let mut sorted_keys_p2 = Vec::new();
    let mut sorted_keys_p3 = Vec::new();

    let mut sorted_data_p1 = Vec::new();
    let mut sorted_data_p2 = Vec::new();
    let mut sorted_data_p3 = Vec::new();

    let x = 256 - (l + FIELD_SIZE + t);

    for i in 0..sorted_p1.len() {
        let mut temp1: BinaryStringShare = BinaryStringShare::new();
        for j in 0..l {
            temp1.push(
                sorted_p1[i].get_binary_share(x + j).value1,
                sorted_p1[i].get_binary_share(x + j).value2,
            );
        }
        sorted_keys_p1.push(temp1);

        let mut temp1: BinaryStringShare = BinaryStringShare::new();
        for j in 0..t {
            temp1.push(
                sorted_p1[i]
                    .get_binary_share((x + l + FIELD_SIZE) + j)
                    .value1,
                sorted_p1[i]
                    .get_binary_share((x + l + FIELD_SIZE) + j)
                    .value2,
            );
        }
        sorted_data_p1.push(temp1);

        let mut temp2: BinaryStringShare = BinaryStringShare::new();
        for j in 0..l {
            temp2.push(
                sorted_p2[i].get_binary_share(x + j).value1,
                sorted_p2[i].get_binary_share(x + j).value2,
            );
        }
        sorted_keys_p2.push(temp2);

        let mut temp2: BinaryStringShare = BinaryStringShare::new();
        for j in 0..t {
            temp2.push(
                sorted_p2[i]
                    .get_binary_share((x + l + FIELD_SIZE) + j)
                    .value1,
                sorted_p2[i]
                    .get_binary_share((x + l + FIELD_SIZE) + j)
                    .value2,
            );
        }
        sorted_data_p2.push(temp2);

        let mut temp3: BinaryStringShare = BinaryStringShare::new();
        for j in 0..l {
            temp3.push(
                sorted_p3[i].get_binary_share(x + j).value1,
                sorted_p3[i].get_binary_share(x + j).value2,
            );
        }
        sorted_keys_p3.push(temp3);

        let mut temp3: BinaryStringShare = BinaryStringShare::new();
        for j in 0..t {
            temp3.push(
                sorted_p3[i]
                    .get_binary_share((x + l + FIELD_SIZE) + j)
                    .value1,
                sorted_p3[i]
                    .get_binary_share((x + l + FIELD_SIZE) + j)
                    .value2,
            );
        }
        sorted_data_p3.push(temp3);
    }

    (
        StableSortPartyOutput {
            key: sorted_keys_p1,
            data: sorted_data_p1,
        },
        StableSortPartyOutput {
            key: sorted_keys_p2,
            data: sorted_data_p2,
        },
        StableSortPartyOutput {
            key: sorted_keys_p3,
            data: sorted_data_p3,
        },
    )
}

/// Implementation of Protocol 3.16 (StableSort) from https://github.com/silence-laboratories/research-silent-compute/blob/main/paper/main.pdf.
#[allow(clippy::too_many_arguments)]
pub async fn run_stable_sort<T, R>(
    _setup: &T,
    _mpc_encryption: &mut MPCEncryption,
    _tag_offset_counter: &mut TagOffsetCounter,
    _relay: &mut FilteredMsgRelay<R>,
    _ord: bool,
    _key: &[BinaryStringShare],
    _data: &[BinaryStringShare],
    _serverstate: &mut ServerState,
) -> Result<StableSortPartyOutput, ProtocolError>
where
    T: CommonSetupMessage,
    R: Relay,
{
    todo!();
}

/// Test stable_sort protocol
#[cfg(any(test, feature = "test-support"))]
async fn test_stable_sort_protocol<T, R>(
    setup: T,
    seed: Seed,
    params: (bool, Vec<BinaryStringShare>, Vec<BinaryStringShare>),
    relay: R,
) -> Result<(usize, StableSortPartyOutput), ProtocolError>
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

    let ord = params.0;
    let key = params.1;
    let data = params.2;
    let result = run_stable_sort(
        &setup,
        &mut mpc_encryption,
        &mut tag_offset_counter,
        &mut relay,
        ord,
        &key,
        &data,
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
    use super::{
        test_quick_sort_protocol, test_run_stable_sort, test_stable_sort_protocol,
        StableSortPartyOutput,
    };
    use crate::mpc::common_randomness::test_run_get_serverstate;
    use crate::proto::{
        convert_bin_to_arith, get_default_bin_share_from_bin_string,
        reconstruct_binary_string_share,
    };
    use crate::transport::test_utils::setup_mpc;
    use crate::types::{BinaryArithmeticShare, BinaryStringShare, FieldElement};
    use crate::utility::sort::StableSortPartyInput;
    use crate::{constants::FIELD_SIZE, proto::convert_arith_to_bin};
    use sl_mpc_mate::coord::{MessageRelayService, Relay};
    use tokio::task::JoinSet;

    async fn _sim_quick_sort<S, R>(
        coord: S,
        sim_params: &[(bool, Vec<BinaryArithmeticShare>); 3],
    ) -> Vec<Vec<BinaryArithmeticShare>>
    where
        S: MessageRelayService<MessageRelay = R>,
        R: Relay + Send + 'static,
    {
        let parties = setup_mpc(None, sim_params);

        let mut jset = JoinSet::new();
        for (setup, seed, params) in parties {
            let relay = coord.connect().await.unwrap();

            jset.spawn(test_quick_sort_protocol(setup, seed, params, relay));
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

    async fn _sim_stable_sort<S, R>(
        coord: S,
        sim_params: &[(bool, Vec<BinaryStringShare>, Vec<BinaryStringShare>); 3],
    ) -> Vec<StableSortPartyOutput>
    where
        S: MessageRelayService<MessageRelay = R>,
        R: Relay + Send + 'static,
    {
        let parties = setup_mpc(None, sim_params);

        let mut jset = JoinSet::new();
        for (setup, seed, params) in parties {
            let relay = coord.connect().await.unwrap();

            jset.spawn(test_stable_sort_protocol(setup, seed, params, relay));
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

    #[test]
    fn test_sort() {
        let (mut serverstate_p1, mut serverstate_p2, mut serverstate_p3) =
            test_run_get_serverstate();

        let test_array_key = [
            FieldElement::from(2u64),
            FieldElement::from(3u64),
            FieldElement::from(4u64),
            FieldElement::from(1u64),
            FieldElement::from(5u64),
            FieldElement::from(6u64),
            FieldElement::from(7u64),
            FieldElement::from(8u64),
            FieldElement::from(9u64),
            FieldElement::from(10u64),
        ];

        let test_array_data = [
            FieldElement::from(200u64),
            FieldElement::from(300u64),
            FieldElement::from(400u64),
            FieldElement::from(100u64),
            FieldElement::from(500u64),
            FieldElement::from(600u64),
            FieldElement::from(700u64),
            FieldElement::from(800u64),
            FieldElement::from(900u64),
            FieldElement::from(1000u64),
        ];
        let n = test_array_key.len();

        // Generate binary sharings of the test array
        let mut key_p1 = Vec::new();
        let mut key_p2 = Vec::new();
        let mut key_p3 = Vec::new();

        let mut data_p1 = Vec::new();
        let mut data_p2 = Vec::new();
        let mut data_p3 = Vec::new();

        for i in 0..n {
            let (temp1, temp2, temp3) = get_default_bin_share_from_bin_string(
                &convert_arith_to_bin(FIELD_SIZE, &test_array_key[i]),
            );
            key_p1.push(temp1);
            key_p2.push(temp2);
            key_p3.push(temp3);

            let (temp1, temp2, temp3) = get_default_bin_share_from_bin_string(
                &convert_arith_to_bin(FIELD_SIZE, &test_array_data[i]),
            );
            data_p1.push(temp1);
            data_p2.push(temp2);
            data_p3.push(temp3);
        }

        let (sorted_out_p1, sorted_out_p2, sorted_out_p3) = test_run_stable_sort(
            "asc",
            &mut StableSortPartyInput {
                key: &key_p1,
                data: &data_p1,
                serverstate: &mut serverstate_p1,
            },
            &mut StableSortPartyInput {
                key: &key_p2,
                data: &data_p2,
                serverstate: &mut serverstate_p2,
            },
            &mut StableSortPartyInput {
                key: &key_p3,
                data: &data_p3,
                serverstate: &mut serverstate_p3,
            },
        );

        // test_run_verify(
        //     &mut serverstate_p1,
        //     &mut serverstate_p2,
        //     &mut serverstate_p3,
        // );

        let mut result_key = Vec::new();
        for i in 0..n {
            result_key.push(convert_bin_to_arith(reconstruct_binary_string_share(
                &sorted_out_p1.key[i],
                &sorted_out_p2.key[i],
                &sorted_out_p3.key[i],
            )));
        }

        let mut result_data = Vec::new();
        for i in 0..n {
            result_data.push(convert_bin_to_arith(reconstruct_binary_string_share(
                &sorted_out_p1.data[i],
                &sorted_out_p2.data[i],
                &sorted_out_p3.data[i],
            )));
        }

        let required_key = vec![
            FieldElement::from(1u64),
            FieldElement::from(2u64),
            FieldElement::from(3u64),
            FieldElement::from(4u64),
            FieldElement::from(5u64),
            FieldElement::from(6u64),
            FieldElement::from(7u64),
            FieldElement::from(8u64),
            FieldElement::from(9u64),
            FieldElement::from(10u64),
        ];
        let required_data = vec![
            FieldElement::from(100u64),
            FieldElement::from(200u64),
            FieldElement::from(300u64),
            FieldElement::from(400u64),
            FieldElement::from(500u64),
            FieldElement::from(600u64),
            FieldElement::from(700u64),
            FieldElement::from(800u64),
            FieldElement::from(900u64),
            FieldElement::from(1000u64),
        ];

        assert_eq!(required_key, result_key);
        assert_eq!(required_data, result_data)
    }
}
