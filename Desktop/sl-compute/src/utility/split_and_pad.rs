use crate::comparison::compare_equal::run_batch_compare_eq_byte;
use crate::comparison::compare_ge::run_batch_compare_ge;
use crate::conversion::a_to_b::run_batch_arithmetic_to_boolean;
use crate::conversion::b_to_a::run_batch_boolean_to_arithmetic;
use crate::mpc::open_protocol::{run_batch_open_arith, run_batch_open_binary_share};
use crate::transport::proto::FilteredMsgRelay;
use crate::transport::setup::common::MPCEncryption;
use crate::transport::setup::CommonSetupMessage;
use crate::transport::types::ProtocolError;
#[cfg(any(test, feature = "test-support"))]
use crate::transport::utils::Seed;
use crate::transport::utils::TagOffsetCounter;
use crate::types::{BinaryArithmeticShare, ByteShare, FieldElement, ServerState};
use crate::utility::shuffle_input_table::run_shuffle_serialized_table;
use crate::{
    proto::u8_vec_to_binary_string,
    types::{ArithmeticShare, Binary, BinaryShare, BinaryString, BinaryStringShare},
};

use sl_mpc_mate::coord::Relay;

#[derive(Clone)]
pub struct InputTableEntry {
    pub char: ByteShare,
    pub orig_id: ArithmeticShare,
    pub orig_id_clear: FieldElement,
    pub is_delimiter: BinaryShare,
    pub is_delimiter_clear: Binary,
    pub row_id: ArithmeticShare,
    pub row_id_clear: FieldElement,
    pub row_length: ArithmeticShare,
    pub row_cum: ArithmeticShare,
    pub ind_in_row: ArithmeticShare,
    pub target_loc: ArithmeticShare,
    pub target_loc_clear: FieldElement,
}

impl InputTableEntry {
    pub fn new(char: &ByteShare, origin_id: usize, party_index: usize) -> Self {
        let idshare =
            ArithmeticShare::from_constant(&FieldElement::from(origin_id as u64), party_index);
        Self {
            char: *char,
            orig_id: idshare,
            is_delimiter: BinaryShare::ZERO,
            is_delimiter_clear: false,
            row_id: ArithmeticShare::ZERO,
            row_id_clear: FieldElement::ZERO,
            orig_id_clear: FieldElement::ZERO,
            row_length: ArithmeticShare::ZERO,
            row_cum: ArithmeticShare::ZERO,
            ind_in_row: ArithmeticShare::ZERO,
            target_loc: ArithmeticShare::ZERO,
            target_loc_clear: FieldElement::ZERO,
        }
    }
}

#[derive(Clone, Copy)]
pub struct DelimiterTableEntry {
    pub orig_id: ArithmeticShare,
    pub is_delimiter_clear: Binary,
    pub row_id_clear: FieldElement,
    pub row_length: ArithmeticShare,
    pub row_length_wo_del: ArithmeticShare,
}

impl DelimiterTableEntry {
    pub fn new(iptableentry: &InputTableEntry) -> Self {
        Self {
            orig_id: iptableentry.orig_id,
            is_delimiter_clear: iptableentry.is_delimiter_clear,
            row_id_clear: iptableentry.row_id_clear,
            row_length: iptableentry.row_length,
            row_length_wo_del: ArithmeticShare::ZERO,
        }
    }
}

pub struct DelimiterTable {
    table: Vec<DelimiterTableEntry>,
}

impl DelimiterTable {
    pub fn new(iptable: &InputTable) -> DelimiterTable {
        let mut table = Vec::new();
        for i in 0..iptable.0.len() {
            if iptable.0[i].is_delimiter_clear {
                let entry = DelimiterTableEntry::new(&iptable.0[i]);
                table.push(entry);
            }
        }
        Self { table }
    }

    pub fn sort_by_row_id_clear(&mut self) {
        self.table
            .sort_by(|a, b| a.row_id_clear.cmp(&b.row_id_clear));
    }
}

pub struct InputTable(pub Vec<InputTableEntry>);

impl InputTable {
    pub fn new(share: &[ByteShare], party_index: usize) -> Self {
        let mut out = Vec::new();
        for (i, share_i) in share.iter().enumerate() {
            out.push(InputTableEntry::new(share_i, i, party_index));
        }
        InputTable(out)
    }

    pub fn _sort_by_row_id_clear(&mut self) {
        self.0.sort_by(|a, b| a.row_id_clear.cmp(&b.row_id_clear));
    }

    pub fn sort_by_orig_id_clear(&mut self) {
        self.0.sort_by(|a, b| a.orig_id_clear.cmp(&b.orig_id_clear));
    }

    pub fn sort_by_target_loc_clear(&mut self) {
        self.0
            .sort_by(|a, b| a.target_loc_clear.cmp(&b.target_loc_clear));
    }
}

pub fn get_byte_str_share(input: &str, party_id: usize) -> Vec<ByteShare> {
    let mut output = Vec::new();
    for i in input.as_bytes() {
        let booli = u8_vec_to_binary_string(vec![*i]);
        assert!(booli.length == 8);
        let mut outtemp = BinaryStringShare::with_capacity(8);
        for j in 0..8 {
            let booli_j = booli.get(j);
            let share = BinaryShare::from_constant(booli_j, party_id - 1);
            outtemp.push(share.value1, share.value2);
        }
        output.push(ByteShare::from_binary_string_share(&outtemp));
    }
    output
}

pub struct SerializedInputTable {
    pub ser_table: Vec<Vec<BinaryStringShare>>,
}

pub struct SplitAndPadPartyInput<'a> {
    pub share: &'a [BinaryStringShare],
    pub serverstate: &'a mut ServerState,
}

#[derive(Clone)]
pub struct SplitAndPadPltextInput {
    pub pad_character: BinaryString,
    pub max_rec_len: u64,
    pub delimiter: BinaryString,
}

#[derive(Clone)]
pub struct SplitAndPadPartyOutput {
    pub out: Vec<Vec<ByteShare>>,
}

/// Run serialize_input_table
pub async fn run_serialize_input_table<T, R>(
    setup: &T,
    mpc_encryption: &mut MPCEncryption,
    tag_offset_counter: &mut TagOffsetCounter,
    relay: &mut FilteredMsgRelay<R>,
    table: &InputTable,
    serverstate: &mut ServerState,
) -> Result<Vec<Vec<BinaryArithmeticShare>>, ProtocolError>
where
    T: CommonSetupMessage,
    R: Relay,
{
    let mut a2b_values = Vec::new();
    for i in 0..table.0.len() {
        let table_entry = &table.0[i];
        a2b_values.push(table_entry.orig_id);
        a2b_values.push(table_entry.row_id);
        a2b_values.push(table_entry.row_length);
        a2b_values.push(table_entry.row_cum);
        a2b_values.push(table_entry.ind_in_row);
        a2b_values.push(table_entry.target_loc);
    }

    let binary_values = run_batch_arithmetic_to_boolean(
        setup,
        mpc_encryption,
        tag_offset_counter,
        relay,
        &a2b_values,
        serverstate,
    )
    .await?;

    let mut out = Vec::new();
    for i in 0..table.0.len() {
        let mut out_p = binary_values[i * 6..(i + 1) * 6].to_vec();
        let c = &table.0[i].char;
        let d = &table.0[i].is_delimiter;
        let mut temp = BinaryArithmeticShare::ZERO;
        temp.value1[0] = c.value1;
        temp.value2[0] = c.value2;
        temp.value1[1] = d.value1 as u8;
        temp.value2[1] = d.value2 as u8;
        out_p.push(temp);

        out.push(out_p)
    }

    Ok(out)
}

/// Run deserialize_input_table
pub async fn run_deserialize_input_table<T, R>(
    setup: &T,
    mpc_encryption: &mut MPCEncryption,
    tag_offset_counter: &mut TagOffsetCounter,
    relay: &mut FilteredMsgRelay<R>,
    serialized_input_table: &[Vec<BinaryArithmeticShare>],
    serverstate: &mut ServerState,
) -> Result<InputTable, ProtocolError>
where
    T: CommonSetupMessage,
    R: Relay,
{
    let mut char_and_is_delim = Vec::new();
    let mut b2a_values = Vec::new();
    for entry in serialized_input_table {
        b2a_values.extend_from_slice(&entry[0..6]);

        let temp = entry[6];
        let char_p1 = ByteShare {
            value1: temp.value1[0],
            value2: temp.value2[0],
        };
        let isdelim_p1 = BinaryShare {
            value1: temp.value1[1] == 1u8,
            value2: temp.value2[1] == 1u8,
        };
        char_and_is_delim.push((char_p1, isdelim_p1));
    }

    let a_values = run_batch_boolean_to_arithmetic(
        setup,
        mpc_encryption,
        tag_offset_counter,
        relay,
        &b2a_values,
        serverstate,
    )
    .await?;

    let mut output = Vec::new();
    for i in 0..serialized_input_table.len() {
        let (char, is_delim) = char_and_is_delim[i];
        let oid = a_values[i * 6];
        let rid = a_values[1 + i * 6];
        let rlen = a_values[2 + i * 6];
        let rcum = a_values[3 + i * 6];
        let ind = a_values[4 + i * 6];
        let tl = a_values[5 + i * 6];
        let entry = InputTableEntry {
            char,
            orig_id: oid,
            is_delimiter: is_delim,
            is_delimiter_clear: false,
            row_id: rid,
            row_id_clear: FieldElement::ZERO,
            orig_id_clear: FieldElement::ZERO,
            row_length: rlen,
            row_cum: rcum,
            ind_in_row: ind,
            target_loc: tl,
            target_loc_clear: FieldElement::ZERO,
        };
        output.push(entry);
    }

    Ok(InputTable(output))
}

/// Implementation of Protocol 3.20 (SplitAndPad) from https://github.com/silence-laboratories/research-silent-compute/blob/main/paper/main.pdf.
/// Refer to https://docs.google.com/document/d/1nGbOFq41XxLPHaCous5EzGs-gVB3zp_H7aF17jWM-Qg/edit?usp=sharing for an example.
pub async fn run_split_and_pad<T, R>(
    setup: &T,
    mpc_encryption: &mut MPCEncryption,
    tag_offset_counter: &mut TagOffsetCounter,
    relay: &mut FilteredMsgRelay<R>,
    plinput: &SplitAndPadPltextInput,
    share_p: &[ByteShare],
    serverstate: &mut ServerState,
) -> Result<SplitAndPadPartyOutput, ProtocolError>
where
    T: CommonSetupMessage,
    R: Relay,
{
    let n_bytes = share_p.len();
    let party_index = setup.participant_index();
    let mut input_table_p = InputTable::new(share_p, party_index);

    let def_delimiter_p = ByteShare::from_constant(&plinput.delimiter, party_index);

    let mut compare_input_a = Vec::new();
    for i in 0..n_bytes {
        compare_input_a.push(input_table_p.0[i].char);
    }
    let batch_is_delimiter = run_batch_compare_eq_byte(
        setup,
        mpc_encryption,
        tag_offset_counter,
        relay,
        &compare_input_a,
        &vec![def_delimiter_p; n_bytes],
        serverstate,
    )
    .await?;
    for (i, is_delimiter) in batch_is_delimiter.iter().enumerate() {
        input_table_p.0[i].is_delimiter = *is_delimiter;
    }

    let mut row_id_bool_p_values = Vec::new();
    for i in 0..n_bytes {
        row_id_bool_p_values.push(BinaryArithmeticShare::from_binary_share(
            &input_table_p.0[i].is_delimiter,
        ))
    }
    let row_id_p_values = run_batch_boolean_to_arithmetic(
        setup,
        mpc_encryption,
        tag_offset_counter,
        relay,
        &row_id_bool_p_values,
        serverstate,
    )
    .await?;
    #[allow(clippy::needless_range_loop)]
    for i in 0..n_bytes {
        input_table_p.0[i].row_id = row_id_p_values[i];
        if i > 0 {
            input_table_p.0[i].row_id = input_table_p.0[i]
                .row_id
                .add_share(&input_table_p.0[i - 1].row_id);
        }
    }

    let sertable_p = run_serialize_input_table(
        setup,
        mpc_encryption,
        tag_offset_counter,
        relay,
        &input_table_p,
        serverstate,
    )
    .await?;

    let shuffled_sertable_p = run_shuffle_serialized_table(
        setup,
        mpc_encryption,
        tag_offset_counter,
        relay,
        &sertable_p,
        serverstate,
    )
    .await?;

    let mut input_table_p = run_deserialize_input_table(
        setup,
        mpc_encryption,
        tag_offset_counter,
        relay,
        &shuffled_sertable_p,
        serverstate,
    )
    .await?;

    let mut delcount = 0;

    let mut binary_shares_to_open = Vec::new();
    for i in 0..n_bytes {
        binary_shares_to_open.push(input_table_p.0[i].is_delimiter)
    }
    let is_delimiter_values = run_batch_open_binary_share(
        setup,
        mpc_encryption,
        tag_offset_counter,
        relay,
        &binary_shares_to_open,
        serverstate,
    )
    .await?;
    #[allow(clippy::needless_range_loop)]
    for i in 0..n_bytes {
        let is_delimiter = is_delimiter_values[i];
        input_table_p.0[i].is_delimiter_clear = is_delimiter;

        if is_delimiter {
            let row_id = run_batch_open_arith(
                setup,
                mpc_encryption,
                tag_offset_counter,
                relay,
                &[input_table_p.0[i].row_id],
                serverstate,
            )
            .await?[0];
            input_table_p.0[i].row_id_clear = row_id;

            delcount += 1;
        }
    }

    let mut delimiter_table_p = DelimiterTable::new(&input_table_p);
    delimiter_table_p.sort_by_row_id_clear();

    let temp_share_p = ArithmeticShare::from_constant(&FieldElement::from(1u64), party_index);

    delimiter_table_p.table[0].row_length =
        delimiter_table_p.table[0].orig_id.add_share(&temp_share_p);

    for i in 1..delcount {
        delimiter_table_p.table[i].row_length = delimiter_table_p.table[i]
            .orig_id
            .sub_share(&delimiter_table_p.table[i - 1].orig_id);
    }

    for i in 0..delcount {
        for j in 0..n_bytes {
            if delimiter_table_p.table[i].row_id_clear == input_table_p.0[j].row_id_clear {
                input_table_p.0[j].row_length = delimiter_table_p.table[i].row_length;
            }
        }
    }

    // TODO rewrite WET code to DRY
    let sertable_p = run_serialize_input_table(
        setup,
        mpc_encryption,
        tag_offset_counter,
        relay,
        &input_table_p,
        serverstate,
    )
    .await?;

    let shuffled_sertable_p = run_shuffle_serialized_table(
        setup,
        mpc_encryption,
        tag_offset_counter,
        relay,
        &sertable_p,
        serverstate,
    )
    .await?;

    let mut input_table_p = run_deserialize_input_table(
        setup,
        mpc_encryption,
        tag_offset_counter,
        relay,
        &shuffled_sertable_p,
        serverstate,
    )
    .await?;

    let mut arith_shares_to_open = Vec::new();
    for i in 0..n_bytes {
        arith_shares_to_open.push(input_table_p.0[i].orig_id)
    }
    let orig_id_values = run_batch_open_arith(
        setup,
        mpc_encryption,
        tag_offset_counter,
        relay,
        &arith_shares_to_open,
        serverstate,
    )
    .await?;
    #[allow(clippy::needless_range_loop)]
    for i in 0..n_bytes {
        input_table_p.0[i].orig_id_clear = orig_id_values[i];
    }

    input_table_p.sort_by_orig_id_clear();

    for i in 1..n_bytes {
        input_table_p.0[i].row_cum = input_table_p.0[i - 1]
            .row_cum
            .add_share(&input_table_p.0[i].row_length);
    }

    for i in 0..n_bytes {
        input_table_p.0[i].ind_in_row = input_table_p.0[i]
            .orig_id
            .sub_share(&input_table_p.0[i].row_cum);
    }

    // TODO rewrite WET code to DRY
    let sertable_p = run_serialize_input_table(
        setup,
        mpc_encryption,
        tag_offset_counter,
        relay,
        &input_table_p,
        serverstate,
    )
    .await?;

    let shuffled_sertable_p = run_shuffle_serialized_table(
        setup,
        mpc_encryption,
        tag_offset_counter,
        relay,
        &sertable_p,
        serverstate,
    )
    .await?;

    let mut input_table_p = run_deserialize_input_table(
        setup,
        mpc_encryption,
        tag_offset_counter,
        relay,
        &shuffled_sertable_p,
        serverstate,
    )
    .await?;

    let mut binary_shares_to_open = Vec::new();
    for i in 0..n_bytes {
        binary_shares_to_open.push(input_table_p.0[i].is_delimiter)
    }
    let is_delimiter_values = run_batch_open_binary_share(
        setup,
        mpc_encryption,
        tag_offset_counter,
        relay,
        &binary_shares_to_open,
        serverstate,
    )
    .await?;
    #[allow(clippy::needless_range_loop)]
    for i in 0..n_bytes {
        input_table_p.0[i].is_delimiter_clear = is_delimiter_values[i];
    }
    input_table_p.0.retain(|x| !x.is_delimiter_clear);

    let non_del_bytes = n_bytes - delcount;

    for i in 0..non_del_bytes {
        input_table_p.0[i].target_loc = input_table_p.0[i]
            .row_id
            .mul_const(&FieldElement::from(plinput.max_rec_len))
            .add_share(&input_table_p.0[i].ind_in_row);
    }

    let pad_share_p = ByteShare::from_constant(&plinput.pad_character, party_index);

    let mut pad_table_p = InputTable(vec![]);
    for i in 0..((delcount + 1) * (plinput.max_rec_len as usize)) {
        let loc_p = ArithmeticShare::from_constant(&FieldElement::from(i as u64), party_index);
        let entry_p = InputTableEntry {
            char: pad_share_p,
            orig_id: ArithmeticShare::ZERO,
            orig_id_clear: FieldElement::ZERO,
            is_delimiter: BinaryShare {
                value1: false,
                value2: false,
            },
            is_delimiter_clear: false,
            row_id: ArithmeticShare::ZERO,
            row_id_clear: FieldElement::ZERO,
            row_length: ArithmeticShare::ZERO,
            row_cum: ArithmeticShare::ZERO,
            ind_in_row: ArithmeticShare::ZERO,
            target_loc: loc_p,
            target_loc_clear: FieldElement::ZERO,
        };
        pad_table_p.0.push(entry_p);
    }

    let temp_share_p = ArithmeticShare::from_constant(&FieldElement::from(1u64), party_index);

    for j in 0..delcount {
        delimiter_table_p.table[j].row_length_wo_del = delimiter_table_p.table[j]
            .row_length
            .sub_share(&temp_share_p);
    }

    let lastlen_p = temp_share_p
        .mul_const(&FieldElement::from((n_bytes - 1) as u64))
        .sub_share(&delimiter_table_p.table[delcount - 1].orig_id);

    delimiter_table_p.table.push(DelimiterTableEntry {
        orig_id: ArithmeticShare::ZERO,
        is_delimiter_clear: false,
        row_id_clear: FieldElement::ZERO,
        row_length: ArithmeticShare::ZERO,
        row_length_wo_del: lastlen_p,
    });

    let mut row_len_arith_values = Vec::new();
    for row_id in 0..(delcount + 1) {
        row_len_arith_values.push(delimiter_table_p.table[row_id].row_length_wo_del);
    }
    let row_len_bool_values = run_batch_arithmetic_to_boolean(
        setup,
        mpc_encryption,
        tag_offset_counter,
        relay,
        &row_len_arith_values,
        serverstate,
    )
    .await?;

    let mut curr_arith_values = Vec::new();
    for rel_position in 0..(plinput.max_rec_len as usize) {
        let curr_p =
            ArithmeticShare::from_constant(&FieldElement::from(rel_position as u64), party_index);
        curr_arith_values.push(curr_p);
    }
    let curr_bool_values = run_batch_arithmetic_to_boolean(
        setup,
        mpc_encryption,
        tag_offset_counter,
        relay,
        &curr_arith_values,
        serverstate,
    )
    .await?;

    let mut comp_a_values = Vec::new();
    let mut comp_b_values = Vec::new();
    #[allow(clippy::needless_range_loop)]
    for row_id in 0..(delcount + 1) {
        #[allow(clippy::needless_range_loop)]
        for rel_position in 0..(plinput.max_rec_len as usize) {
            let a = curr_bool_values[rel_position];
            let b = row_len_bool_values[row_id];
            comp_a_values.push(a);
            comp_b_values.push(b);
        }
    }
    let comp_res_values = run_batch_compare_ge(
        setup,
        mpc_encryption,
        tag_offset_counter,
        relay,
        &comp_a_values,
        &comp_b_values,
        serverstate,
    )
    .await?;
    for row_id in 0..(delcount + 1) {
        for rel_position in 0..(plinput.max_rec_len as usize) {
            pad_table_p.0[(plinput.max_rec_len as usize) * row_id + rel_position].is_delimiter =
                comp_res_values[(plinput.max_rec_len as usize) * row_id + rel_position];
        }
    }

    // TODO rewrite WET code to DRY
    let ser_pad_table_p = run_serialize_input_table(
        setup,
        mpc_encryption,
        tag_offset_counter,
        relay,
        &pad_table_p,
        serverstate,
    )
    .await?;

    let shuffled_ser_pad_table_p = run_shuffle_serialized_table(
        setup,
        mpc_encryption,
        tag_offset_counter,
        relay,
        &ser_pad_table_p,
        serverstate,
    )
    .await?;

    let pad_table_p = run_deserialize_input_table(
        setup,
        mpc_encryption,
        tag_offset_counter,
        relay,
        &shuffled_ser_pad_table_p,
        serverstate,
    )
    .await?;

    // TODO batch it
    let mut binary_shares_to_open = Vec::new();
    for i in 0..pad_table_p.0.len() {
        binary_shares_to_open.push(pad_table_p.0[i].is_delimiter)
    }
    let is_delimiter_values = run_batch_open_binary_share(
        setup,
        mpc_encryption,
        tag_offset_counter,
        relay,
        &binary_shares_to_open,
        serverstate,
    )
    .await?;

    #[allow(clippy::needless_range_loop)]
    for i in 0..pad_table_p.0.len() {
        let pad_dec = is_delimiter_values[i];
        if pad_dec {
            input_table_p.0.push(pad_table_p.0[i].clone());
        }
    }

    // TODO rewrite WET code to DRY
    let sertable_p = run_serialize_input_table(
        setup,
        mpc_encryption,
        tag_offset_counter,
        relay,
        &input_table_p,
        serverstate,
    )
    .await?;

    let shuffled_sertable_p = run_shuffle_serialized_table(
        setup,
        mpc_encryption,
        tag_offset_counter,
        relay,
        &sertable_p,
        serverstate,
    )
    .await?;

    let mut input_table_p = run_deserialize_input_table(
        setup,
        mpc_encryption,
        tag_offset_counter,
        relay,
        &shuffled_sertable_p,
        serverstate,
    )
    .await?;

    let mut arith_shares_to_open = Vec::new();
    for i in 0..input_table_p.0.len() {
        arith_shares_to_open.push(input_table_p.0[i].target_loc)
    }
    let target_loc_values = run_batch_open_arith(
        setup,
        mpc_encryption,
        tag_offset_counter,
        relay,
        &arith_shares_to_open,
        serverstate,
    )
    .await?;
    #[allow(clippy::needless_range_loop)]
    for i in 0..input_table_p.0.len() {
        input_table_p.0[i].target_loc_clear = target_loc_values[i];
    }

    input_table_p.sort_by_target_loc_clear();

    let mut output_p = Vec::new();

    for i in 0..(delcount + 1) {
        let mut temp_p = Vec::new();
        for j in 0..(plinput.max_rec_len as usize) {
            temp_p.push(input_table_p.0[i * (plinput.max_rec_len as usize) + j].char);
        }
        output_p.push(temp_p);
    }

    Ok(SplitAndPadPartyOutput { out: output_p })
}

// pub async fn run_batch_split_and_pad<T, R>(
//     setup: &T,
//     mpc_encryption: &mut MPCEncryption,
//     tag_offset_counter: &mut TagOffsetCounter,
//     relay: &mut FilteredMsgRelay<R>,
//     plinputs: &[SplitAndPadPltextInput],
//     shares: &[Vec<BinaryStringShare>],
//     serverstate: &mut ServerState,
// ) -> Result<Vec<SplitAndPadPartyOutput>, ProtocolError>
// where
//     T: CommonSetupMessage,
//     R: Relay,
// {
//     todo!();
// }

/// Test split_and_pad protocol
#[cfg(any(test, feature = "test-support"))]
async fn test_split_and_pad_protocol<T, R>(
    setup: T,
    seed: Seed,
    params: (SplitAndPadPltextInput, Vec<ByteShare>),
    relay: R,
) -> Result<(usize, SplitAndPadPartyOutput), ProtocolError>
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

    let pl_input = params.0;
    let share_p = params.1;
    let result = run_split_and_pad(
        &setup,
        &mut mpc_encryption,
        &mut tag_offset_counter,
        &mut relay,
        &pl_input,
        &share_p,
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

    println!("tag_offset_counter = {}", tag_offset_counter.next_value());
    //assert!(false);

    match result {
        Ok(v) => Ok((setup.participant_index(), v)),
        Err(e) => Err(e),
    }
}

#[cfg(test)]
mod tests {
    use crate::proto::reconstruct_byte_share_to_string;
    use crate::transport::test_utils::setup_mpc;
    use crate::types::ByteShare;
    use crate::utility::split_and_pad::{test_split_and_pad_protocol, SplitAndPadPartyOutput};
    use crate::{
        proto::u8_vec_to_binary_string,
        types::BinaryString,
        utility::split_and_pad::{get_byte_str_share, SplitAndPadPltextInput},
    };
    use sl_mpc_mate::coord::{MessageRelayService, Relay, SimpleMessageRelay};
    use tokio::task::JoinSet;

    async fn sim<S, R>(
        coord: S,
        sim_params: &[(SplitAndPadPltextInput, Vec<ByteShare>); 3],
    ) -> Vec<SplitAndPadPartyOutput>
    where
        S: MessageRelayService<MessageRelay = R>,
        R: Relay + Send + 'static,
    {
        let parties = setup_mpc(None, sim_params);

        let mut jset = JoinSet::new();
        for (setup, seed, params) in parties {
            let relay = coord.connect().await.unwrap();

            jset.spawn(test_split_and_pad_protocol(setup, seed, params, relay));
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
    async fn test_parsing_entry_i() {
        let input = r###"Hello this is testing split and pad"###;

        let share_p1 = get_byte_str_share(input, 1);
        let share_p2 = get_byte_str_share(input, 2);
        let share_p3 = get_byte_str_share(input, 3);

        let max_rec_len = 15;

        let delvec = u8_vec_to_binary_string(" ".as_bytes().to_vec());

        let mut delimiter: BinaryString = BinaryString::with_capacity(8);
        for i in 0..8 {
            delimiter.push(delvec.get(i));
        }

        let mut pad_character: BinaryString = BinaryString::with_capacity(8);
        let pad_char = u8_vec_to_binary_string("~".as_bytes().to_vec());
        for i in 0..8 {
            pad_character.push(pad_char.get(i));
        }

        let plain = SplitAndPadPltextInput {
            pad_character,
            max_rec_len,
            delimiter,
        };

        let params = [
            (plain.clone(), share_p1),
            (plain.clone(), share_p2),
            (plain.clone(), share_p3),
        ];

        let results = sim(SimpleMessageRelay::new(), &params).await;
        assert_eq!(results.len(), 3);

        let parsed_ip_p1 = results[0].clone();
        let parsed_ip_p2 = results[1].clone();
        let parsed_ip_p3 = results[2].clone();

        let required_outputs = vec![
            "Hello~~~~~~~~~~".to_string(),
            "this~~~~~~~~~~~".to_string(),
            "is~~~~~~~~~~~~~".to_string(),
            "testing~~~~~~~~".to_string(),
            "split~~~~~~~~~~".to_string(),
            "and~~~~~~~~~~~~".to_string(),
            "pad~~~~~~~~~~~~".to_string(),
        ];

        let mut outputs = Vec::new();
        for i in 0..parsed_ip_p1.out.len() {
            outputs.push(reconstruct_byte_share_to_string(
                parsed_ip_p1.out[i].clone(),
                parsed_ip_p2.out[i].clone(),
                parsed_ip_p3.out[i].clone(),
            ));
        }

        assert_eq!(required_outputs, outputs);
    }
}
