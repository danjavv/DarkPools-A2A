use base64::{prelude::BASE64_STANDARD, Engine};
use serde::{Deserialize, Serialize};
use sl_compute::comparison::compare_equal::{run_batch_compare_eq_byte, run_compare_eq_byte};
use sl_compute::comparison::compare_ge::{run_batch_compare_ge, run_compare_ge};
use sl_compute::constants::{FIELD_SIZE_BYTES, REC_DECIMAL_SIZE_L2};
use sl_compute::conversion::a_to_b::{run_arithmetic_to_boolean, run_batch_arithmetic_to_boolean};
use sl_compute::conversion::b_to_a::{run_batch_boolean_to_arithmetic, run_boolean_to_arithmetic};
use sl_compute::mpc::open_protocol::{
    run_batch_open_binary_share, run_batch_open_byte_share, run_open_byte_share,
};
use sl_compute::mpc::verify::run_verify;
use sl_compute::proto::binary_string_share_to_byte_shares;

use sl_compute::mpc::multiply_binary_shares::run_batch_and_binary_shares;
use sl_compute::transport::proto::FilteredMsgRelay;
use sl_compute::transport::setup::common::MPCEncryption;
use sl_compute::transport::setup::CommonSetupMessage;
use sl_compute::transport::types::ProtocolError;
use sl_compute::transport::utils::Seed;
use sl_compute::transport::utils::TagOffsetCounter;
use sl_compute::types::{BinaryArithmeticShare, ByteShare, FieldElement};
use sl_compute::utility::multiplexer::run_multiplexer_array;
use sl_compute::utility::split_and_pad::{run_split_and_pad, SplitAndPadPartyOutput};
use sl_compute::utility::threshold_dec::run_threshold_decrypt;
use sl_compute::{
    constants::{
        DELIM_1, DELIM_2, DOT_CHAR, FIELD_SIZE, FRACTION_LENGTH, PAD_CHAR, REC_SIZE_L1, REC_SIZE_L2,
    },
    keygen::dkg::parse_remote_public_key,
    proto::u8_vec_to_binary_string,
    types::{
        ArithmeticECShare, ArithmeticShare, BinaryShare, BinaryStringShare, DecimalShare,
        ServerState,
    },
    utility::split_and_pad::SplitAndPadPltextInput,
};
use sl_mpc_mate::coord::Relay;
use std::cmp::min;
use std::time::Instant;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TransactionEntry {
    pub txn_id: Vec<ByteShare>,
    pub type_credit: BinaryShare,
    pub txn_mode: [ByteShare; 3],
    pub txn_amt: DecimalShare,
    pub curr_bal: DecimalShare,
    pub time_stamp: TimeStamp,
    pub narration: Vec<ByteShare>,
    pub reference: Vec<ByteShare>,
    pub category: usize,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
pub struct TimeStamp {
    pub date: ArithmeticShare,
    pub month: ArithmeticShare,
    pub year: ArithmeticShare,
    pub hour: ArithmeticShare,
    pub minute: ArithmeticShare,
    pub second: ArithmeticShare,
    pub plus: BinaryShare,
    pub diff_hour: ArithmeticShare,
    pub diff_minute: ArithmeticShare,
}

impl Default for TimeStamp {
    fn default() -> Self {
        let zero = ArithmeticShare::ZERO;
        Self {
            date: zero,
            month: zero,
            year: zero,
            hour: zero,
            minute: zero,
            second: zero,
            plus: BinaryShare {
                value1: false,
                value2: false,
            },
            diff_hour: zero,
            diff_minute: zero,
        }
    }
}

/// Implementation of Protocol 3.6 from https://github.com/silence-laboratories/sl-compute/blob/sahamati-queries/docs.pdf
async fn run_shave_data_front<T, R>(
    setup: &T,
    mpc_encryption: &mut MPCEncryption,
    tag_offset_counter: &mut TagOffsetCounter,
    relay: &mut FilteredMsgRelay<R>,
    dec_xml_p: &[ByteShare],
    serverstate: &mut ServerState,
) -> Result<Vec<ByteShare>, ProtocolError>
where
    T: CommonSetupMessage,
    R: Relay,
{
    let party_index = setup.participant_index();

    let right_ang = u8_vec_to_binary_string(">".as_bytes().to_vec());
    let ang_p1 = ByteShare::from_binary_string(&right_ang);

    let count_p = ArithmeticShare::from_constant(&FieldElement::from(10u64), party_index);

    let count_bool_p = run_arithmetic_to_boolean(
        setup,
        mpc_encryption,
        tag_offset_counter,
        relay,
        &count_p,
        serverstate,
    )
    .await?;

    let comp_values = run_batch_compare_eq_byte(
        setup,
        mpc_encryption,
        tag_offset_counter,
        relay,
        &vec![ang_p1; dec_xml_p.len()],
        dec_xml_p,
        serverstate,
    )
    .await?;

    let boolean_values = comp_values
        .iter()
        .map(BinaryArithmeticShare::from_binary_share)
        .collect::<Vec<_>>();

    let arith_values = run_batch_boolean_to_arithmetic(
        setup,
        mpc_encryption,
        tag_offset_counter,
        relay,
        &boolean_values,
        serverstate,
    )
    .await?;

    let mut curr_values = Vec::new();
    curr_values.push(arith_values[0]);
    for i in 1..arith_values.len() {
        curr_values.push(curr_values[i - 1].add_share(&arith_values[i]));
    }

    let curr_bool_values = run_batch_arithmetic_to_boolean(
        setup,
        mpc_encryption,
        tag_offset_counter,
        relay,
        &curr_values,
        serverstate,
    )
    .await?;

    let compout_values = run_batch_compare_ge(
        setup,
        mpc_encryption,
        tag_offset_counter,
        relay,
        &curr_bool_values,
        &vec![count_bool_p; curr_bool_values.len()],
        serverstate,
    )
    .await?;

    let compout_opened_values = run_batch_open_binary_share(
        setup,
        mpc_encryption,
        tag_offset_counter,
        relay,
        &compout_values,
        serverstate,
    )
    .await?;

    let mut curr_id = 0;
    while curr_id < dec_xml_p.len() {
        let compout = compout_opened_values[curr_id];

        curr_id += 1;
        if compout {
            break;
        }
    }

    Ok(dec_xml_p[curr_id..dec_xml_p.len()].to_vec())
}

/// Implementation of Protocol 3.6 from https://github.com/silence-laboratories/sl-compute/blob/sahamati-queries/docs.pdf
async fn run_shave_data_back<T, R>(
    setup: &T,
    mpc_encryption: &mut MPCEncryption,
    tag_offset_counter: &mut TagOffsetCounter,
    relay: &mut FilteredMsgRelay<R>,
    dec_xml_p: &[ByteShare],
    serverstate: &mut ServerState,
) -> Result<Vec<ByteShare>, ProtocolError>
where
    T: CommonSetupMessage,
    R: Relay,
{
    let party_index = setup.participant_index();

    let left_ang = u8_vec_to_binary_string("<".as_bytes().to_vec());
    let ang_p = ByteShare::from_binary_string(&left_ang);

    let count_p = ArithmeticShare::from_constant(&FieldElement::from(2u64), party_index);

    let count_bool_p = run_arithmetic_to_boolean(
        setup,
        mpc_encryption,
        tag_offset_counter,
        relay,
        &count_p,
        serverstate,
    )
    .await?;

    let comp_values = run_batch_compare_eq_byte(
        setup,
        mpc_encryption,
        tag_offset_counter,
        relay,
        &vec![ang_p; dec_xml_p.len()],
        dec_xml_p,
        serverstate,
    )
    .await?;

    let boolean_values = comp_values
        .iter()
        .map(BinaryArithmeticShare::from_binary_share)
        .collect::<Vec<_>>();

    let arith_values = run_batch_boolean_to_arithmetic(
        setup,
        mpc_encryption,
        tag_offset_counter,
        relay,
        &boolean_values,
        serverstate,
    )
    .await?;

    let mut curr_p = ArithmeticShare::ZERO;

    let mut curr_id = dec_xml_p.len() - 1;
    while curr_id > 0 {
        curr_p.mut_add_share(&arith_values[curr_id]);

        let curr_bool_p = run_arithmetic_to_boolean(
            setup,
            mpc_encryption,
            tag_offset_counter,
            relay,
            &curr_p,
            serverstate,
        )
        .await?;

        let compout_p = run_compare_ge(
            setup,
            mpc_encryption,
            tag_offset_counter,
            relay,
            &curr_bool_p,
            &count_bool_p,
            serverstate,
        )
        .await?;

        let compout = run_batch_open_binary_share(
            setup,
            mpc_encryption,
            tag_offset_counter,
            relay,
            &[compout_p],
            serverstate,
        )
        .await?[0];

        curr_id -= 1;
        if compout {
            break;
        }
    }

    Ok(dec_xml_p[0..(curr_id + 1)].to_vec())
}

/// Implementation of Section 3.8 from https://github.com/silence-laboratories/sl-compute/blob/sahamati-queries/docs.pdf
async fn run_parse_category<T, R>(
    setup: &T,
    mpc_encryption: &mut MPCEncryption,
    tag_offset_counter: &mut TagOffsetCounter,
    relay: &mut FilteredMsgRelay<R>,
    byte_cat_p: &ByteShare,
    serverstate: &mut ServerState,
) -> Result<usize, ProtocolError>
where
    T: CommonSetupMessage,
    R: Relay,
{
    let x = run_open_byte_share(
        setup,
        mpc_encryption,
        tag_offset_counter,
        relay,
        byte_cat_p,
        serverstate,
    )
    .await?;
    Ok((x - 48) as usize)
}

async fn run_batch_parse_category<T, R>(
    setup: &T,
    mpc_encryption: &mut MPCEncryption,
    tag_offset_counter: &mut TagOffsetCounter,
    relay: &mut FilteredMsgRelay<R>,
    byte_category_values: &[ByteShare],
    serverstate: &mut ServerState,
) -> Result<Vec<usize>, ProtocolError>
where
    T: CommonSetupMessage,
    R: Relay,
{
    let out = run_batch_open_byte_share(
        setup,
        mpc_encryption,
        tag_offset_counter,
        relay,
        byte_category_values,
        serverstate,
    )
    .await?;
    let out: Vec<usize> = out.iter().map(|x| (x - 48) as usize).collect();

    Ok(out)
}

/// Implementation of Protocol 3.14 from https://github.com/silence-laboratories/sl-compute/blob/sahamati-queries/docs.pdf
pub async fn run_batch_get_transaction_entry<T, R>(
    setup: &T,
    mpc_encryption: &mut MPCEncryption,
    tag_offset_counter: &mut TagOffsetCounter,
    relay: &mut FilteredMsgRelay<R>,
    parsed_entries: &[SplitAndPadPartyOutput],
    serverstate: &mut ServerState,
) -> Result<Vec<TransactionEntry>, ProtocolError>
where
    T: CommonSetupMessage,
    R: Relay,
{
    let cap_d = u8_vec_to_binary_string("C".as_bytes().to_vec());
    let capcbool_p = ByteShare::from_binary_string(&cap_d);

    let mut compare_b = Vec::new();
    let mut category_share_values = Vec::new();
    for parsed_entry in parsed_entries {
        compare_b.push(parsed_entry.out[3][0]);
        category_share_values.push(parsed_entry.out[15][0]);
    }
    let type_values = run_batch_compare_eq_byte(
        setup,
        mpc_encryption,
        tag_offset_counter,
        relay,
        &vec![capcbool_p; parsed_entries.len()],
        &compare_b,
        serverstate,
    )
    .await?;

    let category_values = run_batch_parse_category(
        setup,
        mpc_encryption,
        tag_offset_counter,
        relay,
        &category_share_values,
        serverstate,
    )
    .await?;

    let mut output = Vec::new();
    for (i, parsed_entry) in parsed_entries.iter().enumerate() {
        let mode = parse_mode(&parsed_entry.out[5]);

        let amount_p = run_parse_decimal(
            setup,
            mpc_encryption,
            tag_offset_counter,
            relay,
            &parsed_entry.out[7],
            serverstate,
        )
        .await?;

        let balance_p = run_parse_decimal(
            setup,
            mpc_encryption,
            tag_offset_counter,
            relay,
            &parsed_entry.out[9],
            serverstate,
        )
        .await?;

        let dt_p = run_parse_date(
            setup,
            mpc_encryption,
            tag_offset_counter,
            relay,
            &parsed_entry.out[11],
            serverstate,
        )
        .await?;

        let narlen = parsed_entry.out[15].len();

        let transaction_entry = TransactionEntry {
            txn_id: parsed_entry.out[1].clone(),
            type_credit: type_values[i],
            txn_mode: mode,

            txn_amt: amount_p,
            curr_bal: balance_p,
            time_stamp: dt_p,

            narration: parsed_entry.out[15][1..narlen].to_vec(),
            reference: parsed_entry.out[17].to_vec(),
            category: category_values[i],
        };

        output.push(transaction_entry);
    }

    Ok(output)
}

/// Function to extract the first three elements of the input.
fn parse_mode(byte_mode_p: &[ByteShare]) -> [ByteShare; 3] {
    let mut mode_p1 = vec![];
    for v in byte_mode_p.iter().take(3) {
        mode_p1.push(*v);
    }
    mode_p1.try_into().unwrap()
}

/// Implementation of Section 3.10 from https://github.com/silence-laboratories/sl-compute/blob/sahamati-queries/docs.pdf
async fn run_parse_date<T, R>(
    setup: &T,
    mpc_encryption: &mut MPCEncryption,
    tag_offset_counter: &mut TagOffsetCounter,
    relay: &mut FilteredMsgRelay<R>,
    byte_date_p: &[ByteShare],
    serverstate: &mut ServerState,
) -> Result<TimeStamp, ProtocolError>
where
    T: CommonSetupMessage,
    R: Relay,
{
    let mut year_p = ArithmeticShare::ZERO;
    let mut month_p = ArithmeticShare::ZERO;
    let mut date_p = ArithmeticShare::ZERO;

    let mut hour_p = ArithmeticShare::ZERO;
    let mut minute_p = ArithmeticShare::ZERO;
    let mut second_p = ArithmeticShare::ZERO;

    let mut diff_hour_p = ArithmeticShare::ZERO;
    let mut diff_minute_p = ArithmeticShare::ZERO;

    let mut count = 0;

    let num_p_values = run_batch_parse_number(
        setup,
        mpc_encryption,
        tag_offset_counter,
        relay,
        &byte_date_p[0..25],
        serverstate,
    )
    .await?;

    for _ in 0..4 {
        let num_p = num_p_values[count];
        year_p = year_p
            .mul_const(&FieldElement::from(10u64))
            .add_share(&num_p);

        count += 1;
    }
    count += 1;

    for _ in 0..2 {
        let num_p = num_p_values[count];
        month_p = month_p
            .mul_const(&FieldElement::from(10u64))
            .add_share(&num_p);
        count += 1;
    }
    count += 1;

    for _ in 0..2 {
        let num_p = num_p_values[count];
        date_p = date_p
            .mul_const(&FieldElement::from(10u64))
            .add_share(&num_p);
        count += 1;
    }
    count += 1;

    for _ in 0..2 {
        let num_p = num_p_values[count];
        hour_p = hour_p
            .mul_const(&FieldElement::from(10u64))
            .add_share(&num_p);
        count += 1;
    }
    count += 1;

    for _ in 0..2 {
        let num_p = num_p_values[count];
        minute_p = minute_p
            .mul_const(&FieldElement::from(10u64))
            .add_share(&num_p);
        count += 1;
    }
    count += 1;

    for _ in 0..2 {
        let num_p = num_p_values[count];
        second_p = second_p
            .mul_const(&FieldElement::from(10u64))
            .add_share(&num_p);
        count += 1;
    }

    let plus = u8_vec_to_binary_string("+".as_bytes().to_vec());
    let plus_val_p = ByteShare::from_binary_string(&plus);

    let plus_p = run_compare_eq_byte(
        setup,
        mpc_encryption,
        tag_offset_counter,
        relay,
        &plus_val_p,
        &byte_date_p[count],
        serverstate,
    )
    .await?;

    count += 1;

    for _ in 0..2 {
        let num_p = num_p_values[count];
        diff_hour_p = diff_hour_p
            .mul_const(&FieldElement::from(10u64))
            .add_share(&num_p);
        count += 1;
    }
    count += 1;

    for _ in 0..2 {
        let num_p = num_p_values[count];
        diff_minute_p = diff_minute_p
            .mul_const(&FieldElement::from(10u64))
            .add_share(&num_p);
        count += 1;
    }

    let dt_p = TimeStamp {
        date: date_p,
        month: month_p,
        year: year_p,
        hour: hour_p,
        minute: minute_p,
        second: second_p,
        plus: plus_p,
        diff_hour: diff_hour_p,
        diff_minute: diff_minute_p,
    };

    Ok(dt_p)
}

/// Implementation of Protocol 3.7 from https://github.com/silence-laboratories/sl-compute/blob/sahamati-queries/docs.pdf
// ~418 messages
async fn run_parse_decimal<T, R>(
    setup: &T,
    mpc_encryption: &mut MPCEncryption,
    tag_offset_counter: &mut TagOffsetCounter,
    relay: &mut FilteredMsgRelay<R>,
    byte_dec_p: &[ByteShare],
    serverstate: &mut ServerState,
) -> Result<DecimalShare, ProtocolError>
where
    T: CommonSetupMessage,
    R: Relay,
{
    let dot = u8_vec_to_binary_string(DOT_CHAR.as_bytes().to_vec());
    let pad = u8_vec_to_binary_string(PAD_CHAR.as_bytes().to_vec());

    let dot_p = ByteShare::from_binary_string(&dot);
    let pad_p = ByteShare::from_binary_string(&pad);

    let mut num_fin_dec_p = DecimalShare::ZERO;

    let mut point_p = BinaryShare::ZERO;
    let mut frac_1_p = BinaryShare::ZERO;
    let mut frac_2_p: BinaryShare;

    // optimization to not check all REC_SIZE_L2 characters but only REC_DECIMAL_SIZE_L2
    let n = min(byte_dec_p.len(), REC_DECIMAL_SIZE_L2);

    let comp_a_values = &byte_dec_p[0..n];
    let comp_dot_values = run_batch_compare_eq_byte(
        setup,
        mpc_encryption,
        tag_offset_counter,
        relay,
        comp_a_values,
        &vec![dot_p; n],
        serverstate,
    )
    .await?;

    let comp_pad_values = run_batch_compare_eq_byte(
        setup,
        mpc_encryption,
        tag_offset_counter,
        relay,
        comp_a_values,
        &vec![pad_p; n],
        serverstate,
    )
    .await?;

    let num_ar_p_values = run_batch_parse_plain_decimal(
        setup,
        mpc_encryption,
        tag_offset_counter,
        relay,
        &byte_dec_p[0..n],
        serverstate,
    )
    .await?;

    for i in 0..n {
        let comp_dot_p = comp_dot_values[i];
        let comp_pad_p = comp_pad_values[i];

        frac_2_p = frac_1_p;
        frac_1_p = point_p;
        point_p = comp_dot_p;

        // TODO can be batched
        let mul_10_p = run_batch_and_binary_shares(
            setup,
            mpc_encryption,
            tag_offset_counter,
            relay,
            &[frac_2_p],
            &[comp_pad_p],
            serverstate,
        )
        .await?[0];

        let mut num_fin_ar_p = num_fin_dec_p.to_arithmetic();

        let num_ar_p = num_ar_p_values[i];

        let new_val_p = num_fin_ar_p
            .mul_const(&FieldElement::from(10u64))
            .add_share(&num_ar_p.to_arithmetic());

        let fin_10_p = num_fin_ar_p.mul_const(&FieldElement::from(10u64));

        let arith_values = [fin_10_p, num_fin_ar_p, new_val_p];
        let binary_values = run_batch_arithmetic_to_boolean(
            setup,
            mpc_encryption,
            tag_offset_counter,
            relay,
            &arith_values,
            serverstate,
        )
        .await?;
        let fin_10_bin_p = binary_values[0];
        let mut num_fin_ar_bin_p = binary_values[1];
        let mut new_val_bin_p = binary_values[2];

        new_val_bin_p = run_multiplexer_array(
            setup,
            mpc_encryption,
            tag_offset_counter,
            relay,
            &comp_dot_p,
            &num_fin_ar_bin_p,
            &new_val_bin_p,
            serverstate,
        )
        .await?;

        new_val_bin_p = run_multiplexer_array(
            setup,
            mpc_encryption,
            tag_offset_counter,
            relay,
            &comp_pad_p,
            &num_fin_ar_bin_p,
            &new_val_bin_p,
            serverstate,
        )
        .await?;

        num_fin_ar_bin_p = new_val_bin_p;

        num_fin_ar_bin_p = run_multiplexer_array(
            setup,
            mpc_encryption,
            tag_offset_counter,
            relay,
            &mul_10_p,
            &fin_10_bin_p,
            &num_fin_ar_bin_p,
            serverstate,
        )
        .await?;

        num_fin_ar_p = run_boolean_to_arithmetic(
            setup,
            mpc_encryption,
            tag_offset_counter,
            relay,
            &num_fin_ar_bin_p,
            serverstate,
        )
        .await?;

        num_fin_dec_p = DecimalShare::from_arithmetic(&num_fin_ar_p);
    }

    Ok(num_fin_dec_p)
}

/// Implementation of Section 3.9 from https://github.com/silence-laboratories/sl-compute/blob/sahamati-queries/docs.pdf
async fn run_batch_parse_number<T, R>(
    setup: &T,
    mpc_encryption: &mut MPCEncryption,
    tag_offset_counter: &mut TagOffsetCounter,
    relay: &mut FilteredMsgRelay<R>,
    num_bytes: &[ByteShare],
    serverstate: &mut ServerState,
) -> Result<Vec<ArithmeticShare>, ProtocolError>
where
    T: CommonSetupMessage,
    R: Relay,
{
    let party_index = setup.participant_index();

    let num_bool_values: Vec<BinaryArithmeticShare> = num_bytes
        .iter()
        .map(|num_byte_p| {
            let mut num_bool_p = BinaryStringShare {
                length: FIELD_SIZE as u64,
                value1: [0u8; FIELD_SIZE_BYTES].to_vec(),
                value2: [0u8; FIELD_SIZE_BYTES].to_vec(),
            };
            for i in 0..8 {
                num_bool_p
                    .set_binary_share(i + FRACTION_LENGTH, &num_byte_p.get_binary_share(7 - i));
            }
            BinaryArithmeticShare::from_binary_string_share(&num_bool_p)
        })
        .collect();

    let mut num_ar_p_values = run_batch_boolean_to_arithmetic(
        setup,
        mpc_encryption,
        tag_offset_counter,
        relay,
        &num_bool_values,
        serverstate,
    )
    .await?;

    let temp_p = ArithmeticShare::from_constant(&FieldElement::from(48u64), party_index);

    let _ = num_ar_p_values
        .iter_mut()
        .map(|num_ar_p| num_ar_p.mut_sub_share(&temp_p));

    Ok(num_ar_p_values)
}

/// Implementation of Section 3.11 from https://github.com/silence-laboratories/sl-compute/blob/sahamati-queries/docs.pdf
async fn run_batch_parse_plain_decimal<T, R>(
    setup: &T,
    mpc_encryption: &mut MPCEncryption,
    tag_offset_counter: &mut TagOffsetCounter,
    relay: &mut FilteredMsgRelay<R>,
    num_bytes: &[ByteShare],
    serverstate: &mut ServerState,
) -> Result<Vec<DecimalShare>, ProtocolError>
where
    T: CommonSetupMessage,
    R: Relay,
{
    let party_index = setup.participant_index();

    let num_bool_values: Vec<BinaryArithmeticShare> = num_bytes
        .iter()
        .map(|num_byte_p| {
            let mut num_bool_p = BinaryStringShare {
                length: FIELD_SIZE as u64,
                value1: [0u8; FIELD_SIZE_BYTES].to_vec(),
                value2: [0u8; FIELD_SIZE_BYTES].to_vec(),
            };
            for i in 0..8 {
                num_bool_p.set_binary_share(i, &num_byte_p.get_binary_share(7 - i));
            }
            BinaryArithmeticShare::from_binary_string_share(&num_bool_p)
        })
        .collect();

    let mut num_ar_p_values = run_batch_boolean_to_arithmetic(
        setup,
        mpc_encryption,
        tag_offset_counter,
        relay,
        &num_bool_values,
        serverstate,
    )
    .await?;

    let temp_p = ArithmeticShare::from_constant_raw(FieldElement::from(48u64), party_index);

    let res = num_ar_p_values
        .iter_mut()
        .map(|num_ar_p| DecimalShare::from_arithmetic(&num_ar_p.sub_share(&temp_p)))
        .collect();

    Ok(res)
}

#[derive(Clone)]
pub struct GetDataPltextInput {
    pub remote_nonce: String,
    pub our_nonce: String,
    pub remote_public_key: String,
    pub ciphertext: String,
}

/// Implementation of Section 3.15 from https://github.com/silence-laboratories/sl-compute/blob/sahamati-queries/docs.pdf
pub async fn run_get_data<T, R>(
    setup: &T,
    mpc_encryption: &mut MPCEncryption,
    tag_offset_counter: &mut TagOffsetCounter,
    relay: &mut FilteredMsgRelay<R>,
    pltext: GetDataPltextInput,
    own_private_key: &ArithmeticECShare,
    serverstate: &mut ServerState,
) -> Result<Vec<TransactionEntry>, ProtocolError>
where
    T: CommonSetupMessage,
    R: Relay,
{
    let now = Instant::now();
    let r_nonce = u8_vec_to_binary_string(BASE64_STANDARD.decode(pltext.remote_nonce).unwrap());
    let o_nonce = u8_vec_to_binary_string(BASE64_STANDARD.decode(pltext.our_nonce).unwrap());
    let remote_public_key = parse_remote_public_key(pltext.remote_public_key)
        .to_ed_compressed()
        .decompress()
        .unwrap();
    let ciphertext = BASE64_STANDARD.decode(pltext.ciphertext).unwrap();

    let ciphertext = ciphertext[..ciphertext.len() - 16].to_vec();

    let dec_xml_bool_p = run_threshold_decrypt(
        setup,
        mpc_encryption,
        tag_offset_counter,
        relay,
        remote_public_key,
        &r_nonce,
        &o_nonce,
        &ciphertext,
        own_private_key,
        serverstate,
    )
    .await?;

    println!("run_threshold_decrypt {}", tag_offset_counter.next_value());
    let elapsed = now.elapsed();
    println!("run_threshold_decrypt elapsed: {:.2?}", elapsed);

    let now = Instant::now();
    let dec_xml_p = binary_string_share_to_byte_shares(&dec_xml_bool_p).unwrap();

    let out1 = run_shave_data_front(
        setup,
        mpc_encryption,
        tag_offset_counter,
        relay,
        &dec_xml_p,
        serverstate,
    )
    .await?;

    println!("run_shave_data_front {}", tag_offset_counter.next_value());

    let out1 = run_shave_data_back(
        setup,
        mpc_encryption,
        tag_offset_counter,
        relay,
        &out1,
        serverstate,
    )
    .await?;

    println!("run_shave_data_back {}", tag_offset_counter.next_value());
    let elapsed = now.elapsed();
    println!("shave elapsed: {:.2?}", elapsed);

    let now = Instant::now();
    let delim1 = u8_vec_to_binary_string(DELIM_1.as_bytes().to_vec());
    let pad1 = u8_vec_to_binary_string(PAD_CHAR.as_bytes().to_vec());
    let maxreclen1 = REC_SIZE_L1;

    let out1_p = run_split_and_pad(
        setup,
        mpc_encryption,
        tag_offset_counter,
        relay,
        &SplitAndPadPltextInput {
            pad_character: pad1,
            max_rec_len: maxreclen1 as u64,
            delimiter: delim1,
        },
        &out1,
        serverstate,
    )
    .await?;

    println!("run_split_and_pad 1 {}", tag_offset_counter.next_value());
    let elapsed = now.elapsed();
    println!("run_split_and_pad 1 elapsed: {:.2?}", elapsed);

    let delim2 = u8_vec_to_binary_string(DELIM_2.as_bytes().to_vec());
    let pad2 = u8_vec_to_binary_string(PAD_CHAR.as_bytes().to_vec());
    let maxreclen2 = REC_SIZE_L2;

    let now = Instant::now();
    let mut out2_values = Vec::new();
    for i in 0..(out1_p.out.len() - 1) {
        let out2_p = run_split_and_pad(
            setup,
            mpc_encryption,
            tag_offset_counter,
            relay,
            &SplitAndPadPltextInput {
                pad_character: pad2.clone(),
                max_rec_len: maxreclen2 as u64,
                delimiter: delim2.clone(),
            },
            &out1_p.out[i],
            serverstate,
        )
        .await?;
        out2_values.push(out2_p);
    }
    println!("run_split_and_pad 2 {}", tag_offset_counter.next_value());
    let elapsed = now.elapsed();
    println!("run_split_and_pad 2 elapsed: {:.2?}", elapsed);

    let now = Instant::now();
    // let mut transactions_p = Vec::with_capacity(out2_values.len());
    // for out2_p in out2_values.iter() {
    //     let transaction_entry_p = {
    //         run_get_transaction_entry(
    //             setup,
    //             mpc_encryption,
    //             tag_offset_counter,
    //             relay,
    //             &out2_p.out,
    //             serverstate,
    //         )
    //         .await?
    //     };
    //     transactions_p.push(transaction_entry_p);
    // }

    let transactions_p = run_batch_get_transaction_entry(
        setup,
        mpc_encryption,
        tag_offset_counter,
        relay,
        &out2_values,
        serverstate,
    )
    .await?;

    println!(
        "run_get_transaction_entry {}",
        tag_offset_counter.next_value()
    );
    let elapsed = now.elapsed();
    println!("run_get_transaction_entry elapsed: {:.2?}", elapsed);

    Ok(transactions_p)
}

/// Test run_get_data() protocol
#[allow(dead_code)]
pub(crate) async fn test_run_get_data_protocol<T, R>(
    setup: T,
    seed: Seed,
    params: (GetDataPltextInput, ArithmeticECShare),
    relay: R,
) -> Result<(usize, Vec<TransactionEntry>), ProtocolError>
where
    T: CommonSetupMessage,
    R: Relay,
{
    use merlin::Transcript;
    use sl_compute::mpc::common_randomness::run_common_randomness;
    use sl_compute::transport::init::run_init;
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

    let pltext = params.0;
    let own_private_key = params.1;

    let result = run_get_data(
        &setup,
        &mut mpc_encryption,
        &mut tag_offset_counter,
        &mut relay,
        pltext,
        &own_private_key,
        &mut serverstate,
    )
    .await?;

    run_verify(
        &setup,
        &mut mpc_encryption,
        &mut tag_offset_counter,
        &mut relay,
        &mut serverstate,
    )
    .await?;

    let _ = relay.close().await;

    println!("transaction_entry len() =  {}", result.len());
    println!("tag_offset_counter = {}", tag_offset_counter.next_value());
    println!("num of triples = {}", serverstate.and_triples.a.length);
    //assert!(false);

    Ok((setup.participant_index(), result))
}

#[cfg(test)]
mod tests {
    use super::{test_run_get_data_protocol, GetDataPltextInput, TransactionEntry};
    use rust_decimal_macros::dec;
    use sl_compute::proto::reconstruct_byte_share_to_string;
    use sl_compute::transport::test_utils::setup_mpc;
    use sl_compute::{
        proto::reconstruct_decimal, types::ArithmeticECShare, utility::helper::convert_str_to_u256,
    };
    use sl_mpc_mate::coord::{MessageRelayService, Relay, SimpleMessageRelay};
    use tokio::task::JoinSet;

    async fn sim_get_data<S, R>(
        coord: S,
        sim_params: &[(GetDataPltextInput, ArithmeticECShare); 3],
    ) -> Vec<Vec<TransactionEntry>>
    where
        S: MessageRelayService<MessageRelay = R>,
        R: Relay + Send + 'static,
    {
        let parties = setup_mpc(None, sim_params);

        let mut jset = JoinSet::new();
        for (setup, seed, params) in parties {
            let relay = coord.connect().await.unwrap();

            jset.spawn(test_run_get_data_protocol(setup, seed, params, relay));
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
    async fn test_process_plaintext_i() {
        let remote_nonce = "KqhyUQkmkiy25Hl3WXRh2H8fe8gVpbfBrYR70p6yveE=".to_string();
        let encoded_nonce = "mEaPL5byDRWvbvAZhqbZIUudQmg2GAnpNL7JUH//aeU=".to_string();
        let remote_public_key = r###"-----BEGIN PUBLIC KEY-----MIIBMTCB6gYHKoZIzj0CATCB3gIBATArBgcqhkjOPQEBAiB/////////////////////////////////////////7TBEBCAqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqYSRShRAQge0Je0Je0Je0Je0Je0Je0Je0Je0Je0Je0JgtenHcQyGQEQQQqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq0kWiCuGaG4oIa04B7dLHdI0UySPU1+bXxhsinpxaJ+ztPZAiAQAAAAAAAAAAAAAAAAAAAAFN753qL3nNZYEmMaXPXT7QIBCANCAAQkEybsHS1Nu2o/oR14qAykP9jLbyRyTyPXFFRlPW729VF7SdyFX2qfaKG0yvIpEtk2Il7w8ijK5DZ/NI0oLA9q-----END PUBLIC KEY-----"###.to_string();
        let b64_ciphertext = r###"9kEswOIYXNBQJiAAlbGXopLI9A/aLwbF0liXkpxIagPegULHKRpaOX8dNNQEqQgVKoaGo7mA3dxY87EI2vKbeZW103V3bc1WqgWCdCUXvsYu0joOPGlZsJMjBYYuMRhVgBGLzDo2PDEDmwpvBvhrmv7v4MkvO/P1ctU/Q1zj0lYpTGk6/Fa/7tu4/xAvZCgXdtqANw04Mnm+PgEAqxtd37eByHgi0zs60E2IzyTawjx2X3wBE4imWASn4TxFwj7fJIQ1gxMQuuoLHeAXpD1UMdxRZO+bHzZaiYiOgBe6SvCJdx60ueggu2Ju8jXhUBXbywSAGzBVA0e4Uzz85yZDrGhOllgFq7fXac3noavJxkkLOnCvgPMb7Snq9vbAQlZVRvv3CP9imm9TklscNeKn1T+9+thgcylzPsd0PSIeXy1Wft7fZHrerqzqwkROv8L9UDYWXR1dvLGcxQ81hn4eSCTiJ7TYdc7UwV9GIDnSdrZq7TrSGqLKHjYeDPRLomqZUxBQNBVJ2KcbINmfQ2LVLQaL1WipoR2xyNuXFe05tzOCN+z7BqU/qrNocRuyCYxeHi0gm0n/k1nApuiwQCU/Zvme2LocfJqwPxlPo+ZlyGgqn2baRWbBUQMUN/I9FfYCL/tMFrNNeYv+19BefdZ3HVEVy4eGAx2G+2BbEBvOpaEtlASN3dwZKOQ1fkq51AESED9fqnYRPZOBCQxLq8GsL4lqb+bXfk6RnveKHZL8R6uo4xFVLIxkiqj9KMyQGmUZlKC8viUyEiSpuySqTzbmo3hCbU+e7wQBvPCX31xRsPeDKeqrYf5LkSXvRCgk4RrtdqDFoOpsIJn3Cp7YAyREtYnXmBhoqVzmvyzGiOEYVJD2K/c0Eo5oMyfr7Tfngo5YgOqz3/XMycvpzQP11lb26wFWCUblLqVLFCuI0XGFRq2UY8YPN/ngLcR8RatWXYrJ9bXbN8oqvb4IUGQHDSU0fQjWbfz45DZInknxDJnnO7ZHnkoSIlDPdo+YmfBBcG5XXVfiDC9DJKiCs4cZgdDSiedko0PkG5XS8i7gYUibf5hDGJx8BKstV283sRVEjpZnOzskymEnw7e3uzohUjgHmfROMdiVXOnBzULtG/RDwwHkiGSCMH9uZzXZ/JNdg8EN7t/MpyPNVD6VT0QMm2vPuelHuZtmhe3vLxti5mtW6rWD1pJVsguYurfb+oEo2/axgkFtk50c4xpy9/Ptrj6orsz/gKhy6QSCQgd4UMoEsMWm+GqWJYCJp10YLs1i/rbCqBGJzKNrqTIVVoANDFpu5t4s89qJIVQSZO1+Mav7newWLen5RgobUPqHd2uYCObtWwWvHpPw1uQhWPqIDf68esHzzNUg44IigX5OZo7lVG98GUabDdekbUv9WDIbc6eI4FZ3urEjHYTuS3BgyzT+973CEyIYfdLJVrvVlfQVQ6PmLr41ecQTBWaJJPy81plz1RRadfZHGRK78pZGdgjwY3g9QUXOkqj7MO5GPUriNcwpGkVV90/j5C40aLARHA3piqcy8iDzSjAa/ufWZsthYF/VsoNLKo+br9geOz5iJl9s5ryVbMCnZecnkgege3XPqUJR3wu1G+a2OsAUmt69zLC+D7aDoj5+Qd77tmLZ/dm4iSVsu0VCDAR8h/GoBx4WwPwtfi4hs+mwPU6KwDRa3lcjbS6M6FonICTxW9bYHzWybZ4aP24dZkX+2v/Bo1xb0vKWNHfl3rHb5V723IQLDWQW4/0y1TyJxckqIv6xpkagmJFxtUUSvRSZ+Fp8yhjF7u7MVcNG3ttkAkdjsMHmPO5tCnl8eGMgvv1lLeKHY+O4D/Qjt5UCv95qYIYgi3GYScIrYouM6gMv3nLfOmv0ifZk7zLzSfxvYAJZq8kCmkkaAMUdGPIPPI0IHzs/ZNdu4w6zyg30whyPQEE4a+M="###.to_string();
        let secretkey_p0 = ArithmeticECShare {
            value1: convert_str_to_u256(
                "F319C19CFF14BDE7A386245BB7442BD14722C8B79E904823077A2B80DB2FDA05",
            ),
            value2: convert_str_to_u256(
                "4B3DD1D6DE5306925FDA07BAC1880BBBAB22F628E98200A486E45F9BD10B2A08",
            ),
        };
        let secretkey_p1 = ArithmeticECShare {
            value1: convert_str_to_u256(
                "57E7B6DE346FF5CB515902477A4BEAA6EF859B9227A4AE426C6BAD6D42C6B10A",
            ),
            value2: convert_str_to_u256(
                "0CAAE507561BEF39F27EFA8CB8C2DEEB4363A5693E21AE9EE5864DD270BA8702",
            ),
        };
        let secretkey_p2 = ArithmeticECShare {
            value1: convert_str_to_u256(
                "B486D5CD76DCA58F362B172EAE7EFE01E06277F8F32EF61D661C19B77ADE3700",
            ),
            value2: convert_str_to_u256(
                "95B0E5223B24C9AD1A491444D4B5FE2A9CFFD18EB50D487F8095CBE40924B00D",
            ),
        };

        let plaintext = GetDataPltextInput {
            remote_nonce,
            our_nonce: encoded_nonce,
            remote_public_key,
            ciphertext: b64_ciphertext,
        };

        let params = [
            (plaintext.clone(), secretkey_p0),
            (plaintext.clone(), secretkey_p1),
            (plaintext.clone(), secretkey_p2),
        ];

        let results = sim_get_data(SimpleMessageRelay::new(), &params).await;
        assert_eq!(results.len(), 3);

        let out_p1 = results[0].clone();
        let out_p2 = results[1].clone();
        let out_p3 = results[2].clone();

        println!("Size of transactions: {}", out_p1.len());

        let req_currbal = dec!(1193.44);
        let req_txnamt = dec!(400.00);
        let req_nar =
            "PCD/8587/KARNIKA MARKETING PRIV/REWA120622/16:56~~~~~~~~~~~~~~~~~~~~~".to_string();
        let req_ref =
            "216311406416~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~".to_string();

        let nar = reconstruct_byte_share_to_string(
            out_p1[0].narration.clone(),
            out_p2[0].narration.clone(),
            out_p3[0].narration.clone(),
        );
        let refer = reconstruct_byte_share_to_string(
            out_p1[0].reference.clone(),
            out_p2[0].reference.clone(),
            out_p3[0].reference.clone(),
        );
        let currbal =
            reconstruct_decimal(out_p1[0].curr_bal, out_p2[0].curr_bal, out_p3[0].curr_bal);
        let txnamt = reconstruct_decimal(out_p1[0].txn_amt, out_p2[0].txn_amt, out_p3[0].txn_amt);

        assert_eq!(currbal, req_currbal);
        assert_eq!(txnamt, req_txnamt);
        assert_eq!(nar, req_nar);
        assert_eq!(refer, req_ref);
    }
}
