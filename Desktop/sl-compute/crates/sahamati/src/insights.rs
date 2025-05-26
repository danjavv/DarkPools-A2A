use std::collections::HashMap;

use crate::average_eod_balance::run_avg_eod_balance;
use crate::average_eod_balance_all::run_avg_eod_balance_all;
use crate::eod_balances::run_eod_balances;
use crate::eom_balance::run_all_eom_balance;
use crate::monthly_category_debits::run_cat_debit_month;
use crate::process_plaintext_sh::TransactionEntry;
use crate::salary::run_get_salary;
use crate::top_credit::run_top_credit;
use crate::top_debit::run_top_debit;
use crate::total_credit::run_total_credit;
use crate::total_debit::run_total_debit;
use serde::Serialize;
use sl_compute::mpc::open_protocol::run_batch_open_float;
use sl_compute::transport::proto::FilteredMsgRelay;
use sl_compute::transport::setup::common::MPCEncryption;
use sl_compute::transport::setup::CommonSetupMessage;
use sl_compute::transport::types::ProtocolError;
use sl_compute::transport::utils::Seed;
use sl_compute::transport::utils::TagOffsetCounter;
use sl_compute::types::{ArithmeticShare, ServerState};
use sl_mpc_mate::coord::Relay;

#[derive(Clone, Debug, Serialize)]
pub struct FinancialData {
    total_credit: f64,
    total_debit: f64,
    top_credit: Vec<f64>,
    top_debit: Vec<f64>,
    eod_balances: Vec<f64>,
    avg_eod_balance: f64,
    salary: f64,
    eom_balances: Vec<f64>,
    avg_all_eod_balances: Vec<f64>,
    cat_debit: HashMap<usize, f64>,
}

pub async fn run_insights<T, R>(
    setup: &T,
    mpc_encryption: &mut MPCEncryption,
    tag_offset_counter: &mut TagOffsetCounter,
    relay: &mut FilteredMsgRelay<R>,
    transactions: &[TransactionEntry],
    serverstate: &mut ServerState,
) -> Result<FinancialData, ProtocolError>
where
    T: CommonSetupMessage,
    R: Relay,
{
    let num_top = 5;
    let month = 6;

    let top_credit_p = run_top_credit(
        setup,
        mpc_encryption,
        tag_offset_counter,
        relay,
        transactions,
        serverstate,
    )
    .await?;
    println!("run_top_credit {}", tag_offset_counter.next_value());

    let top_credit = run_batch_open_float(
        setup,
        mpc_encryption,
        tag_offset_counter,
        relay,
        &top_credit_p[0..num_top],
        serverstate,
    )
    .await?;

    let top_debit_p = run_top_debit(
        setup,
        mpc_encryption,
        tag_offset_counter,
        relay,
        transactions,
        serverstate,
    )
    .await?;
    let top_debit = run_batch_open_float(
        setup,
        mpc_encryption,
        tag_offset_counter,
        relay,
        &top_debit_p[0..num_top],
        serverstate,
    )
    .await?;

    println!("run_top_debit {}", tag_offset_counter.next_value());

    let total_credit_p = run_total_credit(
        setup,
        mpc_encryption,
        tag_offset_counter,
        relay,
        transactions,
        serverstate,
    )
    .await?;
    let total_credit = run_batch_open_float(
        setup,
        mpc_encryption,
        tag_offset_counter,
        relay,
        &[total_credit_p],
        serverstate,
    )
    .await?[0];

    println!("run_total_credit {}", tag_offset_counter.next_value());

    let total_debit_p = run_total_debit(
        setup,
        mpc_encryption,
        tag_offset_counter,
        relay,
        transactions,
        serverstate,
    )
    .await?;
    let total_debit = run_batch_open_float(
        setup,
        mpc_encryption,
        tag_offset_counter,
        relay,
        &[total_debit_p],
        serverstate,
    )
    .await?[0];

    println!("run_total_debit {}", tag_offset_counter.next_value());

    let eod_p = run_eod_balances(
        setup,
        mpc_encryption,
        tag_offset_counter,
        relay,
        month,
        transactions,
        serverstate,
    )
    .await?;
    let eod_balances = run_batch_open_float(
        setup,
        mpc_encryption,
        tag_offset_counter,
        relay,
        &eod_p,
        serverstate,
    )
    .await?;

    println!("run_eod_balances {}", tag_offset_counter.next_value());

    let avg_eod_p = run_avg_eod_balance(
        setup,
        mpc_encryption,
        tag_offset_counter,
        relay,
        month,
        transactions,
        serverstate,
    )
    .await?;
    let avg_eod_balance = run_batch_open_float(
        setup,
        mpc_encryption,
        tag_offset_counter,
        relay,
        &[avg_eod_p],
        serverstate,
    )
    .await?[0];

    println!("run_avg_eod_balance {}", tag_offset_counter.next_value());

    let salary_p = run_get_salary(
        setup,
        mpc_encryption,
        tag_offset_counter,
        relay,
        month,
        transactions,
        serverstate,
    )
    .await?;
    let salary = run_batch_open_float(
        setup,
        mpc_encryption,
        tag_offset_counter,
        relay,
        &[salary_p],
        serverstate,
    )
    .await?[0];

    println!("run_get_salary {}", tag_offset_counter.next_value());

    let eom_p = run_all_eom_balance(
        setup,
        mpc_encryption,
        tag_offset_counter,
        relay,
        transactions,
        serverstate,
    )
    .await?;
    let eom_balances = run_batch_open_float(
        setup,
        mpc_encryption,
        tag_offset_counter,
        relay,
        &eom_p,
        serverstate,
    )
    .await?;

    println!("run_all_eom_balance {}", tag_offset_counter.next_value());

    let avg_all_eod_p = run_avg_eod_balance_all(
        setup,
        mpc_encryption,
        tag_offset_counter,
        relay,
        transactions,
        serverstate,
    )
    .await?;
    let avg_all_eod_balances = run_batch_open_float(
        setup,
        mpc_encryption,
        tag_offset_counter,
        relay,
        &avg_all_eod_p,
        serverstate,
    )
    .await?;

    println!(
        "run_avg_eod_balance_all {}",
        tag_offset_counter.next_value()
    );

    let cat_debit_p = run_cat_debit_month(
        setup,
        mpc_encryption,
        tag_offset_counter,
        relay,
        month,
        transactions,
        serverstate,
    )
    .await?;

    println!("run_cat_debit_month {}", tag_offset_counter.next_value());

    let mut cat_debit = HashMap::new();
    for i in 1..8 {
        let mut share_p = ArithmeticShare::ZERO;

        if let Some(data_p1) = cat_debit_p.get(&i) {
            share_p = *data_p1;
        } else {
            println!("No data found for key 1");
        }

        let v = run_batch_open_float(
            setup,
            mpc_encryption,
            tag_offset_counter,
            relay,
            &[share_p],
            serverstate,
        )
        .await?[0];

        cat_debit.insert(i, v);
    }

    let data = FinancialData {
        total_credit,
        total_debit,
        top_credit,
        top_debit,
        eod_balances,
        avg_eod_balance,
        salary,
        eom_balances,
        avg_all_eod_balances,
        cat_debit,
    };

    //Ok(serde_json::to_value(data).unwrap())
    Ok(data)
}

/// Test run_insights protocol
#[allow(dead_code)]
async fn test_insights_protocol<T, R>(
    setup: T,
    seed: Seed,
    params: Vec<TransactionEntry>,
    relay: R,
) -> Result<(usize, FinancialData), ProtocolError>
where
    T: CommonSetupMessage,
    R: Relay,
{
    use merlin::Transcript;
    use sl_compute::mpc::common_randomness::run_common_randomness;
    use sl_compute::mpc::verify::run_verify;
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

    let result = run_insights(
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

    println!("tag_offset_counter = {}", tag_offset_counter.next_value());
    // assert!(false);

    let _ = relay.close().await;

    match result {
        Ok(v) => Ok((setup.participant_index(), v)),
        Err(e) => Err(e),
    }
}

#[cfg(test)]
mod tests {
    use crate::insights::{test_insights_protocol, FinancialData};
    use crate::process_plaintext_sh::TransactionEntry;
    use crate::sample_transaction_entries::{TRANSAC_STR_P1, TRANSAC_STR_P2, TRANSAC_STR_P3};
    use sl_compute::transport::test_utils::setup_mpc;
    use sl_mpc_mate::coord::{MessageRelayService, Relay, SimpleMessageRelay};
    use tokio::task::JoinSet;

    async fn sim<S, R>(coord: S, sim_params: &[Vec<TransactionEntry>; 3]) -> Vec<FinancialData>
    where
        S: MessageRelayService<MessageRelay = R>,
        R: Relay + Send + 'static,
    {
        let parties = setup_mpc(None, sim_params);

        let mut jset = JoinSet::new();
        for (setup, seed, params) in parties {
            let relay = coord.connect().await.unwrap();

            jset.spawn(test_insights_protocol(setup, seed, params, relay));
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
    async fn test_insights() {
        let transac_p1: Vec<TransactionEntry> = serde_json::from_str(TRANSAC_STR_P1).unwrap();
        let transac_p2: Vec<TransactionEntry> = serde_json::from_str(TRANSAC_STR_P2).unwrap();
        let transac_p3: Vec<TransactionEntry> = serde_json::from_str(TRANSAC_STR_P3).unwrap();

        let params = [transac_p1, transac_p2, transac_p3];

        let results = sim(SimpleMessageRelay::new(), &params).await;
        assert_eq!(results.len(), 3);

        let res_p1 = results[0].clone();
        let _res_p2 = results[1].clone();
        let _res_p3 = results[2].clone();

        println!("{:?}", res_p1);
    }
}
