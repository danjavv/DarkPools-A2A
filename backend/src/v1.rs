use sl_compute::{
    comparison::compare_ge::run_compare_ge,
    conversion::a_to_b::run_batch_arithmetic_to_boolean,
    mpc::{
        multiply_binary_shares::run_and_binary_shares, open_protocol::run_batch_open_binary_share,
    },
    transport::{
        proto::FilteredMsgRelay,
        setup::{
            CommonSetupMessage,
            common::{MPCEncryption, SetupMessage},
        },
        types::ProtocolError,
        utils::{Seed, TagOffsetCounter},
    },
    types::ServerState,
};
use sl_mpc_mate::coord::Relay;

use crate::types::OrderShare;

pub async fn run_handle_orders_v1<T, R>(
    setup: &T,
    mpc_encryption: &mut MPCEncryption,
    tag_offset_counter: &mut TagOffsetCounter,
    relay: &mut FilteredMsgRelay<R>,
    orders: &[OrderShare],
    serverstate: &mut ServerState,
) -> Result<Vec<(OrderShare, OrderShare)>, ProtocolError>
where
    T: CommonSetupMessage,
    R: Relay,
{
    let mut queue_buy: Vec<OrderShare> = Vec::new();
    let mut queue_sell = Vec::new();

    for i in orders {
        if i.o_type {
            queue_sell.push(Some(i.clone()));
        } else {
            queue_buy.push(i.clone());
        }
    }

    let mut result = Vec::new();

    for buy_order in queue_buy {
        #[allow(clippy::needless_range_loop)]
        for sell_id in 0..queue_sell.len() {
            if let Some(sell_order) = &queue_sell[sell_id] {
                let outputs = run_batch_arithmetic_to_boolean(
                    setup,
                    mpc_encryption,
                    tag_offset_counter,
                    relay,
                    &[
                        buy_order.price,
                        sell_order.price,
                        sell_order.quantity,
                        buy_order.min_execution,
                        buy_order.quantity,
                        sell_order.min_execution,
                    ],
                    serverstate,
                )
                .await?;

                let comp1 = run_compare_ge(
                    setup,
                    mpc_encryption,
                    tag_offset_counter,
                    relay,
                    &outputs[0],
                    &outputs[1],
                    serverstate,
                )
                .await?;

                let comp2 = run_compare_ge(
                    setup,
                    mpc_encryption,
                    tag_offset_counter,
                    relay,
                    &outputs[2],
                    &outputs[3],
                    serverstate,
                )
                .await?;

                let comp3 = run_compare_ge(
                    setup,
                    mpc_encryption,
                    tag_offset_counter,
                    relay,
                    &outputs[4],
                    &outputs[5],
                    serverstate,
                )
                .await?;

                let temp = run_and_binary_shares(
                    setup,
                    mpc_encryption,
                    tag_offset_counter,
                    relay,
                    &comp1,
                    &comp2,
                    serverstate,
                )
                .await?;

                let compres = run_and_binary_shares(
                    setup,
                    mpc_encryption,
                    tag_offset_counter,
                    relay,
                    &temp,
                    &comp3,
                    serverstate,
                )
                .await?;

                let comp = run_batch_open_binary_share(
                    setup,
                    mpc_encryption,
                    tag_offset_counter,
                    relay,
                    &[compres],
                    serverstate,
                )
                .await?[0];

                if comp {
                    result.push((buy_order, sell_order.clone()));
                    queue_sell[sell_id] = None;
                    break;
                }
            }
        }
    }

    Ok(result)
}

pub fn setup_handle_orders_sock_v1(
    instance: Option<[u8; 32]>,
    shares: &[[Vec<OrderShare>; 1]; 3],
) -> Vec<(SetupMessage, [u8; 32], [Vec<OrderShare>; 1])> {
    use sha2::{Digest, Sha256};
    use sl_compute::transport::setup::{NoSigningKey, NoVerifyingKey, ProtocolParticipant};
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
        .zip(shares.iter())
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

pub async fn test_handle_orders_sock_v1<T, R>(
    setup: T,
    seed: Seed,
    share: Vec<OrderShare>,
    relay: R,
) -> Result<(usize, Vec<(OrderShare, OrderShare)>), ProtocolError>
where
    T: CommonSetupMessage,
    R: Relay,
{
    use merlin::Transcript;
    use sl_compute::{
        mpc::{common_randomness::run_common_randomness, verify::run_verify},
        transport::init::run_init,
    };
    use sl_mpc_mate::coord::SinkExt;

    let mut relay = FilteredMsgRelay::new(relay);

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

    let result = run_handle_orders_v1(
        &setup,
        &mut mpc_encryption,
        &mut tag_offset_counter,
        &mut relay,
        &share,
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
    use chrono::Utc;
    use sl_compute::{
        transport::{
            proto::FilteredMsgRelay,
            setup::{CommonSetupMessage, common::SetupMessage},
            types::ProtocolError,
            utils::{Seed, TagOffsetCounter},
        },
        types::{ArithmeticShare, FieldElement, ServerState},
    };
    use sl_mpc_mate::coord::{MessageRelayService, Relay, SimpleMessageRelay};
    use tokio::task::JoinSet;

    use crate::{types::OrderShare, v1::run_handle_orders_v1};

    async fn test_handle_orders_v1<T, R>(
        setup: T,
        seed: Seed,
        share: Vec<OrderShare>,
        relay: R,
    ) -> Result<(usize, Vec<(OrderShare, OrderShare)>), ProtocolError>
    where
        T: CommonSetupMessage,
        R: Relay,
    {
        use merlin::Transcript;
        use sl_compute::{
            mpc::{common_randomness::run_common_randomness, verify::run_verify},
            transport::init::run_init,
        };
        use sl_mpc_mate::coord::SinkExt;

        let mut relay = FilteredMsgRelay::new(relay);

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

        let result = run_handle_orders_v1(
            &setup,
            &mut mpc_encryption,
            &mut tag_offset_counter,
            &mut relay,
            &share,
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

    pub fn setup_handle_orders_v1(
        instance: Option<[u8; 32]>,
        shares: &[[Vec<OrderShare>; 1]; 3],
    ) -> Vec<(SetupMessage, [u8; 32], [Vec<OrderShare>; 1])> {
        use sha2::{Digest, Sha256};
        use sl_compute::transport::setup::{NoSigningKey, NoVerifyingKey, ProtocolParticipant};
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
            .zip(shares.iter())
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

    async fn sim_parties_handle_orders_v1<S, R>(
        parties: Vec<(SetupMessage, [u8; 32], [Vec<OrderShare>; 1])>,
        coord: S,
    ) -> Vec<Vec<(OrderShare, OrderShare)>>
    where
        S: MessageRelayService<MessageRelay = R>,
        R: Send + Relay + 'static,
    {
        let mut jset = JoinSet::new();
        for (setup, seed, share) in parties {
            let relay = coord.connect().await.unwrap();
            jset.spawn(test_handle_orders_v1(setup, seed, share[0].clone(), relay));
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

    async fn sim_handle_orders_v1<S, R>(
        coord: S,
        shares: &[[Vec<OrderShare>; 1]; 3],
    ) -> Vec<Vec<(OrderShare, OrderShare)>>
    where
        S: MessageRelayService<MessageRelay = R>,
        R: Relay + Send + 'static,
    {
        let parties = setup_handle_orders_v1(None, shares);
        sim_parties_handle_orders_v1(parties, coord).await
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_handle_orders_v1_protocol() {
        let orders = [
            (false, "abc1", 100, 200, 50, Utc::now()),
            (true, "abc2", 100, 200, 50, Utc::now()),
            (false, "abc3", 100, 200, 50, Utc::now()),
            (true, "abc4", 100, 200, 50, Utc::now()),
        ];

        let mut orders_p1 = Vec::new();
        let mut orders_p2 = Vec::new();
        let mut orders_p3 = Vec::new();

        for (typ, symb, quan, pric, mine, ts) in orders {
            let quan1 = ArithmeticShare::from_constant(&FieldElement::from(quan as u64), 0);
            let quan2 = ArithmeticShare::from_constant(&FieldElement::from(quan as u64), 1);
            let quan3 = ArithmeticShare::from_constant(&FieldElement::from(quan as u64), 2);

            let pric1 = ArithmeticShare::from_constant(&FieldElement::from(pric as u64), 0);
            let pric2 = ArithmeticShare::from_constant(&FieldElement::from(pric as u64), 1);
            let pric3 = ArithmeticShare::from_constant(&FieldElement::from(pric as u64), 2);

            let mine1 = ArithmeticShare::from_constant(&FieldElement::from(mine as u64), 0);
            let mine2 = ArithmeticShare::from_constant(&FieldElement::from(mine as u64), 1);
            let mine3 = ArithmeticShare::from_constant(&FieldElement::from(mine as u64), 2);

            orders_p1.push(OrderShare {
                o_type: typ,
                symbol: symb.to_owned(),
                quantity: quan1,
                price: pric1,
                min_execution: mine1,
                timestamp: ts,
            });

            orders_p2.push(OrderShare {
                o_type: typ,
                symbol: symb.to_owned(),
                quantity: quan2,
                price: pric2,
                min_execution: mine2,
                timestamp: ts,
            });

            orders_p3.push(OrderShare {
                o_type: typ,
                symbol: symb.to_owned(),
                quantity: quan3,
                price: pric3,
                min_execution: mine3,
                timestamp: ts,
            });
        }

        let shares = [[orders_p1], [orders_p2], [orders_p3]];

        let results = sim_handle_orders_v1(SimpleMessageRelay::new(), &shares).await;

        assert_eq!(results.len(), 3);
        for (b, s) in &results[0] {
            println!("output buy:{} sell: {}", b.symbol, s.symbol);
        }
    }
}
