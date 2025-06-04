use std::time::Duration;

use backend::{
    types::OrderShare,
    v1::{setup_handle_orders_sock_v1, test_handle_orders_sock_v1},
    websocket_relay::WebSocketRelay,
};
use chrono::Utc;
use sl_compute::{
    transport::setup::ProtocolParticipant,
    types::{ArithmeticShare, FieldElement},
};
use tokio::task::JoinSet;
async fn handle_server() {
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
    // 1) Build all (setup, seed) tuples
    let parties = setup_handle_orders_sock_v1(None, &shares); // Vec<(Box<dyn CommonSetupMessage>, Seed)>
    let mut join = JoinSet::new();
    println!("Launching {} parties…", parties.len());
    // 2) Spawn one Tokio task per party (each uses WebSocketRelay)
    for (setup, seed, shares) in parties {
        // let idx = setup.participant_index() as u64;
        // Stagger startup so they don’t all connect at once
        // tokio::time::sleep(Duration::from_secs(idx * 2)).await;
        join.spawn(async move {
            let ws_url = "ws://localhost:9007";
            // 3) Reconnect loop until WebSocketRelay is ready
            let ws_relay = loop {
                match WebSocketRelay::connect(ws_url).await {
                    Ok(r) => break r,
                    Err(_) => {
                        eprintln!(
                            "Party {}: WS connect failed; retrying in 2s…",
                            setup.participant_index(),
                        );
                        tokio::time::sleep(Duration::from_secs(2)).await;
                    }
                }
            };
            // 4) Run the MPC protocol over ws_relay
            test_handle_orders_sock_v1(setup, seed, shares[0].clone(), ws_relay).await
        });
    }

    let mut results = vec![];
    while let Some(fini) = join.join_next().await {
        let fini = fini.unwrap();

        if let Err(ref err) = fini {
            println!("error {}", err);
        }

        let res = fini.unwrap();
        results.push(res);
    }
    results.sort_by_key(|r| r.0);
    let ress: Vec<Vec<(OrderShare, OrderShare)>> = results.into_iter().map(|r| r.1).collect();

    assert_eq!(ress.len(), 3);
    for (b, s) in &ress[0] {
        println!("output buy:{} sell: {}", b.symbol, s.symbol);
    }
    println!("All parties have finished.");
}

#[tokio::main]
async fn main() {
    handle_server().await;
}
