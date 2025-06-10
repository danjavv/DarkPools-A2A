use serde::{Deserialize, Serialize};
use std::collections::VecDeque;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

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

#[derive(Debug, Serialize, Deserialize)]
struct Order {
    o_type: bool, // false for buy, true for sell
    symbol: String,
    quantity: u64,
    price: u64,
    min_execution: u64,
}

async fn handle_server() {
    // Start TCP server to accept orders
    let listener = TcpListener::bind("127.0.0.1:8080")
        .await
        .expect("Failed to bind");
    println!("Order server listening on 127.0.0.1:8080");

    let mut orders = VecDeque::new();
    let timeout = Duration::from_secs(5); // 5 seconds timeout for no new orders

    loop {
        tokio::select! {
            // Accept new connections
            Ok((mut socket, _)) = listener.accept() => {
                let mut buffer = Vec::new();
                let mut buf = [0; 1024];

                loop {
                    match socket.read(&mut buf).await {
                        Ok(0) => break, // Connection closed
                        Ok(n) => buffer.extend_from_slice(&buf[..n]),
                        Err(_) => break,
                    }
                }

                if !buffer.is_empty() {
                    match serde_json::from_slice::<Order>(&buffer) {
                        Ok(order) => {
                            println!("Received order: {:?}", order);
                            orders.push_back((
                                order.o_type,
                                order.symbol,
                                order.quantity,
                                order.price,
                                order.min_execution,
                                Utc::now()
                            ));
                        }
                        Err(e) => println!("Failed to parse order: {}", e),
                    }
                }
            }
            // Timeout after no new orders
            _ = tokio::time::sleep(timeout) => {
                if !orders.is_empty() {
                    println!("No new orders received for {} seconds, processing {} orders", timeout.as_secs(), orders.len());
                    break;
                }
            }
        }
    }

    // Convert received orders to OrderShare format
    let mut orders_p1 = Vec::new();
    let mut orders_p2 = Vec::new();
    let mut orders_p3 = Vec::new();

    for (typ, symb, quan, pric, mine, ts) in orders {
        let quan1 = ArithmeticShare::from_constant(&FieldElement::from(quan), 0);
        let quan2 = ArithmeticShare::from_constant(&FieldElement::from(quan), 1);
        let quan3 = ArithmeticShare::from_constant(&FieldElement::from(quan), 2);

        let pric1 = ArithmeticShare::from_constant(&FieldElement::from(pric), 0);
        let pric2 = ArithmeticShare::from_constant(&FieldElement::from(pric), 1);
        let pric3 = ArithmeticShare::from_constant(&FieldElement::from(pric), 2);

        let mine1 = ArithmeticShare::from_constant(&FieldElement::from(mine), 0);
        let mine2 = ArithmeticShare::from_constant(&FieldElement::from(mine), 1);
        let mine3 = ArithmeticShare::from_constant(&FieldElement::from(mine), 2);

        orders_p1.push(OrderShare {
            o_type: typ,
            symbol: symb.clone(),
            quantity: quan1,
            price: pric1,
            min_execution: mine1,
            timestamp: ts,
        });

        orders_p2.push(OrderShare {
            o_type: typ,
            symbol: symb.clone(),
            quantity: quan2,
            price: pric2,
            min_execution: mine2,
            timestamp: ts,
        });

        orders_p3.push(OrderShare {
            o_type: typ,
            symbol: symb,
            quantity: quan3,
            price: pric3,
            min_execution: mine3,
            timestamp: ts,
        });
    }

    let shares = [[orders_p1], [orders_p2], [orders_p3]];
    // 1) Build all (setup, seed) tuples
    let parties = setup_handle_orders_sock_v1(None, &shares);
    let mut join = JoinSet::new();
    println!("Launching {} parties…", parties.len());

    // 2) Spawn one Tokio task per party (each uses WebSocketRelay)
    for (setup, seed, shares) in parties {
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
