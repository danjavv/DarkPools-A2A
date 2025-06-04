// src/bin/relay_server.rs
use anyhow::Result;
use futures_util::{SinkExt, StreamExt};
use sl_mpc_mate::coord::{MessageRelayService, SimpleMessageRelay, simple::MessageRelay};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::{TcpListener, TcpStream};
use tokio_tungstenite::{accept_async, tungstenite::Message as WsMessage};
/// For each new WebSocket client, spawn a task that bridges:
///   (1) WebSocket ⇄ raw `Vec<u8>` frames,
///   (2) `MessageRelay` handle ⇄ central `SimpleMessageRelay`.
///
/// We run a single select! loop so we do not need to clone `MessageRelay`.
async fn spawn_connection(
    mut relay_handle: MessageRelay,
    ws_stream: tokio_tungstenite::WebSocketStream<TcpStream>,
) {
    let (mut ws_sink, mut ws_stream) = ws_stream.split();
    loop {
        tokio::select! {
            // 1) Read from WebSocket → forward to relay_handle.send(...)
            ws_msg = ws_stream.next() => {
                match ws_msg {
                    Some(Ok(WsMessage::Binary(frame))) => {
                        // Convert Bytes → Vec<u8>
                        let bytes: Vec<u8> = frame.into();
                        if relay_handle.send(bytes).await.is_err() {
                            break;
                        }
                    }
                    Some(Ok(WsMessage::Close(_))) | None => {
                        break;
                    }
                    _ => {
                        // Ignore non‐binary frames
                    }
                }
            }
            // 2) Read from relay_handle.next() → send back to WebSocket
            maybe_frame = relay_handle.next() => {
                match maybe_frame {
                    Some(frame_bytes) => {
                        if ws_sink
                            .send(WsMessage::Binary(frame_bytes.into()))
                            .await
                            .is_err()
                        {
                            break;
                        }
                    }
                    None => {
                        break;
                    }
                }
            }
        }
    }
}
/// Accept incoming TCP connections, upgrade them to WebSocket, and call `spawn_connection`.
pub async fn run_server(listen_addr: SocketAddr) -> Result<()> {
    let listener = TcpListener::bind(listen_addr).await?;
    println!("Relay server listening on ws://{}", listen_addr);
    // One global SimpleMessageRelay (shared among all connections)
    let simple_relay = Arc::new(SimpleMessageRelay::new());
    loop {
        let (tcp_stream, _) = listener.accept().await?;
        let client_addr = tcp_stream
            .peer_addr()
            .unwrap_or_else(|_| "unknown".parse().unwrap());
        // Upgrade to WebSocket
        match accept_async(tcp_stream).await {
            Ok(ws_stream) => {
                println!("New WebSocket connection from {}", client_addr);
                // Call the async trait method explicitly to get a future:
                let relay_handle = MessageRelayService::connect(&*simple_relay).await.unwrap(); // unwrap the Option<MessageRelay>
                // Spawn the broker task (single task with select!).
                tokio::spawn(spawn_connection(relay_handle, ws_stream));
            }
            Err(e) => {
                eprintln!("WebSocket upgrade error from {}: {}", client_addr, e);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::relay::run_server;

    #[tokio::test]
    async fn test_relay_server() {
        // You can make this configurable, e.g. via CLI args or an environment variable.
        let addr = "0.0.0.0:9007".parse().unwrap();
        let _ = run_server(addr).await;
    }
}
