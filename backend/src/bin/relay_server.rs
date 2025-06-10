use std::net::SocketAddr;
use backend::relay::run_server;

#[tokio::main]
async fn main() {
    let addr: SocketAddr = "0.0.0.0:9007".parse().expect("Invalid address");
    if let Err(e) = run_server(addr).await {
        eprintln!("Relay server failed: {}", e);
    }
} 
