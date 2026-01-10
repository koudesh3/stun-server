use std::io;
use stun_server::server::StunServer;

fn main() -> io::Result<()> {
    let bind_address = std::env::var("STUN_BIND_ADDRESS")
        .ok()
        .unwrap_or_else(|| "0.0.0.0:3478".to_string());

    let buffer_size = std::env::var("STUN_BUFFER_SIZE")
        .ok()
        .and_then(|s| (s.parse()).ok())
        .unwrap_or(2048);

    let rate_limit_capacity = std::env::var("STUN_RATE_LIMIT_CAPACITY")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(20.0);

    let rate_limit_rate = std::env::var("STUN_RATE_LIMIT_RATE")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(10.0);

    let (mut server, local_address) = StunServer::new(&bind_address, buffer_size, rate_limit_capacity, rate_limit_rate)?;

    println!("Server listening on {}", local_address);
    server.start()
}