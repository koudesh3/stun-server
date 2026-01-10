use std::io;
use std::net::{UdpSocket, SocketAddr};
use crate::rate_limiter::RateLimiter;
use crate::message::{StunMessage, StunMessageType};

// TODO: Reject packets that are too large

pub struct StunServer {
    socket: UdpSocket,
    buffer_size: usize,
    rate_limiter: RateLimiter,
}

impl StunServer {

    pub fn new(
        socket_address: &str,
        buffer_size: usize,
        bucket_capacity: f64,
        bucket_leak_rate: f64
    ) -> io::Result<(Self, SocketAddr)> {
        let socket = UdpSocket::bind(socket_address)?;
        let local_address = socket.local_addr()?;
        let rate_limiter = RateLimiter::new(bucket_capacity, bucket_leak_rate);
        Ok((
            StunServer {
                socket,
                buffer_size,
                rate_limiter
            },
            local_address
        ))
    }

    fn receive_packet(
        &self,
        buffer: &mut [u8]
    ) -> io::Result<(usize, SocketAddr)> {
        let (bytes_received, remote_peer) = self.socket.recv_from(buffer)?;
        Ok((bytes_received, remote_peer))
    }

    pub fn start(&mut self) -> io::Result<()> {
        let mut buffer = vec![0u8; self.buffer_size];

        loop {
            println!("Waiting for packet...");
            let (bytes_received, remote_peer) = self.receive_packet(&mut buffer)?;
            println!("Received {} bytes from {}", bytes_received, remote_peer);


            // note: IP is rate limited, silently drop packet and continue
            if !self.rate_limiter.check_and_update(remote_peer.ip()) {
                continue;
            }

            // note: If we haven't cleaned up in 5 mins, then clean up all bucket that haven't been touched in 10 mins
            if self.rate_limiter.should_cleanup(300) {
                self.rate_limiter.cleanup_stale_buckets(600);
            }

            let request = match StunMessage::from_bytes(&buffer[0..bytes_received]) {
                    Ok(msg) => {
                        println!("Parsed message type: {:?}", msg.message_type);
                        println!("Unknown required attributes: {:?}", msg.unknown_attributes);
                        msg
                    },
                Err(e) => {
                    println!("STUN message is malformed. Silently discarding: {}", e);
                    continue;
                }
            };

            // note: Constructing a valid StunMessage may fail, so we wrap in Option<T>
            let response : Option<StunMessage> = match request.message_type {
                StunMessageType::Request => {

                    if !request.unknown_attributes.is_empty() {
                        Some(StunMessage {
                            message_type: StunMessageType::Error,
                            message_length: 0,
                            transaction_id: request.transaction_id,
                            reflexive_transport_address: Some(remote_peer),
                            unknown_attributes: request.unknown_attributes.clone(),
                            error_code: Some(420),
                            error_reason: Some("Unknown Attribute".to_string()),
                        })
                    } else {
                        Some(StunMessage {
                            message_type: StunMessageType::Success,
                            message_length: 0, // note: This is constructed on serialization
                            transaction_id: request.transaction_id,
                            reflexive_transport_address: Some(remote_peer),
                            unknown_attributes: Vec::new(),
                            error_code: None,
                            error_reason: None,
                        })
                    }

                },
                StunMessageType::Indication => {
                    // note: No response is required for an indication. These are used as simple "keep alives" for the NAT binding
                    println!("Received binding indication from {}", remote_peer);
                    None
                },
                StunMessageType::Success | StunMessageType::Error => {
                    // note: It isn't realistic for a STUN client to send a "success" or "error" to the server.
                    println!("Received unexpected response from client");
                    None
                }
            };

            if let Some(response) = response {
                println!("Sending response type: {:?}", response.message_type);
                let response_bytes = response.to_bytes()?;
                let bytes_sent : usize = self.socket.send_to(&response_bytes, remote_peer)?;
                println!("Echoed {} bytes to {}", bytes_sent, remote_peer);
            }
        }
    }

}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::IpAddr;

    #[test]
    fn test_server_responds_to_binding_request() {
        use std::thread;
        use std::sync::mpsc;

        // Arrange
        // –––––––––––––––––– 1. Spawn server in bg and wait for it to be ready ––––––––––––––––––
        // note: To ensure that the server has successfully started before we start sending requests, we use a channel instead of the hacky 'sleep'
        let (tx, rx) = mpsc::channel();

        let _server_thread = thread::spawn(move || { // note: 'move' transfers ownership of the transmitter to the created thread
            let (mut server, local_address) = StunServer::new("127.0.0.1:0", 2048, 20.0, 10.0).unwrap();
            tx.send(local_address).unwrap();
            server.start().unwrap();
        });

        let server_address : SocketAddr = rx.recv().unwrap();

        // –––––––––––––––––– 2. Create client socket listener ––––––––––––––––––
        let client = UdpSocket::bind("127.0.0.1:0").unwrap();

        // –––––––––––––––––– 3. Create a STUN binding request ––––––––––––––––––
        let stun_request = StunMessage {
            message_type: StunMessageType::Request,
            message_length: 0,
            transaction_id: [0u8; 12],
            reflexive_transport_address: None,
            unknown_attributes: Vec::new(),
            error_code: None,
            error_reason: None,
        };

        let request_bytes = stun_request.to_bytes().unwrap();

        // Act

        // –––––––––––––––––– 4. Send request to server ––––––––––––––––––
        client.send_to(&request_bytes, server_address).unwrap();

        // –––––––––––––––––– 5. Receive response from server ––––––––––––––––––
        let mut response_buffer = [0u8; 2048];
        let (bytes_received, _) = client.recv_from(&mut response_buffer).unwrap();

        // –––––––––––––––––– 6. Parse STUN response ––––––––––––––––––
        let stun_response = StunMessage::from_bytes(&response_buffer[0..bytes_received]).unwrap();

        // Assert
        assert_eq!(stun_response.message_type, StunMessageType::Success);
        assert_eq!(stun_response.transaction_id, stun_request.transaction_id);
        assert!(stun_response.reflexive_transport_address.is_some());
    }

    #[test]
    fn test_server_returns_420_for_unknown_attribute() {}

    // TODO: Add test_rate_limiter_allows_requests_under_capacity to verify bucket allows bursts up to capacity
    // TODO: Add test_rate_limiter_drops_requests_over_capacity to verify excess requests are dropped
    // TODO: Add test_rate_limiter_leaks_over_time to verify bucket drains at leak_rate and allows new requests
    // TODO: Add test_rate_limiter_isolates_ips to verify different IPs have independent buckets
    // TODO: Add test_cleanup_removes_stale_buckets to verify memory management
}
