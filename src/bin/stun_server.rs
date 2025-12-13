use std::io;
use std::net::{UdpSocket, SocketAddr, IpAddr, Ipv4Addr, Ipv6Addr};
// TODO: Implement rate Limiting (RateLimiter struct)
// TODO: Reject packets that are too large

struct StunServer {
    socket: UdpSocket,
    buffer_size: usize
}

#[derive(Debug, PartialEq)]
struct StunMessage {
    message_type: StunMessageType,
    message_length: u16,
    transaction_id: [u8; 12],
    reflexive_transport_address: Option<SocketAddr>,
    // username: Option<String>,
}

#[derive(Debug, PartialEq)]
enum StunMessageType {
    Request,     // Server receives, sends Success/Error response
    Indication,  // Server receives, does NOT respond
    Success,     // Client receives (response to its request)
    Error,       // Client receives (response to its request)
}

impl StunMessage {
    fn from_bytes(buff: &[u8]) -> io::Result<StunMessage> {
        // Parse header
        if buff.len() < 20 {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "Buffer too short to read message"));
        }
        
        // Check most significant two bits are 00 (byte 1)
        if buff[0] & 0b11000000 != 0 {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "Invalid STUN message"));
        }

        let message_type = u16::from_be_bytes([buff[0], buff[1]]);

        let c0 : u16 = (message_type >> 4) & 0x01;
        let c1 : u16 = (message_type >> 8) & 0x01;
        let class_bits : u16 =  (c1 << 1) | c0;

        // 00 request, 01 indication, 10 success, 11 error
        // These are u16, so there are far more than 4 permutations meaning we need to use the _ catch all
        let class = match class_bits {
            0b00 => StunMessageType::Request,
            0b01 => StunMessageType::Indication,
            0b10 => StunMessageType::Success,
            0b11 => StunMessageType::Error,
            _ => {
                return Err(io::Error::new(io::ErrorKind::InvalidData, "Invalid STUN message"));
            }
        };

        // Check message length (bytes 2 and 3)
        let message_length = u16::from_be_bytes([buff[2], buff[3]]);

        // STUN Magic Cookie 🍪 0x2112A442
        let magic_cookie_bits = u32::from_be_bytes([buff[4], buff[5], buff[6], buff[7]]);

        if magic_cookie_bits != 0x2112A442 {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "Invalid magic cookie for STUN protocol"));
        }

        // Parse transaction id
        let mut transaction_id = [0u8; 12];
        transaction_id.copy_from_slice(&buff[8..20]);

        // Optional properties
        let mut reflexive_transport_address = None;  // before the loop

        // The rest is the message. It is made up of attributes, which are in the format {Type, Length, Value}. We can parse sequentially
        let mut offset = 20; // Start after the header
        let end = 20 + message_length as usize; // End at the header + the message length

        while offset < end {
            // Read attribute header
            // TODO: There is a buffer overflow risk here
            let attribute_type = u16::from_be_bytes([buff[offset], buff[offset+1]]);
            // We must cast to usize if we want to slice buff with this value
            // TODO: There is no bounds checking on attribute_value. This is unsafe.
            let attribute_length = u16::from_be_bytes([buff[offset+2], buff[offset+3]]) as usize;

            // Read attribute
            let attribute_value = &buff[offset+4..offset+4+attribute_length];

            // Parse based on attribute type
            // TODO: Implement other attribute types (ex. username, password)
            match attribute_type {
                0x0020 => {
                    reflexive_transport_address = Some(Self::parse_xor_mapped_address(attribute_value, &transaction_id)?);
                },
                _ => { /* Skip Unimplemented attributes */ }
            }

            // Advance the offset to the next attribute
            offset += 4 + attribute_length;
            let padding = (4 - (attribute_length % 4)) % 4;
            offset += padding;
        }

        Ok(StunMessage { message_type: class, message_length, transaction_id, reflexive_transport_address })

    }

    // We return Vec<u8> instead of [u8] because [u8] is an unsized type we cannot return directly
    // This will serialize either a success or an error
    fn to_bytes(&self) -> io::Result<Vec<u8>> {

        // –––––––––––––––––– 1. Construct the header ––––––––––––––––––

        let method: u16 = 0x001; // Binding method

        let class : u16 = match self.message_type {
            StunMessageType::Request => 0b00,
            StunMessageType::Indication => 0b01,
            StunMessageType::Success => 0b10,
            StunMessageType::Error => 0b11
        };

        // Class and method bits are interlaced, which requires us to do this bit shifting dance to get them in place.
        // To understand this turn these bit masks from hex to binary and analyze which parts of the method/class bit string they align with
        let message_type : u16 = (method & 0xf80) << 2
                               | (method & 0x0070) << 1
                               | (method & 0x000f)
                               | (class & 0b10) << 7 
                               | (class & 0b01) << 4;

        let magic_cookie : u32 = 0x2112A442;

        // –––––––––––––––––– 2. Construct the attributes ––––––––––––––––––

        let attributes : Vec<u8> = match self.message_type {
            StunMessageType::Request => {
                // TODO: Add attributes for auth (ex. username, password)
                Vec::new()
            },
            StunMessageType::Indication => {
                // TODO: See if indications need attributes
                Vec::new()
            },
            StunMessageType::Success => {
                if let Some(reflexive_transport_address) = self.reflexive_transport_address {
                    let xor_mapped_address = StunMessage::construct_xor_mapped_address(
                        reflexive_transport_address,
                        &self.transaction_id
                    )?;
                    StunMessage::construct_attribute(0x0020, xor_mapped_address)
                } else {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "Failed to construct response"
                    ));
                }
            },
            StunMessageType::Error => {
                // TODO: Implement error attributes
                Vec::new()
            }
        };

        // –––––––––––––––––– 3. Construct the payload ––––––––––––––––––
        let message_length = attributes.len() as u16;

        let mut header = [0u8; 20];
        header[0..2].copy_from_slice(&message_type.to_be_bytes());
        header[2..4].copy_from_slice(&message_length.to_be_bytes());
        header[4..8].copy_from_slice(&magic_cookie.to_be_bytes());
        header[8..20].copy_from_slice(&self.transaction_id);

        let mut result = Vec::new();

        result.extend_from_slice(&header);
        result.extend_from_slice(&attributes);

        Ok(result)
    }

    // We return Vec<u8> because the response can be variable length depending on the IP address family
    fn construct_xor_mapped_address(
        peer_address: SocketAddr,
        transaction_id: &[u8; 12]
    ) -> io::Result<Vec<u8>> {
        match peer_address.ip() {
            IpAddr::V4(ipv4_address) => {
                let family : u8 = 0x01;
                let x_port : u16 = peer_address.port() ^ 0x2112;

                let octets = ipv4_address.octets();
                let address_u32 = u32::from_be_bytes(octets);
                let x_address : u32 = address_u32 ^ 0x2112A442;

                let mut result = Vec::new();
                result.push(0x00); // Reserved byte
                result.push(family);
                result.extend_from_slice(&x_port.to_be_bytes());
                result.extend_from_slice(&x_address.to_be_bytes());

                Ok(result)
            },
            IpAddr::V6(ipv6_address) => {
                let family : u8 = 0x02;
                let x_port : u16 = peer_address.port() ^ 0x2112;

                let octets = ipv6_address.octets();
                let address_u128 = u128::from_be_bytes(octets);

                let mut xor_key = [0u8; 16];
                let magic_cookie : u32 = 0x2112A442;
                xor_key[0..4].copy_from_slice(&magic_cookie.to_be_bytes());
                xor_key[4..16].copy_from_slice(transaction_id);
                let xor_key_u128 = u128::from_be_bytes(xor_key);

                let x_address : u128 = address_u128 ^ xor_key_u128;

                let mut result = Vec::new();
                result.push(0x00);
                result.push(family);
                result.extend_from_slice(&x_port.to_be_bytes());
                result.extend_from_slice(&x_address.to_be_bytes());

                Ok(result)
            }
        }
    }

    fn parse_xor_mapped_address(
        buff: &[u8],
        transaction_id: &[u8; 12]
    ) -> io::Result<SocketAddr> {
        let family = buff[1]; // 0x01 for IPv4, 0x02 for IPv6
        let x_port = u16::from_be_bytes([buff[2], buff[3]]);
        let port = x_port ^ 0x2112;

        match family {
            0x01 => {
                // IPv4 (32 bit address)
                let x_address = u32::from_be_bytes([buff[4], buff[5], buff[6], buff[7]]);
                let address = x_address ^ 0x2112A442;
                let ip = Ipv4Addr::from(address.to_be_bytes());
                Ok(SocketAddr::new(IpAddr::V4(ip), port))
            },
            0x02 => {
                // IPv6 (128 bit address)
                // TODO: Check if buffer is long enough, safely handle the unwrap
                let x_address_bytes : [u8; 16] = buff[4..20].try_into().unwrap();
                let x_address = u128::from_be_bytes(x_address_bytes);
                // 1. Concatenate magic cookie with transaction id (u128)
                let mut xor_key = [0u8; 16];
                let magic_cookie : u32 = 0x2112A442;
                xor_key[0..4].copy_from_slice(&magic_cookie.to_be_bytes());
                xor_key[4..16].copy_from_slice(transaction_id);
                let xor_key_u128 = u128::from_be_bytes(xor_key);
                // 2. XOR x_address with that
                let address = x_address ^ xor_key_u128;
                let ip = Ipv6Addr::from(address.to_be_bytes());
                Ok(SocketAddr::new(IpAddr::V6(ip), port))
            },
            _ => {
                return Err(io::Error::new(io::ErrorKind::InvalidData, "Invalid Address Family"));
            }
        }
    }

    fn construct_attribute(
        attribute_type: u16,
        value: Vec<u8>
    ) -> Vec<u8> {
        let length = value.len() as u16;
        let mut result = Vec::new();

        // Attribute Type (2-bytes, big-endian)
        result.extend_from_slice(&attribute_type.to_be_bytes());

        // Attribute Lenght (2-bytes, big-endian)
        result.extend_from_slice(&length.to_be_bytes());

        // Attribute Value
        result.extend_from_slice(&value);

        // Padding to 32-bit boundary
        let padding = (4 - (length % 4)) % 4;
        result.extend(vec![0u8; padding as usize]);

        result
    }
}

impl StunServer {

    fn new(
        socket_address: &str,
        buffer_size: usize
    ) -> io::Result<(Self, SocketAddr)> {
        let udp_socket = UdpSocket::bind(socket_address)?;
        let local_address = udp_socket.local_addr()?;
        Ok((
            StunServer { socket: udp_socket, buffer_size: buffer_size },
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

    fn start(&self) -> io::Result<()> {
        // Declare a buffer to read bytes into
        let mut buffer = vec![0u8; self.buffer_size];

        loop {
            println!("Waiting for packet...");
            let (bytes_received, remote_peer) = self.receive_packet(&mut buffer)?;
            println!("Received {} bytes from {}", bytes_received, remote_peer);

            // Parse datagram into StunMessage
            let request = StunMessage::from_bytes(&buffer[0..bytes_received])?;

            // This may return a StunMessage, or return nothing for unimplemented branches
            let response : Option<StunMessage> = match request.message_type {
                StunMessageType::Request => {
                    Some(StunMessage {
                        message_type: StunMessageType::Success,
                        message_length: request.message_length,
                        transaction_id: request.transaction_id,
                        reflexive_transport_address: Some(remote_peer)
                    })
                },
                StunMessageType::Indication => {
                    // TODO: Implement this branch
                    println!("Received indication. Path not yet implemented");
                    None
                },
                StunMessageType::Success => {
                    // TODO: Implement this branch
                    println!("Received Success. Path not yet implemented");
                    None
                },
                StunMessageType::Error => {
                    // TODO: Implement this branch
                    println!("Received Error. Path not yet implemented");
                    None
                }
            };

            // If the server generated a response, then send it back
            if let Some(response) = response {
                let response_bytes = response.to_bytes()?;
                let bytes_sent : usize = self.socket.send_to(&response_bytes, remote_peer)?;
                println!("Echoed {} bytes to {}", bytes_sent, remote_peer);
            }

        }
    }

}

fn main() -> io::Result<()> {
    // TODO: Read this as an environment variable
    let (server, local_address) = StunServer::new("0.0.0.0:8000", 2048)?;
    println!("Server listening on {}", local_address);
    server.start()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    // XOR an address then un-XOR it
    fn test_xor_round_trip_ipv4() {
        // Arrange
        let socket = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8080);
        let transaction_id = [8u8; 12];

        // Act
        let x_buffer = StunMessage::construct_xor_mapped_address(socket, &transaction_id).unwrap();
        let unxored_address = StunMessage::parse_xor_mapped_address(&x_buffer, &transaction_id).unwrap();

        // Assert
        assert_eq!(socket, unxored_address);
    }

    #[test]
    fn test_xor_round_trip_ipv6() {
        // Arrange
        let socket = SocketAddr::new(IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1)), 8080);
        let transaction_id = [8u8; 12];

        // Act
        let x_buffer = StunMessage::construct_xor_mapped_address(socket, &transaction_id).unwrap();
        let unxored_address = StunMessage::parse_xor_mapped_address(&x_buffer, &transaction_id).unwrap();

        // Assert
        assert_eq!(socket, unxored_address);
    }
    
    #[test]
    fn test_serialization_round_trip() {
        // Arrange
        let socket = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8080);

        let stun_message = StunMessage {
            message_type: StunMessageType::Success,
            message_length: 0,
            transaction_id: [0u8; 12],
            reflexive_transport_address: Some(socket),
        };

        // Act
        let message_as_bytes = stun_message.to_bytes().unwrap();
        let message_as_struct = StunMessage::from_bytes(&message_as_bytes).unwrap();

        // Assert
        assert_eq!(stun_message.message_type, message_as_struct.message_type);
        assert_eq!(stun_message.transaction_id, message_as_struct.transaction_id);
        assert_eq!(stun_message.reflexive_transport_address, message_as_struct.reflexive_transport_address);

    }

    #[test]
    fn test_from_bytes_rejects_short_buffer() {
        let short_buffer = [0u8; 10]; // Less than 20 bytes
        let result = StunMessage::from_bytes(&short_buffer);
        assert!(result.is_err());
    }

    #[test]
    fn test_from_bytes_rejects_invalid_magic_cookie() {
        let mut buffer = [0u8; 20];
        // Set wrong magic cookie
        buffer[4..8].copy_from_slice(&0xCAFFEEEE_u32.to_be_bytes());
        let result = StunMessage::from_bytes(&buffer);
        assert!(result.is_err());
    }

    #[test]
    fn test_from_bytes_rejects_invalid_message_type() {
        let mut buffer = [0u8; 20];
        // Set most significant bits to non-zero (invalid)
        buffer[0] = 0b11000000;
        // Set valid magic cookie
        buffer[4..8].copy_from_slice(&0x2112A442_u32.to_be_bytes());
        let result = StunMessage::from_bytes(&buffer);
        assert!(result.is_err());
    }

    #[test]
    fn test_server_responds_to_binding_request() {
        use std::thread;
        use std::sync::mpsc;

        // Arrange
        // 1. Spawn server in background thread
        let (tx, rx) = mpsc::channel();

        let _server_thread = thread::spawn(move || { // "move" transfers ownership of the transmitter
            let (server, local_address) = StunServer::new("127.0.0.1:0", 2048).unwrap();
            tx.send(local_address).unwrap(); // Send the local port binding to the other thread (ensuring it has started)
            server.start().unwrap();
        });

        // 2. Wait for server to be ready
        let server_address : SocketAddr = rx.recv().unwrap();

        // 3. Create a new client socket listening to packets from the server address
        let client = UdpSocket::bind("127.0.0.1:0").unwrap();

        // 4. Create a STUN binding request
        let stun_request = StunMessage {
            message_type: StunMessageType::Request,
            message_length: 0,
            transaction_id: [0u8; 12],
            reflexive_transport_address: None,
        };

        let request_bytes = stun_request.to_bytes().unwrap();

        // Act

        // 5. Send request to server
        client.send_to(&request_bytes, server_address).unwrap();

        // 6. Receive response from server
        let mut response_buffer = [0u8; 2048];
        let (bytes_received, _) = client.recv_from(&mut response_buffer).unwrap();

        // 7. Parse STUN response
        let stun_response = StunMessage::from_bytes(&response_buffer[0..bytes_received]).unwrap();

        // Assert
        assert_eq!(stun_response.message_type, StunMessageType::Success);
        assert_eq!(stun_response.transaction_id, stun_request.transaction_id);
        assert!(stun_response.reflexive_transport_address.is_some());
    }

}