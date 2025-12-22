use std::io;
use std::net::{UdpSocket, SocketAddr, IpAddr, Ipv4Addr, Ipv6Addr};
// TODO: Implement rate Limiting (RateLimiter struct)
// TODO: Reject packets that are too large

struct StunServer {
    socket: UdpSocket,
    buffer_size: usize
}

// TODO: Implement StunClient struct for use in tests
// struct StunClient {}

#[derive(Debug, PartialEq)]
struct StunMessage {
    message_type: StunMessageType,
    message_length: u16,
    transaction_id: [u8; 12],
    reflexive_transport_address: Option<SocketAddr>,
    unknown_attributes: Vec<u16>, 
    error_code: Option<u16>, 
    error_reason: Option<String>,
}

#[derive(Debug, PartialEq)]
enum StunMessageType {
    Request,     // Server receives, sends Success/Error response
    Indication,  // Server receives, does NOT respond
    Success,     // Client receives (response to its request)
    Error,       // Client receives (response to its request)
}

impl StunMessage {

    // TODO: Implement new_request() and new_indication() so this struct can be used for a STUN client
    // This would generate a cryptographically random transaction_id and otherwise initialize an empty message

    fn from_bytes(buff: &[u8]) -> io::Result<StunMessage> {

        // –––––––––––––––––– 1. Parse the header ––––––––––––––––––
        if buff.len() < 20 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Buffer too short to read message"
            ));
        }
        
        if buff[0] & 0b11000000 != 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Invalid STUN message"
            ));
        }

        let message_type = u16::from_be_bytes([buff[0], buff[1]]);
        let c0 : u16 = (message_type >> 4) & 0x01;
        let c1 : u16 = (message_type >> 8) & 0x01;
        let class_bits : u16 =  (c1 << 1) | c0;

        // 00 request, 01 indication, 10 success, 11 error
        let class = match class_bits {
            0b00 => StunMessageType::Request,
            0b01 => StunMessageType::Indication,
            0b10 => StunMessageType::Success,
            0b11 => StunMessageType::Error,
            _ => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "Invalid STUN message"
                ));
            }
        };

        let message_length = u16::from_be_bytes([buff[2], buff[3]]);

        let magic_cookie_bits = u32::from_be_bytes([buff[4], buff[5], buff[6], buff[7]]);

        if magic_cookie_bits != 0x2112A442 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Invalid magic cookie for STUN protocol"
            ));
        }

        let mut transaction_id = [0u8; 12];
        transaction_id.copy_from_slice(&buff[8..20]);

        // –––––––––––––––––– 2. Parse the attributes ––––––––––––––––––
        // note: Attributes are structured like {Type: 2 bytes, Length: 2 bytes, Value: Variable length}
        let mut reflexive_transport_address = None;
        let mut unknown_attributes = Vec::new();
        let mut error_code = None;
        let mut error_reason = None;

        let mut offset = 20; // note: header is 20 bytes
        let end = 20 + message_length as usize;

        while offset < end {
            // Read attribute header
            if offset + 4 > buff.len() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "Buffer is too short to read attribute header"
                ));
            }

            let attribute_type = u16::from_be_bytes([buff[offset], buff[offset+1]]);
            let attribute_length = u16::from_be_bytes([buff[offset+2], buff[offset+3]]) as usize;

            // Read attribute value
            if offset + 4 + attribute_length > buff.len() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "Buffer is too short to read attribute value"
                ));
            }

            let attribute_value = &buff[offset+4..offset+4+attribute_length];

            // Parse the attribute based on its type
            match attribute_type {
                0x0020 => {
                    reflexive_transport_address = Some(Self::parse_xor_mapped_address(attribute_value, &transaction_id)?);
                },
                0x0009 => {
                    let (code, reason) = Self::parse_error_code(attribute_value)?;
                    error_code = Some(code);
                    error_reason = Some(reason);
                },
                0x000A => {
                    let attributes = Self::parse_unknown_attributes(attribute_value)?;
                    unknown_attributes = attributes;
                },
                0x0003 => {
                    // note: CHANGE-REQUEST (0x0003) is a legacy attribute from RFC 3489, we can ignore it
                },
                _ => {
                    // note: In this range, attribute_type is "comprehension required" (0x0000-0x7FFF)
                    //       otherwise it's "comprehension optional" (0x8000-0xFFFF), so we can safely ignore :)
                    if attribute_type <= 0x7FFF {
                        unknown_attributes.push(attribute_type);
                    }
                    
                }
            }

            // Finally, advance the offset to the next attribute
            offset += 4 + attribute_length;
            let padding = (4 - (attribute_length % 4)) % 4;
            offset += padding;
        }

        // –––––––––––––––––– 3. Return serialized response ––––––––––––––––––
        Ok(StunMessage {
            message_type: class,
            message_length,
            transaction_id,
            reflexive_transport_address,
            unknown_attributes,
            error_code,
            error_reason,
        })

    }

    fn to_bytes(&self) -> io::Result<Vec<u8>> {

        // –––––––––––––––––– 1. Construct the header ––––––––––––––––––

        // note: The only method STUN implements is BINDING (0x001)
        let method: u16 = 0x001;
        let class : u16 = match self.message_type {
            StunMessageType::Request => 0b00,
            StunMessageType::Indication => 0b01,
            StunMessageType::Success => 0b10,
            StunMessageType::Error => 0b11
        };

        // note: Class and method bits are interlaced, which requires us to do this bit shifting dance to get them in place
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
                Vec::new() // note: Binding indications require no attributes
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
                if let Some(error_code) = self.error_code {
                    let mut attributes = Vec::new();

                    let error_code_attribute = Self::construct_error_code_attribute(error_code)?;
                    attributes.extend(Self::construct_attribute(0x0009, error_code_attribute));

                    if error_code == 420 && !self.unknown_attributes.is_empty() {
                        let unknown_attributes = Self::construct_unknown_attribute(&self.unknown_attributes)?;
                        attributes.extend(Self::construct_attribute(0x000A, unknown_attributes));
                    }

                    attributes
                } else {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "Error message must have an error code"
                    ));
                }
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

    fn construct_error_code_attribute(error_code: u16) -> io::Result<Vec<u8>> {
        // note: We extract codes like 420 into 4 and 20 this way.
        let class = (error_code / 100) as u8;
        let number = (error_code % 100) as u8;

        if class < 3 || class > 6 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Error class must be between 3 and 6"
            ));
        }

        // note: The format is rrrr rrrr rrrr rrrr rrrr rccc nnnn nnnn
        let value : u32 = ((class as u32) << 8) | (number as u32);

        let mut result = Vec::new();
        result.extend_from_slice(&value.to_be_bytes());

        let reason = match error_code {
            300 => "Try Alternate",
            400 => "Bad Request",
            401 => "Unauthenticated",
            420 => "Unknown Attribute",
            438 => "Stale Nonce",
            500 => "Server Error",
            _ => "Unknown error"
        };

        // note: This is how we turn strings into UTF-8 encoding
        result.extend_from_slice(reason.as_bytes());

        Ok(result)
    }

    fn construct_unknown_attribute(attributes: &Vec<u16>) -> io::Result<Vec<u8>> {

        let mut result = Vec::new();

        for attribute_type in attributes {
            result.extend_from_slice(&attribute_type.to_be_bytes());
        }

        Ok(result)
    }

    fn parse_unknown_attributes(buff: &[u8]) -> io::Result<Vec<u16>> {

        let mut unknown_attributes = Vec::new();

        if buff.len() % 2 != 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Unknown attribute array is malformed"
            ));
        }

        for i in (0..buff.len()).step_by(2) {
            let attribute = u16::from_be_bytes([buff[i], buff[i+1]]);
            unknown_attributes.push(attribute);
        }

        Ok(unknown_attributes)
    }

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
                result.push(0x00); // note: This is a reserved byte
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

                // note: The magic cookie is too short to XOR an IPv6 address, so we concat with the transaction ID
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
        let family = buff[1]; // note: Family byte is 0x01 for IPv4, 0x02 for IPv6
        let x_port = u16::from_be_bytes([buff[2], buff[3]]);
        let port = x_port ^ 0x2112;

        match family {
            0x01 => {
                if buff.len() < 8 {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "Buffer too short for IPv4 address"
                    ));
                }

                let x_address = u32::from_be_bytes([buff[4], buff[5], buff[6], buff[7]]);
                let address = x_address ^ 0x2112A442;
                let ip = Ipv4Addr::from(address.to_be_bytes());
                Ok(SocketAddr::new(IpAddr::V4(ip), port))
            },
            0x02 => {
                if buff.len() < 20 {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "Buffer too short for IPv6 address"
                    ));
                }

                let x_address_bytes : [u8; 16] = buff[4..20].try_into()
                    .map_err(|_| io::Error::new(
                        io::ErrorKind::InvalidData,
                        "Failed to parse IPv6 address into bytes"
                    ))?;
                let x_address = u128::from_be_bytes(x_address_bytes);

                // note: The magic cookie is too short to XOR an IPv6 address, so we concat with the transaction ID
                let mut xor_key = [0u8; 16];
                let magic_cookie : u32 = 0x2112A442;
                xor_key[0..4].copy_from_slice(&magic_cookie.to_be_bytes());
                xor_key[4..16].copy_from_slice(transaction_id);
                let xor_key_u128 = u128::from_be_bytes(xor_key);
                
                let address = x_address ^ xor_key_u128;
                let ip = Ipv6Addr::from(address.to_be_bytes());
                Ok(SocketAddr::new(IpAddr::V6(ip), port))
            },
            _ => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "Invalid Address Family"
                ));
            }
        }
    }

    fn parse_error_code(buff: &[u8]) -> io::Result<(u16, String)> {
        
        if buff.len() < 4 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Attribute is too short to contain valid error code"
            ));
        }
        
        // note: The format is rrrr rrrr rrrr rrrr rrrr rccc nnnn nnnn   
        let value = u16::from_be_bytes([buff[2], buff[3]]);

        let class = value >> 8 & 0x07;
        let number = value & 0xFF;

        let error_code = class * 100 + number;
        let error_reason = String::from_utf8(buff[4..].to_vec())
            .map_err(|_| io::Error::new(
                io::ErrorKind::InvalidData,
                "Failed to parse error reason into bytes"
            ))?;
        
        Ok((error_code, error_reason))
    }

    // note: Attributes are structured like {Type: 2 bytes, Length: 2 bytes, Value: Variable length}
    fn construct_attribute(
        attribute_type: u16,
        value: Vec<u8>
    ) -> Vec<u8> {
        let length = value.len() as u16;
        let mut result = Vec::new();

        result.extend_from_slice(&attribute_type.to_be_bytes());
        result.extend_from_slice(&length.to_be_bytes());
        result.extend_from_slice(&value);

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
        let mut buffer = vec![0u8; self.buffer_size];

        loop {
            println!("Waiting for packet...");
            let (bytes_received, remote_peer) = self.receive_packet(&mut buffer)?;
            println!("Received {} bytes from {}", bytes_received, remote_peer);

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

fn main() -> io::Result<()> {
    // TODO: When containerized, read this as an environment variable
    let (server, local_address) = StunServer::new("0.0.0.0:8000", 2048)?;
    println!("Server listening on {}", local_address);
    server.start()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
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
            unknown_attributes: Vec::new(),
            error_code: None,
            error_reason: None,
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
        let short_buffer = [0u8; 10]; // note: We need at least 20 bytes to read a header
        let result = StunMessage::from_bytes(&short_buffer);
        assert!(result.is_err());
    }

    #[test]
    fn test_from_bytes_rejects_invalid_magic_cookie() {
        let mut buffer = [0u8; 20];
        buffer[4..8].copy_from_slice(&0xCAFFEEEE_u32.to_be_bytes()); // note: This is the wrong cookie 🍪
        let result = StunMessage::from_bytes(&buffer);
        assert!(result.is_err());
    }

    #[test]
    fn test_from_bytes_rejects_invalid_message_type() {
        let mut buffer = [0u8; 20];
        // note: Here we're setting the most significant 2 bits to non-zero (error condition) with a valid cookie
        buffer[0] = 0b11000000;
        buffer[4..8].copy_from_slice(&0x2112A442_u32.to_be_bytes());
        let result = StunMessage::from_bytes(&buffer);
        assert!(result.is_err());
    }

    #[test]
    fn test_server_responds_to_binding_request() {
        use std::thread;
        use std::sync::mpsc;

        // Arrange
        // –––––––––––––––––– 1. Spawn server in bg and wait for it to be ready ––––––––––––––––––
        // note: To ensure that the server has successfully started before we start sending requests, we use a channel instead of the hacky 'sleep'
        let (tx, rx) = mpsc::channel();

        let _server_thread = thread::spawn(move || { // note: 'move' transfers ownership of the transmitter to the created thread
            let (server, local_address) = StunServer::new("127.0.0.1:0", 2048).unwrap();
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

}