// This program...
// 1. Listens on a TCP port (like 127.0.0.1:7878)
// 2. Accepts incoming connections
// 3. Reads bytes from the connection
// 4. Writes the same bytes back
// 5. Closes the connection

// TODO: Write unit tests

// TODO: Write integration tests using TcpStream::connect()

// TODO: What happens if the server receives over 1024 bytes? Loop until done

// TODO: What happens if the server receives *way* too many bytes? Set a maximum total bytes per connection

// TODO: How do we gracefully shut down the server with SIGINT, SIGTERM?

// TODO: How do we gracefully close the connection if unused? I.e. TTL, Idle timeout

// TODO: Don't crash the whole server if one connection fails

// TODO: Handle concurrent connections (spawn thread per connection).

use std::io;
use std::net::{TcpListener, TcpStream};
use std::io::prelude::*; // This imports common IO traits like Read/Write

struct TcpServer {
    listener: TcpListener
}

impl TcpServer {
    fn new(host_address: &str) -> io::Result<Self> {
        let listener = TcpListener::bind(host_address)?;
        Ok(TcpServer { listener })
    }

    fn start(&self) -> io::Result<()> {
        for stream in self.listener.incoming() {
            match stream {
                Ok(stream) => {
                    self.handle_client(stream)?;
                }
                Err(e) => {
                    eprintln!("Connection failed: {}", e);
                }
            }
        }
        Ok(())
    }

    fn handle_client(&self, mut stream: TcpStream) -> io::Result<()> {
        // Initialize a 1kb empty buffer
        // This is a fixed-size stack-allocated byte array
        let mut buffer = [0u8; 1024];

        // Get the remote peer address from the stream
        let peer_addr = stream.peer_addr().unwrap();

        // Load bytes from input stream into our buffer
        let bytes_received : usize = stream.read(&mut buffer)?;
        println!("Received {} bytes from {}", bytes_received, peer_addr);

        // Write the received bytes 
        stream.write(&buffer[0..bytes_received])?;
        println!("Sent {} bytes to {}", bytes_received, peer_addr);
        println!("Sent the following bytes: {:?}", &buffer[0..bytes_received]);

        Ok(())
    }
}

fn main() -> io::Result<()> {
    let server = TcpServer::new("localhost:9999")?;
    server.start()
}