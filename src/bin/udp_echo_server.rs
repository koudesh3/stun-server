// This program...
// 1. Binds to a UDP port (like 127.0.0.1:7878)
// 2. Waits for incoming packets
// 3. Reads bytes from the packet and the sender's address
// 4. Writes the same bytes back to that sender
// 5. Repeats (UDP socket stays open, no connection to close)

use std::io;
use std::net::UdpSocket;

struct UdpServer {
    socket: UdpSocket,
    buffer_size: usize
}

impl UdpServer {

    fn new(socket_address: &str, buffer_size: usize) -> io::Result<Self> {
        let udp_socket = UdpSocket::bind(socket_address)?;
        Ok(UdpServer { socket: udp_socket, buffer_size: buffer_size })
    }

    fn start(&self) -> io::Result<()> {
        // Declare a buffer to read bytes into
        let mut buffer = vec![0u8; self.buffer_size];

        loop {
            // Unwrap bytes received and peer address into a tuple
            let (bytes_received, remote_peer) = self.socket.recv_from(&mut buffer)?;
            println!("Received {} bytes from {}", bytes_received, remote_peer);

            // Echo byes back to peer
            let message = &mut buffer[0..bytes_received];
            let bytes_sent : usize = self.socket.send_to(message, remote_peer)?;
            println!("Echoed {} bytes to {}", bytes_sent, remote_peer);

        }
    }

}

fn main() -> io::Result<()> {
    let server = UdpServer::new("localhost:8000", 1024)?;
    server.start()
}