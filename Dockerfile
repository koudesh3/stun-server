# Official Rust image
FROM rust:1.83 AS builder

# App directory
WORKDIR /app

# Manifests
COPY Cargo.toml Cargo.lock ./

# Source tree
COPY src ./src

# Build binary for release
RUN cargo build --release --bin stun_server

# Minimal runtime stage
FROM debian:bookworm-slim

# Copy binary from builder stage
COPY --from=builder /app/target/release/stun_server /usr/local/bin/stun_server

# Expose default STUN port
EXPOSE 3478/udp

# Set default environment variables
ENV STUN_BIND_ADDRESS=0.0.0.0:3478
ENV STUN_BUFFER_SIZE=2048

# Run it!
CMD ["stun_server"]