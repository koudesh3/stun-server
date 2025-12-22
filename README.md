## STUN Server

This is a complete, containerized, and RFC-compliant STUN server! I'm building this to learn Rust 🦀⚙️

Source: [RFC 8489](https://datatracker.ietf.org/doc/html/rfc8489)

## What the f is a STUN server?

A **Session Traversal Utilities for NAT (STUN) server** is basically a "mirror" for seeing your public IP address and port when behind a NAT. This is used (among other things) for peer-to-peer protocols like WebRTC, where both clients need to know their public addresses to establish direct connections.

## Does this have any practical use?

No, not at all! Don't use this in production please.

## Quick Start

```bash
# Build the image
make setup

# Start the server (Listens on 0.0.0.0:3478 by default but you can edit that in the Makefile)
make start

# Stop the server
make stop
```

To test, install a stunclient like `stuntman`

```bash
brew install stuntman
```

Then you can hit the server with
```bash
stunclient localhost 3478
```