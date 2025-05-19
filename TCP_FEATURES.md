# WireGuard TCP and Obfuscation Extensions

This fork of WireGuard adds support for using TCP as a transport protocol, along with traffic obfuscation capabilities and automatic key rotation.

## New Features

### TCP Support

- Use TCP instead of UDP for WireGuard connections
- Useful in environments where UDP is blocked or throttled
- Enable with `-tcp` flag

### Traffic Obfuscation

- WebSocket obfuscation: Wraps traffic in WebSocket protocol to make it look like web traffic
- TLS obfuscation: Adds TLS encryption to evade deep packet inspection
- Configure with `-obfs` flag

### Automatic Key Rotation

- Periodically rotates cryptographic keys for enhanced security
- Configurable time interval (default: 24 hours)
- Enable with `-kr` flag

## Usage

```bash
# Start WireGuard with TCP support on port 51820
sudo ./wireguard-go -tcp -p 51820 wg0

# Start WireGuard with WebSocket obfuscation
sudo ./wireguard-go -tcp -obfs ws -wsurl wss://your-server.com/wireguard wg0

# Start WireGuard with TLS obfuscation
sudo ./wireguard-go -tcp -obfs tls wg0

# Enable key rotation every 12 hours
sudo ./wireguard-go -kr 12 wg0

# Combine all features
sudo ./wireguard-go -tcp -p 8443 -obfs ws -wsurl wss://example.com/wg -kr 24 wg0
```

## Command Line Options

```
  -f, --foreground         Run in the foreground
  -tcp, --tcp-mode         Use TCP instead of UDP
  -p, --port PORT          Port to listen on (default: 51820)
  -obfs, --obfuscation TYPE    Traffic obfuscation type: none, ws, tls (default: none)
  -wsurl, --websocket-url URL  WebSocket URL for obfuscation (default: wss://localhost/wireguard)
  -kr, --key-rotation HOURS    Enable key rotation with specified interval in hours (default: 24)
```

## Troubleshooting

### TCP Timeout Issues

- Check firewall rules: `sudo ufw allow 51820/tcp`
- Ensure both server and client are configured to use TCP

### WebSocket Connection Errors

- Verify that the WebSocket URL is correct and accessible
- Check TLS certificates if using secure WebSockets (wss://)
- Try with `-obfs tls` instead if WebSocket is blocked

### TLS Handshake Failures

- Might be caused by restrictive network policies
- Try using WSS (WebSocket Secure) instead with `-obfs ws`

## Implementation Details

The TCP implementation wraps the standard UDP-based WireGuard protocol to work over a reliable TCP connection. This involves:

1. A TCP listener that accepts connections
2. Packet framing to delimit WireGuard messages
3. Connection management for reliability and reconnection

Obfuscation options provide ways to disguise the traffic:

- WebSocket encapsulation makes traffic look like web communication
- TLS wrapper encrypts traffic with standard TLS, hiding WireGuard characteristics

Key rotation enhances security by automatically changing encryption keys at regular intervals, which limits the amount of data encrypted with any single key.
