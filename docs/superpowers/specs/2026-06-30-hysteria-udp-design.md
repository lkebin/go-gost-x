# Hysteria UDP Datagram Relay

## Summary

Add UDP datagram relay through hysteria's native QUIC datagram channel (`client.UDP()` / `HyUDPConn`). Enables UDP traffic (DNS, gaming, etc.) to flow through gost's hysteria dialer to an official hysteria server. Implemented in the connector layer since `network` flows from handler → router → connector, not to the dialer.

## Why connector, not dialer?

The `dialer.Dialer` interface has no `network` parameter — it connects to the proxy node. The `network` ("udp" vs "tcp") is consumed by the **connector** via `Connect(ctx, conn, network, address)`. The hysteria dialer already returns `hyClientConn` (embeds `client.Client`) which exposes both `TCP()` and `UDP()`. The connector just needs to call the right one.

## Components

### connector/hysteria/packet_conn.go (new)

`hyPacketConn` adapts hysteria's `client.HyUDPConn` to Go's `net.PacketConn`. Also implements dummy `net.Conn` methods so it satisfies the connector's `net.Conn` return type.

```
HyUDPConn.Receive() → (data, fromAddr)  →  ReadFrom(b) → (n, addr, err)
HyUDPConn.Send(data, addr)             ←  WriteTo(b, addr) → (n, err)
HyUDPConn.Close()                       ↔  Close()
```

| Method | Behavior |
|--------|----------|
| `ReadFrom(b)` | Calls `hyUDP.Receive()`, parses `fromAddr` string to `net.Addr` via `net.ResolveUDPAddr` |
| `WriteTo(b, addr)` | Calls `hyUDP.Send(b, addr.String())` |
| `Close()` | Calls `hyUDP.Close()` |
| `LocalAddr()` | Returns `&net.UDPAddr{}` — QUIC has no notion of a local UDP address |
| `RemoteAddr()` | Returns hysteria server address |
| `SetDeadline` / `SetReadDeadline` / `SetWriteDeadline` | No-op — `HyUDPConn` does not support deadlines |
| `Read` / `Write` (net.Conn) | Returns error — datagrams must use `ReadFrom`/`WriteTo` |

### connector/hysteria/connector.go (modified)

Add UDP branch before the existing TCP branch in `Connect`:

```go
if network == "udp" {
    if cc, ok := conn.(interface{ UDP() (client.HyUDPConn, error) }); ok {
        conn.Close()
        hyUDP, err := cc.UDP()
        if err != nil {
            return nil, err
        }
        return &hyPacketConn{hyUDP: hyUDP, raddr: conn.RemoteAddr()}, nil
    }
    return conn, nil
}
```

Existing TCP path unchanged. `hyClientConn` (from dialer) embeds `client.Client` which already has `UDP()`, so no dialer changes needed.

### No changes

- `dialer/hysteria/` — `hyClientConn` already embeds `client.Client` with `UDP()` method
- `listener/hysteria/` — out of scope (user deploys official hysteria server)
- No new metadata/config keys needed

## Data flow

```
[App UDP, e.g. DNS] → SOCKS5 UDP handler
                         │
                         │ Router.Dial("udp", "")
                         ▼
                    chain → route → transport
                         │
                         │ hysteria dialer
                         │ returns hyClientConn (embeds client.Client)
                         ▼
                    hysteria connector
                         │
                         │ network == "udp" → type-assert UDP()
                         │ → client.UDP() → HyUDPConn
                         │ → wrap in hyPacketConn
                         ▼
                    hyPacketConn (net.PacketConn + net.Conn)
                         │
                         │ ReadFrom/WriteTo ↔ Receive/Send
                         ▼
                    QUIC Datagrams (TLS 1.3 encrypted)
                         │
                         ▼
                    Official Hysteria Server
                         │
                         │ udpSessionManager → Outbound.UDP()
                         ▼
                    Real UDP target (DNS server, etc.)
```

## Test plan

### Unit tests: `connector/hysteria/packet_conn_test.go`

Mock `HyUDPConn` with a buffered channel-based fake. Written first (TDD).

| Test | Verifies |
|------|----------|
| `TestHyPacketConn_ReadFrom` | `Receive()` data and address flow correctly to `ReadFrom()` |
| `TestHyPacketConn_WriteTo` | `WriteTo(addr)` calls `Send(data, addr.String())` |
| `TestHyPacketConn_Close` | After `Close()`, `ReadFrom`/`WriteTo` return `net.ErrClosed` |
| `TestHyPacketConn_ReceiveError` | `Receive()` error propagates to `ReadFrom()` |
| `TestHyPacketConn_SendError` | `Send()` error propagates to `WriteTo()` |
| `TestHyPacketConn_ImplementsPacketConn` | Compile-time `var _ net.PacketConn = &hyPacketConn{}` |
| `TestHyPacketConn_ReadReturnsError` | `Read()` (stream) returns error |
| `TestHyPacketConn_WriteReturnsError` | `Write()` (stream) returns error |

### Integration tests: `connector/hysteria/connector_test.go`

| Test | Verifies |
|------|----------|
| `TestHyConnector_Connect_UDP` | `network="udp"` with `UDP()`-capable conn returns `*hyPacketConn` |
| `TestHyConnector_Connect_UDP_NoInterface` | `network="udp"` without `UDP()` passes conn through unchanged |
| `TestHyConnector_Connect_TCP_Unchanged` | `network="tcp"` still calls `TCP(address)` |

## Files changed

| File | Action |
|------|--------|
| `connector/hysteria/packet_conn.go` | New |
| `connector/hysteria/packet_conn_test.go` | New |
| `connector/hysteria/connector.go` | Modify |
| `connector/hysteria/connector_test.go` | New |
