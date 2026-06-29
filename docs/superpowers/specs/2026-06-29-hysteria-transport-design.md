# Hysteria 2 Transport Support

## Summary

Add `"hysteria"` as a listener and dialer transport type, enabling gost to accept and initiate Hysteria 2 connections. Integrates `github.com/apernet/hysteria/core/v2` as a library. Phase 1 covers TCP stream proxy only; UDP datagram relay is deferred.

## Components

### listener/hysteria/

Implements `listener.Listener` for gost to act as a Hysteria 2 server.

**Files:**

- `listener.go` — `init()` registers `"hysteria"` in `ListenerRegistry()`. Struct wraps `server.Server`. `Accept()` blocks on a `chan net.Conn` queue.
- `outbound.go` — Implements hysteria's `server.Outbound` interface. `TCP(reqAddr)` uses `net.Pipe()` to create a conn pair: the local end is returned to hysteria's server for proxying; the remote end (carrying `reqAddr`) is pushed into the accept queue.
- `conn.go` — `hyConn` wraps a `net.Conn` and adds `RemoteAddr()` / `LocalAddr()` derived from hysteria connection metadata.
- `metadata.go` — `parseMetadata()` extracts config from `metadata.Metadata`.

**Data flow:**

```
hysteria client → UDP → [server.Server] → Outbound.TCP("host:port")
                                                 │
                                    ┌────────────┘
                                    │ net.Pipe()
                                    ▼
                              remote end → chan → Accept() → socks5 handler → target
                              local end  → server copies target ↔ client
```

### dialer/hysteria/

Implements `dialer.Dialer` for gost to connect through a Hysteria 2 server.

**Files:**

- `dialer.go` — `init()` registers `"hysteria"` in `DialerRegistry()`. `Dial()` creates/caches `client.Client` sessions keyed by server address. Calls `client.TCP(addr)` to open streams. `Multiplex()` returns `true`.
- `metadata.go` — `parseMetadata()` extracts config.

**Data flow:**

```
local socks5 → handler → dialer.Dial() → client.TCP("host:port") → UDP → hysteria server → target
```

## Metadata Keys

### Listener

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `auth` | string | required | Authentication password |
| `congestion` | string | `"bbr"` | Congestion control: `"bbr"` or `"brutal"` |
| `bandwidth.tx` | int | `0` | Max upload bytes/sec (0=unlimited) |
| `bandwidth.rx` | int | `0` | Max download bytes/sec (0=unlimited) |
| `keepAlive` | bool | `false` | Enable QUIC keepalive |
| `ttl` | duration | `"10s"` | Keepalive interval |
| `handshakeTimeout` | duration | `"0"` | QUIC handshake timeout |
| `maxIdleTimeout` | duration | `"0"` | QUIC max idle timeout |
| `backlog` | int | `128` | Accept queue size |
| `disableUDP` | bool | `true` | Disable UDP relay (forced in phase 1) |

### Dialer

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `auth` | string | required | Authentication password |
| `congestion` | string | `"bbr"` | Congestion control |
| `bandwidth.tx` | int | `0` | Max upload bytes/sec |
| `bandwidth.rx` | int | `0` | Max download bytes/sec |
| `fastOpen` | bool | `false` | TCP fast open — return conn before server confirms |
| `keepAlive` | bool | `false` | Enable QUIC keepalive |
| `ttl` | duration | `"10s"` | Keepalive interval |
| `handshakeTimeout` | duration | `"0"` | QUIC handshake timeout |
| `maxIdleTimeout` | duration | `"0"` | QUIC max idle timeout |

## TLS Configuration

TLS uses gost's standard `listener.tls` / `dialer.tls` blocks (not metadata keys):

```yaml
# Listener
listener:
  type: hysteria
  tls:
    cert: /path/to/cert.pem
    key: /path/to/key.pem

# Dialer
dialer:
  type: hysteria
  tls:
    serverName: hy.example.com
    insecure: false
```

## Dependencies

Add `github.com/apernet/hysteria/core/v2` to `go.mod`. This transitively pulls in `github.com/apernet/quic-go` (a fork). Because the module paths differ, this does NOT conflict with the existing `github.com/quic-go/quic-go` used by other QUIC/HTTP3 transports.

## Config Examples

### Server: gost as Hysteria server

```yaml
services:
  - name: hy-entry
    addr: ":443"
    handler:
      type: socks5
      chain: internal-chain
    listener:
      type: hysteria
      tls:
        cert: /etc/gost/cert.pem
        key: /etc/gost/key.pem
      metadata:
        auth: "my-secret"
        congestion: brutal
        bandwidth.tx: 104857600
        bandwidth.rx: 52428800
```

### Client: gost through Hysteria server

```yaml
chains:
  - name: hy-chain
    hops:
      - name: hop-0
        nodes:
          - name: hy-node
            addr: hy.example.com:443
            connector:
              type: relay
            dialer:
              type: hysteria
              tls:
                serverName: hy.example.com
              metadata:
                auth: "my-secret"
                congestion: brutal

services:
  - name: socks-via-hy
    addr: ":1080"
    handler:
      type: socks5
      chain: hy-chain
    listener:
      type: tcp
```

## Error Handling

- Hysteria `ConnectError` → listener drops session, logged at warn level
- Hysteria `AuthError` → listener rejects QUIC connection during handshake
- `DialError` from `client.TCP()` → returned as `net.OpError` wrapping the underlying error
- `ClosedError` → session removed from dialer cache; next `Dial()` creates a fresh client

## Out of Scope (Phase 1)

- UDP datagram relay through hysteria
- Hysteria masquerade (HTTP masq handler)
- Salamander/Gecko obfuscation
- Custom authenticator integration with gost's auther chain
- Bandwidth negotiation feedback to gost metrics
