# Hysteria 2 Transport Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add `"hysteria"` listener and dialer transports to gost, integrating `github.com/apernet/hysteria/core/v2`.

**Architecture:** Two new packages — `listener/hysteria/` (server side: wraps `server.Server`, bridges `Outbound.TCP` into a `net.Conn` queue via `net.Pipe()`) and `dialer/hysteria/` (client side: wraps `client.Client` with session caching, `Dial()` calls `client.TCP(addr)`). No new handler needed; reuses existing handlers (relay/socks5/http). Phase 1: TCP only.

**Tech Stack:** Go 1.26, `github.com/apernet/hysteria/core/v2`, forked `github.com/apernet/quic-go`

---

### Task 1: Add hysteria dependency

**Files:**
- Modify: `go.mod`, `go.sum`

- [ ] **Step 1: Add hysteria/core/v2 dependency**

```bash
cd /Users/kbliu/Workspace/src/gost-x && go get github.com/apernet/hysteria/core/v2@latest
```

- [ ] **Step 2: Verify go.mod updated**

```bash
grep -c 'apernet/hysteria' go.mod
```

Expected: at least 1 (the core/v2 require line). `github.com/apernet/quic-go` appears in indirect deps.

- [ ] **Step 3: Verify `go build ./...` still passes**

```bash
cd /Users/kbliu/Workspace/src/gost-x && go build ./...
```

Expected: no errors (new dependency is not imported yet, just present in module graph).

- [ ] **Step 4: Commit**

```bash
git add go.mod go.sum
git commit -m "deps: add github.com/apernet/hysteria/core/v2

Co-Authored-By: Claude Opus 4.7 <noreply@anthropic.com>"
```

---

### Task 2: Create listener metadata types and parsing

**Files:**
- Create: `listener/hysteria/metadata.go`

- [ ] **Step 1: Create listener/hysteria/ directory**

```bash
mkdir -p /Users/kbliu/Workspace/src/gost-x/listener/hysteria
```

- [ ] **Step 2: Write metadata.go**

```go
package hysteria

import (
	mdata "github.com/go-gost/core/metadata"
	mdutil "github.com/go-gost/x/metadata/util"
)

const (
	defaultBacklog = 128
)

type metadata struct {
	auth            string
	congestionType  string
	bandwidthTx     uint64
	bandwidthRx     uint64
	keepAlivePeriod int64
	handshakeTimeout int64
	maxIdleTimeout  int64
	disableUDP      bool
	backlog         int
}

func (l *hysteriaListener) parseMetadata(md mdata.Metadata) (err error) {
	const (
		keyAuth             = "auth"
		keyCongestion       = "congestion"
		keyBandwidthTx      = "bandwidth.tx"
		keyBandwidthRx      = "bandwidth.rx"
		keyKeepAlive        = "keepAlive"
		keyTTL              = "ttl"
		keyHandshakeTimeout = "handshakeTimeout"
		keyMaxIdleTimeout   = "maxIdleTimeout"
		keyDisableUDP       = "disableUDP"
		keyBacklog          = "backlog"
	)

	l.md.auth = mdutil.GetString(md, keyAuth)
	l.md.congestionType = mdutil.GetString(md, keyCongestion)
	if l.md.congestionType == "" {
		l.md.congestionType = "bbr"
	}
	l.md.bandwidthTx = uint64(mdutil.GetInt(md, keyBandwidthTx))
	l.md.bandwidthRx = uint64(mdutil.GetInt(md, keyBandwidthRx))
	l.md.disableUDP = mdutil.GetBool(md, keyDisableUDP)

	if mdutil.GetBool(md, keyKeepAlive) {
		l.md.keepAlivePeriod = mdutil.GetInt(md, keyTTL)
		if l.md.keepAlivePeriod <= 0 {
			l.md.keepAlivePeriod = 10
		}
	}
	l.md.handshakeTimeout = mdutil.GetInt(md, keyHandshakeTimeout)
	l.md.maxIdleTimeout = mdutil.GetInt(md, keyMaxIdleTimeout)

	l.md.backlog = mdutil.GetInt(md, keyBacklog)
	if l.md.backlog <= 0 {
		l.md.backlog = defaultBacklog
	}

	return
}
```

- [ ] **Step 3: Verify compilation (expected to fail — hysteriaListener not defined yet)**

```bash
cd /Users/kbliu/Workspace/src/gost-x && go build ./listener/hysteria/ 2>&1 | head -5
```

Expected: error about undefined `hysteriaListener`. Accept this; the type will be defined in Task 3.

- [ ] **Step 4: Commit**

```bash
git add listener/hysteria/metadata.go
git commit -m "feat: add hysteria listener metadata parsing

Co-Authored-By: Claude Opus 4.7 <noreply@anthropic.com>"
```

---

### Task 3: Create listener conn wrapper and outbound

**Files:**
- Create: `listener/hysteria/conn.go`
- Create: `listener/hysteria/outbound.go`

- [ ] **Step 1: Write conn.go**

```go
package hysteria

import "net"

type hyConn struct {
	net.Conn
	laddr net.Addr
	raddr net.Addr
}

func (c *hyConn) LocalAddr() net.Addr {
	return c.laddr
}

func (c *hyConn) RemoteAddr() net.Addr {
	return c.raddr
}
```

- [ ] **Step 2: Write outbound.go**

```go
package hysteria

import (
	"net"

	"github.com/apernet/hysteria/core/v2/server"
)

type hyOutbound struct {
	queue chan<- net.Conn
	laddr net.Addr
}

func (ob *hyOutbound) TCP(reqAddr string) (net.Conn, error) {
	local, remote := net.Pipe()
	conn := &hyConn{
		Conn:  remote,
		laddr: ob.laddr,
		raddr: &hyAddr{network: "tcp", addr: reqAddr},
	}

	select {
	case ob.queue <- conn:
	default:
		remote.Close()
		local.Close()
	}
	return local, nil
}

func (ob *hyOutbound) UDP(reqAddr string) (server.UDPConn, error) {
	return nil, net.ErrClosed
}

func (ob *hyOutbound) CheckUDP(reqAddr string) error {
	return net.ErrClosed
}

type hyAddr struct {
	network string
	addr    string
}

func (a *hyAddr) Network() string { return a.network }
func (a *hyAddr) String() string  { return a.addr }
```

- [ ] **Step 3: Verify compilation**

```bash
cd /Users/kbliu/Workspace/src/gost-x && go build ./listener/hysteria/ 2>&1
```

Expected: fails with `undefined: hysteriaListener` (from metadata.go). Accept — will be defined in Task 4.

- [ ] **Step 4: Commit**

```bash
git add listener/hysteria/conn.go listener/hysteria/outbound.go
git commit -m "feat: add hysteria listener conn and outbound

Co-Authored-By: Claude Opus 4.7 <noreply@anthropic.com>"
```

---

### Task 4: Create listener.go — the main listener

**Files:**
- Create: `listener/hysteria/listener.go`

- [ ] **Step 1: Write listener.go**

```go
package hysteria

import (
	"crypto/tls"
	"net"
	"strings"
	"time"

	"github.com/apernet/hysteria/core/v2/server"
	"github.com/go-gost/core/listener"
	"github.com/go-gost/core/logger"
	md "github.com/go-gost/core/metadata"
	xnet "github.com/go-gost/x/internal/net"
	"github.com/go-gost/x/registry"
)

func init() {
	registry.ListenerRegistry().Register("hysteria", NewListener)
}

type hysteriaListener struct {
	server  server.Server
	ln      net.PacketConn
	queue   chan net.Conn
	errChan chan error
	logger  logger.Logger
	md      metadata
	options listener.Options
}

func NewListener(opts ...listener.Option) listener.Listener {
	options := listener.Options{}
	for _, opt := range opts {
		opt(&options)
	}
	return &hysteriaListener{
		logger:  options.Logger,
		options: options,
	}
}

func (l *hysteriaListener) Init(md md.Metadata) (err error) {
	if err = l.parseMetadata(md); err != nil {
		return
	}

	addr := l.options.Addr
	if _, _, err := net.SplitHostPort(addr); err != nil {
		addr = net.JoinHostPort(strings.Trim(addr, "[]"), "443")
	}

	network := "udp"
	if xnet.IsIPv4(addr) {
		network = "udp4"
	}
	laddr, err := net.ResolveUDPAddr(network, addr)
	if err != nil {
		return
	}
	conn, err := net.ListenUDP(network, laddr)
	if err != nil {
		return
	}
	l.ln = conn

	l.queue = make(chan net.Conn, l.md.backlog)
	l.errChan = make(chan error, 1)

	tlsCfg := l.options.TLSConfig
	if tlsCfg == nil {
		tlsCfg = &tls.Config{}
	}

	var keepAlivePeriod time.Duration
	if l.md.keepAlivePeriod > 0 {
		keepAlivePeriod = time.Duration(l.md.keepAlivePeriod) * time.Second
	}

	sv, err := server.NewServer(&server.Config{
		TLSConfig: server.TLSConfig{
			Certificates:   tlsCfg.Certificates,
			GetCertificate: tlsCfg.GetCertificate,
		},
		Conn: conn,
		QUICConfig: server.QUICConfig{
			MaxIdleTimeout:  time.Duration(l.md.maxIdleTimeout) * time.Second,
		},
		CongestionConfig: server.CongestionConfig{
			Type: l.md.congestionType,
		},
		BandwidthConfig: server.BandwidthConfig{
			MaxTx: l.md.bandwidthTx,
			MaxRx: l.md.bandwidthRx,
		},
		IgnoreClientBandwidth: l.md.bandwidthTx <= 0 && l.md.bandwidthRx <= 0,
		DisableUDP:            l.md.disableUDP,
		Authenticator: &passwordAuthenticator{
			password: l.md.auth,
		},
		Outbound: &hyOutbound{
			queue: l.queue,
			laddr: conn.LocalAddr(),
		},
	})
	if err != nil {
		conn.Close()
		return err
	}

	l.server = sv

	go func() {
		if err := sv.Serve(); err != nil {
			l.errChan <- err
		}
		close(l.errChan)
	}()

	return
}

func (l *hysteriaListener) Accept() (conn net.Conn, err error) {
	var ok bool
	select {
	case conn = <-l.queue:
	case err, ok = <-l.errChan:
		if !ok {
			err = listener.ErrClosed
		}
	}
	return
}

func (l *hysteriaListener) Close() error {
	return l.server.Close()
}

func (l *hysteriaListener) Addr() net.Addr {
	return l.ln.LocalAddr()
}

type passwordAuthenticator struct {
	password string
}

func (a *passwordAuthenticator) Authenticate(addr net.Addr, auth string, tx uint64) (ok bool, id string) {
	return auth == a.password, ""
}
```

- [ ] **Step 2: Verify compilation**

```bash
cd /Users/kbliu/Workspace/src/gost-x && go build ./listener/hysteria/
```

Expected: compiles without errors.

- [ ] **Step 3: Run go vet**

```bash
cd /Users/kbliu/Workspace/src/gost-x && go vet ./listener/hysteria/
```

Expected: no warnings.

- [ ] **Step 4: Commit**

```bash
git add listener/hysteria/listener.go
git commit -m "feat: add hysteria listener

Co-Authored-By: Claude Opus 4.7 <noreply@anthropic.com>"
```

---

### Task 5: Create dialer metadata types and parsing

**Files:**
- Create: `dialer/hysteria/metadata.go`

- [ ] **Step 1: Create dialer/hysteria/ directory**

```bash
mkdir -p /Users/kbliu/Workspace/src/gost-x/dialer/hysteria
```

- [ ] **Step 2: Write metadata.go**

```go
package hysteria

import (
	mdata "github.com/go-gost/core/metadata"
	mdutil "github.com/go-gost/x/metadata/util"
)

type metadata struct {
	auth             string
	congestionType   string
	bandwidthTx      uint64
	bandwidthRx      uint64
	fastOpen         bool
	keepAlivePeriod  int64
	handshakeTimeout int64
	maxIdleTimeout   int64
}

func (d *hysteriaDialer) parseMetadata(md mdata.Metadata) (err error) {
	const (
		keyAuth             = "auth"
		keyCongestion       = "congestion"
		keyBandwidthTx      = "bandwidth.tx"
		keyBandwidthRx      = "bandwidth.rx"
		keyFastOpen         = "fastOpen"
		keyKeepAlive        = "keepAlive"
		keyTTL              = "ttl"
		keyHandshakeTimeout = "handshakeTimeout"
		keyMaxIdleTimeout   = "maxIdleTimeout"
	)

	d.md.auth = mdutil.GetString(md, keyAuth)
	d.md.congestionType = mdutil.GetString(md, keyCongestion)
	if d.md.congestionType == "" {
		d.md.congestionType = "bbr"
	}
	d.md.bandwidthTx = uint64(mdutil.GetInt(md, keyBandwidthTx))
	d.md.bandwidthRx = uint64(mdutil.GetInt(md, keyBandwidthRx))
	d.md.fastOpen = mdutil.GetBool(md, keyFastOpen)

	if mdutil.GetBool(md, keyKeepAlive) {
		d.md.keepAlivePeriod = mdutil.GetInt(md, keyTTL)
		if d.md.keepAlivePeriod <= 0 {
			d.md.keepAlivePeriod = 10
		}
	}
	d.md.handshakeTimeout = mdutil.GetInt(md, keyHandshakeTimeout)
	d.md.maxIdleTimeout = mdutil.GetInt(md, keyMaxIdleTimeout)

	return
}
```

- [ ] **Step 3: Verify compilation (expected to fail — hysteriaDialer not defined)**

```bash
cd /Users/kbliu/Workspace/src/gost-x && go build ./dialer/hysteria/ 2>&1 | head -5
```

Expected: error about undefined `hysteriaDialer`.

- [ ] **Step 4: Commit**

```bash
git add dialer/hysteria/metadata.go
git commit -m "feat: add hysteria dialer metadata parsing

Co-Authored-By: Claude Opus 4.7 <noreply@anthropic.com>"
```

---

### Task 6: Create dialer.go — the main dialer

**Files:**
- Create: `dialer/hysteria/dialer.go`

- [ ] **Step 1: Write dialer.go**

```go
package hysteria

import (
	"context"
	"crypto/tls"
	"net"
	"sync"
	"time"

	"github.com/apernet/hysteria/core/v2/client"
	"github.com/go-gost/core/dialer"
	"github.com/go-gost/core/logger"
	md "github.com/go-gost/core/metadata"
	"github.com/go-gost/x/registry"
)

func init() {
	registry.DialerRegistry().Register("hysteria", NewDialer)
}

type hysteriaDialer struct {
	sessions     map[string]*hySession
	sessionMutex sync.Mutex
	logger       logger.Logger
	md           metadata
	options      dialer.Options
}

type hySession struct {
	client.Client
}

func NewDialer(opts ...dialer.Option) dialer.Dialer {
	options := dialer.Options{}
	for _, opt := range opts {
		opt(&options)
	}
	return &hysteriaDialer{
		sessions: make(map[string]*hySession),
		logger:   options.Logger,
		options:  options,
	}
}

func (d *hysteriaDialer) Init(md md.Metadata) (err error) {
	return d.parseMetadata(md)
}

func (d *hysteriaDialer) Dial(ctx context.Context, addr string, opts ...dialer.DialOption) (conn net.Conn, err error) {
	d.sessionMutex.Lock()
	defer d.sessionMutex.Unlock()

	session, ok := d.sessions[addr]
	if !ok {
		tlsCfg := d.options.TLSConfig
		if tlsCfg == nil {
			tlsCfg = &tls.Config{}
		}

		serverAddr, err := net.ResolveUDPAddr("udp", addr)
		if err != nil {
			return nil, err
		}

		var keepAlivePeriod time.Duration
		if d.md.keepAlivePeriod > 0 {
			keepAlivePeriod = time.Duration(d.md.keepAlivePeriod) * time.Second
		}

		hyClient, _, err := client.NewClient(&client.Config{
			ServerAddr: serverAddr,
			Auth:       d.md.auth,
			TLSConfig: client.TLSConfig{
				ServerName:         tlsCfg.ServerName,
				InsecureSkipVerify: tlsCfg.InsecureSkipVerify,
				RootCAs:            tlsCfg.RootCAs,
			},
			QUICConfig: client.QUICConfig{
				KeepAlivePeriod: keepAlivePeriod,
				MaxIdleTimeout:  time.Duration(d.md.maxIdleTimeout) * time.Second,
			},
			CongestionConfig: client.CongestionConfig{
				Type: d.md.congestionType,
			},
			BandwidthConfig: client.BandwidthConfig{
				MaxTx: d.md.bandwidthTx,
				MaxRx: d.md.bandwidthRx,
			},
			FastOpen: d.md.fastOpen,
		})
		if err != nil {
			return nil, err
		}

		session = &hySession{Client: hyClient}
		d.sessions[addr] = session
	}

	conn, err = session.TCP("")
	if err != nil {
		session.Close()
		delete(d.sessions, addr)
		return nil, err
	}

	return
}

func (d *hysteriaDialer) Multiplex() bool {
	return true
}
```

- [ ] **Step 2: Verify compilation**

```bash
cd /Users/kbliu/Workspace/src/gost-x && go build ./dialer/hysteria/
```

Expected: compiles without errors.

- [ ] **Step 3: Run go vet**

```bash
cd /Users/kbliu/Workspace/src/gost-x && go vet ./dialer/hysteria/
```

Expected: no warnings.

- [ ] **Step 4: Commit**

```bash
git add dialer/hysteria/dialer.go
git commit -m "feat: add hysteria dialer

Co-Authored-By: Claude Opus 4.7 <noreply@anthropic.com>"
```

---

### Task 7: Final build verification

**Files:**
- No new files

- [ ] **Step 1: Full build + vet**

```bash
cd /Users/kbliu/Workspace/src/gost-x && go build ./... && go vet ./...
```

Expected: no errors, no warnings.

- [ ] **Step 2: Verify registrations appear**

```bash
cd /Users/kbliu/Workspace/src/gost-x && go run -exec '' 2>&1 <<'GOEOF'
package main

import (
	"fmt"
	_ "github.com/go-gost/x/listener/hysteria"
	_ "github.com/go-gost/x/dialer/hysteria"
	"github.com/go-gost/x/registry"
)

func main() {
	if ln := registry.ListenerRegistry().Get("hysteria"); ln != nil {
		fmt.Println("hysteria listener registered: OK")
	} else {
		fmt.Println("hysteria listener registered: FAIL")
	}
	if d := registry.DialerRegistry().Get("hysteria"); d != nil {
		fmt.Println("hysteria dialer registered: OK")
	} else {
		fmt.Println("hysteria dialer registered: FAIL")
	}
}
GOEOF
```

Expected: both OK.

Note: the `go run` inline approach may not work directly. Alternative verification: check the build succeeded in Step 1 (the registry packages are imported transitively via `listener/hysteria/` and `dialer/hysteria/`). Registry registration happens in `init()`, so if the packages compile and link, the registrations are active.

- [ ] **Step 3: Commit (if any changes from fixups)**

```bash
git status
```

Expected: clean working tree.
