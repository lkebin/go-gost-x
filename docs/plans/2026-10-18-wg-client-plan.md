# gost-x WireGuard 客户端实现计划

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 让 gost-x 具备真实可用的 WireGuard 客户端（`dialer/wg` + `connector/wg`），配合已有的 hop 级 bypass 白名单，把指定目标 IP/CIDR 的流量经 WG 隧道送出、其余直连。

**Architecture:** 复刻仓库既有的 hysteria 双件套范式：`dialer/wg` 用 wireguard-go（userspace device + gvisor netstack）建立隧道，`Dial` 返回一个"隧道句柄"conn；`connector/wg` 用该句柄在隧道内建立到最终目标的 TCP/UDP 连接。分流完全复用 gost 现有能力（`bypasses[].whitelist` + `hops[].bypass`），不改 `go-gost/core`。

**Tech Stack:** Go 1.26、`golang.zx2c4.com/wireguard`（device / conn / tun/netstack）、`gvisor.dev/gvisor`（netstack）、`golang.org/x/crypto/curve25519`（仅测试用）、gost-x 的 registry / metadata / logger 惯例。

**Spec:** `docs/plans/2026-10-18-wg-client-design.md`

## Global Constraints

- 不修改 `github.com/go-gost/core`；不新增第三方依赖（wireguard、gvisor、x/crypto 均已在 `go.mod`）。
- 功能边界：单 peer、单隧道、IPv4；不做 IPv6、`presharedKey`、隧道内 DNS 服务、WG 服务端（listener）、多 peer failover。
- 配置键：metadata 键名小写不敏感，每个键同时接受 `xxx` 与 `wg.xxx`；列表字段同时接受数组与逗号分隔字符串。
- `localIPs` 必填；`allowedIPs` 默认 `0.0.0.0/0`；`mtu` 默认 1420（范围 576–65535）；`keepalive` 默认 0。
- `dialer/wg` 不实现 `dialer.Multiplexer`。
- 提交信息用 Conventional Commits（如 `feat(wg): ...`、`fix(wg): ...`），一次提交只做一件事。
- 仓库根目录就是 Go module（`module github.com/go-gost/x`）；CLAUDE.md 里 `cd x` 的写法已过时，所有命令都在仓库根执行。
- 每个任务结束时仓库必须能 `go build ./...` 通过。

## Review Focus

下列 5 类输入/失败模式最容易在真实使用中咬人，每一条都必须在拥有该代码的任务里被测试固定住：

1. 配置把列表字段写成标量字符串（`localIPs: 10.7.0.2/32`、`allowedIPs: "10.7.0.0/24, 10.8.0.0/24"`）时必须仍能解析 —— Task 1（`TestParseMetadata_ScalarStringList`）。
2. 并发 `Dial` 只能创建一个 WG device，否则会重复建隧道/泄漏 fd —— Task 4（`TestDialerCreatesDeviceOnce`）。
3. `Close()` 必须幂等，且 `Close()` 之后再 `Dial` 不能 panic/死锁 —— Task 4（`TestDialerCloseIdempotentAndDialAfterClose`）。
4. 目标不是 IP 且未配 `dns` 时，必须立刻返回明确错误（不得挂起、不得依赖 netstack 的退化 DNS 路径）—— Task 4（`TestConnDomainWithoutDNS`）。
5. 目标落在 `allowedIPs` 之外时 wireguard 会静默丢包，表现为**超时**而不是报错 —— Task 6（`TestE2E_OutsideAllowedIPsTimesOut`）。

---

### Task 1: metadata 解析与密钥处理

**Files:**
- Modify: `dialer/wg/metadata.go`（整体重写）
- Create: `dialer/wg/metadata_test.go`

**Interfaces:**
- Consumes: `mdutil.GetString/GetInt/GetDuration`（`github.com/go-gost/x/metadata/util`）、`xmetadata.NewMetadata`（测试）
- Produces:
  - `type key [32]byte`，方法 `func (k key) hex() string`
  - `func parseKey(s string) (key, error)`
  - `type metadata struct { privateKey key; peerPublicKey key; endpoint string; localIPs []netip.Prefix; allowedIPs []netip.Prefix; dns []netip.Addr; mtu int; keepalive time.Duration }`
  - `func getStrings(md mdata.Metadata, keys ...string) []string`
  - `func parsePrefix(s string) (netip.Prefix, error)`
  - `func (d *wgDialer) parseMetadata(md mdata.Metadata) error`

- [ ] **Step 1: 写失败的测试**

创建 `dialer/wg/metadata_test.go`：

```go
package wg

import (
	"encoding/base64"
	"testing"
	"time"

	xmetadata "github.com/go-gost/x/metadata"
)

func testPrivateKey() string {
	b := make([]byte, 32)
	for i := range b {
		b[i] = byte(i)
	}
	return base64.StdEncoding.EncodeToString(b)
}

func testPublicKey() string {
	b := make([]byte, 32)
	for i := range b {
		b[i] = byte(255 - i)
	}
	return base64.StdEncoding.EncodeToString(b)
}

// validRaw returns a minimal valid raw config map (callers mutate a copy).
func validRaw() map[string]any {
	return map[string]any{
		"privateKey":    testPrivateKey(),
		"peerPublicKey": testPublicKey(),
		"endpoint":      "wg.example.com:51820",
		"localIPs":      "10.7.0.2/32",
	}
}

func parseRaw(t *testing.T, raw map[string]any) (*wgDialer, error) {
	t.Helper()
	d := &wgDialer{}
	err := d.parseMetadata(xmetadata.NewMetadata(raw))
	return d, err
}

func TestParseMetadata_RequiredFields(t *testing.T) {
	for _, key := range []string{"privateKey", "peerPublicKey", "endpoint", "localIPs"} {
		t.Run("missing "+key, func(t *testing.T) {
			raw := validRaw()
			delete(raw, key)
			if _, err := parseRaw(t, raw); err == nil {
				t.Fatalf("expected error when %s is missing", key)
			}
		})
	}
}

func TestParseMetadata_InvalidKeys(t *testing.T) {
	tests := []struct {
		name string
		key  string
		val  string
	}{
		{"bad base64", "privateKey", "not-base64!!"},
		{"short key", "privateKey", base64.StdEncoding.EncodeToString([]byte("short"))},
		{"bad peer base64", "peerPublicKey", "***"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			raw := validRaw()
			raw[tt.key] = tt.val
			if _, err := parseRaw(t, raw); err == nil {
				t.Fatal("expected error")
			}
		})
	}
}

func TestParseMetadata_Defaults(t *testing.T) {
	d, err := parseRaw(t, validRaw())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if d.md.mtu != defaultMTU {
		t.Errorf("mtu = %d, want %d", d.md.mtu, defaultMTU)
	}
	if len(d.md.allowedIPs) != 1 || d.md.allowedIPs[0].String() != defaultAllowedIPs {
		t.Errorf("allowedIPs = %v, want [%s]", d.md.allowedIPs, defaultAllowedIPs)
	}
	if len(d.md.localIPs) != 1 || d.md.localIPs[0].String() != "10.7.0.2/32" {
		t.Errorf("localIPs = %v, want [10.7.0.2/32]", d.md.localIPs)
	}
	if d.md.keepalive != 0 {
		t.Errorf("keepalive = %v, want 0", d.md.keepalive)
	}
	if len(d.md.dns) != 0 {
		t.Errorf("dns = %v, want empty", d.md.dns)
	}
}

// Scalar strings must work: config authors write "10.7.0.2/32", not a list.
func TestParseMetadata_ScalarStringList(t *testing.T) {
	raw := validRaw()
	raw["localIPs"] = "10.7.0.2/32"
	raw["allowedIPs"] = "10.7.0.0/24, 10.8.0.0/24"
	raw["dns"] = "10.7.0.1"

	d, err := parseRaw(t, raw)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(d.md.localIPs) != 1 {
		t.Fatalf("localIPs = %v, want 1 entry", d.md.localIPs)
	}
	if len(d.md.allowedIPs) != 2 || d.md.allowedIPs[1].String() != "10.8.0.0/24" {
		t.Fatalf("allowedIPs = %v, want 2 entries", d.md.allowedIPs)
	}
	if len(d.md.dns) != 1 || d.md.dns[0].String() != "10.7.0.1" {
		t.Fatalf("dns = %v, want [10.7.0.1]", d.md.dns)
	}
}

func TestParseMetadata_ListValues(t *testing.T) {
	raw := validRaw()
	raw["localIPs"] = []string{"10.7.0.2/32", "10.7.0.3/32"}
	raw["allowedIPs"] = []any{"10.7.0.0/24"}
	raw["dns"] = []string{"10.7.0.1", "10.7.0.2"}

	d, err := parseRaw(t, raw)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(d.md.localIPs) != 2 || len(d.md.allowedIPs) != 1 || len(d.md.dns) != 2 {
		t.Fatalf("localIPs=%v allowedIPs=%v dns=%v", d.md.localIPs, d.md.allowedIPs, d.md.dns)
	}
}

// A bare IP without a prefix length is accepted and treated as /32.
func TestParseMetadata_BareIPAsPrefix(t *testing.T) {
	raw := validRaw()
	raw["localIPs"] = "10.7.0.2"
	d, err := parseRaw(t, raw)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if d.md.localIPs[0].String() != "10.7.0.2/32" {
		t.Fatalf("localIPs[0] = %s, want 10.7.0.2/32", d.md.localIPs[0])
	}
}

func TestParseMetadata_WgPrefixedKeys(t *testing.T) {
	raw := map[string]any{
		"wg.privateKey":    testPrivateKey(),
		"wg.peerPublicKey": testPublicKey(),
		"wg.endpoint":      "127.0.0.1:51820",
		"wg.localIPs":      "10.7.0.2/32",
	}
	if _, err := parseRaw(t, raw); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestParseMetadata_MTURange(t *testing.T) {
	for _, mtu := range []int{575, 65536} {
		raw := validRaw()
		raw["mtu"] = mtu
		if _, err := parseRaw(t, raw); err == nil {
			t.Fatalf("expected error for mtu %d", mtu)
		}
	}
	raw := validRaw()
	raw["mtu"] = 1280
	d, err := parseRaw(t, raw)
	if err != nil || d.md.mtu != 1280 {
		t.Fatalf("mtu = %d, err = %v", d.md.mtu, err)
	}
}

func TestParseMetadata_Keepalive(t *testing.T) {
	raw := validRaw()
	raw["keepalive"] = "25s"
	d, err := parseRaw(t, raw)
	if err != nil || d.md.keepalive != 25*time.Second {
		t.Fatalf("keepalive = %v, err = %v", d.md.keepalive, err)
	}

	raw = validRaw()
	raw["keepalive"] = 30 // integer seconds
	d, err = parseRaw(t, raw)
	if err != nil || d.md.keepalive != 30*time.Second {
		t.Fatalf("keepalive = %v, err = %v", d.md.keepalive, err)
	}

	raw = validRaw()
	raw["keepalive"] = "48h"
	if _, err := parseRaw(t, raw); err == nil {
		t.Fatal("expected error for keepalive above the uapi limit")
	}
}

func TestParseMetadata_InvalidIPs(t *testing.T) {
	for _, tt := range []struct{ key, val string }{
		{"localIPs", "not-an-ip"},
		{"allowedIPs", "10.0.0.0/99"},
		{"dns", "not-an-ip"},
	} {
		raw := validRaw()
		raw[tt.key] = tt.val
		if _, err := parseRaw(t, raw); err == nil {
			t.Fatalf("expected error for %s=%q", tt.key, tt.val)
		}
	}
}

func TestParseKey_RoundTrip(t *testing.T) {
	k, err := parseKey(testPrivateKey()) // test key bytes are 0x00..0x1f
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want := "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
	if k.hex() != want {
		t.Fatalf("hex = %q, want %q", k.hex(), want)
	}
}
```

- [ ] **Step 2: 运行测试确认失败**

Run: `go test ./dialer/wg/ -run 'TestParseMetadata|TestParseKey' -v`
Expected: 编译失败（`undefined: parseMetadata 相关字段 / defaultMTU / parseKey`）。

- [ ] **Step 3: 实现 metadata 解析**

把 `dialer/wg/metadata.go` 整体替换为：

```go
package wg

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net/netip"
	"strings"
	"time"

	mdata "github.com/go-gost/core/metadata"
	mdutil "github.com/go-gost/x/metadata/util"
)

const (
	defaultMTU        = 1420
	minMTU            = 576
	maxMTU            = 65535
	defaultAllowedIPs = "0.0.0.0/0"
)

// key is a 32-byte WireGuard key (private or public).
type key [32]byte

// hex returns the uapi representation of the key.
func (k key) hex() string { return hex.EncodeToString(k[:]) }

// parseKey decodes a wg-quick style base64 WireGuard key.
func parseKey(s string) (k key, err error) {
	b, err := base64.StdEncoding.DecodeString(strings.TrimSpace(s))
	if err != nil {
		return k, fmt.Errorf("invalid base64 key: %w", err)
	}
	if len(b) != len(k) {
		return k, fmt.Errorf("invalid key length %d, want %d", len(b), len(k))
	}
	copy(k[:], b)
	return k, nil
}

type metadata struct {
	privateKey    key
	peerPublicKey key
	endpoint      string
	localIPs      []netip.Prefix
	allowedIPs    []netip.Prefix
	dns           []netip.Addr
	mtu           int
	keepalive     time.Duration
}

// getStrings returns a list-valued metadata field. mdutil.GetStrings only
// accepts []string / []any (metadata/util/util.go), so a single
// comma-separated string is handled here as well.
func getStrings(md mdata.Metadata, keys ...string) (ss []string) {
	if ss = mdutil.GetStrings(md, keys...); len(ss) > 0 {
		return
	}
	for _, s := range strings.Split(mdutil.GetString(md, keys...), ",") {
		if s = strings.TrimSpace(s); s != "" {
			ss = append(ss, s)
		}
	}
	return
}

// parsePrefix parses "10.7.0.2/32"; a bare "10.7.0.2" becomes /32 (/128 for v6).
func parsePrefix(s string) (netip.Prefix, error) {
	if p, err := netip.ParsePrefix(s); err == nil {
		return p, nil
	}
	addr, err := netip.ParseAddr(s)
	if err != nil {
		return netip.Prefix{}, err
	}
	return netip.PrefixFrom(addr, addr.BitLen()), nil
}

func (d *wgDialer) parseMetadata(md mdata.Metadata) error {
	const (
		keyPrivateKey    = "privateKey"
		keyPeerPublicKey = "peerPublicKey"
		keyEndpoint      = "endpoint"
		keyLocalIPs      = "localIPs"
		keyAllowedIPs    = "allowedIPs"
		keyDNS           = "dns"
		keyMTU           = "mtu"
		keyKeepalive     = "keepalive"
	)

	s := mdutil.GetString(md, keyPrivateKey, "wg.privateKey")
	if s == "" {
		return fmt.Errorf("wg: privateKey is required")
	}
	privateKey, err := parseKey(s)
	if err != nil {
		return fmt.Errorf("wg: privateKey: %w", err)
	}

	s = mdutil.GetString(md, keyPeerPublicKey, "wg.peerPublicKey")
	if s == "" {
		return fmt.Errorf("wg: peerPublicKey is required")
	}
	peerPublicKey, err := parseKey(s)
	if err != nil {
		return fmt.Errorf("wg: peerPublicKey: %w", err)
	}

	endpoint := strings.TrimSpace(mdutil.GetString(md, keyEndpoint, "wg.endpoint"))
	if endpoint == "" {
		return fmt.Errorf("wg: endpoint is required")
	}

	var localIPs []netip.Prefix
	for _, s := range getStrings(md, keyLocalIPs, "wg.localIPs") {
		p, err := parsePrefix(s)
		if err != nil {
			return fmt.Errorf("wg: localIPs: invalid %q: %w", s, err)
		}
		localIPs = append(localIPs, p)
	}
	if len(localIPs) == 0 {
		return fmt.Errorf("wg: localIPs is required")
	}

	allowedIPStrs := getStrings(md, keyAllowedIPs, "wg.allowedIPs")
	if len(allowedIPStrs) == 0 {
		allowedIPStrs = []string{defaultAllowedIPs}
	}
	var allowedIPs []netip.Prefix
	for _, s := range allowedIPStrs {
		p, err := parsePrefix(s)
		if err != nil {
			return fmt.Errorf("wg: allowedIPs: invalid %q: %w", s, err)
		}
		allowedIPs = append(allowedIPs, p)
	}

	var dns []netip.Addr
	for _, s := range getStrings(md, keyDNS, "wg.dns") {
		addr, err := netip.ParseAddr(s)
		if err != nil {
			return fmt.Errorf("wg: dns: invalid %q: %w", s, err)
		}
		dns = append(dns, addr)
	}

	mtu := mdutil.GetInt(md, keyMTU, "wg.mtu")
	if mtu == 0 {
		mtu = defaultMTU
	}
	if mtu < minMTU || mtu > maxMTU {
		return fmt.Errorf("wg: mtu %d out of range [%d, %d]", mtu, minMTU, maxMTU)
	}

	keepalive := mdutil.GetDuration(md, keyKeepalive, "wg.keepalive")
	if keepalive < 0 {
		return fmt.Errorf("wg: keepalive must not be negative")
	}
	if secs := keepalive.Seconds(); secs > 65535 {
		return fmt.Errorf("wg: keepalive %s exceeds the uapi limit of 65535s", keepalive)
	}

	d.md.privateKey = privateKey
	d.md.peerPublicKey = peerPublicKey
	d.md.endpoint = endpoint
	d.md.localIPs = localIPs
	d.md.allowedIPs = allowedIPs
	d.md.dns = dns
	d.md.mtu = mtu
	d.md.keepalive = keepalive
	return nil
}
```

- [ ] **Step 4: 运行测试确认通过**

Run: `go test ./dialer/wg/ -run 'TestParseMetadata|TestParseKey' -v`
Expected: PASS（`TestParseMetadata_ScalarStringList` 是 Review Focus 1 的固定）。

- [ ] **Step 5: 构建 + 提交**

```bash
go build ./... && go vet ./dialer/wg/
git add dialer/wg/metadata.go dialer/wg/metadata_test.go
git commit -m "feat(wg): parse and validate WireGuard dialer metadata"
```

---

### Task 2: 自定义 conn.Bind（protect / mark）

**Files:**
- Create: `dialer/wg/bind.go`
- Create: `dialer/wg/bind_test.go`

**Interfaces:**
- Consumes: `netdialer.GlobalSocketControl`（`github.com/go-gost/x/internal/net/dialer`，类型 `func(fd uintptr)`）、`conn.NewDefaultBind()`、`conn.Bind` 接口
- Produces: `type bind struct { conn.Bind }`、`func newBind() *bind`；`bind` 满足 `conn.Bind`（`Open` 被覆写，其余方法透传内嵌实现）

- [ ] **Step 1: 写失败的测试**

创建 `dialer/wg/bind_test.go`：

```go
package wg

import (
	"errors"
	"testing"

	netdialer "github.com/go-gost/x/internal/net/dialer"
	"golang.zx2c4.com/wireguard/conn"
)

// fakeBind is a minimal conn.Bind without fd peeking (non-Android behaviour).
type fakeBind struct {
	fns      []conn.ReceiveFunc
	lastPort uint16
	openErr  error
}

func (b *fakeBind) Open(port uint16) ([]conn.ReceiveFunc, uint16, error) {
	if b.openErr != nil {
		return nil, 0, b.openErr
	}
	b.lastPort = port
	return b.fns, port, nil
}
func (b *fakeBind) Close() error                             { return nil }
func (b *fakeBind) SetMark(mark uint32) error                { return nil }
func (b *fakeBind) Send(bufs [][]byte, ep conn.Endpoint) error { return nil }
func (b *fakeBind) ParseEndpoint(s string) (conn.Endpoint, error) { return nil, nil }
func (b *fakeBind) BatchSize() int                           { return 1 }

// fakePeekBind additionally implements the fd-peek interfaces that
// wireguard-go provides on Android.
type fakePeekBind struct {
	*fakeBind
	fd4, fd6 int
}

func (b *fakePeekBind) PeekLookAtSocketFd4() (int, error) { return b.fd4, nil }
func (b *fakePeekBind) PeekLookAtSocketFd6() (int, error) { return b.fd6, nil }

func withSocketControl(t *testing.T, fn func(fd uintptr)) {
	t.Helper()
	old := netdialer.GlobalSocketControl
	netdialer.GlobalSocketControl = fn
	t.Cleanup(func() { netdialer.GlobalSocketControl = old })
}

func TestBindOpenAppliesSocketControl(t *testing.T) {
	var got []uintptr
	withSocketControl(t, func(fd uintptr) { got = append(got, fd) })

	b := &bind{Bind: &fakePeekBind{fakeBind: &fakeBind{}, fd4: 7, fd6: 9}}
	if _, _, err := b.Open(0); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(got) != 2 || got[0] != 7 || got[1] != 9 {
		t.Fatalf("socket control called with %v, want [7 9]", got)
	}
}

func TestBindOpenWithoutPeekSupport(t *testing.T) {
	called := false
	withSocketControl(t, func(fd uintptr) { called = true })

	b := &bind{Bind: &fakeBind{}}
	if _, _, err := b.Open(0); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if called {
		t.Fatal("socket control must not be called when the bind exposes no fd")
	}
}

func TestBindOpenPropagatesError(t *testing.T) {
	withSocketControl(t, func(fd uintptr) { t.Fatal("must not be called on failure") })

	wantErr := errors.New("boom")
	b := &bind{Bind: &fakeBind{openErr: wantErr}}
	if _, _, err := b.Open(0); !errors.Is(err, wantErr) {
		t.Fatalf("err = %v, want %v", err, wantErr)
	}
}

func TestBindOpenReturnsUnderlyingValues(t *testing.T) {
	recv := func(packets [][]byte, sizes []int, eps []conn.Endpoint) (int, error) { return 0, nil }
	b := &bind{Bind: &fakeBind{fns: []conn.ReceiveFunc{recv}}}
	gotFns, port, err := b.Open(51820)
	if err != nil || len(gotFns) != 1 || port != 51820 {
		t.Fatalf("fns=%v port=%d err=%v", gotFns, port, err)
	}
}
```

- [ ] **Step 2: 运行测试确认失败**

Run: `go test ./dialer/wg/ -run TestBind -v`
Expected: 编译失败（`undefined: bind`）。

- [ ] **Step 3: 实现 bind**

创建 `dialer/wg/bind.go`：

```go
package wg

import (
	netdialer "github.com/go-gost/x/internal/net/dialer"
	"golang.zx2c4.com/wireguard/conn"
)

// bind wraps a wireguard conn.Bind and applies gost's global socket control
// hook (Android VpnService.protect) to every UDP socket it opens, so the
// WireGuard transport does not loop back into the app's own TUN device.
type bind struct {
	conn.Bind
}

func newBind() *bind {
	return &bind{Bind: conn.NewDefaultBind()}
}

// fdPeeker4/fdPeeker6 are implemented by wireguard-go's StdNetBind on Android
// (conn/boundif_android.go). Elsewhere no fd is exposed and the socket
// control hook is simply not applied.
type fdPeeker4 interface{ PeekLookAtSocketFd4() (int, error) }
type fdPeeker6 interface{ PeekLookAtSocketFd6() (int, error) }

func (b *bind) Open(port uint16) ([]conn.ReceiveFunc, uint16, error) {
	fns, actualPort, err := b.Bind.Open(port)
	if err != nil {
		return nil, 0, err
	}

	if fn := netdialer.GlobalSocketControl; fn != nil {
		if p, ok := b.Bind.(fdPeeker4); ok {
			if fd, err := p.PeekLookAtSocketFd4(); err == nil {
				fn(uintptr(fd))
			}
		}
		if p, ok := b.Bind.(fdPeeker6); ok {
			if fd, err := p.PeekLookAtSocketFd6(); err == nil {
				fn(uintptr(fd))
			}
		}
	}

	return fns, actualPort, nil
}
```

- [ ] **Step 4: 运行测试确认通过**

Run: `go test ./dialer/wg/ -run TestBind -v`
Expected: PASS。

- [ ] **Step 5: 构建 + 提交**

```bash
go build ./... && go vet ./dialer/wg/
git add dialer/wg/bind.go dialer/wg/bind_test.go
git commit -m "feat(wg): apply gost socket control to wireguard sockets"
```

---

### Task 3: device 构建（endpoint 解析 + uapi 配置）

**Files:**
- Create: `dialer/wg/device.go`
- Create: `dialer/wg/device_test.go`

**Interfaces:**
- Consumes: Task 1 的 `metadata` / `key.hex()`；Task 2 的 `newBind()`
- Produces:
  - `type wgDevice struct { dev *device.Device; net *netstack.Net }`，方法 `Close() error`
  - `func resolveEndpoint(ctx context.Context, endpoint string) (netip.AddrPort, error)`
  - `func ipcConfig(md metadata, endpoint netip.AddrPort) string`
  - `func wgLogger(log logger.Logger) *device.Logger`
  - `func newDevice(ctx context.Context, md metadata, log logger.Logger, mark int) (*wgDevice, error)`

- [ ] **Step 1: 写失败的测试**

创建 `dialer/wg/device_test.go`：

```go
package wg

import (
	"context"
	"net/netip"
	"strings"
	"testing"
	"time"
)

func TestResolveEndpoint_Literal(t *testing.T) {
	ap, err := resolveEndpoint(context.Background(), "127.0.0.1:51820")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ap.String() != "127.0.0.1:51820" {
		t.Fatalf("endpoint = %s", ap)
	}
}

// conn.StdNetBind.ParseEndpoint only accepts a literal ip:port, so a domain
// has to be resolved before it is handed to the uapi.
func TestResolveEndpoint_Domain(t *testing.T) {
	ap, err := resolveEndpoint(context.Background(), "localhost:51820")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !ap.Addr().IsLoopback() || ap.Port() != 51820 {
		t.Fatalf("endpoint = %s", ap)
	}
}

func TestResolveEndpoint_Errors(t *testing.T) {
	for _, endpoint := range []string{
		"localhost",              // no port
		"127.0.0.1:not-a-number", // bad port
		"invalid.invalid:51820",  // unresolvable
	} {
		if _, err := resolveEndpoint(context.Background(), endpoint); err == nil {
			t.Fatalf("expected error for endpoint %q", endpoint)
		}
	}
}

func TestIPCConfig(t *testing.T) {
	k1, err := parseKey(testPrivateKey())
	if err != nil {
		t.Fatal(err)
	}
	k2, err := parseKey(testPublicKey())
	if err != nil {
		t.Fatal(err)
	}

	md := metadata{
		privateKey:    k1,
		peerPublicKey: k2,
		allowedIPs: []netip.Prefix{
			netip.MustParsePrefix("10.7.0.0/24"),
			netip.MustParsePrefix("10.8.0.0/24"),
		},
		keepalive: 25 * time.Second,
	}

	got := ipcConfig(md, netip.MustParseAddrPort("127.0.0.1:51820"))
	want := strings.Join([]string{
		"private_key=" + k1.hex(),
		"public_key=" + k2.hex(),
		"allowed_ip=10.7.0.0/24",
		"allowed_ip=10.8.0.0/24",
		"endpoint=127.0.0.1:51820",
		"persistent_keepalive_interval=25",
		"",
	}, "\n")
	if got != want {
		t.Fatalf("ipcConfig mismatch:\ngot:\n%s\nwant:\n%s", got, want)
	}
}

func TestIPCConfig_NoKeepalive(t *testing.T) {
	md := metadata{allowedIPs: []netip.Prefix{netip.MustParsePrefix("0.0.0.0/0")}}
	got := ipcConfig(md, netip.MustParseAddrPort("127.0.0.1:51820"))
	if strings.Contains(got, "persistent_keepalive_interval") {
		t.Fatalf("keepalive must be omitted when unset:\n%s", got)
	}
}
```

- [ ] **Step 2: 运行测试确认失败**

Run: `go test ./dialer/wg/ -run 'TestResolveEndpoint|TestIPCConfig' -v`
Expected: 编译失败（`undefined: resolveEndpoint / ipcConfig`）。

- [ ] **Step 3: 实现 device 构建**

创建 `dialer/wg/device.go`：

```go
package wg

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"github.com/go-gost/core/logger"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun/netstack"
)

// wgDevice owns the userspace WireGuard device and its gVisor netstack.
type wgDevice struct {
	dev *device.Device
	net *netstack.Net
}

// Close tears down the device; wireguard-go's Device.Close also closes the
// netstack and is idempotent.
func (d *wgDevice) Close() error {
	if d == nil || d.dev == nil {
		return nil
	}
	d.dev.Close()
	return nil
}

// resolveEndpoint turns the configured endpoint into a literal ip:port.
// wireguard-go's conn.StdNetBind.ParseEndpoint only accepts a literal address
// (conn/bind_std.go), so a domain must be resolved here.
func resolveEndpoint(ctx context.Context, endpoint string) (netip.AddrPort, error) {
	if ap, err := netip.ParseAddrPort(endpoint); err == nil {
		return ap, nil
	}

	host, port, err := net.SplitHostPort(endpoint)
	if err != nil {
		return netip.AddrPort{}, fmt.Errorf("invalid endpoint %q: %w", endpoint, err)
	}
	p, err := strconv.ParseUint(port, 10, 16)
	if err != nil {
		return netip.AddrPort{}, fmt.Errorf("invalid endpoint port %q: %w", port, err)
	}
	ips, err := net.DefaultResolver.LookupNetIP(ctx, "ip4", host)
	if err != nil {
		return netip.AddrPort{}, fmt.Errorf("resolve endpoint %q: %w", endpoint, err)
	}
	if len(ips) == 0 {
		return netip.AddrPort{}, fmt.Errorf("resolve endpoint %q: no address", endpoint)
	}
	return netip.AddrPortFrom(ips[0], uint16(p)), nil
}

// ipcConfig renders the uapi configuration for a single peer.
func ipcConfig(md metadata, endpoint netip.AddrPort) string {
	var sb strings.Builder
	fmt.Fprintf(&sb, "private_key=%s\n", md.privateKey.hex())
	fmt.Fprintf(&sb, "public_key=%s\n", md.peerPublicKey.hex())
	for _, p := range md.allowedIPs {
		fmt.Fprintf(&sb, "allowed_ip=%s\n", p.String())
	}
	fmt.Fprintf(&sb, "endpoint=%s\n", endpoint.String())
	if md.keepalive >= time.Second {
		fmt.Fprintf(&sb, "persistent_keepalive_interval=%d\n", int(md.keepalive.Seconds()))
	}
	return sb.String()
}

// wgLogger bridges wireguard-go's logger into gost's logger.
func wgLogger(log logger.Logger) *device.Logger {
	return &device.Logger{
		Errorf:   func(format string, args ...any) { log.Errorf(format, args...) },
		Verbosef: func(format string, args ...any) { log.Debugf(format, args...) },
	}
}

// newDevice creates and brings up the userspace WireGuard device.
func newDevice(ctx context.Context, md metadata, log logger.Logger, mark int) (*wgDevice, error) {
	endpoint, err := resolveEndpoint(ctx, md.endpoint)
	if err != nil {
		return nil, fmt.Errorf("wg: %w", err)
	}

	addrs := make([]netip.Addr, 0, len(md.localIPs))
	for _, p := range md.localIPs {
		addrs = append(addrs, p.Addr())
	}

	tunDev, netStack, err := netstack.CreateNetTUN(addrs, md.dns, md.mtu)
	if err != nil {
		return nil, fmt.Errorf("wg: create netstack: %w", err)
	}

	dev := device.NewDevice(tunDev, newBind(), wgLogger(log))
	if err := dev.IpcSet(ipcConfig(md, endpoint)); err != nil {
		dev.Close()
		return nil, fmt.Errorf("wg: configure device: %w", err)
	}
	if mark > 0 {
		if err := dev.BindSetMark(uint32(mark)); err != nil {
			log.Warnf("wg: set socket mark %d: %v", mark, err)
		}
	}
	if err := dev.Up(); err != nil {
		dev.Close()
		return nil, fmt.Errorf("wg: bring device up: %w", err)
	}

	log.Infof("wg: tunnel up, endpoint=%s, local=%v, mtu=%d", endpoint, md.localIPs, md.mtu)
	return &wgDevice{dev: dev, net: netStack}, nil
}
```

- [ ] **Step 4: 运行测试确认通过**

Run: `go test ./dialer/wg/ -run 'TestResolveEndpoint|TestIPCConfig' -v`
Expected: PASS。

- [ ] **Step 5: 构建 + 提交**

```bash
go build ./... && go vet ./dialer/wg/
git add dialer/wg/device.go dialer/wg/device_test.go
git commit -m "feat(wg): build userspace wireguard device from dialer metadata"
```

---

### Task 4: 重写 dialer（惰性 device、隧道句柄、Close）

**Files:**
- Modify: `dialer/wg/dialer.go`（整体重写）
- Create: `dialer/wg/conn.go`
- Create: `dialer/wg/dialer_test.go`

**Interfaces:**
- Consumes: Task 1 的 `metadata`、Task 3 的 `wgDevice` / `newDevice`、`netdialer.Dialer`（读 `Interface`/`Mark`）
- Produces:
  - `type conn struct { net *netstack.Net; hasDNS bool }`，实现 `net.Conn`，并有 `func (c *conn) TCP(ctx context.Context, addr string) (net.Conn, error)`、`func (c *conn) UDP(ctx context.Context, addr string) (net.PacketConn, error)`
  - `func (c *conn) addrPort(ctx context.Context, addr string) (netip.AddrPort, error)`
  - `wgDialer` 字段：`md metadata`、`logger logger.Logger`、`mu sync.Mutex`、`dev *wgDevice`；实现 `dialer.Dialer` 与 `io.Closer`
  - `var newDeviceFunc = newDevice`（测试替换点）

- [ ] **Step 1: 写失败的测试**

创建 `dialer/wg/dialer_test.go`：

```go
package wg

import (
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/go-gost/core/dialer"
	"github.com/go-gost/core/logger"
	xlogger "github.com/go-gost/x/logger"
	xmetadata "github.com/go-gost/x/metadata"
)

func newTestDialer(t *testing.T) *wgDialer {
	t.Helper()
	d := NewDialer(dialer.LoggerOption(xlogger.Nop())).(*wgDialer)
	if err := d.Init(xmetadata.NewMetadata(validRaw())); err != nil {
		t.Fatalf("init: %v", err)
	}
	return d
}

// withDeviceFunc substitutes the device factory for the duration of a test.
func withDeviceFunc(t *testing.T, fn func(context.Context, metadata, logger.Logger, int) (*wgDevice, error)) {
	t.Helper()
	old := newDeviceFunc
	newDeviceFunc = fn
	t.Cleanup(func() { newDeviceFunc = old })
}

// Review Focus 2: concurrent Dial calls must create exactly one device.
func TestDialerCreatesDeviceOnce(t *testing.T) {
	d := newTestDialer(t)

	var calls int32
	withDeviceFunc(t, func(ctx context.Context, md metadata, log logger.Logger, mark int) (*wgDevice, error) {
		atomic.AddInt32(&calls, 1)
		return &wgDevice{}, nil
	})

	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := d.Dial(context.Background(), ""); err != nil {
				t.Errorf("dial: %v", err)
			}
		}()
	}
	wg.Wait()

	if got := atomic.LoadInt32(&calls); got != 1 {
		t.Fatalf("device created %d times, want 1", got)
	}
}

// Review Focus 3: Close is idempotent and Dial still works afterwards.
func TestDialerCloseIdempotentAndDialAfterClose(t *testing.T) {
	d := newTestDialer(t)

	var calls int32
	withDeviceFunc(t, func(ctx context.Context, md metadata, log logger.Logger, mark int) (*wgDevice, error) {
		atomic.AddInt32(&calls, 1)
		return &wgDevice{}, nil
	})

	if _, err := d.Dial(context.Background(), ""); err != nil {
		t.Fatal(err)
	}
	if err := d.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	if err := d.Close(); err != nil {
		t.Fatalf("second close: %v", err)
	}
	if _, err := d.Dial(context.Background(), ""); err != nil {
		t.Fatalf("dial after close: %v", err)
	}
	if got := atomic.LoadInt32(&calls); got != 2 {
		t.Fatalf("device created %d times, want 2 (one per tunnel lifetime)", got)
	}
}

func TestDialerDialErrorNotCached(t *testing.T) {
	d := newTestDialer(t)

	var calls int32
	withDeviceFunc(t, func(ctx context.Context, md metadata, log logger.Logger, mark int) (*wgDevice, error) {
		if atomic.AddInt32(&calls, 1) == 1 {
			return nil, errors.New("boom")
		}
		return &wgDevice{}, nil
	})

	if _, err := d.Dial(context.Background(), ""); err == nil {
		t.Fatal("expected error")
	}
	if _, err := d.Dial(context.Background(), ""); err != nil {
		t.Fatalf("second dial must retry: %v", err)
	}
}

// Review Focus 4: a domain target without a dns server must fail fast and
// explicitly instead of relying on netstack's degraded lookup.
func TestConnDomainWithoutDNS(t *testing.T) {
	c := &conn{hasDNS: false}
	if _, err := c.TCP(context.Background(), "example.com:80"); err == nil {
		t.Fatal("expected an error for a domain without dns")
	}
	if _, err := c.UDP(context.Background(), "example.com:80"); err == nil {
		t.Fatal("expected an error for a domain without dns")
	}
}

func TestConnSatisfiesNetConn(t *testing.T) {
	var _ net.Conn = (*conn)(nil)
	c := &conn{}
	if _, err := c.Read(make([]byte, 1)); err != io.EOF {
		t.Fatalf("Read err = %v, want EOF", err)
	}
	if _, err := c.Write([]byte("x")); err == nil {
		t.Fatal("Write must fail on the tunnel handle")
	}
	if err := c.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
}
```

`newDeviceFunc` 的签名必须与 `newDevice` 一致：`func(context.Context, metadata, logger.Logger, int) (*wgDevice, error)`。测试替身返回 `&wgDevice{}` 即可——`wgDevice.Close()` 对 nil 内部 device 是安全的（Task 3）。

- [ ] **Step 2: 运行测试确认失败**

Run: `go test ./dialer/wg/ -run 'TestDialer|TestConn' -v`
Expected: 编译失败（`wgDialer` 还没有 `Close`/`dev` 字段、`newDeviceFunc` 未定义、`conn` 未定义）。

- [ ] **Step 3: 实现 conn**

创建 `dialer/wg/conn.go`：

```go
package wg

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strconv"
	"time"

	"golang.zx2c4.com/wireguard/tun/netstack"
)

// conn is the tunnel handle returned by wgDialer.Dial. It carries no payload
// of its own: connector/wg uses it to open per-destination connections inside
// the tunnel (mirrors dialer/hysteria's hyClientConn).
type conn struct {
	net    *netstack.Net
	hasDNS bool
}

// TCP dials addr inside the tunnel.
func (c *conn) TCP(ctx context.Context, addr string) (net.Conn, error) {
	ap, err := c.addrPort(ctx, addr)
	if err != nil {
		return nil, err
	}
	return c.net.DialContextTCPAddrPort(ctx, ap)
}

// UDP dials addr inside the tunnel, returning a connected datagram socket.
func (c *conn) UDP(ctx context.Context, addr string) (net.PacketConn, error) {
	ap, err := c.addrPort(ctx, addr)
	if err != nil {
		return nil, err
	}
	return c.net.DialUDPAddrPort(netip.AddrPort{}, ap)
}

// addrPort resolves addr to an ip:port usable inside the tunnel. Domains are
// only resolved when a dns server is configured: wireguard-go's netstack
// degrades to an empty lookup when it has no dns servers, so we refuse early
// with an explicit error instead.
func (c *conn) addrPort(ctx context.Context, addr string) (netip.AddrPort, error) {
	if ap, err := netip.ParseAddrPort(addr); err == nil {
		return ap, nil
	}

	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return netip.AddrPort{}, fmt.Errorf("wg: invalid address %q: %w", addr, err)
	}
	p, err := strconv.ParseUint(port, 10, 16)
	if err != nil {
		return netip.AddrPort{}, fmt.Errorf("wg: invalid port %q: %w", port, err)
	}

	if a, err := netip.ParseAddr(host); err == nil {
		return netip.AddrPortFrom(a, uint16(p)), nil
	}
	if !c.hasDNS {
		return netip.AddrPort{}, fmt.Errorf("wg: %q is not an IP address and no dns is configured", addr)
	}

	ips, err := c.net.LookupContextHost(ctx, host)
	if err != nil {
		return netip.AddrPort{}, fmt.Errorf("wg: resolve %q: %w", host, err)
	}
	for _, s := range ips {
		if a, err := netip.ParseAddr(s); err == nil {
			return netip.AddrPortFrom(a, uint16(p)), nil
		}
	}
	return netip.AddrPort{}, fmt.Errorf("wg: resolve %q: no usable address", host)
}

// net.Conn: the handle is a placeholder, all payload flows through TCP/UDP.

func (c *conn) Read(b []byte) (int, error)         { return 0, io.EOF }
func (c *conn) Write(b []byte) (int, error)        { return 0, io.ErrClosedPipe }
func (c *conn) Close() error                       { return nil }
func (c *conn) LocalAddr() net.Addr                { return &net.TCPAddr{} }
func (c *conn) RemoteAddr() net.Addr               { return &net.TCPAddr{} }
func (c *conn) SetDeadline(t time.Time) error      { return nil }
func (c *conn) SetReadDeadline(t time.Time) error  { return nil }
func (c *conn) SetWriteDeadline(t time.Time) error { return nil }

var _ net.Conn = (*conn)(nil)
```

- [ ] **Step 4: 重写 dialer**

把 `dialer/wg/dialer.go` 整体替换为：

```go
package wg

import (
	"context"
	"io"
	"net"
	"sync"

	"github.com/go-gost/core/dialer"
	"github.com/go-gost/core/logger"
	md "github.com/go-gost/core/metadata"
	netdialer "github.com/go-gost/x/internal/net/dialer"
	"github.com/go-gost/x/registry"
)

func init() {
	registry.DialerRegistry().Register("wg", NewDialer)
}

// newDeviceFunc builds the WireGuard device; a variable so tests can
// substitute a fake without touching wireguard-go.
var newDeviceFunc = newDevice

type wgDialer struct {
	md     metadata
	logger logger.Logger

	mu  sync.Mutex
	dev *wgDevice
}

func NewDialer(opts ...dialer.Option) dialer.Dialer {
	options := &dialer.Options{}
	for _, opt := range opts {
		opt(options)
	}
	log := options.Logger
	if log == nil {
		log = logger.Default()
	}
	return &wgDialer{
		logger: log.WithFields(map[string]any{"kind": "dialer", "dialer": "wg"}),
	}
}

func (d *wgDialer) Init(md md.Metadata) error {
	return d.parseMetadata(md)
}

// Dial returns a tunnel handle. The WireGuard device is created on first use
// and reused afterwards; addr is ignored (the peer comes from the metadata).
func (d *wgDialer) Dial(ctx context.Context, addr string, opts ...dialer.DialOption) (net.Conn, error) {
	var options dialer.DialOptions
	for _, opt := range opts {
		opt(&options)
	}

	dev, err := d.device(ctx, options)
	if err != nil {
		return nil, err
	}
	return &conn{net: dev.net, hasDNS: len(d.md.dns) > 0}, nil
}

func (d *wgDialer) device(ctx context.Context, options dialer.DialOptions) (*wgDevice, error) {
	d.mu.Lock()
	defer d.mu.Unlock()

	if d.dev != nil {
		return d.dev, nil
	}

	var ifce string
	var mark int
	if nd, ok := options.Dialer.(*netdialer.Dialer); ok && nd != nil {
		ifce, mark = nd.Interface, nd.Mark
	}
	if ifce != "" {
		// wireguard-go's StdNetBind only supports interface binding on
		// Windows; on unix the socket follows the routing table.
		d.logger.Warnf("wg: metadata.interface %q is not supported, ignoring", ifce)
	}

	dev, err := newDeviceFunc(ctx, d.md, d.logger, mark)
	if err != nil {
		return nil, err
	}
	d.dev = dev
	return dev, nil
}

// Close implements io.Closer. gost closes a node's transport when the config
// is reloaded (chain.Transport.Close -> hop's chainHop.Close), which releases
// the WireGuard device. Safe to call repeatedly.
func (d *wgDialer) Close() error {
	d.mu.Lock()
	defer d.mu.Unlock()

	if d.dev == nil {
		return nil
	}
	dev := d.dev
	d.dev = nil
	return dev.Close()
}

var _ io.Closer = (*wgDialer)(nil)
```

- [ ] **Step 5: 运行测试确认通过**

Run: `go test ./dialer/wg/ -v`
Expected: 全部 PASS（`TestDialerCreatesDeviceOnce` 是 Review Focus 2、`TestDialerCloseIdempotentAndDialAfterClose` 是 Review Focus 3、`TestConnDomainWithoutDNS` 是 Review Focus 4）。

- [ ] **Step 6: 构建 + 提交**

```bash
go build ./... && go vet ./dialer/wg/
git add dialer/wg/dialer.go dialer/wg/conn.go dialer/wg/dialer_test.go
git commit -m "feat(wg): make dialer/wg a real WireGuard client"
```

---

### Task 5: connector/wg

**Files:**
- Create: `connector/wg/connector.go`
- Create: `connector/wg/connector_test.go`

**Interfaces:**
- Consumes: 运行期依赖 `dialer/wg` 的 conn 结构方法（用结构化接口断言，不 import `dialer/wg`）
- Produces:
  - `type tunnels interface { TCP(ctx context.Context, addr string) (net.Conn, error); UDP(ctx context.Context, addr string) (net.PacketConn, error) }`
  - `func NewConnector(opts ...connector.Option) connector.Connector`，注册名 `"wg"`

- [ ] **Step 1: 写失败的测试**

创建 `connector/wg/connector_test.go`：

```go
package wg

import (
	"context"
	"errors"
	"io"
	"net"
	"testing"
	"time"
)

// tcpStub is a minimal net.Conn.
type tcpStub struct{}

func (c *tcpStub) Read(b []byte) (int, error)         { return 0, io.EOF }
func (c *tcpStub) Write(b []byte) (int, error)        { return len(b), nil }
func (c *tcpStub) Close() error                       { return nil }
func (c *tcpStub) LocalAddr() net.Addr                { return &net.TCPAddr{} }
func (c *tcpStub) RemoteAddr() net.Addr               { return &net.TCPAddr{} }
func (c *tcpStub) SetDeadline(t time.Time) error      { return nil }
func (c *tcpStub) SetReadDeadline(t time.Time) error  { return nil }
func (c *tcpStub) SetWriteDeadline(t time.Time) error { return nil }

// udpStub is a minimal net.PacketConn that is also a net.Conn, mirroring
// netstack's gonet.UDPConn.
type udpStub struct{}

func (c *udpStub) Read(b []byte) (int, error)                { return 0, io.EOF }
func (c *udpStub) Write(b []byte) (int, error)               { return len(b), nil }
func (c *udpStub) ReadFrom(b []byte) (int, net.Addr, error)  { return 0, nil, io.EOF }
func (c *udpStub) WriteTo(b []byte, a net.Addr) (int, error) { return len(b), nil }
func (c *udpStub) Close() error                              { return nil }
func (c *udpStub) LocalAddr() net.Addr                       { return &net.UDPAddr{} }
func (c *udpStub) RemoteAddr() net.Addr                      { return &net.UDPAddr{} }
func (c *udpStub) SetDeadline(t time.Time) error             { return nil }
func (c *udpStub) SetReadDeadline(t time.Time) error         { return nil }
func (c *udpStub) SetWriteDeadline(t time.Time) error        { return nil }

// fakeTunnels plays the role of dialer/wg's tunnel handle.
type fakeTunnels struct {
	tcpAddr, udpAddr string
	tcpErr, udpErr   error
	closed           bool
	tcpConn          net.Conn
	udpConn          net.PacketConn
}

func (f *fakeTunnels) TCP(ctx context.Context, addr string) (net.Conn, error) {
	f.tcpAddr = addr
	return f.tcpConn, f.tcpErr
}
func (f *fakeTunnels) UDP(ctx context.Context, addr string) (net.PacketConn, error) {
	f.udpAddr = addr
	return f.udpConn, f.udpErr
}
func (f *fakeTunnels) Read(b []byte) (int, error)         { return 0, io.EOF }
func (f *fakeTunnels) Write(b []byte) (int, error)        { return len(b), nil }
func (f *fakeTunnels) Close() error                       { f.closed = true; return nil }
func (f *fakeTunnels) LocalAddr() net.Addr                { return &net.TCPAddr{} }
func (f *fakeTunnels) RemoteAddr() net.Addr               { return &net.TCPAddr{} }
func (f *fakeTunnels) SetDeadline(t time.Time) error      { return nil }
func (f *fakeTunnels) SetReadDeadline(t time.Time) error  { return nil }
func (f *fakeTunnels) SetWriteDeadline(t time.Time) error { return nil }

func TestConnect_TCP(t *testing.T) {
	f := &fakeTunnels{tcpConn: &tcpStub{}}
	got, err := NewConnector().Connect(context.Background(), f, "tcp", "10.7.0.1:443")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got == nil || f.tcpAddr != "10.7.0.1:443" || !f.closed {
		t.Fatalf("got=%v tcpAddr=%q closed=%v", got, f.tcpAddr, f.closed)
	}
}

func TestConnect_TCP6Network(t *testing.T) {
	f := &fakeTunnels{tcpConn: &tcpStub{}}
	if _, err := NewConnector().Connect(context.Background(), f, "tcp6", "10.7.0.1:443"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if f.tcpAddr != "10.7.0.1:443" {
		t.Fatalf("tcpAddr = %q", f.tcpAddr)
	}
}

func TestConnect_UDP(t *testing.T) {
	f := &fakeTunnels{udpConn: &udpStub{}}
	got, err := NewConnector().Connect(context.Background(), f, "udp4", "10.7.0.1:53")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got == nil || f.udpAddr != "10.7.0.1:53" || !f.closed {
		t.Fatalf("got=%v udpAddr=%q closed=%v", got, f.udpAddr, f.closed)
	}
	if _, ok := got.(net.PacketConn); !ok {
		t.Fatal("udp connections must be net.PacketConn")
	}
}

func TestConnect_Errors(t *testing.T) {
	c := NewConnector()

	wantErr := errors.New("boom")
	if _, err := c.Connect(context.Background(), &fakeTunnels{tcpErr: wantErr}, "tcp", "x:1"); !errors.Is(err, wantErr) {
		t.Fatalf("err = %v, want %v", err, wantErr)
	}
	if _, err := c.Connect(context.Background(), &fakeTunnels{udpErr: wantErr}, "udp", "x:1"); !errors.Is(err, wantErr) {
		t.Fatalf("err = %v, want %v", err, wantErr)
	}
}

func TestConnect_WrongConnType(t *testing.T) {
	if _, err := NewConnector().Connect(context.Background(), &tcpStub{}, "tcp", "10.7.0.1:443"); err == nil {
		t.Fatal("expected an error for a connection that is not a tunnel handle")
	}
}

func TestInit(t *testing.T) {
	if err := NewConnector().Init(nil); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}
```

- [ ] **Step 2: 运行测试确认失败**

Run: `go test ./connector/wg/ -v`
Expected: 编译失败（package `wg` 不存在）。

- [ ] **Step 3: 实现 connector**

创建 `connector/wg/connector.go`：

```go
package wg

import (
	"context"
	"fmt"
	"net"

	"github.com/go-gost/core/connector"
	md "github.com/go-gost/core/metadata"
	"github.com/go-gost/x/registry"
)

func init() {
	registry.ConnectorRegistry().Register("wg", NewConnector)
}

type wgConnector struct {
	options connector.Options
}

func NewConnector(opts ...connector.Option) connector.Connector {
	options := connector.Options{}
	for _, opt := range opts {
		opt(&options)
	}
	return &wgConnector{options: options}
}

func (c *wgConnector) Init(md md.Metadata) error {
	return nil
}

// tunnels is implemented by the connection handle returned by dialer/wg.
type tunnels interface {
	TCP(ctx context.Context, addr string) (net.Conn, error)
	UDP(ctx context.Context, addr string) (net.PacketConn, error)
}

// Connect dials the target inside the WireGuard tunnel. The incoming conn is
// the tunnel handle, not a data connection: it is closed once the real
// per-destination connection exists.
func (c *wgConnector) Connect(ctx context.Context, conn net.Conn, network, address string, opts ...connector.ConnectOption) (net.Conn, error) {
	t, ok := conn.(tunnels)
	if !ok {
		return nil, fmt.Errorf("wg: unsupported connection type %T", conn)
	}

	switch network {
	case "udp", "udp4", "udp6":
		pc, err := t.UDP(ctx, address)
		if err != nil {
			return nil, err
		}
		// gost's UDP paths expect a conn that is both a net.Conn and a
		// net.PacketConn (netstack's gonet.UDPConn is both).
		cc, ok := pc.(net.Conn)
		if !ok {
			return nil, fmt.Errorf("wg: udp connection %T is not a net.Conn", pc)
		}
		conn.Close()
		return cc, nil
	default:
		cc, err := t.TCP(ctx, address)
		if err != nil {
			return nil, err
		}
		conn.Close()
		return cc, nil
	}
}
```

- [ ] **Step 4: 运行测试确认通过**

Run: `go test ./connector/wg/ -v`
Expected: PASS。

- [ ] **Step 5: 构建 + 提交**

```bash
go build ./... && go vet ./connector/wg/
git add connector/wg/
git commit -m "feat(wg): add connector that dials destinations inside the tunnel"
```

---

### Task 6: 端到端测试（进程内 WG 对端）

**Files:**
- Create: `connector/wg/e2e_test.go`
- Create: `connector/wg/wgtest_test.go`（共享测试替身）

**Interfaces:**
- Consumes: `dialer/wg`（生产代码）、`connector/wg`（生产代码）、`netstack.CreateNetTUN`、`device.NewDevice`、`conn.NewDefaultBind`、`curve25519.X25519`
- Produces（仅测试内部）：`newKeyPair(t) keyPair`、`b64([32]byte) string`、`hexKey([32]byte) string`、`testBind`、`startWGServer(...)`、`startTCPEcho(...)`、`startUDPEcho(...)`

- [ ] **Step 1: 写共享测试替身**

创建 `connector/wg/wgtest_test.go`：

```go
package wg

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"io"
	"net"
	"net/netip"
	"strconv"
	"testing"

	"golang.org/x/crypto/curve25519"
	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun/netstack"
)

type keyPair struct {
	priv [32]byte
	pub  [32]byte
}

func newKeyPair(t *testing.T) keyPair {
	t.Helper()
	var kp keyPair
	if _, err := rand.Read(kp.priv[:]); err != nil {
		t.Fatal(err)
	}
	pub, err := curve25519.X25519(kp.priv[:], curve25519.Basepoint)
	if err != nil {
		t.Fatal(err)
	}
	copy(kp.pub[:], pub)
	return kp
}

func b64(k [32]byte) string  { return base64.StdEncoding.EncodeToString(k[:]) }
func hexKey(k [32]byte) string { return hex.EncodeToString(k[:]) }

// testBind records the UDP port the device actually bound to.
type testBind struct {
	conn.Bind
	port uint16
}

func (b *testBind) Open(port uint16) ([]conn.ReceiveFunc, uint16, error) {
	fns, actual, err := b.Bind.Open(port)
	b.port = actual
	return fns, actual, err
}

// startWGServer starts an in-process WireGuard endpoint with a gVisor
// netstack and returns its UDP port plus the netstack.
func startWGServer(t *testing.T, server keyPair, clientPub [32]byte, serverAddr, clientAddr netip.Addr, mtu int) (uint16, *netstack.Net, func()) {
	t.Helper()

	tunDev, ns, err := netstack.CreateNetTUN([]netip.Addr{serverAddr}, nil, mtu)
	if err != nil {
		t.Fatalf("create netstack: %v", err)
	}

	b := &testBind{Bind: conn.NewDefaultBind()}
	dev := device.NewDevice(tunDev, b, device.NewLogger(device.LogLevelError, "wg-test:"))
	cfg := "private_key=" + hexKey(server.priv) + "\n" +
		"public_key=" + hexKey(clientPub) + "\n" +
		"allowed_ip=" + clientAddr.String() + "/32\n"
	if err := dev.IpcSet(cfg); err != nil {
		dev.Close()
		t.Fatalf("ipc set: %v", err)
	}
	if err := dev.Up(); err != nil {
		dev.Close()
		t.Fatalf("up: %v", err)
	}
	// Up() opens the bind synchronously (device.BindUpdate), so the port is
	// known here.
	if b.port == 0 {
		dev.Close()
		t.Fatal("server bind did not open a udp port")
	}
	return b.port, ns, func() { dev.Close() }
}

func startTCPEcho(t *testing.T, ns *netstack.Net, ip netip.Addr) int {
	t.Helper()
	ln, err := ns.ListenTCPAddrPort(netip.AddrPortFrom(ip, 0))
	if err != nil {
		t.Fatalf("listen tcp: %v", err)
	}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				io.Copy(c, c)
			}()
		}
	}()
	_, port, err := net.SplitHostPort(ln.Addr().String())
	if err != nil {
		t.Fatalf("listener addr %q: %v", ln.Addr(), err)
	}
	p, err := strconv.Atoi(port)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func startUDPEcho(t *testing.T, ns *netstack.Net, ip netip.Addr) int {
	t.Helper()
	pc, err := ns.ListenUDPAddrPort(netip.AddrPortFrom(ip, 0))
	if err != nil {
		t.Fatalf("listen udp: %v", err)
	}
	go func() {
		buf := make([]byte, 2048)
		for {
			n, addr, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			pc.WriteTo(buf[:n], addr)
		}
	}()
	_, port, err := net.SplitHostPort(pc.LocalAddr().String())
	if err != nil {
		t.Fatalf("udp addr %q: %v", pc.LocalAddr(), err)
	}
	p, err := strconv.Atoi(port)
	if err != nil {
		t.Fatal(err)
	}
	return p
}
```

- [ ] **Step 2: 写端到端测试**

创建 `connector/wg/e2e_test.go`：

```go
package wg

import (
	"context"
	"io"
	"net"
	"net/netip"
	"strconv"
	"testing"
	"time"

	"github.com/go-gost/core/dialer"
	xwg "github.com/go-gost/x/dialer/wg"
	xmetadata "github.com/go-gost/x/metadata"
)

const e2eMTU = 1420

var (
	e2eServerAddr = netip.MustParseAddr("10.7.0.1")
	e2eClientAddr = netip.MustParseAddr("10.7.0.2")
)

// newTunnelDialer builds a dialer/wg client pointing at the in-process server.
func newTunnelDialer(t *testing.T, server keyPair, client keyPair, serverPort uint16, allowed ...string) dialer.Dialer {
	t.Helper()
	if len(allowed) == 0 {
		allowed = []string{e2eServerAddr.String() + "/32"}
	}
	d := xwg.NewDialer()
	if err := d.Init(xmetadata.NewMetadata(map[string]any{
		"privateKey":    b64(client.priv),
		"peerPublicKey": b64(server.pub),
		"endpoint":      net.JoinHostPort("127.0.0.1", strconv.Itoa(int(serverPort))),
		"localIPs":      e2eClientAddr.String() + "/32",
		"allowedIPs":    allowed,
		"mtu":           e2eMTU,
	})); err != nil {
		t.Fatalf("init dialer: %v", err)
	}
	return d
}

func TestE2E_TCPThroughTunnel(t *testing.T) {
	serverKP, clientKP := newKeyPair(t), newKeyPair(t)
	port, ns, cleanup := startWGServer(t, serverKP, clientKP.pub, e2eServerAddr, e2eClientAddr, e2eMTU)
	defer cleanup()
	echoPort := startTCPEcho(t, ns, e2eServerAddr)

	d := newTunnelDialer(t, serverKP, clientKP, port)
	defer d.(io.Closer).Close()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	handle, err := d.Dial(ctx, "")
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	cc, err := NewConnector().Connect(ctx, handle, "tcp",
		netip.AddrPortFrom(e2eServerAddr, uint16(echoPort)).String())
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer cc.Close()

	payload := []byte("hello wireguard")
	if _, err := cc.Write(payload); err != nil {
		t.Fatalf("write: %v", err)
	}
	buf := make([]byte, len(payload))
	if _, err := io.ReadFull(cc, buf); err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(buf) != string(payload) {
		t.Fatalf("echo = %q, want %q", buf, payload)
	}
}

func TestE2E_UDPThroughTunnel(t *testing.T) {
	serverKP, clientKP := newKeyPair(t), newKeyPair(t)
	port, ns, cleanup := startWGServer(t, serverKP, clientKP.pub, e2eServerAddr, e2eClientAddr, e2eMTU)
	defer cleanup()
	echoPort := startUDPEcho(t, ns, e2eServerAddr)

	d := newTunnelDialer(t, serverKP, clientKP, port)
	defer d.(io.Closer).Close()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	handle, err := d.Dial(ctx, "")
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	cc, err := NewConnector().Connect(ctx, handle, "udp",
		netip.AddrPortFrom(e2eServerAddr, uint16(echoPort)).String())
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer cc.Close()

	pc, ok := cc.(net.PacketConn)
	if !ok {
		t.Fatalf("udp connection is %T, want net.PacketConn", cc)
	}

	payload := []byte("ping")
	if _, err := pc.WriteTo(payload, &net.UDPAddr{IP: e2eServerAddr.AsSlice(), Port: echoPort}); err != nil {
		t.Fatalf("write: %v", err)
	}
	pc.SetReadDeadline(time.Now().Add(5 * time.Second))
	buf := make([]byte, 64)
	n, _, err := pc.ReadFrom(buf)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(buf[:n]) != string(payload) {
		t.Fatalf("echo = %q, want %q", buf[:n], payload)
	}
}

// WireGuard silently drops packets whose destination is outside the peer's
// allowed IPs, so the failure surfaces as a timeout, not as an error from
// Connect. This test pins that behaviour.
func TestE2E_OutsideAllowedIPsTimesOut(t *testing.T) {
	serverKP, clientKP := newKeyPair(t), newKeyPair(t)
	port, _, cleanup := startWGServer(t, serverKP, clientKP.pub, e2eServerAddr, e2eClientAddr, e2eMTU)
	defer cleanup()

	d := newTunnelDialer(t, serverKP, clientKP, port, "10.7.0.0/24")
	defer d.(io.Closer).Close()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	handle, err := d.Dial(ctx, "")
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	if _, err := NewConnector().Connect(ctx, handle, "tcp", "10.9.9.9:80"); err == nil {
		t.Fatal("expected a timeout error for a destination outside allowedIPs")
	}
}
```

- [ ] **Step 3: 运行测试确认通过**

Run: `go test ./connector/wg/ -run TestE2E -v -timeout 120s`
Expected: PASS（TCP/UDP 各一条经由真实 WireGuard 握手；越界目标按预期超时）。若 `TestE2E_OutsideAllowedIPsTimesOut` 偶发失败（机器极慢），把 ctx 放宽到 5s，但**不要**删掉该用例。

- [ ] **Step 4: 全量测试 + 提交**

```bash
go test ./dialer/wg/ ./connector/wg/ -timeout 180s
go build ./... && go vet ./dialer/wg/ ./connector/wg/
git add connector/wg/e2e_test.go connector/wg/wgtest_test.go
git commit -m "test(wg): end-to-end TCP/UDP through an in-process wireguard peer"
```

---

### Task 7: 关闭链（reload 时释放 device）

**Files:**
- Modify: `chain/transport.go`（新增 `Close()`）
- Modify: `hop/hop.go`（`chainHop.Close()` 关闭每个 node 的 transport）
- Create: `chain/transport_test.go`
- Modify: `hop/hop_test.go`（追加一个用例）

**Interfaces:**
- Consumes: `chain.Transporter`（`Options()` 返回 `*chain.TransportOptions`，含 `Transport chain.Transporter`）、`*xchain.Transport` 已有 `dialer`/`connector` 字段
- Produces: `func (tr *Transport) Close() error`

- [ ] **Step 1: 写失败的测试**

创建 `chain/transport_test.go`：

```go
package chain

import (
	"context"
	"net"
	"testing"

	"github.com/go-gost/core/connector"
	"github.com/go-gost/core/dialer"
	"github.com/go-gost/core/metadata"
)

type closingDialer struct {
	closed int
}

func (d *closingDialer) Init(md metadata.Metadata) error { return nil }
func (d *closingDialer) Dial(ctx context.Context, addr string, opts ...dialer.DialOption) (net.Conn, error) {
	return &testConn{}, nil
}
func (d *closingDialer) Close() error {
	d.closed++
	return nil
}

type plainDialer struct{}

func (d *plainDialer) Init(md metadata.Metadata) error { return nil }
func (d *plainDialer) Dial(ctx context.Context, addr string, opts ...dialer.DialOption) (net.Conn, error) {
	return &testConn{}, nil
}

type plainConnector struct{}

func (c *plainConnector) Init(md metadata.Metadata) error { return nil }
func (c *plainConnector) Connect(ctx context.Context, conn net.Conn, network, address string, opts ...connector.ConnectOption) (net.Conn, error) {
	return conn, nil
}

func TestTransportClose(t *testing.T) {
	d := &closingDialer{}
	tr := NewTransport(d, &plainConnector{})
	if err := tr.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	if d.closed != 1 {
		t.Fatalf("dialer closed %d times, want 1", d.closed)
	}
}

func TestTransportCloseWithoutCloser(t *testing.T) {
	tr := NewTransport(&plainDialer{}, &plainConnector{})
	if err := tr.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
}
```

`testConn` 已存在于 `chain/chain_test.go`（同包），直接复用；若名称冲突则使用其中已有的测试 conn 类型。

在 `hop/hop_test.go` 末尾追加：

```go
// closingTestDialer counts Close calls so the hop close path can be asserted.
type closingTestDialer struct {
	closed int
}

func (d *closingTestDialer) Init(md metadata.Metadata) error { return nil }
func (d *closingTestDialer) Dial(ctx context.Context, addr string, opts ...dialer.DialOption) (net.Conn, error) {
	return nil, errors.New("not used")
}
func (d *closingTestDialer) Close() error {
	d.closed++
	return nil
}

func TestChainHopCloseClosesNodeTransport(t *testing.T) {
	d := &closingTestDialer{}
	tr := xchain.NewTransport(d, newStubConnector())
	node := chain.NewNode("n1", "127.0.0.1:8080", chain.TransportNodeOption(tr))

	h := newTestHop(NodeOption(node))
	if err := h.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	if d.closed != 1 {
		t.Fatalf("dialer closed %d times, want 1", d.closed)
	}
}
```

`xchain` 指 `github.com/go-gost/x/chain`（`hop_test.go` 里若尚未 import，需要补上；`newStubConnector` 与 `newTestHop` 已在该文件中定义）。

- [ ] **Step 2: 运行测试确认失败**

Run: `go test ./chain/ -run TestTransportClose -v && go test ./hop/ -run TestChainHopCloseClosesNodeTransport -v`
Expected: 两条都 FAIL（`tr.Close` / hop 关闭路径未实现）。

- [ ] **Step 3: 实现**

在 `chain/transport.go` 的 `Multiplex()` 之后新增（并在 import 中补 `io`）：

```go
// Close releases resources held by the transport. A tunnel dialer (e.g.
// dialer/wg holds a WireGuard device) keeps its resources for the lifetime of
// the node, so closing it on config reload / service stop is what actually
// releases them.
func (tr *Transport) Close() error {
	if c, ok := tr.dialer.(io.Closer); ok {
		if err := c.Close(); err != nil {
			return err
		}
	}
	if c, ok := tr.connector.(io.Closer); ok {
		return c.Close()
	}
	return nil
}
```

在 `hop/hop.go` 的 `chainHop.Close()` 中，把节点循环改成：

```go
	for _, n := range p.Nodes() {
		if n == nil {
			continue
		}
		n.Close()
		// Close the node's transport so tunnel dialers release their
		// resources (e.g. dialer/wg's WireGuard device) on reload.
		if tr := n.Options().Transport; tr != nil {
			if c, ok := tr.(io.Closer); ok {
				c.Close()
			}
		}
	}
```

- [ ] **Step 4: 运行测试确认通过**

Run: `go test ./chain/ ./hop/ -v`
Expected: PASS（含既有用例）。

- [ ] **Step 5: 全量验证 + 提交**

```bash
go build ./... && go vet ./chain/ ./hop/
go test ./chain/ ./hop/ ./dialer/wg/ ./connector/wg/ -timeout 180s
git add chain/transport.go chain/transport_test.go hop/hop.go hop/hop_test.go
git commit -m "feat(chain): release node transports on close"
```

---

### Task 8: GostX 侧（依赖、配置模板、测试）

**Files:**
- Modify: `~/Workspace/project/GostX/libgost/go.mod`（replace 目标）
- Create: `~/Workspace/project/GostX/libgost/wg_profile_test.go`
- Modify: `~/Workspace/project/GostX/config.yaml.example`（追加 wg 示例）

**Interfaces:**
- Consumes: gost-x 的 `wg` dialer / connector（注册名 `wg`）、GostX `libgost` 的 `StartGost` / `StopGost` / `ValidateConfig` / `resetTestState` / `waitForRunning` 测试辅助
- Produces: 一条可用的 VPN profile 示例与对应测试

- [ ] **Step 1: 让 GostX 指向本地 gost-x**

```bash
cd ~/Workspace/project/GostX/libgost
go mod edit -replace github.com/go-gost/x=../../../src/gost-x
go build ./...
```

Expected: 构建通过（本步骤只是开发期临时定向，**不要**提交这个路径 replace）。

- [ ] **Step 2: 写测试**

创建 `libgost/wg_profile_test.go`：

```go
package libgost

import (
	"testing"
)

// testVPNWGProfileYAML is a VPN profile that sends the whitelisted targets
// through a WireGuard node and lets everything else go direct.
const testVPNWGProfileYAML = `
bypasses:
  - name: wg-ips
    whitelist: true
    matchers:
      - 10.8.0.0/16
chains:
  - name: vpn-chain
    hops:
      - name: wg-hop
        bypass: wg-ips
        nodes:
          - name: wg-node
            dialer:
              type: wg
              metadata:
                privateKey: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
                peerPublicKey: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
                endpoint: wg.example.com:51820
                localIPs: 10.7.0.2/32
            connector:
              type: wg
services:
  - name: _test_tungo
    handler:
      type: tungo
      chain: vpn-chain
  - name: test-socks5
    addr: 127.0.0.1:19080
    handler:
      type: socks5
    listener:
      type: tcp`

func TestValidateConfig_WGProfile(t *testing.T) {
	if got := ValidateConfig(testVPNWGProfileYAML); got != "" {
		t.Fatalf("ValidateConfig() = %q, want empty", got)
	}
}

func TestStartGost_WGProfile(t *testing.T) {
	resetTestState(t)
	if err := StartGost(testVPNWGProfileYAML, ""); err != nil {
		t.Fatalf("StartGost() failed: %v", err)
	}
	defer StopGost()
	waitForRunning(t)
}
```

- [ ] **Step 3: 运行测试**

Run: `cd ~/Workspace/project/GostX/libgost && go test -run 'WGProfile' -v ./...`
Expected: PASS。这里只校验配置能被解析/加载（`dialer.Init` 只做静态校验、不建隧道），不需要真实 WG 服务端；端口 19080 需空闲。

- [ ] **Step 4: 补配置示例**

在 `config.yaml.example` 末尾追加（保留原有示例不动）：

```yaml

# --- Split tunnel through WireGuard -----------------------------------------
#
# Targets covered by the whitelisted bypass go through the WireGuard peer;
# everything else bypasses the chain and is dialed directly (the app protects
# its own sockets, so direct traffic does not loop back into the TUN).
#
# bypasses:
#   - name: wg-ips
#     whitelist: true
#     matchers:
#       - 10.8.0.0/16
#       - 192.168.9.13
# chains:
#   - name: vpn-chain-wg
#     hops:
#       - name: wg-hop
#         bypass: wg-ips
#         nodes:
#           - name: wg-node
#             dialer:
#               type: wg
#               metadata:
#                 privateKey: "<client private key, base64>"
#                 peerPublicKey: "<server public key, base64>"
#                 endpoint: wg.example.com:51820
#                 localIPs: 10.7.0.2/32
#                 # allowedIPs defaults to 0.0.0.0/0; keep it that way and let
#                 # the bypass decide what enters the tunnel.
#                 mtu: 1420
#                 keepalive: 25s
#             connector:
#               type: wg
# services:
#   - name: vpn
#     handler:
#       type: tungo
#       chain: vpn-chain-wg
```

- [ ] **Step 5: 提交（GostX 仓）**

```bash
cd ~/Workspace/project/GostX
git add libgost/wg_profile_test.go config.yaml.example
git commit -m "feat(libgost): support WireGuard split-tunnel profiles"
```

`libgost/go.mod` 的 replace 在 Task 9（gost-x 推送到远端后）改成固定版本再提交，避免提交本地路径。

---

### Task 9: 全量验证与收尾

**Files:**
- Modify: `~/Workspace/project/GostX/libgost/go.mod`（改为固定的 fork 版本）
- Modify: `docs/plans/2026-10-18-wg-client-design.md`（如有与实现不一致处）

**Interfaces:**
- Consumes: 前述全部任务
- Produces: 可发布的 gost-x 提交 + GostX 指向该提交的 replace

- [ ] **Step 1: gost-x 全量验证**

```bash
cd ~/Workspace/src/gost-x
go build ./... && go vet ./...
go test ./dialer/wg/ ./connector/wg/ ./chain/ ./hop/ -timeout 300s
```

Expected: 全部通过。

- [ ] **Step 2: 推送 gost-x 并锁定 GostX 的依赖**

```bash
cd ~/Workspace/src/gost-x && git push origin <当前分支>
cd ~/Workspace/project/GostX/libgost
go mod edit -replace github.com/go-gost/x=github.com/lkebin/go-gost-x@<新提交 sha>
go mod tidy
go build ./... && go test -run 'WGProfile' ./...
cd ~/Workspace/project/GostX
git add libgost/go.mod libgost/go.sum
git commit -m "chore(deps): point go-gost/x at the WireGuard client build"
```

- [ ] **Step 3: 手工验证清单（Android / macOS）**

逐条执行并记录结论：

1. 用真实 WG 服务端配置启动 VPN profile → 日志出现 `wg: tunnel up, endpoint=..., local=[...], mtu=1420`。
2. 访问白名单内的目标（隧道内的 HTTP/echo 服务）→ 连通；访问白名单外的目标 → 按直连路径连通（日志里该连接没有 wg 节点）。
3. 无回环：VPN 开启后隧道流量正常（若回环，Android 上会看到连接被反复吸入 TUN、流量几乎为零）；`setMemoryLimit(true)` 下堆占用不持续增长。
4. 切换 profile / 停止 VPN → 日志出现 device 关闭（wireguard-go 的 `Device closed`）；反复启停 5 次后 app 内存回到基线附近。
5. 配置错误场景（密钥长度不对、`localIPs` 缺失）→ 启动时报明确错误，不 panic。

- [ ] **Step 4: 提交收尾**

```bash
cd ~/Workspace/project/GostX && git status --short
```

Expected: 只剩预期的改动；若有手工验证暴露的问题，按需新开分支/任务修复，不要在本次计划里临时扩大范围。

---

## 附：任务依赖关系

```
Task 1 (metadata) ─┬─> Task 3 (device) ──> Task 4 (dialer) ─┬─> Task 6 (e2e)
Task 2 (bind) ─────┘                                        │
                                                            ├─> Task 5 (connector) ──> Task 6
Task 7 (close chain, 独立) ────────────────────────────────┴─> Task 8 (GostX) ──> Task 9 (验证)
```

Task 7 与 Task 1–5 无代码依赖，可以并行或提前做（它只影响 device 的释放时机）。Task 8/9 必须在 gost-x 的提交可用之后执行。