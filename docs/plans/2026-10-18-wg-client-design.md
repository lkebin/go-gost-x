# Design: gost-x 的 WireGuard 客户端与按目标 IP 分流

**日期:** 2026-10-18
**状态:** 设计待评审（review 通过后再写实现计划）
**范围:** gost-x 新增真实可用的 WireGuard 客户端（`dialer/wg` + `connector/wg`），分流复用 gost 既有的 hop 级 bypass 白名单；GostX（Android / macOS VPN app）侧升级依赖并落地配置模板与验证。

## 1. 背景与问题

gost-x 目前**不支持 WireGuard 协议**：

- `dialer/wg/dialer.go` 只是占位：注册了 `"wg"` 名字，但 `Dial()` 直接走 `options.Dialer.Dial(ctx, "tcp", addr)`，`parseMetadata` 直接 `return`，没有任何 WireGuard 握手/加密封装。上游 `go-gost/x` HEAD 与此完全一致。
- 全仓库与 `wireguard` 相关的其它位置只是借用 `golang.zx2c4.com/wireguard/tun` 这个 **TUN 设备驱动**来创建虚拟网卡（`listener/tun`、`listener/tungo`），与 WireGuard 协议无关。

目标使用场景是 **GostX**（Android / macOS 的 VPN app）。它的 VPN 模式并不使用 gost-x 的 `tungo` listener/handler：

- `libgost.StartGost` 把 `type: tungo` 的 service 从配置里摘掉（`libgost/libgost.go:281` 的 `extractTungoService`），只记住它的 chain 名；
- `StartTun` 用 sing-tun 建 TUN + system stack，每条流通过 `xchain.NewRouter(ChainRouterOption(chainer))` 用那条 chain 拨号（`libgost/tun.go:112-146`、`tun.go:396/444`）。

因此我们要的是：**gost 作为 WireGuard 客户端**，把"目标为特定 IP（段）"的流量放进 WG 隧道，其余流量直连；分流决定由 gost 的链路配置表达，GostX 只提供配置与生命周期。

依赖已具备，不需要新增：`golang.zx2c4.com/wireguard`、`gvisor.dev/gvisor` 已是 `go.mod` 直接依赖（纯 userspace 实现，不需要内核模块 / TUN 设备 / root）。

## 2. 目标与非目标

**目标**

1. `dialer/wg` 成为真实的 WireGuard 客户端：对接标准 WireGuard 服务端（`wg-quick` / 官方实现的任意一端），支持 TCP 与 UDP。
2. 按目标 IP/CIDR 分流：命中的目标走 WG 隧道，未命中的走直连。
3. 在 GostX 的 VPN 模式下可用，且不产生路由回环。

**非目标**

- WG 服务端（listener）、多 peer / 多 endpoint failover、IPv6、`presharedKey`、隧道内 DNS 服务。
- WG 的 UDP 流量经前置代理（链式隧道）；前置节点不支持。
- 改动 `github.com/go-gost/core`（本次全部改动都在 `x` 内与 GostX 内完成）。

## 3. 分流方案：复用 hop 级 bypass 白名单

不需要新增路由能力。gost 已经具备"仅这些目标走这一跳，其余走直连"的机制：

- hop 级 bypass 在 `Select` 最开始判定，用的是**已解析的 IP**（`hop/hop.go:182` 传入 `options.Addr`）加 host；
- bypass 的**白名单模式**语义即"命中 → 走代理链；未命中 → bypass"（`bypass/bypass.go:482-492`），由 `bypasses[].whitelist: true` 开启（`config/config.go:182`、`config/parsing/bypass/parse.go:52`）；
- 模式串支持 CIDR、单 IP、IP 区间与通配域名（`bypass/bypass.go:329-363` 的 `classifyPatterns`：`net.ParseCIDR` / `IPRange` / `glob`）；
- hop 的 `bypass` / `bypasses` 已接线到 `xhop.BypassOption`（`config/parsing/hop/parse.go:165`）。

于是链路结构为：chain → hop（`bypass: <whitelist bypass>`）→ node（`dialer: wg` + `connector: wg`）。

- 命中白名单：hop 选中 wg 节点 → 路由 = [wg node] → 在 WG 隧道内连接目标；
- 未命中：`hop.Select` 返回 nil → `Chain.Route` 返回空路由 → `chainRoute.Dial` 走 `DefaultRoute`（`chain/route.go:144`）→ gost 内部 net dialer **直连**。在 GostX 里该 socket 会经过 `GlobalSocketControl` → `VpnService.protect`，不会回环。

## 4. 架构

### 4.1 实现范式：复刻 hysteria 双件套

仓库里已有完全对应的范式：`dialer/hysteria` 建立隧道并返回一个"隧道句柄"conn（暴露 `TCP(addr)` / `UDP()`），`connector/hysteria` 在这个 conn 上连接最终目标（`connector/hysteria/connector.go:31-60`、`dialer/hysteria/dialer.go` 的 `hyClientConn`）。WG 照此实现，`dialer` 负责隧道，`connector` 负责"在隧道内连目标"。

之所以需要单独的 connector：gost 的链路模型里，`Transport.Dial` 只拿到节点地址（`chain/transport.go:51-52`），**目标地址是在 `Connect` 阶段传给 connector 的**（`chain/route.go:158`）；只有 connector 才拿得到 `network` + `address`。

### 4.2 文件清单

| 文件 | 动作 | 职责 |
|------|------|------|
| `dialer/wg/dialer.go` | 重写 | `wgDialer`：metadata 入口、惰性创建并缓存 device、`Dial` 返回 stub conn、实现 `io.Closer` |
| `dialer/wg/device.go` | 新增 | `newDevice(md)`：`netstack.CreateNetTUN` → `device.NewDevice` → `IpcSet` → `Up` |
| `dialer/wg/conn.go` | 新增 | stub conn（`net.Conn` 空实现）+ `TCP(addr) (net.Conn, error)` / `UDP() (net.PacketConn, error)` |
| `dialer/wg/bind.go` | 新增 | 自定义 `conn.Bind`：包装 `conn.NewStdNetBind()`，`Open` 后借 `PeekLookAtSocketFd4/6`（Android）套 `netdialer.GlobalSocketControl`，其余方法透传 |
| `dialer/wg/metadata.go` | 改 | 解析并静态校验配置项 |
| `connector/wg/connector.go` | 新增 | `tcp` → netstack 的 TCP dial；`udp` → netstack 的 UDP dial（`*gonet.UDPConn` 本身即 `net.PacketConn`）；注册名 `wg` |
| `chain/transport.go` | 改 | 新增 `Close()`：dialer（其次 connector）实现 `io.Closer` 则转调 |
| `hop/hop.go` | 改 | `chainHop.Close()` 中关闭每个 node 的 `Transport` |

`dialer/wg` **不实现** `dialer.Multiplexer`。含义：wg 节点可以作为链路的传输层（链上后续节点的地址会被连接于隧道内），但**前置节点不支持**——WG 自己的 UDP 不会走前置代理。

## 5. 数据流

以 GostX VPN 模式下一个 TCP 连接（目标 `10.8.1.5:443`，该 IP 在白名单内）为例：

```
应用 → TUN → sing-tun stack → singTunHandler
  → router.Dial("tcp", "10.8.1.5:443")                        (libgost/tun.go)
  → chain.Router.dial: 解析地址 → Chain.Route(network, "10.8.1.5:443")
  → hop.Select: hop 级 bypass 白名单命中 → 选中 wg node        (hop/hop.go:182)
  → Transport.Dial(node.addr) → wgDialer.Dial → 确认 device 已 Up → stub conn
  → Transport.Connect(conn, "tcp", "10.8.1.5:443")            (chain/route.go:158)
  → connector/wg: netstack DialContextTCP(10.8.1.5:443)       ← 真实 TCP 在 userspace netstack 里
  → SYN 经 WG 隧道出物理网卡 → 对端 WG 服务端 → 目标
```

- **未命中白名单**：`hop.Select` 返回 nil → 空路由 → `DefaultRoute.Dial` → 直连（`GlobalSocketControl` / `VpnService.protect` 已生效）。
- **UDP**：同一路径，`network="udp"` → netstack 的 UDP dial，返回值是 `net.PacketConn`，`Router.Dial` 原样透传（不会被 `packetConn` 再包一层，`chain/router.go:302`）。
- **隧道自身出网**：WG 的 UDP socket 由自定义 bind 创建，走物理网卡；它**不经过** gost 链路，也**不进** TUN。

## 6. 配置面

### 6.1 `dialer.metadata`

| 键 | 类型 | 必填 | 默认 | 说明 |
|---|---|---|---|---|
| `privateKey` | base64 string | 是 | — | 客户端私钥（32 字节） |
| `peerPublicKey` | base64 string | 是 | — | 单 peer 公钥 |
| `endpoint` | `host:port` | 是 | — | 见 6.3 |
| `localIPs` | string / []string | 是 | — | 隧道接口地址（如 `10.7.0.2/32`），逗号分隔或数组 |
| `allowedIPs` | string / []string | 否 | `0.0.0.0/0` | peer 的 `allowed_ips`；见 7.3 |
| `mtu` | int | 否 | 1420 | netstack 与 device 的 MTU |
| `keepalive` | duration / int | 否 | 0（关闭） | → `persistent_keepalive_interval`，建议 25s |
| `dns` | string / []string | 否 | 空 | 仅"域名目标"需要，见 6.3 |

约定沿用 gost 惯例：键名大小写不敏感（metadata 统一小写），每个键同时尝试 `xxx` 与 `wg.xxx` 两种写法。

列表类字段（`localIPs` / `allowedIPs` / `dns`）的解析要同时接受数组与逗号分隔的字符串：`mdutil.GetStrings` **不接受普通字符串**（只处理 `[]string` / `[]any`，`metadata/util/util.go:180`），所以用一个薄 helper 按 `listener/tun/metadata.go:63-70` 的既有写法合并 `GetStrings` 与 `GetString` + `strings.Split(s, ",")` 两条路径。

不引入 `dialTimeout`（现有占位实现里的那个常量随重写一并去掉）：连接超时统一由 gost 的链路 `ctx` / `Router` 超时控制。

`localIPs` 必填的原因：`netstack.CreateNetTUN` 用它给 NIC 添加协议地址，并据此添加 IPv4/IPv6 默认路由；为空时隧道内既无地址也无路由。

### 6.2 节点级沿用（不新增键）

`metadata.so_mark`（SO_MARK）沿用 gost 现有的**节点级** metadata：`config/parsing/node/parse.go:198-200` 会把它放进 `TransportOptions`，`chain/transport.go:51` 再通过内部 net dialer 传进来，`wgDialer.Dial` 读出后应用到隧道（`device.BindSetMark`），bind 自身继续套 `GlobalSocketControl`。

`metadata.interface` **暂不支持**：WG 的 UDP socket 由 wireguard-go 的 `StdNetBind` 创建，unix 上它不提供按网卡绑定（`BindSocketToInterface` 只有 Windows 实现）。若配置了 `interface`，只记一条 warn 日志并忽略，socket 跟随系统路由表。

### 6.3 两条"名解析"规则

1. **`endpoint` 是域名时必须由我们自己解析。** wireguard-go 的 `conn.StdNetBind.ParseEndpoint` 只接受字面量 `netip.ParseAddrPort`（`conn/bind_std.go:90`），不支持域名；直接写域名会让 `device.IpcSet` 报 `failed to set endpoint`。因此在建 device 时用系统 resolver 解析成 `ip:port` 再写入 uapi，解析失败则明确报错。域名只在**首次建隧道时解析一次**，之后依赖 WireGuard 的 endpoint roaming（见 10）。
2. **隧道内目标的域名解析。** connector 拿到的 `address` 通常是 IP（`Router.dial` 已先解析，`chain/router.go:158`）；若是域名：配了 `dns` 就用 netstack 内置解析器在隧道内解析，没配 `dns` 就返回明确错误。这里刻意**不**回退调用 netstack 的 `LookupHost`：wireguard-go 的 `tun/netstack` 在 `dnsServers` 为空时 `tryOneName` 会走到"空结果 + nil error"的退化路径（`tun/netstack/tun.go:747-810`），只会给出含混的 DNS 错误。

### 6.4 密钥形态

配置用 wg-quick 风格的 base64（与用户服务端配置一致），内部解码为 32 字节再转 hex 传给 `IpcSet`（uapi 要求 hex）。不做 `privateKeyFile`（YAGNI；GostX 的配置存在 app 配置里）。

### 6.5 配置示例（GostX VPN profile）

```yaml
bypasses:
- name: wg-ips
  whitelist: true          # 命中 → 走代理链；未命中 → 直连
  matchers:
  - 10.8.0.0/16            # CIDR
  - 1.2.3.4                # 单 IP
  # 也支持 1.2.3.4-1.2.3.10 区间、*.example.com 通配域名
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
          privateKey: "<client private key, base64>"
          peerPublicKey: "<server public key, base64>"
          endpoint: wg.example.com:51820
          localIPs: 10.7.0.2/32
          allowedIPs: 0.0.0.0/0     # 默认值，可省
          mtu: 1420
          keepalive: 25s
          dns: 10.7.0.1             # 仅当目标可能是域名时需要
      connector:
        type: wg
services:
- name: vpn
  handler: {type: tungo, chain: vpn-chain}
```

## 7. 错误处理、并发与生命周期

### 7.1 隧道就绪与失败语义

- `dev.Up()` 立即返回，握手在首次发包时惰性触发，因此**不做**显式探活（不加 ping / 健康检查）：连接失败会以 `Connect` 阶段的超时或错误暴露，wireguard-go 自身会周期性重试握手。
- 失败分级：
  - **静态配置错误**（密钥非 base64 / 长度不为 32、`endpoint` 缺 host:port、`localIPs` / `allowedIPs` 不可解析、mtu 越界）→ `Init` 报错 → 配置加载阶段即失败（fail fast）。
  - **建 device 失败**（endpoint 域名解析失败、`IpcSet` 失败、`Up` 失败）→ `Dial` 返回错误，且**不缓存失败结果**，下次 `Dial` 重建。
  - **连接失败**（超时、对端拒绝、无路由）→ netstack 返回标准 `*net.OpError` 风格错误，交给 gost 的 route retry / handler 处理。

### 7.2 device 生命周期与释放

现状：`registry.Unregister` 会先 Close 实现了 `io.Closer` 的值（`registry/registry.go:88`）；`loader.Load` 每次都是 `registerGroup` → `unregisterAll`（`config/loader/loader.go:106-123`），GostX 每次 `StartGost` 都会走这条路径（`libgost/libgost.go:137`）；`Chain.Close()` 会关闭每个 hop（`chain/chain.go:120`）；但 `chainHop.Close()` 目前只调 `node.Close()`（core 里只停探活，`hop/hop.go:514`），关闭链到不了 dialer。因此补三处：

1. `dialer/wg` 实现 `io.Closer`：`Close()` → `dev.Close()`（wireguard-go 的 `Device.Close()` 已包含关闭 netstack tun，且自身幂等，`device/device.go:370`），内部用状态锁保证**重复调用安全**（`Transport.Copy()` 会让多个 transport 共享同一个 dialer）。
2. `chain/transport.go` 新增 `Close()`。
3. `hop/hop.go` 的 `chainHop.Close()` 里对每个 node 的 `Transport` 做 `io.Closer` 断言并关闭。

效果：切换 profile / reload / `StopGost` 时旧 device 会被释放——这在 Android 端 100MB 堆限制下是必要的。附带收益：`dialer/hysteria` 的 QUIC session 将来可沿同一条链释放（本次不改它）。

### 7.3 `allowedIPs` 与分流的配合

wireguard-go 会**静默丢弃**目标不在 peer `allowedIPs` 内的包，表现为**超时而不是报错**。因此文档明确：建议保持 `allowedIPs` 默认 `0.0.0.0/0`，分流交给 bypass；把它设窄也不会报错，只是连不上。

### 7.4 并发与缓存

- 一个 dialer 实例 = 一个节点 = 一个 device（node parse 时每个节点各建一个 dialer 实例，`config/parsing/node/parse.go:173`），因此不需要 hysteria 那样按地址缓存 session。
- 惰性创建加锁：并发 `Dial` 只建一次；`Close()` 与 `Dial()` 用同一把锁串行化状态切换。
- 隧道本身并发安全（多流复用同一个 device）。

### 7.5 日志

用节点级 logger：`info` 记录隧道建立/关闭（endpoint、本地地址），`debug` 记录 device 复用与解析细节，`warn`/`error` 记录 endpoint 解析失败、`IpcSet`/`Up` 失败等。GostX 的 `installLogger` 已把 gost 默认 logger 接到 app 日志面板，可直接看到。

## 8. 测试与验证

### 8.1 单元测试（`x/dialer/wg`）

- metadata 解析：必填缺失报错；默认值（`allowedIPs=0.0.0.0/0`、`mtu=1420`、`keepalive=0`）；`localIPs` 逗号串与数组；`keepalive` 的 `25s` 与整数秒；`xxx` / `wg.xxx` 键名回退；大小写不敏感。
- 密钥处理：base64 → 内部 hex 正确；长度不足 / base64 非法 → 报错。

### 8.2 端到端测试（`x/dialer/wg`，进程内两个 userspace WG 端点）

- 服务端：`netstack.CreateNetTUN([10.7.0.1/24], nil, mtu)` + `device.NewDevice(tun, testBind, logger)` + `IpcSet`（服务端私钥、客户端公钥、`allowed_ip=10.7.0.2/32`）+ `Up()`；在它的 netstack 内用 `ListenTCP` / `ListenUDP` 各起一个 echo 服务。
- 客户端走**生产代码**（`dialer/wg` + `connector/wg`），`endpoint = 127.0.0.1:<服务端 bind 的实际 UDP 端口>`（测试里用一个薄包装捕获 `Open()` 返回的 `actualPort`）：
  - TCP：`Dial` → `Connect(ctx, "tcp", "10.7.0.1:<echoPort>")` → 写读断言；
  - UDP：`Connect(ctx, "udp", ...)` 返回 `net.PacketConn` → `WriteTo` / `ReadFrom` 断言；
  - 反向断言：目标不在 `allowedIPs` 内时短 ctx 下返回超时错误（把 7.3 的行为固化）；
  - 生命周期：`Close()` 幂等、可重复调用。
- 密钥生成：`crypto/rand` + `golang.org/x/crypto/curve25519`（已是依赖），`X25519(priv, basepoint)` 推公钥，与 WireGuard 的 clamp 规则一致。wireguard-go 的 `device` 包不导出 `NewPrivateKey` 之类助手，测试不依赖它。

### 8.3 构建与静态检查

`cd x && go build ./... && go vet ./...`（仓库既有验证路径）+ `go test ./dialer/wg/... ./connector/wg/...`。CLAUDE.md 写"没有测试"，但仓库实际已有大量 `_test.go`（`bypass/bypass_test.go`、`hop/*_test.go`、`connector/direct/connector_test.go` 等），加测试符合现状。

### 8.4 GostX 侧验证

- 单测（`libgost`）：新增含 wg 节点的 VPN profile 测试 YAML，覆盖 `extractTungoService`（摘掉 tungo service 后 wg 节点 / hop / chain 仍在）与 `ValidateConfig`（返回空字符串，不误报未知类型）。
- 手工清单（Android / macOS）：
  1. 启动 VPN → 日志出现"WG 隧道建立（endpoint、本地地址）"；
  2. 白名单内的目标可访问（隧道内的 echo / HTTP 服务）；非白名单目标走直连（日志与抓包确认）；
  3. 无回环：WG 的 UDP 不会被再次吸进 TUN（`VpnService.protect` 生效），`setMemoryLimit(true)` 下堆占用正常；
  4. 切换 profile / `Stop` → 日志出现 device closed；反复启停不泄漏。

### 8.5 不做

不做真实第三方 WG 服务端的自动化联调（放到手工清单）；不做吞吐 / 性能基准。

## 9. GostX 侧改动

1. 升级 `libgost/go.mod` 的 `replace github.com/go-gost/x => github.com/lkebin/go-gost-x <新版本>`。
2. 提供 VPN profile 配置模板/示例（含 `bypasses` whitelist + wg hop/node），并同步到 app 的文档/默认配置。
3. `libgost` 单测覆盖该模板（8.4）。
4. 手工验证按 8.4 执行。

GostX 的 `ValidateConfig` 只校验 service 的 handler / listener 类型与 chain 引用（`libgost.go:391-425`），不校验 dialer / connector 名，因此**不需要**改校验逻辑。

## 10. 已知限制

- `endpoint` 域名只在首次建隧道时解析一次；此后的服务端 IP 变化依赖 WireGuard 的 endpoint roaming（收到包后会更新对端地址）。服务端长时间更换 IP 且无流量往返时，需要重建服务/节点。
- 前置节点 / 链式隧道不支持（WG 的 UDP 不走前置代理）。
- 多 peer / IPv6 / `presharedKey` / 隧道内 DNS 服务不做。
- 不做显式隧道探活：对端不可达时表现为"首个连接慢 / 超时"。
- `hopGroup` 内层 hop 的关闭缺口是既有问题（`hop/group.go:193` 只取消探测），不在本次范围。

## 11. 备选方案（未采纳）

- **把隧道下沉到 dialer 内部、connector 复用 `direct`**：需要改 `Transport` 让 netd 走隧道拨号器，会动到链路核心并隐式替换 `direct` 的语义；与 hysteria 等既有模式不一致。未采纳。
- **做成 `listener/wg` + 复用 `handler/tungo`**：与 GostX 的架构错位（GostX 自己用 sing-tun 起 stack、按流调 `Router.Dial`，不使用 gost 的 tungo handler），且分流粒度变粗、实现量大。未采纳。

## 12. 影响面

- **新增**：`dialer/wg/{device,conn,bind}.go`、`connector/wg/*`、对应 `_test.go`。
- **重写**：`dialer/wg/dialer.go`、`dialer/wg/metadata.go`。
- **小改**：`chain/transport.go`（加 `Close()`）、`hop/hop.go`（`chainHop.Close()` 关 transport）。
- **无核心依赖变更**：不改 `github.com/go-gost/core`，不新增第三方依赖。
- **GostX**：`libgost/go.mod` 的 replace 版本 + 配置模板/示例 + 单测。