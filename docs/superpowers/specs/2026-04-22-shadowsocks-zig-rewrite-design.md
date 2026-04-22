# 1. Executive summary

The recommended direction is a core-first Zig rewrite with thin frontends, using the Rust repository as the compatibility oracle rather than as an architectural template. The first shippable Zig deliverable should be Linux-first, expose only `sslocal` and `ssserver`, and prioritize strict wire compatibility for classic Shadowsocks AEAD over TCP and UDP.

The MVP should intentionally narrow the surface area:

- `sslocal`: SOCKS5 only, with `CONNECT` and `UDP ASSOCIATE`
- `ssserver`: classic Shadowsocks TCP and UDP relay
- ciphers: `aes-128-gcm`, `aes-256-gcm`, `chacha20-ietf-poly1305`
- config: common single-server config compatibility, including practical JSON5-style syntax support for comments and trailing commas
- CLI: smaller than upstream, preserving the important operational concepts without cloning all flags

The Zig implementation should separate config, crypto, wire protocol, local frontend protocol, and networking. MVP should avoid platform service wrappers, manager mode, plugins, TUN, redir, fake DNS, HTTP local, SOCKS4, multi-server balancing, and deprecated stream ciphers.

The runtime recommendation for MVP is simple blocking I/O plus explicit threads:

- one accept thread per TCP listener
- one thread per active TCP session
- one long-lived UDP loop per service
- one periodic cleanup path for UDP associations

That choice is deliberate. It favors debuggability, explicit ownership, and easier resource cleanup over early throughput maximization. If a more evented model is needed later, the crypto, wire, config, and frontend layers should remain reusable.

# 2. Upstream repository map

## 2.1 Workspace and binaries

Repository root package: `shadowsocks-rust` `1.25.0`

Workspace members:

- `crates/shadowsocks`
- `crates/shadowsocks-service`

Top-level binaries declared in [Cargo.toml](</C:/zig/Shadowsocks/Cargo.toml:1>):

- `sslocal` at [bin/sslocal.rs](</C:/zig/Shadowsocks/bin/sslocal.rs:1>)
- `ssserver` at [bin/ssserver.rs](</C:/zig/Shadowsocks/bin/ssserver.rs:1>)
- `ssurl` at [bin/ssurl.rs](</C:/zig/Shadowsocks/bin/ssurl.rs:1>)
- `ssmanager` at [bin/ssmanager.rs](</C:/zig/Shadowsocks/bin/ssmanager.rs:1>)
- `ssservice` at [bin/ssservice.rs](</C:/zig/Shadowsocks/bin/ssservice.rs:1>)
- `sswinservice` at [bin/sswinservice.rs](</C:/zig/Shadowsocks/bin/sswinservice.rs:1>)

Top-level library helpers in [src/lib.rs](</C:/zig/Shadowsocks/src/lib.rs:1>):

- allocator, config, error, logging, monitor, password, service, sys, CLI-facing parsing helpers

## 2.2 Internal crates and major modules

Core crate [`crates/shadowsocks`](</C:/zig/Shadowsocks/crates/shadowsocks/src/lib.rs:1>):

- `config`
  - server address types
  - mode enums
  - server config
  - manager address/config pieces
- `context`
  - nonce generation
  - replay policy
  - shared security state
- `dns_resolver`
  - resolver abstraction
  - Hickory-backed resolver integration
- `manager`
  - manager protocol datagrams, listener, client
- `net`
  - socket/platform helpers
- `plugin`
  - SIP003 plugin process integration
- `relay`
  - `socks5` address/header codecs
  - `tcprelay`
  - `udprelay`
  - AEAD, AEAD-2022, stream-cipher code paths

Service crate [`crates/shadowsocks-service`](</C:/zig/Shadowsocks/crates/shadowsocks-service/src/lib.rs:1>):

- `acl`
  - ACL parsing and matching
- `config`
  - large extended runtime config model and parsing
- `local`
  - SOCKS
  - HTTP local
  - tunnel
  - redir
  - DNS relay
  - TUN
  - fake DNS
  - online config
  - load balancing
  - local net helpers
- `server`
  - TCP and UDP relay orchestration
- `manager`
  - manager server runtime
- `net`
  - packet windows
  - HTTP connect helpers
  - outbound proxy helpers
  - monitoring wrappers
- `sys`
  - platform support

## 2.3 Feature flags

Top-level feature groups in [Cargo.toml](</C:/zig/Shadowsocks/Cargo.toml:1>):

- `basic`
  - logging, DNS, local, server, multithreaded, AEAD
- `full`
  - local, server, manager, service, HTTP local, tunnel, SOCKS4, DNS, redir, TUN, online config, stream ciphers, AEAD, AEAD-2022
- `full-extra`
  - fake DNS, extra AEAD variants, replay attack detection

Key feature families:

- service roles
  - `local`
  - `server`
  - `manager`
  - `service`
  - `winservice`
- local modes
  - `local-http`
  - `local-tunnel`
  - `local-socks4`
  - `local-dns`
  - `local-redir`
  - `local-tun`
  - `local-fake-dns`
  - `local-online-config`
- crypto
  - `stream-cipher`
  - `aead-cipher`
  - `aead-cipher-extra`
  - `aead-cipher-2022`
  - `aead-cipher-2022-extra`
  - `security-replay-attack-detect`
- DNS/TLS
  - `hickory-dns`
  - `dns-over-tls`
  - `dns-over-https`
  - `dns-over-h3`

## 2.4 Config formats and protocol/config extras

Observed config and config-adjacent surfaces:

- common single-server config
  - `server`, `server_port`, `local_address`, `local_port`, `password`, `method`, `mode`
- extended multi-server config
  - `servers`
  - `locals`
  - per-instance protocol selection
  - per-instance ACL and auth config
- practical parser behavior
  - upstream uses `json5::from_str` in [src/config.rs](</C:/zig/Shadowsocks/src/config.rs:122>) and [crates/shadowsocks-service/src/config.rs](</C:/zig/Shadowsocks/crates/shadowsocks-service/src/config.rs:2780>)
  - comments and trailing commas are therefore a real operator-facing compatibility consideration
- SIP002 URI support
  - used by `ssurl` and config import paths
- SIP003 plugin config
  - `plugin`, `plugin_opts`, `plugin_args`, `plugin_mode`
- SIP008 online config
- manager protocol config
- outbound proxy chain config

## 2.5 Protocol variants and runtime modes

Core protocol capabilities present upstream:

- classic Shadowsocks TCP relay
- classic Shadowsocks UDP relay
- AEAD-2022 TCP relay
- AEAD-2022 UDP relay
- stream-cipher legacy paths

Local frontend modes present upstream:

- SOCKS5
- SOCKS4/4a
- HTTP proxy
- tunnel
- redir
- DNS relay
- TUN

## 2.6 Platform-specific code

Platform-specific or platform-heavy code observed:

- Unix daemonization in [src/daemonize.rs](</C:/zig/Shadowsocks/src/daemonize.rs:1>)
- Windows service binary in [bin/sswinservice.rs](</C:/zig/Shadowsocks/bin/sswinservice.rs:1>)
- service crate `sys` modules
- macOS launchd socket activation
- redir syscall backends for Linux, BSD, macOS, Windows
- TUN integration with `tun` and `smoltcp`

## 2.7 Tests, examples, and packaging surface

Examples:

- [examples/config.json](</C:/zig/Shadowsocks/examples/config.json:1>)
- [examples/config_ext.json](</C:/zig/Shadowsocks/examples/config_ext.json:1>)

Integration tests:

- [tests/socks5.rs](</C:/zig/Shadowsocks/tests/socks5.rs:1>)
- [tests/udp.rs](</C:/zig/Shadowsocks/tests/udp.rs:1>)
- [tests/http.rs](</C:/zig/Shadowsocks/tests/http.rs:1>)
- [tests/socks4.rs](</C:/zig/Shadowsocks/tests/socks4.rs:1>)
- [tests/dns.rs](</C:/zig/Shadowsocks/tests/dns.rs:1>)
- [tests/tunnel.rs](</C:/zig/Shadowsocks/tests/tunnel.rs:1>)

Core crate tests:

- [crates/shadowsocks/tests/tcp.rs](</C:/zig/Shadowsocks/crates/shadowsocks/tests/tcp.rs:1>)
- [crates/shadowsocks/tests/udp.rs](</C:/zig/Shadowsocks/crates/shadowsocks/tests/udp.rs:1>)

Operational packaging in upstream README:

- Docker
- Kubernetes/Helm
- Homebrew
- Snap
- release artifacts

These are important deployment references, but they should not shape the Zig MVP architecture.

## 2.8 Dependency inventory

Crypto dependencies in Rust:

- `shadowsocks-crypto`
- `ring` through feature wiring
- `aes`
- `blake3`
- `rand`
- optional replay filters and caches

Async/runtime dependencies:

- `tokio`
- `futures`
- `tokio-tfo`
- `pin-project`

DNS/resolver dependencies:

- `hickory-resolver`
- `arc-swap`
- `notify`

CLI/config/logging dependencies:

- `clap`
- `json5`
- `serde`, `serde_json`
- `log`, `log4rs`, `tracing`, `tracing-subscriber`

HTTP/TLS dependencies:

- `hyper`
- `http`, `http-body-util`, `httparse`
- `tokio-native-tls`, `native-tls`
- `tokio-rustls`, `webpki-roots`, `rustls-native-certs`

Service/platform integration dependencies:

- `windows-service`
- `socket2`
- `libc`
- `nix`
- `tun`
- `smoltcp`
- `rocksdb`

Rewrite recommendation:

- MVP Zig should use Zig stdlib for crypto
- avoid an async runtime dependency entirely
- avoid plugin, manager, HTTP, TUN, redir, fake DNS, and service-wrapper dependency equivalents in MVP

# 3. Feature matrix

| Feature / Mode | What it does | Main Rust location | Protocol criticality | Complexity | Security sensitivity | Target |
|---|---|---|---|---|---|---|
| Classic AEAD TCP relay | Encrypted Shadowsocks TCP transport | [crates/shadowsocks/src/relay/tcprelay](</C:/zig/Shadowsocks/crates/shadowsocks/src/relay/tcprelay/mod.rs:1>) | Critical | Medium | High | MVP |
| Classic AEAD UDP relay | Encrypted Shadowsocks UDP transport | [crates/shadowsocks/src/relay/udprelay](</C:/zig/Shadowsocks/crates/shadowsocks/src/relay/udprelay/mod.rs:1>) | Critical | Medium | High | MVP |
| SOCKS5 CONNECT | Local TCP frontend | [local/socks/server/socks5/tcprelay.rs](</C:/zig/Shadowsocks/crates/shadowsocks-service/src/local/socks/server/socks5/tcprelay.rs:1>) | Critical for `sslocal` | Medium | Medium | MVP |
| SOCKS5 UDP ASSOCIATE | Local UDP frontend/control flow | [local/socks/server/socks5/udprelay.rs](</C:/zig/Shadowsocks/crates/shadowsocks-service/src/local/socks/server/socks5/udprelay.rs:1>) | Critical for UDP local mode | High | High | MVP |
| Single-server config | Basic deployment config | [crates/shadowsocks-service/src/config.rs](</C:/zig/Shadowsocks/crates/shadowsocks-service/src/config.rs:1>) | High | Medium | Medium | MVP |
| JSON5-style config acceptance | Comments/trailing commas in configs | [src/config.rs](</C:/zig/Shadowsocks/src/config.rs:122>) | Medium | Low | Low | MVP |
| Basic CLI flags | Minimal operator-facing startup | [bin/sslocal.rs](</C:/zig/Shadowsocks/bin/sslocal.rs:1>), [bin/ssserver.rs](</C:/zig/Shadowsocks/bin/ssserver.rs:1>) | Medium | Low | Low | MVP |
| AEAD-2022 | Newer cipher suite and session semantics | [aead_2022.rs](</C:/zig/Shadowsocks/crates/shadowsocks/src/relay/tcprelay/aead_2022.rs:1>) | Important later | High | High | v2 |
| Multi-server balancing | Multiple remotes and health-based selection | [local/loadbalancing](</C:/zig/Shadowsocks/crates/shadowsocks-service/src/local/loadbalancing/mod.rs:1>) | Low for first ship | High | Medium | v2 |
| ACL | Inbound/outbound allow/block rules | [acl/mod.rs](</C:/zig/Shadowsocks/crates/shadowsocks-service/src/acl/mod.rs:1>) | Low for protocol | Medium | High | Later |
| Outbound proxy chaining | Route egress through SOCKS/HTTP proxy | [config.rs](</C:/zig/Shadowsocks/crates/shadowsocks-service/src/config.rs:1>), [net/outbound_proxy.rs](</C:/zig/Shadowsocks/crates/shadowsocks-service/src/net/outbound_proxy.rs:1>) | Low | Medium | Medium | Later |
| HTTP local | HTTP proxy frontend | [local/http](</C:/zig/Shadowsocks/crates/shadowsocks-service/src/local/http/mod.rs:1>) | Low | Medium | Medium | Later |
| SOCKS4/4a local | SOCKS4 frontend | [local/socks/server/socks4](</C:/zig/Shadowsocks/crates/shadowsocks-service/src/local/socks/server/socks4/mod.rs:1>) | Low | Low | Low | Later |
| Tunnel local | Fixed-target TCP/UDP tunnel | [local/tunnel](</C:/zig/Shadowsocks/crates/shadowsocks-service/src/local/tunnel/mod.rs:1>) | Low | Medium | Medium | Later |
| DNS relay | DNS-aware local service | [local/dns](</C:/zig/Shadowsocks/crates/shadowsocks-service/src/local/dns/mod.rs:1>) | Low | High | Medium | Later |
| Redir | Transparent proxy mode | [local/redir](</C:/zig/Shadowsocks/crates/shadowsocks-service/src/local/redir/mod.rs:1>) | Low | High | High | Later |
| TUN | Full virtual interface mode | [local/tun](</C:/zig/Shadowsocks/crates/shadowsocks-service/src/local/tun/mod.rs:1>) | Low | Very high | High | Later |
| Fake DNS | Fake address mapping for TUN/redir workflows | [local/fake_dns](</C:/zig/Shadowsocks/crates/shadowsocks-service/src/local/fake_dns/mod.rs:1>) | Low | High | High | Later |
| SIP003 plugin support | External transport plugins | [crates/shadowsocks/src/plugin](</C:/zig/Shadowsocks/crates/shadowsocks/src/plugin/mod.rs:1>) | Low for core wire | Medium | High | Maybe later |
| SIP008 online config | Remote config loading | [local/online_config](</C:/zig/Shadowsocks/crates/shadowsocks-service/src/local/online_config/mod.rs:1>) | Low | Medium | High | Maybe later |
| Manager API | Start/manage servers dynamically | [manager](</C:/zig/Shadowsocks/crates/shadowsocks-service/src/manager/mod.rs:1>) | Low | High | High | Maybe later |
| Service wrappers | Daemon/service integrations | [bin/ssservice.rs](</C:/zig/Shadowsocks/bin/ssservice.rs:1>), [bin/sswinservice.rs](</C:/zig/Shadowsocks/bin/sswinservice.rs:1>) | Low | Medium | Medium | Later |
| Stream ciphers | Deprecated legacy methods | feature-gated crypto paths | Compatibility-only | Medium | High | Maybe never |
| `none` / plaintext | Debugging/no-encryption mode | config/method parsing | Not required | Low | High | Maybe never |

# 4. Compatibility contract

## 4.1 Wire protocol compatibility

MVP must preserve exact wire compatibility for:

- classic Shadowsocks AEAD TCP framing
- classic Shadowsocks AEAD UDP packet format
- address encoding for IPv4, IPv6, and domain names
- SOCKS5 local behavior needed for `CONNECT` and `UDP ASSOCIATE`

Parity matters exactly here. This is the non-negotiable part of the rewrite.

Intentional divergence:

- no stream-cipher support in MVP
- no AEAD-2022 in MVP
- no plugin framing or external transport indirection in MVP

## 4.2 Config compatibility

MVP config compatibility target:

- support common single-server fields needed for ordinary `sslocal` and `ssserver` deployments
- support JSON5-style file syntax sufficient for comments and trailing commas, because upstream uses JSON5 in practice
- reject unsupported advanced config keys with clear diagnostics

Supported config fields for MVP:

- `server`
- `server_port`
- `password`
- `method`
- `protocol`
- `mode`
- `timeout`
- `local_address`
- `local_port`
- `local_udp_address`
- `local_udp_port`
- `udp_timeout`
- `udp_max_associations`
- `no_delay`
- `keep_alive`

Rejected in MVP:

- `servers`
- `locals`
- `server_url`
- `plugin`, `plugin_opts`, `plugin_args`, `plugin_mode`
- ACL fields
- `socks5_auth_config_path`
- HTTP auth config
- online config
- `fast_open`
- `ipv6_first`
- `ipv6_only`
- `mptcp`
- `udp_mtu`
- socket buffer size knobs
- `outbound_udp_allow_fragmentation`
- TUN/redir/fake-DNS fields
- outbound proxy chain fields

Special compatibility rule:

- when running `ssserver`, tolerate local-only compatibility fields such as `local_address`, `local_port`, `local_udp_address`, and `local_udp_port` in shared config files and ignore them
- reject unrelated advanced features rather than silently ignoring them

## 4.3 CLI compatibility

MVP should preserve the operator concepts, not the full upstream CLI.

Must-have CLI concepts:

- config file path
- server bind / local bind
- server remote address
- method
- password
- mode
- timeout
- UDP bind/associate override

Intentional divergence:

- no full flag parity
- no attempt to preserve every alias, environment variable, or utility binary

## 4.4 Plugin compatibility

No plugin compatibility in MVP.

Reasoning:

- plugins are not required for Shadowsocks wire compatibility
- SIP003 explicitly only forwards TCP traffic, not UDP
- subprocess lifecycle, environment wiring, and failure behavior increase the trusted operational surface significantly

## 4.5 Test vector compatibility

Parity must matter here:

- classic key derivation
- salt generation constraints
- TCP and UDP packet/frame encoding
- known successful interop against Rust implementations

## 4.6 Operational behavior compatibility

Required behavioral compatibility in MVP:

- `sslocal` SOCKS5 `UDP ASSOCIATE` keeps the TCP control connection alive
- UDP packets with `FRAG != 0` are dropped
- unsupported config fails loudly
- TCP replay protection for classic AEAD is enabled on the server side
- UDP association state expires and is cleaned up

Intentional divergence:

- no load balancing
- no service wrappers
- no ACL
- no plugin subprocess management
- no platform-specific operational knobs outside Linux-first needs

## 4.7 Platform behavior compatibility

Target platform in MVP:

- Linux first

Portability posture:

- do not hard-code Linux assumptions into core, crypto, or wire layers
- isolate OS-specific socket operations inside `net/`

Intentional divergence:

- no Windows service
- no macOS launchd support
- no BSD-specific redir behavior

# 5. Proposed Zig architecture

## 5.1 Top-level structure

Planned Zig library/application layout:

- `core/`
- `config/`
- `crypto/`
- `security/`
- `wire/`
- `frontend/`
- `net/`
- `app/`
- `cli/`
- `test/`

## 5.2 Layer descriptions

### `core/`

Purpose:

- fundamental types used across the project

Contents:

- `address.zig`
- `mode.zig`
- `buffer.zig`
- `errors.zig`
- `constants.zig`

Public API:

- `Address`
- `Endpoint`
- `Mode`
- shared error sets

Likely Zig types:

- tagged unions for address forms
- small plain structs for ports and endpoints

Ownership:

- caller-owned buffers and slices
- avoid hidden heap allocation where possible

### `config/`

Purpose:

- parse external config into a smaller normalized runtime model

Contents:

- `raw.zig`
- `runtime.zig`
- `json5_compat.zig`
- `validate.zig`

Public API:

- `loadFromFile(allocator, path) !RuntimeConfig`
- `loadFromSlice(allocator, bytes) !RuntimeConfig`

Design call:

- keep `raw` parsing separate from `runtime` config so unsupported fields can be rejected cleanly
- accept JSON5-style comments/trailing commas via a lightweight compatibility preprocessor, then feed strict JSON into Zig stdlib parsing

Ownership:

- runtime config owns copied strings
- app layer owns the runtime config for process lifetime

### `crypto/`

Purpose:

- cipher selection and authenticated encryption

Contents:

- `methods.zig`
- `kdf.zig`
- `aead.zig`
- `nonce.zig`

Public API:

- `Method`
- `deriveKeyClassic(...)`
- `encryptTcpChunk(...)`
- `decryptTcpChunk(...)`
- `encryptUdpPacket(...)`
- `decryptUdpPacket(...)`

Dependencies:

- Zig `0.16.0` stdlib only

Planned primitives:

- `std.crypto.aead.aes_gcm.Aes128Gcm`
- `std.crypto.aead.aes_gcm.Aes256Gcm`
- `std.crypto.aead.chacha_poly.ChaCha20Poly1305`
- `std.crypto.md5`
- `std.crypto.random`

Ownership:

- cipher contexts are stack-local or connection-local
- zeroize sensitive buffers after use where practical

### `security/`

Purpose:

- security policy and replay-sensitive logic not hidden inside crypto wrappers

Contents:

- `replay.zig`
- `zeroize.zig`
- `policy.zig`

Public API:

- replay filter structs
- helper routines for constant-time comparisons and secure clearing

Design call:

- TCP AEAD replay protection is always enabled in MVP
- UDP replay filtering is deferred unless required by the selected protocol variant

### `wire/`

Purpose:

- encode/decode Shadowsocks payloads and SOCKS address forms without owning sockets

Contents:

- `socks_addr.zig`
- `ss_tcp.zig`
- `ss_udp.zig`

Public API:

- read/write functions operating on caller-provided buffers

Ownership:

- pure slice-based parsing where possible

### `frontend/`

Purpose:

- local application protocols layered above the Shadowsocks wire protocol

Contents:

- `socks5/handshake.zig`
- `socks5/tcp_connect.zig`
- `socks5/udp_associate.zig`

Public API:

- `readClientGreeting(...)`
- `handleConnect(...)`
- `handleUdpAssociate(...)`

Design call:

- frontend parsing stays outside `app/local` orchestration so it can be unit-tested in isolation

### `net/`

Purpose:

- OS-facing sockets, resolution, and socket options

Contents:

- `tcp.zig`
- `udp.zig`
- `dns.zig`
- `socket_opts.zig`

Public API:

- listener/connect helpers
- UDP send/recv wrappers
- resolver abstraction

Design call:

- MVP resolver implementation is system DNS only
- no pluggable DNS backends in MVP

### `app/`

Purpose:

- compose the lower layers into runnable services

Contents:

- `local/service.zig`
- `local/tcp_session.zig`
- `local/udp_assoc.zig`
- `server/service.zig`
- `server/tcp_session.zig`
- `server/udp_assoc.zig`

Public API:

- `runLocal(...)`
- `runServer(...)`

Ownership:

- app context owns config and shared state
- per-connection allocators own session buffers
- UDP association map owns session state and expiry bookkeeping

### `cli/`

Purpose:

- thin command dispatch and diagnostics

Contents:

- `args.zig`
- `diag.zig`
- `sslocal_main.zig`
- `ssserver_main.zig`

Public API:

- internal only, binary entrypoints

### `test/`

Purpose:

- unit, golden, integration, and Rust interop validation

Contents:

- `unit/`
- `golden/`
- `integration/`
- `interop/`

## 5.3 Memory ownership model

Rules:

- config strings and paths are owned by the runtime config object
- parsers do not allocate unless a field truly needs ownership
- per-connection buffers use a connection-local allocator
- long-lived shared structures use a process allocator owned by the service
- avoid shared mutable heap state across TCP sessions except narrow service registries such as UDP association tables

## 5.4 Concurrency model

MVP recommendation:

- no Zig async runtime dependency
- blocking sockets
- explicit threads

Rationale:

- simpler debugging
- obvious lifetime boundaries
- easier deterministic cleanup
- avoids reproducing Tokio-centric architecture too early

Known tradeoff:

- thread-per-session is not the final scalability ceiling we want, but it is acceptable for MVP

## 5.5 Error propagation strategy

Rules:

- use layer-specific Zig error sets
- convert to operator-facing diagnostics only in `cli/`
- malformed packet, auth failure, unsupported config, and replay rejection should remain distinguishable internally

# 6. Recommended MVP scope

## 6.1 Binaries and modes

Ship exactly two binaries:

- `sslocal`
- `ssserver`

`sslocal` MVP behavior:

- SOCKS5 only
- supports `CONNECT`
- supports `UDP ASSOCIATE`
- supports `tcp_only`
- supports `tcp_and_udp`
- rejects `udp_only`
- no SOCKS5 username/password auth

`ssserver` MVP behavior:

- classic Shadowsocks relay
- supports `tcp_only`
- supports `tcp_and_udp`

## 6.2 Cipher support

Required ciphers:

- `aes-128-gcm`
- `aes-256-gcm`
- `chacha20-ietf-poly1305`

Explicitly excluded:

- stream ciphers
- non-standard extra AEAD variants
- AEAD-2022
- `none`

## 6.3 Config support

MVP config compatibility target:

- common single-server config only
- JSON5-style comments/trailing commas accepted
- unsupported keys rejected loudly

Supported fields:

- `server`
- `server_port`
- `password`
- `method`
- `protocol`
- `mode`
- `timeout`
- `local_address`
- `local_port`
- `local_udp_address`
- `local_udp_port`
- `udp_timeout`
- `udp_max_associations`
- `no_delay`
- `keep_alive`

## 6.4 CLI support

Recommended MVP CLI flags:

- `-c`, `--config`
- `-s`, `--server-addr`
- `-b`, `--bind-addr`
- `-m`, `--method`
- `-k`, `--password`
- `--mode`
- `--timeout`
- `--udp-bind-addr`
- `--udp-associate-addr`

Explicitly deferred from CLI MVP:

- `--server-url`
- `ssurl`-style SIP002 encode/decode utilities

## 6.5 Required runtime semantics

TCP:

- SOCKS5 client connects to `sslocal`
- `sslocal` validates handshake and target
- `sslocal` opens one encrypted Shadowsocks TCP session to `ssserver`
- `ssserver` decrypts, connects to target, and pumps bytes both directions

UDP:

- SOCKS5 client performs `UDP ASSOCIATE`
- `sslocal` returns configured or derived UDP associate address
- TCP control connection remains open
- local UDP associations are keyed by full client source endpoint
- UDP packets with `FRAG != 0` are dropped
- local UDP associations expire on inactivity
- local UDP association count can be bounded by `udp_max_associations`
- `ssserver` relays UDP to the target and back

Security:

- TCP AEAD replay protection always enabled on server side
- sensitive material zeroized where practical
- unsupported config features fail fast

Recommended default behavior:

- if `mode` is omitted, default to `tcp_only`
- if `protocol` is omitted for `sslocal`, default to `socks`
- accept only `protocol = "socks"` in MVP and reject other protocol strings
- if `local_port` is provided and `local_address` is omitted, default bind to `127.0.0.1` in MVP
- operators who want IPv6 local bind in MVP must set `local_address` explicitly
- if `ssserver` is started from a shared config file containing local-only keys, parse and ignore those keys rather than rejecting the whole file

# 7. Deferred features

## 7.1 First post-MVP candidates

- AEAD-2022
- multi-server balancing
- SIP002 `--server-url` import and `ssurl`
- improved operational diagnostics and counters

## 7.2 Later parity expansion

- ACL
- outbound proxy chaining
- HTTP local
- SOCKS4/4a local
- tunnel local
- manager API
- service wrappers

## 7.3 Likely much later

- DNS relay
- redir
- TUN
- fake DNS
- online config

## 7.4 Maybe never

- deprecated stream ciphers
- plaintext `none`

Rationale:

- both are undesirable defaults
- they increase compatibility burden without improving the security posture of a new Zig implementation

# 8. Main technical risks

## 8.1 UDP association semantics

Risk:

- the biggest source of subtle correctness bugs

Failure modes:

- wrong endpoint mapping
- broken return path
- stale associations
- control-connection lifetime mismatch

Mitigation:

- dedicated UDP association modules
- integration tests for associate lifetime and expiry
- Rust interop tests in both directions

## 8.2 Classic key derivation compatibility

Risk:

- easy to “modernize” incorrectly and break interop

Mitigation:

- lock vectors early
- keep derivation code isolated
- compare against Rust outputs and golden fixtures

## 8.3 Replay handling

Risk:

- replay behavior is security-sensitive and not identical across every path upstream

Mitigation:

- explicit `security/` layer
- always-on TCP replay checks in MVP
- dedicated negative tests for replayed salt/nonces

## 8.4 Config migration ambiguity

Risk:

- upstream accepts a much broader config surface, and it also accepts JSON5-style syntax

Mitigation:

- narrow raw config schema
- clear unsupported-key diagnostics
- tests for rejection paths

## 8.5 Performance and scaling

Risk:

- thread-per-session will not be the long-term scaling story

Mitigation:

- keep transport orchestration out of crypto and wire layers
- treat runtime model as replaceable

## 8.6 Portability creep

Risk:

- service wrappers and syscall-heavy features can distort the core design too early

Mitigation:

- isolate OS-specific code in `net/`
- keep MVP Linux-first

# 9. Validation and interop plan

## 9.1 Unit tests

- address codec for IPv4, IPv6, domain names
- SOCKS5 greeting/request/response parsing
- SOCKS5 UDP associate header parsing
- classic KDF vectors
- AEAD encrypt/decrypt round trips
- replay filter behavior
- config acceptance and rejection paths

## 9.2 Golden and boundary tests

- fixed derived-key vectors
- fixed TCP encrypted frame vectors
- fixed UDP encrypted packet vectors
- malformed packet cases
- short salt/tag/address cases
- max packet boundary tests for TCP
- oversized UDP payload handling policy tests
- `FRAG != 0` drop tests

## 9.3 Integration tests

Local deterministic fixtures only:

- local TCP echo
- local HTTP responder
- local UDP echo

Scenarios:

- Zig `sslocal` -> Zig `ssserver` TCP
- Zig `sslocal` -> Zig `ssserver` UDP
- `UDP ASSOCIATE` lifetime tied to TCP control connection
- association expiry and recreation
- unexpected source endpoint rejected

## 9.4 Rust interop tests

Required matrix:

- Zig `sslocal` <-> Rust `ssserver`
- Rust `sslocal` <-> Zig `ssserver`
- each supported classic AEAD cipher
- TCP and UDP for IPv4, IPv6, and domain-name targets where environment permits

Negative interop:

- wrong password
- wrong method
- replayed TCP salt
- malformed SOCKS5 request
- unsupported config

## 9.5 Comparison method

Compare Zig and Rust using:

- same config values
- same method/password
- same target fixtures
- same payloads
- same expected success/failure behavior

Acceptance rule:

- Zig is acceptable when observable behavior matches the Rust implementation or intentionally documented divergence

## 9.6 CI strategy

- no internet-dependent tests
- local fixtures only
- keep interop harness deterministic
- separate fast unit jobs from slower cross-process interop jobs

# 10. Phased roadmap

## M0: Audit and scope freeze

Deliverables:

- repository audit
- compatibility contract
- architecture decision
- approved design spec

Dependencies:

- none

Risks:

- accidental parity sprawl

Exit criteria:

- scope explicitly frozen for MVP

## M1: Project scaffold, core model, and CLI skeleton

Deliverables:

- `build.zig`
- `build.zig.zon`
- directory skeleton
- `core/`
- `config/`
- `cli/` shell entrypoints

Dependencies:

- M0

Risks:

- config boundary not staying narrow

Exit criteria:

- binaries compile
- config loads into normalized runtime model

## M2: Crypto layer

Deliverables:

- method enum and selection
- classic KDF
- AEAD wrappers for supported ciphers
- crypto vectors

Dependencies:

- M1

Risks:

- KDF mismatch
- subtle nonce misuse

Exit criteria:

- vector tests pass

## M3: TCP local/server happy path

Deliverables:

- SOCKS5 CONNECT frontend
- Shadowsocks TCP client/server path
- bidirectional copy loop

Dependencies:

- M2

Risks:

- framing bugs
- cleanup bugs

Exit criteria:

- Zig local/server TCP integration passes
- basic Rust interop for TCP passes

## M4: UDP relay

Deliverables:

- SOCKS5 UDP ASSOCIATE frontend
- local UDP association management
- server UDP relay
- expiry cleanup

Dependencies:

- M2
- M3 for shared service plumbing

Risks:

- source endpoint mapping
- control connection lifetime semantics

Exit criteria:

- Zig local/server UDP integration passes
- `FRAG != 0` handling tested

## M5: Interop stabilization

Deliverables:

- Rust interop harness
- negative test coverage
- config rejection tests

Dependencies:

- M3
- M4

Risks:

- hidden divergence from Rust behavior

Exit criteria:

- supported TCP and UDP interop matrix passes

## M6: Hardening and performance tuning

Deliverables:

- allocator review
- buffer sizing review
- error-path cleanup review
- basic performance measurements

Dependencies:

- M5

Risks:

- fixing performance in ways that break clarity

Exit criteria:

- memory/resource behavior acceptable under repeat test load

## M7: Optional advanced features

Deliverables:

- AEAD-2022
- optional multi-server support

Dependencies:

- M5

Risks:

- session semantics complexity

Exit criteria:

- feature-specific vectors and interop pass

## M8: Parity expansion

Deliverables:

- selected deferred features based on real demand

Dependencies:

- M6
- optionally M7

Risks:

- importing upstream complexity without preserving clean boundaries

Exit criteria:

- each added feature has a dedicated compatibility contract and tests

# 11. Initial Zig project skeleton

This section describes the intended MVP scaffold. It is the structure to create after the design review gate, not an instruction to port the whole repository at once.

## 11.1 Planned file tree

```text
build.zig
build.zig.zon
src/
  root.zig
  core/
    address.zig
    mode.zig
    buffer.zig
    errors.zig
    constants.zig
  config/
    raw.zig
    runtime.zig
    json5_compat.zig
    validate.zig
  crypto/
    methods.zig
    kdf.zig
    aead.zig
    nonce.zig
  security/
    replay.zig
    zeroize.zig
    policy.zig
  wire/
    socks_addr.zig
    ss_tcp.zig
    ss_udp.zig
  frontend/
    socks5/
      handshake.zig
      tcp_connect.zig
      udp_associate.zig
  net/
    tcp.zig
    udp.zig
    dns.zig
    socket_opts.zig
  app/
    local/
      service.zig
      tcp_session.zig
      udp_assoc.zig
    server/
      service.zig
      tcp_session.zig
      udp_assoc.zig
  cli/
    args.zig
    diag.zig
    sslocal_main.zig
    ssserver_main.zig
test/
  unit/
  golden/
  integration/
  interop/
```

## 11.2 Planned build targets

- `zig build sslocal`
- `zig build ssserver`
- `zig build test`
- `zig build interop`
- `zig build check`

## 11.3 Planned scaffold rules

- `src/root.zig` re-exports stable public library surface only
- binaries live as thin wrappers around `app/` and `cli/`
- every placeholder file should include a roadmap marker such as `TODO(M2)` or `TODO(M4)`
- no feature modules beyond MVP in the initial scaffold

# 12. Open questions that must be resolved before implementation

These are narrow execution questions, not scope questions.

## 12.1 JSON5 compatibility depth

Recommendation:

- MVP should support comments and trailing commas only
- do not attempt full JSON5 number/identifier semantics unless required by real configs

## 12.2 CLI naming fidelity

Recommendation:

- preserve common upstream flag names where they map cleanly
- do not preserve every alias or environment-variable convention

Additional recommendation:

- defer `--server-url` and `ssurl` until after basic config-file and direct-flag workflows are stable

## 12.3 UDP client binding rule

Recommendation:

- key local UDP associations by full client source endpoint, not just source IP
- this is stricter and aligns better with observed upstream behavior

## 12.4 Domain resolution policy in MVP

Recommendation:

- use system resolver only
- perform resolution at the same place in the flow that the Rust behavior implies for the chosen operation
- defer custom DNS backends and rule-driven resolver behavior

## 12.5 Shared-config compatibility for `ssserver`

Recommendation:

- accept common shared config files that include local-only keys
- ignore those local-only keys on `ssserver`
- reject advanced unsupported features such as plugins, ACL, outbound proxies, and online config

## 12.6 Omitted local bind defaults

Recommendation:

- if `local_port` is configured without `local_address`, default to `127.0.0.1`
- do not implement `ipv6_first` in MVP
- require explicit `local_address = "::1"` or another IPv6 bind if the operator wants IPv6 locally

## 12.7 Git/commit handling for this checkout

Observed workspace state:

- this checkout is inside a Git work tree but has no commits yet, and all upstream files are currently untracked

Recommendation:

- avoid creating a misleading initial commit that captures only the design doc
- create the scaffold and any commits only after the user confirms how they want history handled in this checkout
