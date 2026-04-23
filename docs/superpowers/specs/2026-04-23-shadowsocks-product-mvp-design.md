# Shadowsocks Zig Product MVP Design

## 1. Executive Summary

This design updates the Zig rewrite target from a narrow protocol MVP to a product-grade replacement MVP for common `shadowsocks-rust` usage.

The MVP ships two Zig binaries:

- `sslocal`
- `ssserver`

The product promise is Linux and Windows support. Linux and Windows builds must pass the release acceptance bar, produce downloadable artifacts, and interoperate with `shadowsocks-rust` for supported classic AEAD TCP and UDP paths. macOS can remain a best-effort artifact later, but it does not define MVP success.

The MVP supports:

- classic AEAD methods: `aes-128-gcm`, `aes-256-gcm`, `chacha20-ietf-poly1305`
- `sslocal` SOCKS5 `CONNECT`
- `sslocal` SOCKS5 `UDP ASSOCIATE`
- `ssserver` TCP and UDP relay
- common single-server config files with JSON5-style comments and trailing commas
- common CLI overrides
- SIP002 `ss://` URL parsing/import
- explicit unsupported-feature diagnostics
- Linux Docker packaging for common server deployments
- diagnostics tooling for CI, development, and operator troubleshooting

The MVP does not include full upstream feature parity. It intentionally defers manager mode, plugins, ACL, HTTP local, tunnel mode, redir, TUN, DNS relay, fake DNS, service wrappers, multi-server balancing, deprecated stream ciphers, and AEAD-2022.

## 2. Product Scope

The target is a usable replacement for ordinary Shadowsocks deployments, not a complete port of every Rust feature.

### 2.1 In Scope

- Native `sslocal` and `ssserver` binaries for Linux and Windows.
- Classic AEAD TCP and UDP wire compatibility.
- SOCKS5 local frontend with no-auth `CONNECT` and `UDP ASSOCIATE`.
- Single-server configuration compatible with common `shadowsocks-rust` config files.
- JSON5-style config tolerance for comments and trailing commas.
- CLI flags for config file path, bind addresses, remote server address, method, password, mode, timeout, UDP bind, and SIP002 import.
- SIP002 `ss://` URL parser that feeds the normalized runtime config model.
- Clear diagnostics for unsupported config keys, unsupported CLI values, malformed inputs, bind failures, connection failures, replay detection, and UDP association behavior.
- Linux Docker image build and smoke test.
- Linux and Windows CI validation and release artifacts.
- Rust interop tests for supported methods and TCP/UDP flows.

### 2.2 Deferred

- AEAD-2022.
- Manager API and manager binary.
- SIP003 plugins.
- ACL.
- HTTP local.
- SOCKS4/4a.
- Tunnel local.
- Redir.
- TUN.
- DNS relay, fake DNS, and custom DNS resolver backends.
- Online config.
- Multi-server balancing.
- Service wrappers and platform service installers.
- Deprecated stream ciphers.
- Plaintext `none`.

## 3. Compatibility Contract

### 3.1 Wire Protocol

The MVP must preserve wire compatibility for:

- classic Shadowsocks AEAD TCP framing
- classic Shadowsocks AEAD UDP packet format
- IPv4, IPv6, and domain address encoding
- SOCKS5 no-auth greeting and request handling
- SOCKS5 `CONNECT`
- SOCKS5 `UDP ASSOCIATE`

Unsupported protocol variants must fail explicitly rather than falling through to undefined behavior.

### 3.2 Config

The config layer supports common single-server fields:

- `server`
- `server_port`
- `local_address`
- `local_port`
- `local_udp_address`
- `local_udp_port`
- `password`
- `method`
- `mode`
- `timeout`
- `udp_timeout`
- `udp_max_associations`
- `no_delay`
- `keep_alive`

For `ssserver`, local-only fields from shared config files are tolerated and ignored. Unsupported advanced fields are rejected with diagnostics that name the field.

Rejected MVP fields include:

- `servers`
- `locals`
- `server_url` when used as a config-file feature outside the explicit SIP002 import path
- `plugin`, `plugin_opts`, `plugin_args`, `plugin_mode`
- ACL fields
- HTTP auth fields
- online config fields
- redir, TUN, fake DNS, and outbound proxy fields
- socket and platform knobs not implemented in the MVP

### 3.3 CLI

The CLI preserves common operational concepts, not full flag parity.

Required flags:

- `-c`, `--config`
- `-s`, `--server-addr`
- `-b`, `--bind-addr`
- `-m`, `--method`
- `-k`, `--password`
- `--mode`
- `--timeout`
- `--udp-bind-addr`
- `--udp-associate-addr`
- `--ss-url`
- `--verbose` or `--log-level`

Config files, SIP002 URLs, and CLI overrides merge into one normalized runtime config. CLI overrides win over file and URL input. The merge rules must be tested.

### 3.4 Rust Interop

The acceptance matrix includes:

- Zig `sslocal` to Zig `ssserver`
- Zig `sslocal` to Rust `ssserver`
- Rust `sslocal` to Zig `ssserver`
- TCP and UDP
- all supported classic AEAD methods
- wrong password and wrong method negative cases

Observable behavior must match Rust for supported features, except for explicitly documented MVP divergences.

## 4. Architecture

The architecture keeps the existing Zig-first module boundaries and expands the product surface around them.

### 4.1 `core`

Owns fundamental shared types:

- addresses and endpoints
- modes
- constants
- shared error sets

`core` must not depend on sockets, config parsing, or crypto implementation details.

### 4.2 `config`

Owns external config parsing, JSON5-style normalization, raw schema handling, validation, defaulting, and runtime config construction.

Responsibilities:

- parse file config
- accept comments and trailing commas
- reject unsupported fields by name
- tolerate local-only shared-config fields for `ssserver`
- normalize into role-specific runtime config
- expose merge helpers for CLI and SIP002 input

### 4.3 `crypto`

Owns supported classic AEAD methods and key material handling:

- method parsing and sizes
- EVP_BytesToKey-compatible master key derivation
- HKDF-SHA1 session subkey derivation
- random salt generation
- nonce counters
- AEAD seal/open wrappers
- zeroization hooks where practical

`crypto` does not own sockets or service orchestration.

### 4.4 `security`

Owns policy that should remain visible rather than hidden inside crypto wrappers:

- TCP salt replay detection
- secure clearing helpers
- future security-policy switches if needed

TCP replay protection is always enabled on the server side in the MVP.

### 4.5 `wire`

Owns protocol codecs that are testable without live sockets:

- Shadowsocks/SOCKS address encoding
- classic AEAD TCP chunk framing
- classic AEAD UDP packet encoding
- SIP002 `ss://` URL parsing

SIP002 parsing produces structured config fragments and does not create a separate startup path.

### 4.6 `frontend/socks5`

Owns local SOCKS5 behavior:

- no-auth greeting
- `CONNECT` request parsing and replies
- `UDP ASSOCIATE` request parsing and replies
- SOCKS5 UDP header parsing
- `FRAG != 0` rejection/drop behavior

### 4.7 `net`

Owns OS-facing socket behavior and portability:

- TCP bind/listen/connect helpers
- UDP bind/send/receive helpers
- socket options for Linux and Windows
- system DNS resolver wrapper

Linux and Windows differences stay here so protocol, config, and crypto remain portable.

### 4.8 `app/local` and `app/server`

Own service orchestration:

- listener setup
- explicit threads
- session lifetime
- TCP relay pumps
- UDP association maps
- UDP expiry
- service shutdown behavior

The MVP uses blocking sockets and explicit threads. This favors a small, debuggable product over an early event-loop rewrite.

### 4.9 `cli`

Owns binary entrypoints:

- argument parsing
- config loading
- SIP002 import
- merge/default behavior
- diagnostics rendering
- process exit codes

Lower layers return typed errors. `cli/diag` converts those errors into operator-facing messages.

### 4.10 `ops`

Owns release and deployment assets:

- GitHub Actions workflows
- Linux and Windows archive packaging
- checksums
- Dockerfile and container smoke test
- README deployment examples

Docker is packaging, not a runtime architecture layer.

## 5. Data Flow

### 5.1 TCP

1. A client connects to `sslocal`.
2. `sslocal` performs SOCKS5 no-auth negotiation.
3. The client sends a SOCKS5 `CONNECT` request.
4. `sslocal` opens an encrypted Shadowsocks TCP session to `ssserver`.
5. The first encrypted Shadowsocks payload carries the target address.
6. `ssserver` decrypts the target address, connects to the target, and relays framed AEAD chunks in both directions.
7. Either side closing the stream tears down the session and releases resources.

### 5.2 UDP

1. A client creates a SOCKS5 `UDP ASSOCIATE` control connection.
2. `sslocal` replies with the UDP associate endpoint and keeps the TCP control connection alive.
3. UDP client datagrams are keyed by full client source endpoint.
4. `sslocal` drops SOCKS5 UDP packets with `FRAG != 0`.
5. `sslocal` wraps valid UDP payloads as Shadowsocks UDP packets and sends them to `ssserver`.
6. `ssserver` decrypts, forwards to the target, encrypts responses, and sends them back.
7. `sslocal` unwraps responses into SOCKS5 UDP packets and sends them to the original client endpoint.
8. Associations expire on inactivity and respect `udp_max_associations`.

### 5.3 SIP002 URLs

SIP002 parsing extracts method, password, server host, server port, plugin-free query values that are supported by the MVP, and optional display metadata. Parsed values feed the same runtime config model as file config and CLI flags.

Unsupported SIP002 features, such as plugin options, are rejected with named diagnostics.

## 6. Runtime Behavior

Defaults:

- omitted `mode` defaults to `tcp_only`
- `sslocal` supports `tcp_only` and `tcp_and_udp`
- `ssserver` supports `tcp_only` and `tcp_and_udp`
- omitted local address with a local port defaults to `127.0.0.1`
- IPv6 local binding requires explicit config or CLI input
- system DNS is the only resolver in the MVP

Security behavior:

- TCP replay protection is enabled for `ssserver`
- wrong password and wrong method fail without plaintext leakage
- sensitive buffers are zeroized where practical
- unsupported ciphers fail at config/CLI parsing time

UDP behavior:

- `FRAG != 0` packets are dropped
- source endpoint mismatch is rejected
- association creation is bounded by `udp_max_associations`
- stale associations are reaped by inactivity timeout

## 7. Docker And Packaging

The MVP adds Docker as a Linux deployment target.

Docker requirements:

- build a small Linux `ssserver` image
- optionally build an `sslocal` image from the same binary bundle
- mount config at `/etc/shadowsocks/config.json`
- expose TCP and UDP server ports
- run as a normal foreground process
- log startup and runtime diagnostics to stderr/stdout
- include a CI container smoke test with the example config

Native release requirements:

- Linux x86_64 archive containing `sslocal`, `ssserver`, README, and checksums
- Windows x86_64 archive containing `sslocal.exe`, `ssserver.exe`, README, and checksums
- archive verification in CI
- release workflow documentation

The current repository already has native archive packaging through GitHub Actions and `scripts/ci/package-release.ps1`. The product MVP should align that surface with the Linux + Windows release promise.

## 8. Diagnostics

### 8.1 Operator Diagnostics

Runtime diagnostics distinguish:

- config parse errors
- unsupported config fields
- unsupported CLI values
- unsupported SIP002 values
- SOCKS5 protocol errors
- Shadowsocks authentication/decryption failures
- replay detection
- DNS and target connect failures
- bind/listen failures
- UDP association limit, expiry, source mismatch, and fragmented-packet drops

`--verbose` or `--log-level debug` enables connection lifecycle and UDP association messages without logging decrypted payload contents.

### 8.2 Development Diagnostics

Add a diagnostics build lane:

- `zig build diagnose`
- `zig build fuzz`

`zig build diagnose` should run formatting, package tests, integration tests, config rejection tests, CLI tests, and interop smoke checks where configured.

`zig build fuzz` should focus on parser and codec surfaces:

- config JSON5 normalization
- SIP002 parsing
- SOCKS5 request parsing
- SOCKS5 UDP headers
- Shadowsocks address codecs
- TCP frame decoding
- UDP packet decoding

Linux CI should include selected diagnostics runs under tools such as Valgrind and ThreadSanitizer where practical. These tools are development and CI dependencies, not runtime dependencies.

### 8.3 Network Debugging Recipes

Documentation should include concise troubleshooting recipes for:

- checking process startup
- confirming TCP and UDP ports are bound
- running native binaries with debug logs
- running the Docker image and inspecting logs
- capturing encrypted TCP/UDP traffic with `tcpdump` or Wireshark for reachability debugging

The documentation must state that packet captures cannot inspect encrypted Shadowsocks payload contents.

## 9. Testing And Acceptance

### 9.1 Unit Tests

Required unit coverage:

- mode parsing
- config defaults and unsupported-field rejection
- JSON5-style comment and trailing-comma handling
- SIP002 parsing
- address codec round trips
- SOCKS5 greeting, `CONNECT`, and `UDP ASSOCIATE`
- classic KDF vectors
- HKDF-SHA1 subkey vectors
- AEAD seal/open behavior
- TCP frame encode/decode
- UDP packet encode/decode
- replay detection
- UDP association bookkeeping

### 9.2 Integration Tests

Required integration coverage:

- Zig `sslocal` to Zig `ssserver` TCP echo
- Zig `sslocal` to Zig `ssserver` UDP echo
- SOCKS5 `UDP ASSOCIATE` control-connection lifetime
- association expiry and recreation
- unexpected UDP source endpoint rejection
- CLI config loading and override precedence
- SIP002 import into runtime config

### 9.3 Rust Interop Tests

Required interop coverage:

- Zig `sslocal` to Rust `ssserver`
- Rust `sslocal` to Zig `ssserver`
- TCP and UDP
- `aes-128-gcm`
- `aes-256-gcm`
- `chacha20-ietf-poly1305`
- wrong password
- wrong method
- replayed TCP salt
- malformed SOCKS5 request

Interop tests may require environment variables pointing to Rust binaries. When those variables are missing, the failure must be obvious and actionable.

### 9.4 Packaging Tests

Required packaging checks:

- Linux release archive contains both binaries and metadata
- Windows release archive contains both binaries and metadata
- checksums are generated
- archives can be listed and verified
- Docker image builds
- Docker container starts with the example config
- container exposes the documented TCP and UDP ports

### 9.5 Acceptance Criteria

The MVP is accepted when:

- `zig fmt --check .` passes
- `zig build check` passes
- `zig build test` passes
- `zig build diagnose` passes on supported CI lanes
- Linux and Windows CI produce validated artifacts
- Docker image build and smoke test pass
- Rust interop matrix passes for all supported methods over TCP and UDP
- README documents supported scope, Docker usage, native usage, diagnostics, and non-goals
- unsupported upstream features fail with explicit diagnostics

## 10. Risks And Mitigations

### 10.1 UDP Association Semantics

Risk: endpoint mapping and control-connection lifetime are easy to get subtly wrong.

Mitigation: keep UDP association management isolated in `app/local/udp_assoc.zig`, test source endpoint keys, expiry, association limits, and TCP control lifetime.

### 10.2 Crypto Compatibility

Risk: a small KDF, salt, nonce, or frame ordering mismatch breaks interop.

Mitigation: maintain golden vectors, Rust interop tests, negative tests, and isolated crypto/wire APIs.

### 10.3 Windows Socket Behavior

Risk: Linux-oriented socket assumptions leak into protocol code.

Mitigation: isolate OS behavior in `net`, keep CI on Windows, and add Windows-specific startup and bind tests.

### 10.4 Scope Creep

Risk: full Rust parity pressure pulls in plugins, TUN, redir, manager, or AEAD-2022 before the MVP is stable.

Mitigation: reject deferred features explicitly, document non-goals, and require a separate design for each post-MVP feature.

### 10.5 Diagnostics Noise

Risk: debug logging exposes sensitive data or overwhelms users.

Mitigation: log lifecycle and error context, never decrypted payloads or passwords, and keep debug logging opt-in.

## 11. Implementation Sequence

The implementation plan should update the existing MVP plan rather than starting from scratch.

Recommended phases:

1. Align scope and build graph with product MVP targets.
2. Complete config, CLI merge rules, and SIP002 parsing.
3. Finish classic crypto and wire compatibility.
4. Finish SOCKS5 TCP and UDP frontend behavior.
5. Finish local/server TCP relay.
6. Finish local/server UDP relay and association cleanup.
7. Add Rust interop matrix and negative tests.
8. Add Linux + Windows packaging checks and checksums.
9. Add Dockerfile, example config path, and container smoke test.
10. Add `diagnose` and `fuzz` build steps.
11. Update README with supported scope, usage, Docker, diagnostics, and non-goals.

Implementation must stay inside this product MVP unless a later design explicitly changes scope.
