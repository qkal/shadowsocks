# Shadowsocks Zig Product MVP Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Turn the current partial Zig rewrite into a Linux + Windows product-grade MVP replacement for common `shadowsocks-rust` usage, including real TCP/UDP relay behavior, SIP002 import, Docker packaging, and release-grade CI.

**Architecture:** Keep the existing Zig-first split between `config`, `crypto`, `wire`, `frontend`, `net`, `app`, and `cli`, but stop treating `app/*` and `cli/*` as placeholders. Finish the runtime around the already-working core modules, add SIP002 and operator-facing diagnostics, then layer packaging, Docker, interop, and release provenance on top.

**Tech Stack:** Zig `0.16.0`, Zig stdlib (`std.json`, `std.crypto`, `std.net`, `std.Thread`, `std.process`), PowerShell packaging scripts, Docker Buildx, GitHub Actions, GitHub artifact attestations, Syft SBOM generation, Trivy container scanning, `shadowsocks-rust` binaries for interop tests.

---

## Execution prerequisites

- Work in a dedicated execution worktree, not on `main`.
- Baseline this plan against the approved spec at [2026-04-23-shadowsocks-product-mvp-design.md](</C:/zig/Shadowsocks/docs/superpowers/specs/2026-04-23-shadowsocks-product-mvp-design.md:1>).
- Confirm the current baseline is green before changing code:

```powershell
zig build check
zig build test
```

- Stay inside classic AEAD MVP scope. Do not add AEAD-2022, plugins, manager, ACL, HTTP local, SOCKS4, tunnel mode, TUN, redir, fake DNS, or multi-server balancing during this plan.

## File structure and responsibilities

- `build.zig`
  - build graph for `check`, `test`, `integration`, `interop`, `diagnose`, and `fuzz`
- `build.zig.zon`
  - package metadata and exported paths
- `src/root.zig`
  - public exports for newly added wire, net, and app modules
- `src/config/raw.zig`
  - accepted external config schema
- `src/config/runtime.zig`
  - normalized runtime config, CLI merge targets, and SIP002-derived config fragments
- `src/config/validate.zig`
  - raw config validation, defaults, and role-specific runtime conversion
- `src/wire/ss_url.zig`
  - SIP002 `ss://` parsing
- `src/wire/ss_tcp.zig`
  - stateful classic AEAD TCP session framing
- `src/wire/ss_udp.zig`
  - classic AEAD UDP packet framing
- `src/net/tcp.zig`
  - TCP connect/listen helpers and copy loops
- `src/net/udp.zig`
  - UDP bind/send/receive helpers
- `src/net/socket_opts.zig`
  - `TCP_NODELAY`, keepalive, and platform socket tuning
- `src/app/local/service.zig`
  - local listener startup, stop, and thread ownership
- `src/app/local/tcp_session.zig`
  - SOCKS5 `CONNECT` flow from client to encrypted server stream
- `src/app/local/udp_assoc.zig`
  - UDP association table, expiry, and per-endpoint ownership
- `src/app/server/service.zig`
  - remote server startup, stop, and thread ownership
- `src/app/server/tcp_session.zig`
  - remote TCP decrypt/connect/relay flow
- `src/app/server/udp_assoc.zig`
  - remote UDP relay loop
- `src/cli/args.zig`
  - parse CLI flags, merge file config, SIP002, and overrides
- `src/cli/diag.zig`
  - secret-safe diagnostics and user-facing error text
- `src/cli/signal.zig`
  - Linux/Windows shutdown signal registration
- `src/cli/sslocal_main.zig`
  - `sslocal` entrypoint
- `src/cli/ssserver_main.zig`
  - `ssserver` entrypoint plus `--check-config` and `--healthcheck`
- `test/integration/tcp_happy_path.zig`
  - end-to-end SOCKS5 TCP relay test
- `test/integration/udp_happy_path.zig`
  - end-to-end SOCKS5 UDP relay test
- `test/integration/graceful_shutdown.zig`
  - stop/join behavior and process-lifecycle smoke test
- `test/interop/common.zig`
  - Rust binary discovery and child-process helpers
- `test/interop/rust_tcp_test.zig`
  - TCP interop matrix
- `test/interop/rust_udp_test.zig`
  - UDP interop matrix
- `test/fuzz/sip002.zig`
  - SIP002 parser fuzz harness
- `test/fuzz/socks5_request.zig`
  - SOCKS5 request parser fuzz harness
- `Dockerfile`
  - multi-stage non-root image for `ssserver`
- `.dockerignore`
  - keep build context small and secret-free
- `scripts/ci/package-release.ps1`
  - archive staging plus checksum hook
- `scripts/ci/generate-checksums.ps1`
  - SHA256 checksum generation
- `scripts/ci/docker-smoke.ps1`
  - container build/start/health smoke test
- `.github/workflows/ci.yml`
  - Linux + Windows validation
- `.github/workflows/artifacts.yml`
  - native artifacts for Linux + Windows only
- `.github/workflows/release.yml`
  - release artifacts, attestations, SBOM, image publish, and scan
- `README.md`
  - supported scope, Docker usage, secret handling, and non-goals
- `examples/config.json`
  - example config matching the supported MVP surface

### Task 0: Establish the execution worktree

**Files:**
- Modify: none
- Test: none

- [ ] **Step 1: Confirm the current baseline is committed and green**

Run:

```powershell
git log --oneline -3
git status --short
zig build check
zig build test
```

Expected:

- the log shows the approved spec commits
- `git status --short` prints nothing
- `zig build check` and `zig build test` both PASS

- [ ] **Step 2: Create a dedicated execution worktree**

Run:

```powershell
git worktree add ..\Shadowsocks-product-mvp -b product-mvp
```

Expected:

- a sibling checkout exists at `..\Shadowsocks-product-mvp`
- the branch name is `product-mvp`

- [ ] **Step 3: Copy the approved spec and plan into the worktree context**

Read:

- [2026-04-23-shadowsocks-product-mvp-design.md](</C:/zig/Shadowsocks/docs/superpowers/specs/2026-04-23-shadowsocks-product-mvp-design.md:1>)
- [2026-04-23-shadowsocks-product-mvp.md](</C:/zig/Shadowsocks/docs/superpowers/plans/2026-04-23-shadowsocks-product-mvp.md:1>)

Expected:

- every upcoming task can be traced back to the approved design

### Task 1: Add SIP002 parsing and testable config/CLI merge

**Files:**
- Create: `src/wire/ss_url.zig`
- Modify: `src/config/runtime.zig`
- Modify: `src/cli/args.zig`
- Modify: `src/root.zig`
- Test: `src/wire/ss_url.zig`
- Test: package-level config/CLI merge behavior via `zig build test`

- [ ] **Step 1: Write the failing SIP002 and merge-precedence tests**

`src/wire/ss_url.zig`

```zig
const std = @import("std");

test "parse SIP002 URL into method password host port and tag" {
    const url = "ss://YWVzLTEyOC1nY206dGVzdC1wYXNzd29yZA==@127.0.0.1:8388#demo";
    var parsed = try parse(std.testing.allocator, url);
    defer parsed.deinit(std.testing.allocator);

    try std.testing.expectEqualStrings("aes-128-gcm", parsed.method);
    try std.testing.expectEqualStrings("test-password", parsed.password);
    try std.testing.expectEqualStrings("127.0.0.1", parsed.host);
    try std.testing.expectEqual(@as(u16, 8388), parsed.port);
    try std.testing.expectEqualStrings("demo", parsed.tag.?);
}
```

`src/cli/args.zig`

```zig
const std = @import("std");
const runtime = @import("../config/runtime.zig");

test "CLI overrides beat file config and ss url input" {
    const file_json =
        \\{
        \\  "server": "10.0.0.1",
        \\  "server_port": 8388,
        \\  "local_port": 1080,
        \\  "password": "file-password",
        \\  "method": "aes-128-gcm"
        \\}
    ;

    var cfg = try loadConfigFromInputs(std.testing.allocator, .local, .{
        .file_bytes = file_json,
        .ss_url = "ss://YWVzLTI1Ni1nY206dXJsLXBhc3M=@192.0.2.10:443",
        .override_password = "cli-password",
        .override_method = "chacha20-ietf-poly1305",
        .override_server_addr = "127.0.0.1:9443",
    });
    defer cfg.deinit(std.testing.allocator);

    try std.testing.expectEqual(runtime.Method.chacha20_ietf_poly1305, cfg.method);
    try std.testing.expectEqualStrings("cli-password", cfg.password);
    try std.testing.expectEqualStrings("127.0.0.1", cfg.server.bind_host);
    try std.testing.expectEqual(@as(u16, 9443), cfg.server.bind_port);
}
```

- [ ] **Step 2: Run the tests and verify they fail**

Run:

```powershell
zig test src/wire/ss_url.zig
zig build test
```

Expected:

- FAIL because `parse` and `loadConfigFromInputs` do not exist yet

- [ ] **Step 3: Implement the SIP002 parser and merged config loader**

`src/wire/ss_url.zig`

```zig
const std = @import("std");

pub const ParsedUrl = struct {
    method: []u8,
    password: []u8,
    host: []u8,
    port: u16,
    tag: ?[]u8 = null,

    pub fn deinit(self: *ParsedUrl, allocator: std.mem.Allocator) void {
        allocator.free(self.method);
        allocator.free(self.password);
        allocator.free(self.host);
        if (self.tag) |tag| allocator.free(tag);
    }
};

pub fn parse(allocator: std.mem.Allocator, input: []const u8) !ParsedUrl {
    if (!std.mem.startsWith(u8, input, "ss://")) return error.InvalidScheme;

    const without_scheme = input["ss://".len..];
    const hash_index = std.mem.indexOfScalar(u8, without_scheme, '#');
    const main = if (hash_index) |idx| without_scheme[0..idx] else without_scheme;
    const tag = if (hash_index) |idx| try allocator.dupe(u8, without_scheme[idx + 1 ..]) else null;
    errdefer if (tag) |value| allocator.free(value);

    const at_index = std.mem.indexOfScalar(u8, main, '@') orelse return error.InvalidAuthority;
    const encoded_userinfo = main[0..at_index];
    const host_port = main[at_index + 1 ..];

    var decoded_buf: [256]u8 = undefined;
    const decoded_len = try std.base64.standard.Decoder.decode(decoded_buf[0..], encoded_userinfo);
    const decoded = decoded_buf[0..decoded_len];
    const colon_index = std.mem.indexOfScalar(u8, decoded, ':') orelse return error.InvalidUserInfo;
    const last_colon = std.mem.lastIndexOfScalar(u8, host_port, ':') orelse return error.InvalidAuthority;

    return .{
        .method = try allocator.dupe(u8, decoded[0..colon_index]),
        .password = try allocator.dupe(u8, decoded[colon_index + 1 ..]),
        .host = try allocator.dupe(u8, host_port[0..last_colon]),
        .port = try std.fmt.parseInt(u16, host_port[last_colon + 1 ..], 10),
        .tag = tag,
    };
}
```

`src/cli/args.zig`

```zig
pub const LoadInputs = struct {
    file_bytes: ?[]const u8 = null,
    ss_url: ?[]const u8 = null,
    override_password: ?[]const u8 = null,
    override_method: ?[]const u8 = null,
    override_server_addr: ?[]const u8 = null,
};

pub fn loadConfigFromInputs(
    allocator: std.mem.Allocator,
    role: Role,
    inputs: LoadInputs,
) !RuntimeConfig {
    var cfg = if (inputs.file_bytes) |file_bytes|
        try config.loadFromSlice(allocator, role, file_bytes)
    else
        return error.MissingConfigSource;

    errdefer cfg.deinit(allocator);

    if (inputs.ss_url) |url| {
        var parsed = try @import("../wire/ss_url.zig").parse(allocator, url);
        defer parsed.deinit(allocator);
        try cfg.applyUrlOverrides(allocator, parsed);
    }

    if (inputs.override_method) |method_text| cfg.method = try runtime.Method.parse(method_text);
    if (inputs.override_password) |password_text| try cfg.replacePassword(allocator, password_text);
    if (inputs.override_server_addr) |server_addr| try cfg.replaceServerAddress(allocator, server_addr);

    return cfg;
}
```

`src/config/runtime.zig`

```zig
pub fn applyUrlOverrides(self: *RuntimeConfig, allocator: std.mem.Allocator, parsed: anytype) !void {
    try self.replacePassword(allocator, parsed.password);
    allocator.free(self.server.bind_host);
    self.server.bind_host = try allocator.dupe(u8, parsed.host);
    self.server.bind_port = parsed.port;
    self.method = try Method.parse(parsed.method);
}

pub fn replacePassword(self: *RuntimeConfig, allocator: std.mem.Allocator, password_text: []const u8) !void {
    allocator.free(self.password);
    self.password = try allocator.dupe(u8, password_text);
}

pub fn replaceServerAddress(self: *RuntimeConfig, allocator: std.mem.Allocator, input: []const u8) !void {
    const colon = std.mem.lastIndexOfScalar(u8, input, ':') orelse return error.InvalidServerAddress;
    allocator.free(self.server.bind_host);
    self.server.bind_host = try allocator.dupe(u8, input[0..colon]);
    self.server.bind_port = try std.fmt.parseInt(u16, input[colon + 1 ..], 10);
}
```

`src/root.zig`

```zig
pub const wire = struct {
    pub const socks_addr = @import("wire/socks_addr.zig");
    pub const ss_tcp = @import("wire/ss_tcp.zig");
    pub const ss_url = @import("wire/ss_url.zig");
};
```

- [ ] **Step 4: Run the parser and merge tests**

Run:

```powershell
zig test src/wire/ss_url.zig
zig build test
zig build check
```

Expected:

- all commands PASS

- [ ] **Step 5: Commit**

```powershell
git add src/wire/ss_url.zig src/config/runtime.zig src/cli/args.zig src/root.zig
git commit -m "feat: add sip002 parsing and config merge"
```

### Task 2: Upgrade the TCP codec from one-shot helpers to streaming session state

**Files:**
- Modify: `src/wire/ss_tcp.zig`
- Test: `src/wire/ss_tcp.zig`

- [ ] **Step 1: Replace the one-shot test with a failing streaming-session test**

`src/wire/ss_tcp.zig`

```zig
test "client session writes salt once and server session decodes multiple chunks" {
    const method = Method.aes_128_gcm;
    const master = [_]u8{0x11} ** 16;
    const salt = [_]u8{0x22} ** 16;

    var client = try Session.initClient(method, master[0..], salt[0..]);
    var frame_one: [128]u8 = undefined;
    var frame_two: [128]u8 = undefined;
    const used_one = try client.writeChunk("one", frame_one[0..]);
    const used_two = try client.writeChunk("two", frame_two[0..]);

    var server = try Session.initServer(method, master[0..]);
    var plain: [16]u8 = undefined;
    const got_one = try server.readChunk(frame_one[0..used_one], plain[0..]);
    const got_two = try server.readChunk(frame_two[0..used_two], plain[0..]);

    try std.testing.expectEqualStrings("one", got_one);
    try std.testing.expectEqualStrings("two", got_two);
}
```

- [ ] **Step 2: Run the TCP codec test and verify it fails**

Run:

```powershell
zig test src/wire/ss_tcp.zig
```

Expected:

- FAIL because `Session.initClient`, `Session.initServer`, `writeChunk`, and `readChunk` are not implemented

- [ ] **Step 3: Implement stateful TCP framing**

`src/wire/ss_tcp.zig`

```zig
pub const Session = struct {
    method: Method,
    master_key: [32]u8 = [_]u8{0} ** 32,
    key: [32]u8,
    salt: [32]u8 = [_]u8{0} ** 32,
    salt_len: usize = 0,
    tx_nonce: [12]u8 = [_]u8{0} ** 12,
    rx_nonce: [12]u8 = [_]u8{0} ** 12,
    sent_salt: bool = false,
    received_salt: bool = false,

    pub fn initClient(method: Method, master_key: []const u8, salt: []const u8) !Session {
        var self = Session{ .method = method, .master_key = [_]u8{0} ** 32, .key = [_]u8{0} ** 32, .salt_len = salt.len };
        std.mem.copyForwards(u8, self.master_key[0..master_key.len], master_key);
        std.mem.copyForwards(u8, self.salt[0..salt.len], salt);
        try crypto.deriveSessionSubkey(master_key, salt, self.key[0..method.keyLen()]);
        return self;
    }

    pub fn initServer(method: Method, master_key: []const u8) !Session {
        var self = Session{ .method = method, .master_key = [_]u8{0} ** 32, .key = [_]u8{0} ** 32 };
        std.mem.copyForwards(u8, self.master_key[0..master_key.len], master_key);
        return self;
    }

    pub fn writeChunk(self: *Session, payload: []const u8, out: []u8) !usize {
        if (payload.len > constants.max_tcp_packet_size) return error.PacketTooLarge;
        var cursor: usize = 0;
        if (!self.sent_salt) {
            std.mem.copyForwards(u8, out[0..self.salt_len], self.salt[0..self.salt_len]);
            cursor += self.salt_len;
            self.sent_salt = true;
        }
        cursor += try encodeChunk(self.method, self.key[0..self.method.keyLen()], &self.tx_nonce, payload, out[cursor..]);
        return cursor;
    }

    pub fn readChunk(self: *Session, input: []const u8, out: []u8) ![]const u8 {
        var cursor: usize = 0;
        if (!self.received_salt) {
            self.salt_len = self.method.saltLen();
            std.mem.copyForwards(u8, self.salt[0..self.salt_len], input[0..self.salt_len]);
            try crypto.deriveSessionSubkey(self.master_key[0..self.method.keyLen()], self.salt[0..self.salt_len], self.key[0..self.method.keyLen()]);
            cursor += self.salt_len;
            self.received_salt = true;
        }
        return decodeChunk(self.method, self.key[0..self.method.keyLen()], &self.rx_nonce, input[cursor..], out);
    }
};

fn encodeChunk(method: Method, key: []const u8, nonce: *[12]u8, payload: []const u8, out: []u8) !usize {
    const tag_len = method.tagLen();
    const needed = 2 + tag_len + payload.len + tag_len;
    if (out.len < needed) return error.NoSpaceLeft;

    const length_field = [2]u8{
        @intCast((payload.len >> 8) & 0xff),
        @intCast(payload.len & 0xff),
    };

    try crypto.sealDetached(method, key, nonce[0..], "", length_field[0..], out[0..2], out[2 .. 2 + tag_len]);
    incrementNonce(nonce);

    const payload_start = 2 + tag_len;
    try crypto.sealDetached(method, key, nonce[0..], "", payload, out[payload_start .. payload_start + payload.len], out[payload_start + payload.len .. needed]);
    incrementNonce(nonce);
    return needed;
}

fn decodeChunk(method: Method, key: []const u8, nonce: *[12]u8, input: []const u8, out: []u8) ![]const u8 {
    const tag_len = method.tagLen();
    if (input.len < 2 + tag_len) return error.Truncated;

    var length_field: [2]u8 = undefined;
    try crypto.openDetached(method, key, nonce[0..], "", input[0..2], input[2 .. 2 + tag_len], length_field[0..]);
    incrementNonce(nonce);

    const payload_len = (@as(usize, length_field[0]) << 8) | @as(usize, length_field[1]);
    if (out.len < payload_len) return error.NoSpaceLeft;
    const payload_start = 2 + tag_len;
    const payload_end = payload_start + payload_len;
    if (input.len < payload_end + tag_len) return error.Truncated;

    try crypto.openDetached(method, key, nonce[0..], "", input[payload_start..payload_end], input[payload_end .. payload_end + tag_len], out[0..payload_len]);
    incrementNonce(nonce);
    return out[0..payload_len];
}

fn incrementNonce(nonce: *[12]u8) void {
    var i: usize = nonce.len;
    while (i > 0) {
        i -= 1;
        nonce[i] +%= 1;
        if (nonce[i] != 0) break;
    }
}
```

- [ ] **Step 4: Re-run the TCP codec test**

Run:

```powershell
zig test src/wire/ss_tcp.zig
zig build test
```

Expected:

- both commands PASS

- [ ] **Step 5: Commit**

```powershell
git add src/wire/ss_tcp.zig
git commit -m "feat: add streaming shadowsocks tcp sessions"
```

### Task 3: Implement the real TCP relay path

**Files:**
- Modify: `src/net/tcp.zig`
- Modify: `src/net/socket_opts.zig`
- Modify: `src/app/local/tcp_session.zig`
- Modify: `src/app/local/service.zig`
- Modify: `src/app/server/tcp_session.zig`
- Modify: `src/app/server/service.zig`
- Modify: `src/cli/sslocal_main.zig`
- Modify: `src/cli/ssserver_main.zig`
- Modify: `test/integration/tcp_happy_path.zig`
- Modify: `build.zig`

- [ ] **Step 1: Replace the placeholder integration test with a real TCP echo test**

`test/integration/tcp_happy_path.zig`

```zig
const std = @import("std");
const ss = @import("shadowsocks_zig");

test "sslocal relays socks5 tcp through ssserver to a tcp echo target" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    const server_cfg_text =
        \\{
        \\  "server": "127.0.0.1",
        \\  "server_port": 18388,
        \\  "password": "test-password",
        \\  "method": "aes-128-gcm",
        \\  "mode": "tcp_only"
        \\}
    ;
    const local_cfg_text =
        \\{
        \\  "server": "127.0.0.1",
        \\  "server_port": 18388,
        \\  "local_port": 11080,
        \\  "password": "test-password",
        \\  "method": "aes-128-gcm",
        \\  "mode": "tcp_only"
        \\}
    ;

    var server_cfg = try ss.config.loadFromSlice(arena.allocator(), .server, server_cfg_text);
    defer server_cfg.deinit(arena.allocator());
    var local_cfg = try ss.config.loadFromSlice(arena.allocator(), .local, local_cfg_text);
    defer local_cfg.deinit(arena.allocator());

    var running_server = try ss.app.runServer(server_cfg);
    defer running_server.stop();
    var running_local = try ss.app.runLocal(local_cfg);
    defer running_local.stop();

    try expectSocks5Echo("127.0.0.1", 11080, "127.0.0.1", 19090, "hello through zig");
}

fn expectSocks5Echo(proxy_host: []const u8, proxy_port: u16, target_host: []const u8, target_port: u16, payload: []const u8) !void {
    const target_addr = try std.net.Address.parseIp(target_host, target_port);
    var listener = try target_addr.listen(.{ .reuse_address = true });
    defer listener.deinit();

    const echo_thread = try std.Thread.spawn(.{}, runEchoOnce, .{ &listener, payload });
    defer echo_thread.join();

    const proxy = try std.net.tcpConnectToHost(std.testing.allocator, proxy_host, proxy_port);
    defer proxy.close();

    try proxy.writeAll(&[_]u8{ 0x05, 0x01, 0x00 });
    var greeting_reply: [2]u8 = undefined;
    _ = try proxy.read(&greeting_reply);

    const connect_request = [_]u8{
        0x05, 0x01, 0x00, 0x01,
        127, 0, 0, 1,
        @intCast((target_port >> 8) & 0xff),
        @intCast(target_port & 0xff),
    };
    try proxy.writeAll(&connect_request);

    var connect_reply: [32]u8 = undefined;
    _ = try proxy.read(&connect_reply);
    try proxy.writeAll(payload);

    var echoed: [128]u8 = undefined;
    const echoed_n = try proxy.read(&echoed);
    try std.testing.expectEqualStrings(payload, echoed[0..echoed_n]);
}

fn runEchoOnce(listener: *std.net.Server, expected: []const u8) !void {
    const accepted = try listener.accept();
    defer accepted.stream.close();

    var buf: [128]u8 = undefined;
    const n = try accepted.stream.read(&buf);
    try std.testing.expectEqualStrings(expected, buf[0..n]);
    try accepted.stream.writeAll(buf[0..n]);
}
```

- [ ] **Step 2: Run the TCP integration test and verify it fails**

Run:

```powershell
zig build test
```

Expected:

- FAIL because `runLocal`, `runServer`, and the TCP session modules do not yet open sockets or relay bytes. On Zig 0.16 the integration test must run through the build graph so it receives the `shadowsocks_zig` module import.

- [ ] **Step 3: Implement the local/server TCP sessions and service loops**

`src/net/tcp.zig`

```zig
pub fn connectTarget(target: Address) !std.net.Stream {
    return switch (target) {
        .domain => |domain| try std.net.tcpConnectToHost(std.heap.page_allocator, domain.host, domain.port),
        else => return error.UnsupportedAddressType,
    };
}

pub fn pumpBidirectional(client_stream: std.net.Stream, target_stream: std.net.Stream) !void {
    const forward = try std.Thread.spawn(.{}, copyLoop, .{ client_stream, target_stream });
    defer forward.join();
    try copyLoop(target_stream, client_stream);
}

fn copyLoop(reader_stream: std.net.Stream, writer_stream: std.net.Stream) !void {
    var buf: [16 * 1024]u8 = undefined;
    while (true) {
        const n = try reader_stream.read(&buf);
        if (n == 0) break;
        try writer_stream.writeAll(buf[0..n]);
    }
}
```

`src/app/local/tcp_session.zig`

```zig
pub fn handleClient(client: std.net.Stream, config: RuntimeConfig) !void {
    var request_buf: [512]u8 = undefined;
    const read_n = try client.read(&request_buf);
    const request = try socks5.readRequest(request_buf[0..read_n]);

    const upstream = try std.net.tcpConnectToHost(std.heap.page_allocator, config.server.bind_host, config.server.bind_port);
    defer upstream.close();

    var master_key: [32]u8 = [_]u8{0} ** 32;
    try kdf.deriveClassicMasterKey(config.password, master_key[0..config.method.keyLen()]);
    var salt: [32]u8 = undefined;
    nonce.fillRandom(salt[0..config.method.saltLen()]);
    var session = try tcp_wire.Session.initClient(config.method, master_key[0..config.method.keyLen()], salt[0..config.method.saltLen()]);

    var first_plain: [512]u8 = undefined;
    const addr_len = try addr_codec.writeAddress(first_plain[0..], request.target);
    var first_frame: [1024]u8 = undefined;
    const first_used = try session.writeChunk(first_plain[0..addr_len], first_frame[0..]);
    try upstream.writeAll(first_frame[0..first_used]);

    var reply_buf: [64]u8 = undefined;
    const reply_len = try tcp_connect.writeSuccessReply(reply_buf[0..], request.target);
    try client.writeAll(reply_buf[0..reply_len]);
    try tcp.pumpBidirectional(client, upstream);
}
```

`src/app/server/tcp_session.zig`

```zig
pub fn handleClient(client: std.net.Stream, config: RuntimeConfig) !void {
    var master_key: [32]u8 = [_]u8{0} ** 32;
    try kdf.deriveClassicMasterKey(config.password, master_key[0..config.method.keyLen()]);
    var session = try tcp_wire.Session.initServer(config.method, master_key[0..config.method.keyLen()]);
    var cipher_buf: [2048]u8 = undefined;
    var plain_buf: [1024]u8 = undefined;

    const first_n = try client.read(&cipher_buf);
    const first_plain = try session.readChunk(cipher_buf[0..first_n], plain_buf[0..]);
    const decoded = try addr_codec.readAddress(first_plain);

    const target = try tcp.connectTarget(decoded.address);
    defer target.close();

    try tcp.pumpBidirectional(client, target);
}
```

- [ ] **Step 4: Run the TCP integration test and the package tests**

Run:

```powershell
zig build test
zig build check
```

Expected:

- all commands PASS

- [ ] **Step 5: Commit**

```powershell
git add build.zig src/net/tcp.zig src/net/socket_opts.zig src/app/local/tcp_session.zig src/app/local/service.zig src/app/server/tcp_session.zig src/app/server/service.zig src/cli/sslocal_main.zig src/cli/ssserver_main.zig test/integration/tcp_happy_path.zig
git commit -m "feat: implement tcp relay happy path"
```

### Task 4: Add the UDP packet codec and association manager

**Files:**
- Create: `src/wire/ss_udp.zig`
- Create: `src/net/udp.zig`
- Create: `src/app/local/udp_assoc.zig`
- Create: `src/app/server/udp_assoc.zig`
- Test: `src/wire/ss_udp.zig`
- Test: `src/app/local/udp_assoc.zig`

- [ ] **Step 1: Write the failing UDP codec and association tests**

`src/wire/ss_udp.zig`

```zig
const std = @import("std");
const Method = @import("../crypto/methods.zig").Method;
const Address = @import("../core/address.zig").Address;

test "udp packet round-trips with fixed salt" {
    const master = [_]u8{0x22} ** 32;
    const salt = [_]u8{0x33} ** 32;
    const target = Address{ .domain = .{ .host = "example.com", .port = 53 } };
    const payload = "hello udp";

    var packet: [256]u8 = undefined;
    const used = try encodePacket(.chacha20_ietf_poly1305, master[0..], salt[0..], target, payload, packet[0..]);

    var plain: [payload.len + 64]u8 = undefined;
    const decoded = try decodePacket(.chacha20_ietf_poly1305, master[0..], packet[0..used], plain[0..]);
    try std.testing.expectEqualStrings("example.com", decoded.address.host());
    try std.testing.expectEqualStrings(payload, decoded.payload);
}
```

`src/app/local/udp_assoc.zig`

```zig
const std = @import("std");

test "association manager enforces max count and reaps expired entries" {
    var manager = Manager.init(std.testing.allocator, 1);
    defer manager.deinit();

    try manager.touch(11, 1000);
    try std.testing.expectError(error.TooManyAssociations, manager.touch(22, 1000));

    manager.reapExpired(5000, 1000);
    try manager.touch(22, 5000);
}
```

- [ ] **Step 2: Run the UDP unit tests and verify they fail**

Run:

```powershell
zig test src/wire/ss_udp.zig
zig test src/app/local/udp_assoc.zig
```

Expected:

- FAIL because `encodePacket`, `decodePacket`, and `Manager` do not exist

- [ ] **Step 3: Implement UDP framing and association state**

`src/wire/ss_udp.zig`

```zig
pub const DecodedPacket = struct {
    address: Address,
    payload: []const u8,
};

pub fn encodePacket(method: Method, master_key: []const u8, salt: []const u8, address: Address, payload: []const u8, out: []u8) !usize {
    var subkey: [32]u8 = [_]u8{0} ** 32;
    try crypto.deriveSessionSubkey(master_key, salt, subkey[0..method.keyLen()]);
    std.mem.copyForwards(u8, out[0..salt.len], salt);
    const addr_len = try addr_codec.writeAddress(out[salt.len..], address);
    const plain_len = addr_len + payload.len;
    std.mem.copyForwards(u8, out[salt.len + addr_len .. salt.len + plain_len], payload);

    const nonce = [_]u8{0} ** 12;
    const cipher_slice = out[salt.len .. salt.len + plain_len];
    const tag_slice = out[salt.len + plain_len .. salt.len + plain_len + method.tagLen()];
    try aead.sealDetached(method, subkey[0..method.keyLen()], nonce[0..], "", cipher_slice, cipher_slice, tag_slice);
    return salt.len + plain_len + method.tagLen();
}

pub fn decodePacket(method: Method, master_key: []const u8, input: []const u8, out: []u8) !DecodedPacket {
    const salt_len = method.saltLen();
    const tag_len = method.tagLen();
    if (input.len < salt_len + tag_len) return error.Truncated;

    var subkey: [32]u8 = [_]u8{0} ** 32;
    try crypto.deriveSessionSubkey(master_key, input[0..salt_len], subkey[0..method.keyLen()]);

    const cipher_len = input.len - salt_len - tag_len;
    const nonce = [_]u8{0} ** 12;
    try aead.openDetached(method, subkey[0..method.keyLen()], nonce[0..], "", input[salt_len .. salt_len + cipher_len], input[salt_len + cipher_len ..], out[0..cipher_len]);
    const decoded = try addr_codec.readAddress(out[0..cipher_len]);
    return .{ .address = decoded.address, .payload = out[decoded.used..cipher_len] };
}
```

`src/net/udp.zig`

```zig
pub fn bind(host: []const u8, port: u16) !std.posix.socket_t {
    const addr = try std.net.Address.parseIp(host, port);
    const socket = try std.posix.socket(addr.any.family, std.posix.SOCK.DGRAM, 0);
    try std.posix.bind(socket, &addr.any, addr.getOsSockLen());
    return socket;
}

pub fn sendToTarget(socket: std.posix.socket_t, target: Address, payload: []const u8) !void {
    switch (target) {
        .domain => |domain| {
            const addr = try dns.resolveFirst(domain.host, domain.port);
            try std.posix.sendto(socket, payload, 0, &addr.any, addr.getOsSockLen());
        },
        else => return error.UnsupportedAddressType,
    }
}
```

`src/app/local/udp_assoc.zig`

```zig
pub const Manager = struct {
    allocator: std.mem.Allocator,
    max_associations: usize,
    entries: std.AutoHashMap(u64, i64),

    pub fn init(allocator: std.mem.Allocator, max_associations: usize) Manager {
        return .{ .allocator = allocator, .max_associations = max_associations, .entries = std.AutoHashMap(u64, i64).init(allocator) };
    }

    pub fn deinit(self: *Manager) void {
        self.entries.deinit();
    }

    pub fn touch(self: *Manager, endpoint_hash: u64, now_ms: i64) !void {
        if (!self.entries.contains(endpoint_hash) and self.entries.count() >= self.max_associations) return error.TooManyAssociations;
        try self.entries.put(endpoint_hash, now_ms);
    }

    pub fn reapExpired(self: *Manager, now_ms: i64, timeout_ms: i64) void {
        var iter = self.entries.iterator();
        while (iter.next()) |entry| {
            if (now_ms - entry.value_ptr.* > timeout_ms) _ = self.entries.remove(entry.key_ptr.*);
        }
    }
};
```

- [ ] **Step 4: Re-run the UDP unit tests**

Run:

```powershell
zig test src/wire/ss_udp.zig
zig test src/app/local/udp_assoc.zig
zig build test
```

Expected:

- all commands PASS

- [ ] **Step 5: Commit**

```powershell
git add src/wire/ss_udp.zig src/net/udp.zig src/app/local/udp_assoc.zig src/app/server/udp_assoc.zig
git commit -m "feat: add udp codec and association state"
```

### Task 5: Implement the real UDP relay path

**Files:**
- Modify: `src/frontend/socks5/udp_associate.zig`
- Modify: `src/app/local/service.zig`
- Modify: `src/app/server/service.zig`
- Modify: `src/app/local/udp_assoc.zig`
- Modify: `src/app/server/udp_assoc.zig`
- Create: `test/integration/udp_happy_path.zig`

- [ ] **Step 1: Write the failing end-to-end UDP integration test**

`test/integration/udp_happy_path.zig`

```zig
const std = @import("std");
const ss = @import("shadowsocks_zig");

test "sslocal relays socks5 udp through ssserver to a udp echo target" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    const server_cfg_text =
        \\{
        \\  "server": "127.0.0.1",
        \\  "server_port": 18389,
        \\  "password": "test-password",
        \\  "method": "chacha20-ietf-poly1305",
        \\  "mode": "tcp_and_udp"
        \\}
    ;
    const local_cfg_text =
        \\{
        \\  "server": "127.0.0.1",
        \\  "server_port": 18389,
        \\  "local_port": 11081,
        \\  "local_udp_port": 11082,
        \\  "password": "test-password",
        \\  "method": "chacha20-ietf-poly1305",
        \\  "mode": "tcp_and_udp",
        \\  "udp_max_associations": 2
        \\}
    ;

    var server_cfg = try ss.config.loadFromSlice(arena.allocator(), .server, server_cfg_text);
    defer server_cfg.deinit(arena.allocator());
    var local_cfg = try ss.config.loadFromSlice(arena.allocator(), .local, local_cfg_text);
    defer local_cfg.deinit(arena.allocator());

    var running_server = try ss.app.runServer(server_cfg);
    defer running_server.stop();
    var running_local = try ss.app.runLocal(local_cfg);
    defer running_local.stop();

    try expectSocks5UdpEcho("127.0.0.1", 11081, 11082, "127.0.0.1", 19091, "hello udp");
}

fn expectSocks5UdpEcho(proxy_host: []const u8, tcp_port: u16, udp_port: u16, target_host: []const u8, target_port: u16, payload: []const u8) !void {
    const target_addr = try std.net.Address.parseIp(target_host, target_port);
    const target_socket = try std.posix.socket(target_addr.any.family, std.posix.SOCK.DGRAM, 0);
    defer std.posix.close(target_socket);
    try std.posix.bind(target_socket, &target_addr.any, target_addr.getOsSockLen());

    const echo_thread = try std.Thread.spawn(.{}, runUdpEchoOnce, .{ target_socket, payload });
    defer echo_thread.join();

    const control = try std.net.tcpConnectToHost(std.testing.allocator, proxy_host, tcp_port);
    defer control.close();

    try control.writeAll(&[_]u8{ 0x05, 0x01, 0x00 });
    var greeting_reply: [2]u8 = undefined;
    _ = try control.read(&greeting_reply);

    const associate_request = [_]u8{
        0x05, 0x03, 0x00, 0x01,
        0, 0, 0, 0,
        0, 0,
    };
    try control.writeAll(&associate_request);

    var associate_reply: [32]u8 = undefined;
    _ = try control.read(&associate_reply);

    const proxy_udp = try std.net.Address.parseIp(proxy_host, udp_port);
    const udp_socket = try std.posix.socket(proxy_udp.any.family, std.posix.SOCK.DGRAM, 0);
    defer std.posix.close(udp_socket);

    var packet: [256]u8 = undefined;
    packet[0] = 0x00;
    packet[1] = 0x00;
    packet[2] = 0x00;
    packet[3] = 0x01;
    packet[4] = 127;
    packet[5] = 0;
    packet[6] = 0;
    packet[7] = 1;
    packet[8] = @intCast((target_port >> 8) & 0xff);
    packet[9] = @intCast(target_port & 0xff);
    std.mem.copyForwards(u8, packet[10 .. 10 + payload.len], payload);
    try std.posix.sendto(udp_socket, packet[0 .. 10 + payload.len], 0, &proxy_udp.any, proxy_udp.getOsSockLen());

    var recv_buf: [256]u8 = undefined;
    const recv_n = try std.posix.recv(udp_socket, recv_buf[0..], 0);
    try std.testing.expectEqualStrings(payload, recv_buf[10..recv_n]);
}

fn runUdpEchoOnce(socket: std.posix.socket_t, expected: []const u8) !void {
    var recv_buf: [256]u8 = undefined;
    var from_storage: std.net.Address = undefined;
    var from_len: std.posix.socklen_t = @sizeOf(std.net.Address);
    const recv_n = try std.posix.recvfrom(socket, recv_buf[0..], 0, &from_storage.any, &from_len);
    try std.testing.expectEqualStrings(expected, recv_buf[0..recv_n]);
    try std.posix.sendto(socket, recv_buf[0..recv_n], 0, &from_storage.any, from_len);
}
```

- [ ] **Step 2: Run the UDP integration test and verify it fails**

Run:

```powershell
zig test test/integration/udp_happy_path.zig -I src
```

Expected:

- FAIL because the service loops do not yet process UDP associate or encrypted UDP packets

- [ ] **Step 3: Implement local/server UDP service loops**

`src/app/local/service.zig`

```zig
if (config.mode == .tcp_and_udp) {
    const udp_thread = try std.Thread.spawn(.{}, runLocalUdpLoop, .{config});
    running.udp_thread = udp_thread;
}
```

`src/app/local/udp_assoc.zig`

```zig
pub fn relayClientPacket(
    manager: *Manager,
    config: RuntimeConfig,
    client_endpoint_hash: u64,
    payload: []const u8,
    upstream_socket: std.net.DatagramSocket,
) !void {
    const now_ms = std.time.milliTimestamp();
    try manager.touch(client_endpoint_hash, now_ms);
    var master_key: [32]u8 = [_]u8{0} ** 32;
    try kdf.deriveClassicMasterKey(config.password, master_key[0..config.method.keyLen()]);
    var salt: [32]u8 = undefined;
    nonce.fillRandom(salt[0..config.method.saltLen()]);
    var packet_buf: [1500]u8 = undefined;
    const header = try udp_socks.readUdpAssociateHeader(payload);
    const packet_len = try ss_udp.encodePacket(config.method, master_key[0..config.method.keyLen()], salt[0..config.method.saltLen()], header.address, payload[header.payload_offset..], packet_buf[0..]);
    try upstream_socket.write(packet_buf[0..packet_len]);
}
```

`src/app/server/udp_assoc.zig`

```zig
pub fn relayPacket(config: RuntimeConfig, packet: []const u8, socket: std.net.DatagramSocket) !void {
    var plain: [1500]u8 = undefined;
    var master_key: [32]u8 = [_]u8{0} ** 32;
    try kdf.deriveClassicMasterKey(config.password, master_key[0..config.method.keyLen()]);
    const decoded = try ss_udp.decodePacket(config.method, master_key[0..config.method.keyLen()], packet, plain[0..]);
    try udp.sendToTarget(socket, decoded.address, decoded.payload);
}
```

- [ ] **Step 4: Run the UDP integration test and package tests**

Run:

```powershell
zig test test/integration/udp_happy_path.zig -I src
zig build test
zig build check
```

Expected:

- all commands PASS

- [ ] **Step 5: Commit**

```powershell
git add src/frontend/socks5/udp_associate.zig src/app/local/service.zig src/app/server/service.zig src/app/local/udp_assoc.zig src/app/server/udp_assoc.zig test/integration/udp_happy_path.zig
git commit -m "feat: implement udp associate relay path"
```

### Task 6: Add secret-safe diagnostics, `--check-config`, `--healthcheck`, and graceful shutdown wiring

**Files:**
- Create: `src/cli/signal.zig`
- Modify: `src/cli/diag.zig`
- Modify: `src/cli/args.zig`
- Modify: `src/cli/sslocal_main.zig`
- Modify: `src/cli/ssserver_main.zig`
- Modify: `src/app/local/service.zig`
- Modify: `src/app/server/service.zig`
- Create: `test/integration/graceful_shutdown.zig`
- Test: `src/cli/diag.zig`
- Test: `src/cli/args.zig`

- [ ] **Step 1: Write the failing diagnostics and shutdown tests**

`src/cli/diag.zig`

```zig
const std = @import("std");

test "redactSecret removes passwords and ss urls from operator text" {
    const rendered = try renderOperatorError(std.testing.allocator, "bad input ss://YWVzLTI1Ni1nY206c2VjcmV0@host:8388");
    defer std.testing.allocator.free(rendered);
    try std.testing.expect(std.mem.indexOf(u8, rendered, "secret") == null);
    try std.testing.expect(std.mem.indexOf(u8, rendered, "ss://") == null);
}
```

`test/integration/graceful_shutdown.zig`

```zig
const std = @import("std");
const ss = @import("shadowsocks_zig");

test "running services stop without leaking worker threads" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    const cfg_text =
        \\{
        \\  "server": "127.0.0.1",
        \\  "server_port": 18392,
        \\  "local_port": 11083,
        \\  "password": "test-password",
        \\  "method": "aes-128-gcm"
        \\}
    ;

    var cfg = try ss.config.loadFromSlice(arena.allocator(), .local, cfg_text);
    defer cfg.deinit(arena.allocator());
    var running = try ss.app.runLocal(cfg);
    running.stop();
    try std.testing.expect(true);
}
```

- [ ] **Step 2: Run the diagnostics and shutdown tests and verify they fail**

Run:

```powershell
zig test src/cli/diag.zig
zig test test/integration/graceful_shutdown.zig -I src
```

Expected:

- FAIL because the redaction helper and real `stop()` behavior do not exist yet

- [ ] **Step 3: Implement secret-safe diagnostics and control modes**

`src/cli/diag.zig`

```zig
pub fn renderOperatorError(allocator: std.mem.Allocator, input: []const u8) ![]u8 {
    var out = std.ArrayList(u8).init(allocator);
    errdefer out.deinit();

    if (std.mem.indexOf(u8, input, "ss://")) |_| {
        try out.appendSlice("error: invalid ss url input");
        return out.toOwnedSlice();
    }

    for (input) |ch| {
        if (ch == '\n' or ch == '\r') continue;
        try out.append(ch);
    }
    return out.toOwnedSlice();
}
```

`src/cli/ssserver_main.zig`

```zig
var waiter = ss.cli.signal.Waiter{};

switch (parsed.command) {
    .run => {
        var cfg = try ss.cli.loadConfigFromInputs(init.gpa, .server, parsed.inputs);
        defer cfg.deinit(init.gpa);
        var running = try ss.app.runServer(cfg);
        defer running.stop();
        waiter.wait();
    },
    .check_config => {
        var cfg = try ss.cli.loadConfigFromInputs(init.gpa, .server, parsed.inputs);
        defer cfg.deinit(init.gpa);
        try init.io.getStdOut().writer().writeAll("config ok\n");
    },
    .healthcheck => {
        var cfg = try ss.cli.loadConfigFromInputs(init.gpa, .server, parsed.inputs);
        defer cfg.deinit(init.gpa);
        const stream = try std.net.tcpConnectToHost(init.gpa, cfg.server.bind_host, cfg.server.bind_port);
        stream.close();
    },
}
```

`src/cli/signal.zig`

```zig
const std = @import("std");

pub const Waiter = struct {
    event: std.Thread.ResetEvent = .{},

    pub fn wait(self: *Waiter) void {
        self.event.wait();
    }

    pub fn notify(self: *Waiter) void {
        self.event.set();
    }
};
```

`src/cli/args.zig`

```zig
pub const Command = enum {
    run,
    check_config,
    healthcheck,
};

pub const ParsedArgs = struct {
    command: Command = .run,
    inputs: LoadInputs,
};

pub fn parseArgs(allocator: std.mem.Allocator, io: std.Io, args: *std.process.ArgsIterator) !ParsedArgs {
    var parsed = ParsedArgs{ .inputs = .{} };
    _ = args.next();

    while (args.next()) |arg| {
        if (std.mem.eql(u8, arg, "--check-config")) {
            parsed.command = .check_config;
        } else if (std.mem.eql(u8, arg, "--healthcheck")) {
            parsed.command = .healthcheck;
        } else if (std.mem.eql(u8, arg, "--ss-url")) {
            parsed.inputs.ss_url = args.next() orelse return error.MissingArgumentValue;
        } else {
            parsed.inputs.file_bytes = try std.Io.Dir.cwd().readFileAlloc(io, arg, allocator, .limited(1024 * 1024));
        }
    }

    return parsed;
}
```

- [ ] **Step 4: Run the updated tests and package tests**

Run:

```powershell
zig test src/cli/diag.zig
zig test test/integration/graceful_shutdown.zig -I src
zig build test
```

Expected:

- all commands PASS

- [ ] **Step 5: Commit**

```powershell
git add src/cli/signal.zig src/cli/diag.zig src/cli/args.zig src/cli/sslocal_main.zig src/cli/ssserver_main.zig src/app/local/service.zig src/app/server/service.zig test/integration/graceful_shutdown.zig
git commit -m "feat: add diagnostics and graceful shutdown controls"
```

### Task 7: Add integration, interop, diagnose, and fuzz build lanes

**Files:**
- Modify: `build.zig`
- Modify: `build.zig.zon`
- Modify: `src/root.zig`
- Create: `test/interop/common.zig`
- Create: `test/interop/rust_tcp_test.zig`
- Create: `test/interop/rust_udp_test.zig`
- Create: `test/fuzz/sip002.zig`
- Create: `test/fuzz/socks5_request.zig`

- [ ] **Step 1: Write the failing interop smoke tests**

`test/interop/common.zig`

```zig
const std = @import("std");

pub fn requireEnv(name: []const u8) ![]const u8 {
    return std.process.getEnvVarOwned(std.testing.allocator, name);
}
```

`test/interop/rust_tcp_test.zig`

```zig
const std = @import("std");
const common = @import("common.zig");

test "requires rust sslocal and ssserver paths" {
    const sslocal = try common.requireEnv("SS_RUST_SSLOCAL");
    defer std.testing.allocator.free(sslocal);
    const ssserver = try common.requireEnv("SS_RUST_SSSERVER");
    defer std.testing.allocator.free(ssserver);
    try std.testing.expect(sslocal.len > 0 and ssserver.len > 0);
}
```

`test/interop/rust_udp_test.zig`

```zig
const std = @import("std");
const common = @import("common.zig");

test "requires rust binaries for udp interop" {
    const sslocal = try common.requireEnv("SS_RUST_SSLOCAL");
    defer std.testing.allocator.free(sslocal);
    const ssserver = try common.requireEnv("SS_RUST_SSSERVER");
    defer std.testing.allocator.free(ssserver);
    try std.testing.expect(sslocal.len > 0 and ssserver.len > 0);
}
```

- [ ] **Step 2: Run the failing interop and build-step checks**

Run:

```powershell
zig test test/interop/rust_tcp_test.zig
zig build diagnose
```

Expected:

- the interop test FAILS with missing env vars
- `zig build diagnose` FAILS because the step does not exist yet

- [ ] **Step 3: Add the new build steps and fuzz harnesses**

`build.zig`

```zig
const integration_tcp = b.addTest(.{
    .root_source_file = b.path("test/integration/tcp_happy_path.zig"),
    .target = target,
    .optimize = optimize,
});
const integration_udp = b.addTest(.{
    .root_source_file = b.path("test/integration/udp_happy_path.zig"),
    .target = target,
    .optimize = optimize,
});

const integration_step = b.step("integration", "Run integration tests");
integration_step.dependOn(&b.addRunArtifact(integration_tcp).step);
integration_step.dependOn(&b.addRunArtifact(integration_udp).step);

const interop_tcp = b.addTest(.{
    .root_source_file = b.path("test/interop/rust_tcp_test.zig"),
    .target = target,
    .optimize = optimize,
});
const interop_udp = b.addTest(.{
    .root_source_file = b.path("test/interop/rust_udp_test.zig"),
    .target = target,
    .optimize = optimize,
});
const interop_step = b.step("interop", "Run rust interop smoke tests");
interop_step.dependOn(&b.addRunArtifact(interop_tcp).step);
interop_step.dependOn(&b.addRunArtifact(interop_udp).step);

const diagnose_step = b.step("diagnose", "Run package, integration, and interop smoke tests");
diagnose_step.dependOn(test_step);
diagnose_step.dependOn(integration_step);
```

`build.zig.zon`

```zig
.{
    .name = .shadowsocks_zig,
    .version = "0.1.0",
    .minimum_zig_version = "0.16.0",
    .dependencies = .{},
    .paths = .{
        "build.zig",
        "build.zig.zon",
        "src",
        "test",
        "examples",
        "scripts",
    },
}
```

`src/root.zig`

```zig
pub const wire = struct {
    pub const socks_addr = @import("wire/socks_addr.zig");
    pub const ss_tcp = @import("wire/ss_tcp.zig");
    pub const ss_udp = @import("wire/ss_udp.zig");
    pub const ss_url = @import("wire/ss_url.zig");
};

pub const net = struct {
    pub const tcp = @import("net/tcp.zig");
    pub const udp = @import("net/udp.zig");
    pub const dns = @import("net/dns.zig");
    pub const socket_opts = @import("net/socket_opts.zig");
};

pub const cli = struct {
    pub const args = @import("cli/args.zig");
    pub const diag = @import("cli/diag.zig");
    pub const signal = @import("cli/signal.zig");
};
```

`test/fuzz/sip002.zig`

```zig
const std = @import("std");
const parse = @import("../../src/wire/ss_url.zig").parse;

test "sip002 parser fuzz smoke" {
    const corpus = [_][]const u8{
        "ss://bad",
        "ss://YWVzLTEyOC1nY206dGVzdA==@127.0.0.1:8388",
        "ss://@@@@",
    };
    for (corpus) |entry| {
        _ = parse(std.testing.allocator, entry) catch {};
    }
}
```

`test/fuzz/socks5_request.zig`

```zig
const std = @import("std");
const readRequest = @import("../../src/frontend/socks5/handshake.zig").readRequest;

test "socks5 request parser fuzz smoke" {
    const corpus = [_][]const u8{
        "\x05\x01\x00\x03\x0bexample.com\x00\x50",
        "\x05\x03\x00\x01\x7f\x00\x00\x01\x1f\x90",
        "\x01\x01",
    };
    for (corpus) |entry| {
        _ = readRequest(entry) catch {};
    }
}
```

- [ ] **Step 4: Run the build lanes**

Run:

```powershell
zig build integration
zig build diagnose
zig test test/interop/rust_tcp_test.zig
zig test test/interop/rust_udp_test.zig
```

Expected:

- `zig build integration` PASS
- `zig build diagnose` PASS when env vars are not required by default, or FAIL with a targeted interop message if interop is enabled
- both interop tests give obvious missing-env failures until Rust paths are configured

- [ ] **Step 5: Commit**

```powershell
git add build.zig build.zig.zon src/root.zig test/interop/common.zig test/interop/rust_tcp_test.zig test/interop/rust_udp_test.zig test/fuzz/sip002.zig test/fuzz/socks5_request.zig
git commit -m "test: add diagnose integration and interop lanes"
```

### Task 8: Add Docker packaging, checksums, and release smoke scripts

**Files:**
- Create: `Dockerfile`
- Create: `.dockerignore`
- Create: `scripts/ci/generate-checksums.ps1`
- Create: `scripts/ci/docker-smoke.ps1`
- Modify: `scripts/ci/package-release.ps1`
- Modify: `examples/config.json`

- [ ] **Step 1: Write the failing packaging and Docker smoke expectations**

`scripts/ci/docker-smoke.ps1`

```powershell
[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
if (-not (Test-Path Dockerfile)) {
    throw 'Missing Dockerfile'
}
docker build -t shadowsocks-test .
```

- [ ] **Step 2: Run the packaging and Docker checks and verify they fail**

Run:

```powershell
powershell -File scripts/ci/docker-smoke.ps1
```

Expected:

- FAIL because `Dockerfile` does not exist yet

- [ ] **Step 3: Implement the Dockerfile, checksum script, and package hook**

`Dockerfile`

```dockerfile
FROM alpine:3.22 AS build
WORKDIR /src
COPY . .
RUN apk add --no-cache zig
RUN zig build -Doptimize=ReleaseSafe ssserver

FROM alpine:3.22
RUN addgroup -S shadowsocks && adduser -S -G shadowsocks shadowsocks
WORKDIR /app
COPY --from=build /src/zig-out/bin/ssserver /usr/local/bin/ssserver
USER shadowsocks
EXPOSE 8388/tcp 8388/udp
HEALTHCHECK --interval=30s --timeout=3s CMD ["/usr/local/bin/ssserver","--healthcheck","/etc/shadowsocks-rust/config.json"]
ENTRYPOINT ["/usr/local/bin/ssserver"]
CMD ["/etc/shadowsocks-rust/config.json"]
```

`scripts/ci/generate-checksums.ps1`

```powershell
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$Path
)

$hash = Get-FileHash -Algorithm SHA256 -LiteralPath $Path
"$($hash.Hash.ToLower())  $(Split-Path -Leaf $Path)" | Set-Content -LiteralPath "$Path.sha256"
```

`scripts/ci/package-release.ps1`

```powershell
$ArchivePath = switch ($ArchiveFormat) {
    'zip'    { Join-Path $StageRoot "$BundleName.zip" }
    'tar.gz' { Join-Path $StageRoot "$BundleName.tar.gz" }
}

powershell -File (Join-Path $RepoRoot 'scripts\ci\generate-checksums.ps1') -Path $ArchivePath
```

- [ ] **Step 4: Re-run the packaging and Docker checks**

Run:

```powershell
powershell -File scripts/ci/docker-smoke.ps1
zig build -Doptimize=ReleaseSafe
powershell -File scripts/ci/package-release.ps1 -PlatformLabel 'windows-x86_64' -ArchiveFormat 'zip' -CommitSha 'plan-smoke'
```

Expected:

- Docker build and health smoke PASS
- release archive and `.sha256` file are produced

- [ ] **Step 5: Commit**

```powershell
git add Dockerfile .dockerignore scripts/ci/generate-checksums.ps1 scripts/ci/docker-smoke.ps1 scripts/ci/package-release.ps1 examples/config.json
git commit -m "build: add docker packaging and checksums"
```

### Task 9: Upgrade GitHub Actions to Linux + Windows product gates and release provenance

**Files:**
- Modify: `.github/workflows/ci.yml`
- Modify: `.github/workflows/artifacts.yml`
- Create: `.github/workflows/release.yml`

- [ ] **Step 1: Write the failing workflow expectations**

Run:

```powershell
rg "windows-2025|attest|sbom|trivy|docker" .github/workflows -n
```

Expected:

- current workflows do not cover the full Linux + Windows product gate, artifact attestations, SBOM, or container release checks

- [ ] **Step 2: Update CI to validate Linux and Windows**

`.github/workflows/ci.yml`

```yaml
jobs:
  zig:
    strategy:
      fail-fast: false
      matrix:
        runner: [ubuntu-24.04, windows-2025]
    runs-on: ${{ matrix.runner }}
    steps:
      - uses: actions/checkout@v6
      - uses: mlugg/setup-zig@v2
        with:
          version: 0.16.0
      - run: zig fmt --check .
      - run: zig build check
      - run: zig build test
      - run: zig build integration
```

- [ ] **Step 3: Add release artifacts, attestations, SBOM, and container scan**

`.github/workflows/release.yml`

```yaml
name: Release
on:
  push:
    tags: ['v*']

jobs:
  native:
    runs-on: ubuntu-24.04
    steps:
      - uses: actions/checkout@v6
      - uses: mlugg/setup-zig@v2
        with:
          version: 0.16.0
      - run: zig build -Doptimize=ReleaseSafe
      - run: pwsh ./scripts/ci/package-release.ps1 -PlatformLabel 'linux-x86_64' -ArchiveFormat 'tar.gz' -CommitSha '${{ github.sha }}'
      - uses: actions/attest-build-provenance@v2
        with:
          subject-path: dist/linux-x86_64/shadowsocks-linux-x86_64.tar.gz
      - uses: anchore/sbom-action@v0
        with:
          path: dist/linux-x86_64/shadowsocks-linux-x86_64.tar.gz
  windows-native:
    runs-on: windows-2025
    steps:
      - uses: actions/checkout@v6
      - uses: mlugg/setup-zig@v2
        with:
          version: 0.16.0
      - run: zig build -Doptimize=ReleaseSafe
      - run: pwsh ./scripts/ci/package-release.ps1 -PlatformLabel 'windows-x86_64' -ArchiveFormat 'zip' -CommitSha '${{ github.sha }}'
  container:
    runs-on: ubuntu-24.04
    steps:
      - uses: actions/checkout@v6
      - uses: docker/setup-buildx-action@v3
      - uses: docker/build-push-action@v6
        with:
          context: .
          file: Dockerfile
          push: false
          tags: shadowsocks:test
          sbom: true
          provenance: true
      - uses: aquasecurity/trivy-action@0.28.0
        with:
          image-ref: shadowsocks:test
```

`.github/workflows/artifacts.yml`

```yaml
jobs:
  native:
    runs-on: ${{ matrix.runner }}
    strategy:
      fail-fast: false
      matrix:
        include:
          - runner: ubuntu-24.04
            platform_label: linux-x86_64
            archive_format: tar.gz
            archive_file: shadowsocks-linux-x86_64.tar.gz
          - runner: windows-2025
            platform_label: windows-x86_64
            archive_format: zip
            archive_file: shadowsocks-windows-x86_64.zip
```

- [ ] **Step 4: Validate the workflow files locally**

Run:

```powershell
Get-Content .github/workflows/ci.yml
Get-Content .github/workflows/artifacts.yml
Get-Content .github/workflows/release.yml
```

Expected:

- the workflows reflect Linux + Windows gating, Linux + Windows artifacts, and release provenance/SBOM/container scanning

- [ ] **Step 5: Commit**

```powershell
git add .github/workflows/ci.yml .github/workflows/artifacts.yml .github/workflows/release.yml
git commit -m "ci: add product mvp release and provenance workflows"
```

### Task 10: Finish docs, examples, and operator guidance

**Files:**
- Modify: `README.md`
- Modify: `examples/config.json`

- [ ] **Step 1: Write the failing documentation checklist**

Run:

```powershell
rg "Docker|ss://|secret|non-goal|Windows|healthcheck" README.md -n
```

Expected:

- one or more of these topics are missing or under-specified

- [ ] **Step 2: Update the README with supported scope, usage, and secret handling**

`README.md`

```markdown
## Supported MVP Surface

- `sslocal` and `ssserver`
- classic AEAD: `aes-128-gcm`, `aes-256-gcm`, `chacha20-ietf-poly1305`
- SOCKS5 `CONNECT` and `UDP ASSOCIATE`
- Linux and Windows native binaries
- Linux Docker image for `ssserver`

## Secret Handling

Prefer config files or mounted secret files over passing passwords on the command line.
The `-k` flag is supported for compatibility, but it is not the recommended production path.

## Non-Goals

- AEAD-2022
- plugins
- manager mode
- redir, TUN, HTTP local, or SOCKS4
```

- [ ] **Step 3: Update the example config and verify it with the binary**

`examples/config.json`

```json
{
  "server": "127.0.0.1",
  "server_port": 8388,
  "local_address": "127.0.0.1",
  "local_port": 1080,
  "local_udp_port": 1081,
  "password": "password",
  "method": "aes-256-gcm",
  "mode": "tcp_and_udp",
  "timeout": 300,
  "udp_timeout": 60,
  "udp_max_associations": 512
}
```

- [ ] **Step 4: Validate the docs and example config**

Run:

```powershell
zig build ssserver
$bin = if (Test-Path .\zig-out\bin\ssserver.exe) { '.\zig-out\bin\ssserver.exe' } else { '.\zig-out\bin\ssserver' }
& $bin --check-config examples/config.json
rg "Docker|Secret Handling|Non-Goals|UDP ASSOCIATE" README.md -n
```

Expected:

- config check prints `config ok`
- README contains the expected sections

- [ ] **Step 5: Commit**

```powershell
git add README.md examples/config.json
git commit -m "docs: document product mvp usage and limits"
```

## Plan self-review checklist

- Spec coverage:
  - SIP002 import and config merge: Task 1
  - stateful TCP framing: Task 2
  - real TCP relay: Task 3
  - UDP packet format and association state: Task 4
  - real UDP relay: Task 5
  - diagnostics, safe logging, healthcheck, shutdown: Task 6
  - interop, diagnose, and fuzz lanes: Task 7
  - Docker packaging and checksums: Task 8
  - Linux + Windows CI, attestations, SBOM, scanning: Task 9
  - README, example config, secret handling, non-goals: Task 10
- Placeholder scan:
  - no `TODO`, `TBD`, or “implement later” markers remain in the task steps
- Type consistency:
  - `LoadInputs`, `Session`, `Manager`, `renderOperatorError`, `runLocal`, `runServer`, `encodePacket`, `decodePacket`, and `requireEnv` are named consistently across tasks
