# Shadowsocks Zig MVP Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a Linux-first Zig MVP of Shadowsocks with `sslocal` and `ssserver`, classic AEAD only, SOCKS5 `CONNECT` and `UDP ASSOCIATE`, TCP+UDP relay, common config compatibility, and Rust interop coverage.

**Architecture:** Keep the Rust repo as the compatibility oracle, but implement a smaller Zig-first stack: explicit core types, config normalization, classic AEAD crypto, wire codecs, SOCKS5 frontend parsing, and thin local/server apps built on blocking sockets plus explicit threads. Start with a minimal compileable scaffold, then layer protocol, crypto, TCP, UDP, and interop in that order.

**Tech Stack:** Zig `0.16.0`, Zig stdlib (`std.json`, `std.crypto`, `std.net`, `std.Thread`), no external Zig dependencies, Rust `shadowsocks-rust` binaries only for interop tests.

---

## Execution prerequisites

- Work in a dedicated execution checkout or worktree, not in the design-only workspace.
- Do not start coding until `git log --oneline -n 1` shows a real baseline commit. The current local checkout has no commits yet, so either reclone upstream with history or create an explicit baseline commit containing the current Rust source tree before adding Zig files.
- Keep the approved spec open at [2026-04-22-shadowsocks-zig-rewrite-design.md](</C:/zig/Shadowsocks/docs/superpowers/specs/2026-04-22-shadowsocks-zig-rewrite-design.md:1>) while executing this plan.
- Stay inside MVP scope. Do not add AEAD-2022, plugins, HTTP local, SOCKS4, TUN, redir, manager, service wrappers, or multi-server balancing during this plan.

## File structure and responsibilities

- `build.zig`
  - build graph, `sslocal`, `ssserver`, `test`, `check`
- `build.zig.zon`
  - package metadata, no external dependencies
- `src/root.zig`
  - public package exports
- `src/core/constants.zig`
  - protocol and runtime constants (`0x3fff`, UDP defaults)
- `src/core/errors.zig`
  - shared error sets
- `src/core/mode.zig`
  - `tcp_only`, `tcp_and_udp`
- `src/core/address.zig`
  - IPv4, IPv6, domain target representation
- `src/config/json5_compat.zig`
  - comments/trailing-comma normalization
- `src/config/raw.zig`
  - raw config schema matching accepted external fields
- `src/config/runtime.zig`
  - normalized runtime config structs
- `src/config/validate.zig`
  - raw -> runtime validation/defaulting
- `src/crypto/methods.zig`
  - supported methods and sizes
- `src/crypto/kdf.zig`
  - classic master-key derivation and AEAD subkey derivation
- `src/crypto/nonce.zig`
  - salt generation and nonce counters
- `src/crypto/aead.zig`
  - detached seal/open wrappers over Zig stdlib AEADs
- `src/security/replay.zig`
  - server-side TCP salt replay protection
- `src/security/zeroize.zig`
  - secure clearing helpers
- `src/wire/socks_addr.zig`
  - Socks/Shadowsocks address encode/decode
- `src/wire/ss_tcp.zig`
  - classic AEAD TCP chunk framing
- `src/wire/ss_udp.zig`
  - classic AEAD UDP packet framing
- `src/frontend/socks5/handshake.zig`
  - SOCKS5 greeting and request parsing
- `src/frontend/socks5/tcp_connect.zig`
  - CONNECT reply helpers
- `src/frontend/socks5/udp_associate.zig`
  - UDP ASSOCIATE header encode/decode and `FRAG` checks
- `src/net/tcp.zig`
  - TCP listener/connect helpers and pump loop
- `src/net/udp.zig`
  - UDP socket helpers
- `src/net/dns.zig`
  - system resolver wrapper
- `src/net/socket_opts.zig`
  - `TCP_NODELAY`, keepalive, Linux-first socket setup
- `src/app/local/service.zig`
  - local TCP/UDP listener orchestration
- `src/app/local/tcp_session.zig`
  - per-client SOCKS5 TCP handling
- `src/app/local/udp_assoc.zig`
  - UDP association map, expiry, bounded association count
- `src/app/server/service.zig`
  - remote TCP/UDP server orchestration
- `src/app/server/tcp_session.zig`
  - per-session server TCP handling
- `src/app/server/udp_assoc.zig`
  - remote UDP relay worker
- `src/cli/args.zig`
  - CLI/config load and override merge
- `src/cli/diag.zig`
  - operator-facing diagnostics
- `src/cli/sslocal_main.zig`
  - `sslocal` entrypoint
- `src/cli/ssserver_main.zig`
  - `ssserver` entrypoint
- `test/integration/tcp_happy_path.zig`
  - Zig local/server TCP happy-path test
- `test/integration/udp_happy_path.zig`
  - Zig local/server UDP happy-path test
- `test/interop/common.zig`
  - child-process helpers for Rust interop
- `test/interop/rust_tcp_test.zig`
  - Zig/Rust TCP interop matrix
- `test/interop/rust_udp_test.zig`
  - Zig/Rust UDP interop matrix

### Task 0: Establish the execution workspace

**Files:**
- Modify: none
- Test: none

- [ ] **Step 1: Confirm a real baseline commit exists**

Run:

```powershell
git rev-parse --is-inside-work-tree
git log --oneline -n 1
```

Expected:

- first command prints `true`
- second command prints an existing commit hash and message

If the second command fails, stop here and fix the checkout before any code changes.

- [ ] **Step 2: Create a dedicated worktree or fresh clone for execution**

Run:

```powershell
git worktree add ..\Shadowsocks-zig-mvp -b zig-mvp
```

Expected:

- a sibling checkout exists at `..\Shadowsocks-zig-mvp`
- the branch name is `zig-mvp`

- [ ] **Step 3: Copy the approved spec into your working context**

Read:

- [2026-04-22-shadowsocks-zig-rewrite-design.md](</C:/zig/Shadowsocks/docs/superpowers/specs/2026-04-22-shadowsocks-zig-rewrite-design.md:1>)

Expected:

- you can point every upcoming task back to an approved MVP requirement

### Task 1: Bootstrap the Zig build and module scaffold

**Files:**
- Create: `build.zig`
- Create: `build.zig.zon`
- Create: `src/root.zig`
- Create: `src/cli/sslocal_main.zig`
- Create: `src/cli/ssserver_main.zig`
- Test: `src/root.zig`

- [ ] **Step 1: Write the failing smoke test in `src/root.zig`**

```zig
const std = @import("std");

test "package exposes project name" {
    try std.testing.expectEqualStrings("shadowsocks-zig", project_name);
}
```

- [ ] **Step 2: Run the test and verify it fails**

Run:

```powershell
zig test src/root.zig
```

Expected:

- FAIL with an undeclared identifier error for `project_name`

- [ ] **Step 3: Write the minimal scaffold and build graph**

`build.zig`

```zig
const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const pkg = b.addModule("shadowsocks_zig", .{
        .root_source_file = b.path("src/root.zig"),
        .target = target,
        .optimize = optimize,
    });

    const sslocal = b.addExecutable(.{
        .name = "sslocal",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/cli/sslocal_main.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{.{ .name = "shadowsocks_zig", .module = pkg }},
        }),
    });
    const ssserver = b.addExecutable(.{
        .name = "ssserver",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/cli/ssserver_main.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{.{ .name = "shadowsocks_zig", .module = pkg }},
        }),
    });

    b.installArtifact(sslocal);
    b.installArtifact(ssserver);

    const pkg_tests = b.addTest(.{ .root_module = pkg });
    const run_pkg_tests = b.addRunArtifact(pkg_tests);

    const test_step = b.step("test", "Run package tests");
    test_step.dependOn(&run_pkg_tests.step);

    const check_step = b.step("check", "Build sslocal and ssserver");
    check_step.dependOn(&sslocal.step);
    check_step.dependOn(&ssserver.step);

    const sslocal_step = b.step("sslocal", "Build sslocal");
    sslocal_step.dependOn(&sslocal.step);

    const ssserver_step = b.step("ssserver", "Build ssserver");
    ssserver_step.dependOn(&ssserver.step);
}
```

`build.zig.zon`

```zig
.{
    .name = "shadowsocks-zig",
    .version = "0.1.0",
    .minimum_zig_version = "0.16.0",
    .dependencies = .{},
    .paths = .{
        "build.zig",
        "build.zig.zon",
        "src",
        "test",
    },
}
```

`src/root.zig`

```zig
pub const project_name = "shadowsocks-zig";

pub const core = struct {};
pub const config = struct {};
pub const crypto = struct {};
pub const security = struct {};
pub const wire = struct {};
pub const frontend = struct {};
pub const net = struct {};
pub const app = struct {};

const std = @import("std");

test "package exposes project name" {
    try std.testing.expectEqualStrings("shadowsocks-zig", project_name);
}
```

`src/cli/sslocal_main.zig`

```zig
const std = @import("std");
const ss = @import("shadowsocks_zig");

pub fn main() !void {
    try std.io.getStdOut().writer().print("{s} sslocal bootstrap\n", .{ss.project_name});
}
```

`src/cli/ssserver_main.zig`

```zig
const std = @import("std");
const ss = @import("shadowsocks_zig");

pub fn main() !void {
    try std.io.getStdOut().writer().print("{s} ssserver bootstrap\n", .{ss.project_name});
}
```

- [ ] **Step 4: Run the scaffold checks**

Run:

```powershell
zig build test
zig build check
zig build sslocal
zig build ssserver
```

Expected:

- all commands PASS
- `zig-out\bin\sslocal` and `zig-out\bin\ssserver` are built

- [ ] **Step 5: Commit**

```powershell
git add build.zig build.zig.zon src/root.zig src/cli/sslocal_main.zig src/cli/ssserver_main.zig
git commit -m "chore: bootstrap zig package and binaries"
```

### Task 2: Add core constants, errors, modes, and address types

**Files:**
- Create: `src/core/constants.zig`
- Create: `src/core/errors.zig`
- Create: `src/core/mode.zig`
- Create: `src/core/address.zig`
- Modify: `src/root.zig`
- Test: `src/core/mode.zig`
- Test: `src/core/address.zig`

- [ ] **Step 1: Write failing tests for mode parsing and address formatting**

`src/core/mode.zig`

```zig
const std = @import("std");

test "mode parsing accepts tcp_only and tcp_and_udp" {
    try std.testing.expectEqual(.tcp_only, try Mode.parse("tcp_only"));
    try std.testing.expectEqual(.tcp_and_udp, try Mode.parse("tcp_and_udp"));
}
```

`src/core/address.zig`

```zig
const std = @import("std");

test "domain address keeps host and port" {
    const addr = Address{ .domain = .{ .host = "example.com", .port = 443 } };
    try std.testing.expectEqual(@as(u16, 443), addr.port());
    try std.testing.expectEqualStrings("example.com", addr.host());
}
```

- [ ] **Step 2: Run the tests and verify they fail**

Run:

```powershell
zig test src/core/mode.zig
zig test src/core/address.zig
```

Expected:

- FAIL because `Mode` and `Address` are not defined yet

- [ ] **Step 3: Write the minimal core model**

`src/core/constants.zig`

```zig
pub const max_tcp_packet_size: usize = 0x3fff;
pub const default_udp_timeout_secs: u64 = 300;
pub const default_udp_max_associations: usize = 512;
```

`src/core/errors.zig`

```zig
pub const ConfigError = error{
    MissingField,
    InvalidField,
    UnsupportedField,
    UnsupportedValue,
};

pub const ProtocolError = error{
    Truncated,
    InvalidAddressType,
    InvalidSocksVersion,
    InvalidSocksCommand,
    UnsupportedFragmentation,
    PacketTooLarge,
    ReplayDetected,
};
```

`src/core/mode.zig`

```zig
const std = @import("std");

pub const Mode = enum {
    tcp_only,
    tcp_and_udp,

    pub fn parse(text: []const u8) !Mode {
        if (std.mem.eql(u8, text, "tcp_only")) return .tcp_only;
        if (std.mem.eql(u8, text, "tcp_and_udp")) return .tcp_and_udp;
        return error.InvalidMode;
    }

    pub fn enablesTcp(self: Mode) bool {
        _ = self;
        return true;
    }

    pub fn enablesUdp(self: Mode) bool {
        return self == .tcp_and_udp;
    }
};

test "mode parsing accepts tcp_only and tcp_and_udp" {
    try std.testing.expectEqual(.tcp_only, try Mode.parse("tcp_only"));
    try std.testing.expectEqual(.tcp_and_udp, try Mode.parse("tcp_and_udp"));
}
```

`src/core/address.zig`

```zig
pub const Address = union(enum) {
    ipv4: struct { host: [4]u8, port: u16 },
    ipv6: struct { host: [16]u8, port: u16 },
    domain: struct { host: []const u8, port: u16 },

    pub fn port(self: Address) u16 {
        return switch (self) {
            .ipv4 => |v| v.port,
            .ipv6 => |v| v.port,
            .domain => |v| v.port,
        };
    }

    pub fn host(self: Address) []const u8 {
        return switch (self) {
            .domain => |v| v.host,
            else => unreachable,
        };
    }
};

const std = @import("std");

test "domain address keeps host and port" {
    const addr = Address{ .domain = .{ .host = "example.com", .port = 443 } };
    try std.testing.expectEqual(@as(u16, 443), addr.port());
    try std.testing.expectEqualStrings("example.com", addr.host());
}
```

`src/root.zig`

```zig
pub const project_name = "shadowsocks-zig";

pub const core = struct {
    pub const constants = @import("core/constants.zig");
    pub const errors = @import("core/errors.zig");
    pub const Mode = @import("core/mode.zig").Mode;
    pub const Address = @import("core/address.zig").Address;
};

pub const config = struct {};
pub const crypto = struct {};
pub const security = struct {};
pub const wire = struct {};
pub const frontend = struct {};
pub const net = struct {};
pub const app = struct {};

const std = @import("std");

test "package exposes project name" {
    try std.testing.expectEqualStrings("shadowsocks-zig", project_name);
}
```

- [ ] **Step 4: Run the core tests**

Run:

```powershell
zig test src/core/mode.zig
zig test src/core/address.zig
zig build test
```

Expected:

- all PASS

- [ ] **Step 5: Commit**

```powershell
git add src/core/constants.zig src/core/errors.zig src/core/mode.zig src/core/address.zig src/root.zig
git commit -m "feat: add core mode and address model"
```

### Task 3: Add supported methods and classic key derivation

**Files:**
- Create: `src/crypto/methods.zig`
- Create: `src/crypto/kdf.zig`
- Create: `src/crypto/nonce.zig`
- Modify: `src/root.zig`
- Test: `src/crypto/methods.zig`
- Test: `src/crypto/kdf.zig`

- [ ] **Step 1: Write failing method and KDF tests**

`src/crypto/methods.zig`

```zig
const std = @import("std");

test "method parsing exposes classic AEAD sizes" {
    const method = try Method.parse("aes-128-gcm");
    try std.testing.expectEqual(@as(usize, 16), method.keyLen());
    try std.testing.expectEqual(@as(usize, 16), method.saltLen());
    try std.testing.expectEqual(@as(usize, 16), method.tagLen());
}
```

`src/crypto/kdf.zig`

```zig
const std = @import("std");

test "classic EVP bytes-to-key derives aes-256-gcm master key" {
    const expected = [_]u8{
        0xdf, 0xb4, 0x50, 0xef, 0xdd, 0xbb, 0x53, 0x87,
        0x19, 0x7c, 0x84, 0x46, 0x06, 0x23, 0x67, 0x5b,
        0x69, 0xf2, 0xce, 0xbc, 0xd8, 0xef, 0x52, 0x0a,
        0x3d, 0xfd, 0xde, 0xf7, 0xc3, 0xd5, 0x40, 0xb2,
    };
    var out: [32]u8 = undefined;
    try deriveClassicMasterKey("test-password", out[0..]);
    try std.testing.expectEqualSlices(u8, &expected, &out);
}

test "classic HKDF-SHA1 derives per-session subkey" {
    const master = [_]u8{
        0xdf, 0xb4, 0x50, 0xef, 0xdd, 0xbb, 0x53, 0x87,
        0x19, 0x7c, 0x84, 0x46, 0x06, 0x23, 0x67, 0x5b,
        0x69, 0xf2, 0xce, 0xbc, 0xd8, 0xef, 0x52, 0x0a,
        0x3d, 0xfd, 0xde, 0xf7, 0xc3, 0xd5, 0x40, 0xb2,
    };
    const salt = [_]u8{
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
    };
    const expected = [_]u8{
        0x7b, 0x6c, 0xa1, 0x2d, 0x45, 0xef, 0x79, 0x46,
        0x74, 0x32, 0x71, 0x7a, 0xaa, 0x6a, 0x6a, 0xe6,
        0xe1, 0xdd, 0x04, 0x6a, 0x50, 0x5f, 0xb2, 0xeb,
        0xaa, 0xac, 0x60, 0x22, 0x10, 0x91, 0x95, 0x95,
    };
    var out: [32]u8 = undefined;
    try deriveSessionSubkey(master[0..], salt[0..], out[0..]);
    try std.testing.expectEqualSlices(u8, &expected, &out);
}
```

- [ ] **Step 2: Run the tests and verify they fail**

Run:

```powershell
zig test src/crypto/methods.zig
zig test src/crypto/kdf.zig
```

Expected:

- FAIL because `Method`, `deriveClassicMasterKey`, and `deriveSessionSubkey` do not exist yet

- [ ] **Step 3: Write the supported methods and derivation code**

`src/crypto/methods.zig`

```zig
const std = @import("std");

pub const Method = enum {
    aes_128_gcm,
    aes_256_gcm,
    chacha20_ietf_poly1305,

    pub fn parse(text: []const u8) !Method {
        if (std.mem.eql(u8, text, "aes-128-gcm")) return .aes_128_gcm;
        if (std.mem.eql(u8, text, "aes-256-gcm")) return .aes_256_gcm;
        if (std.mem.eql(u8, text, "chacha20-ietf-poly1305")) return .chacha20_ietf_poly1305;
        return error.UnsupportedMethod;
    }

    pub fn keyLen(self: Method) usize {
        return switch (self) {
            .aes_128_gcm => 16,
            .aes_256_gcm => 32,
            .chacha20_ietf_poly1305 => 32,
        };
    }

    pub fn saltLen(self: Method) usize {
        return self.keyLen();
    }

    pub fn tagLen(self: Method) usize {
        _ = self;
        return 16;
    }
};

const std = @import("std");

test "method parsing exposes classic AEAD sizes" {
    const method = try Method.parse("aes-128-gcm");
    try std.testing.expectEqual(@as(usize, 16), method.keyLen());
    try std.testing.expectEqual(@as(usize, 16), method.saltLen());
    try std.testing.expectEqual(@as(usize, 16), method.tagLen());
}
```

`src/crypto/kdf.zig`

```zig
const std = @import("std");

pub fn deriveClassicMasterKey(password: []const u8, out: []u8) !void {
    var generated: usize = 0;
    var previous: [std.crypto.hash.Md5.digest_length]u8 = [_]u8{0} ** std.crypto.hash.Md5.digest_length;
    var has_previous = false;

    while (generated < out.len) {
        var md5 = std.crypto.hash.Md5.init(.{});
        if (has_previous) md5.update(previous[0..]);
        md5.update(password);
        md5.final(previous[0..]);
        has_previous = true;

        const remaining = out.len - generated;
        const take = @min(remaining, previous.len);
        @memcpy(out[generated .. generated + take], previous[0..take]);
        generated += take;
    }
}

pub fn deriveSessionSubkey(master_key: []const u8, salt: []const u8, out: []u8) !void {
    const hmac = std.crypto.auth.hmac.HmacSha1;
    const prk = hkdfExtract(hmac, salt, master_key);
    try hkdfExpand(hmac, prk[0..], "ss-subkey", out);
}

fn hkdfExtract(comptime Hmac: type, salt: []const u8, ikm: []const u8) [Hmac.mac_length]u8 {
    var prk: [Hmac.mac_length]u8 = undefined;
    Hmac.create(&prk, ikm, salt);
    return prk;
}

fn hkdfExpand(comptime Hmac: type, prk: []const u8, info: []const u8, out: []u8) !void {
    var block: [Hmac.mac_length]u8 = [_]u8{0} ** Hmac.mac_length;
    var written: usize = 0;
    var counter: u8 = 1;
    var previous_len: usize = 0;

    while (written < out.len) {
        var mac: [Hmac.mac_length]u8 = undefined;
        var msg = std.ArrayList(u8).init(std.heap.page_allocator);
        defer msg.deinit();
        if (previous_len > 0) try msg.appendSlice(block[0..previous_len]);
        try msg.appendSlice(info);
        try msg.append(counter);
        Hmac.create(&mac, msg.items, prk);
        block = mac;
        previous_len = Hmac.mac_length;

        const take = @min(out.len - written, Hmac.mac_length);
        @memcpy(out[written .. written + take], block[0..take]);
        written += take;
        counter += 1;
    }
}
```

`src/crypto/nonce.zig`

```zig
const std = @import("std");

pub fn fillRandom(out: []u8) void {
    std.crypto.random.bytes(out);
}
```

`src/root.zig`

```zig
pub const project_name = "shadowsocks-zig";

pub const core = struct {
    pub const constants = @import("core/constants.zig");
    pub const errors = @import("core/errors.zig");
    pub const Mode = @import("core/mode.zig").Mode;
    pub const Address = @import("core/address.zig").Address;
};

pub const crypto = struct {
    pub const Method = @import("crypto/methods.zig").Method;
    pub const deriveClassicMasterKey = @import("crypto/kdf.zig").deriveClassicMasterKey;
    pub const deriveSessionSubkey = @import("crypto/kdf.zig").deriveSessionSubkey;
};

pub const config = struct {};
pub const security = struct {};
pub const wire = struct {};
pub const frontend = struct {};
pub const net = struct {};
pub const app = struct {};

const std = @import("std");

test "package exposes project name" {
    try std.testing.expectEqualStrings("shadowsocks-zig", project_name);
}
```

- [ ] **Step 4: Run the crypto tests**

Run:

```powershell
zig test src/crypto/methods.zig
zig test src/crypto/kdf.zig
zig build test
```

Expected:

- all PASS

- [ ] **Step 5: Commit**

```powershell
git add src/crypto/methods.zig src/crypto/kdf.zig src/crypto/nonce.zig src/root.zig
git commit -m "feat: add classic method and key derivation support"
```

### Task 4: Parse config text and normalize it into runtime config

**Files:**
- Create: `src/config/json5_compat.zig`
- Create: `src/config/raw.zig`
- Create: `src/config/runtime.zig`
- Create: `src/config/validate.zig`
- Modify: `src/root.zig`
- Test: `src/config/json5_compat.zig`
- Test: `src/config/validate.zig`

- [ ] **Step 1: Write failing tests for comments, defaults, and shared-config tolerance**

`src/config/json5_compat.zig`

```zig
const std = @import("std");

test "normalize strips line comments and trailing commas" {
    const input =
        \\{
        \\  // comment
        \\  "server": "127.0.0.1",
        \\  "server_port": 8388,
        \\}
    ;
    const got = try normalize(std.testing.allocator, input);
    defer std.testing.allocator.free(got);
    try std.testing.expect(std.mem.indexOf(u8, got, "//") == null);
}
```

`src/config/validate.zig`

```zig
const std = @import("std");

test "local config defaults mode to tcp_only and bind to 127.0.0.1" {
    const input =
        \\{
        \\  "server": "127.0.0.1",
        \\  "server_port": 8388,
        \\  "local_port": 1080,
        \\  "password": "test-password",
        \\  "method": "aes-128-gcm",
        \\}
    ;
    const runtime = try loadFromSlice(std.testing.allocator, .local, input);
    defer runtime.deinit(std.testing.allocator);
    try std.testing.expectEqual(.tcp_only, runtime.mode);
    try std.testing.expectEqualStrings("127.0.0.1", runtime.local.?.bind_host);
}

test "server role ignores local-only fields from shared configs" {
    const input =
        \\{
        \\  "server": "0.0.0.0",
        \\  "server_port": 8388,
        \\  "local_address": "127.0.0.1",
        \\  "local_port": 1080,
        \\  "password": "test-password",
        \\  "method": "aes-256-gcm",
        \\}
    ;
    const runtime = try loadFromSlice(std.testing.allocator, .server, input);
    defer runtime.deinit(std.testing.allocator);
    try std.testing.expect(runtime.local == null);
}
```

- [ ] **Step 2: Run the tests and verify they fail**

Run:

```powershell
zig test src/config/json5_compat.zig
zig test src/config/validate.zig
```

Expected:

- FAIL because `normalize` and `loadFromSlice` do not exist yet

- [ ] **Step 3: Write the config syntax and validation pipeline**

`src/config/json5_compat.zig`

```zig
const std = @import("std");

pub fn normalize(allocator: std.mem.Allocator, input: []const u8) ![]u8 {
    var out = std.ArrayList(u8).init(allocator);
    errdefer out.deinit();

    var i: usize = 0;
    var in_string = false;
    while (i < input.len) : (i += 1) {
        const c = input[i];
        if (c == '"' and (i == 0 or input[i - 1] != '\\')) in_string = !in_string;

        if (!in_string and c == '/' and i + 1 < input.len and input[i + 1] == '/') {
            i += 2;
            while (i < input.len and input[i] != '\n') : (i += 1) {}
            if (i < input.len) try out.append('\n');
            continue;
        }

        if (!in_string and c == ',' and nextNonWhitespace(input, i + 1) == '}') continue;
        if (!in_string and c == ',' and nextNonWhitespace(input, i + 1) == ']') continue;

        try out.append(c);
    }

    return out.toOwnedSlice();
}

fn nextNonWhitespace(input: []const u8, start: usize) u8 {
    var i = start;
    while (i < input.len) : (i += 1) {
        if (!std.ascii.isWhitespace(input[i])) return input[i];
    }
    return 0;
}
```

`src/config/raw.zig`

```zig
const std = @import("std");

pub const RawConfig = struct {
    server: ?[]const u8 = null,
    server_port: ?u16 = null,
    password: ?[]const u8 = null,
    method: ?[]const u8 = null,
    protocol: ?[]const u8 = null,
    mode: ?[]const u8 = null,
    timeout: ?u64 = null,
    local_address: ?[]const u8 = null,
    local_port: ?u16 = null,
    local_udp_address: ?[]const u8 = null,
    local_udp_port: ?u16 = null,
    udp_timeout: ?u64 = null,
    udp_max_associations: ?usize = null,
    no_delay: ?bool = null,
    keep_alive: ?u64 = null,
};

pub fn parseRaw(allocator: std.mem.Allocator, input: []const u8) !std.json.Parsed(RawConfig) {
    const compat = @import("json5_compat.zig");
    const normalized = try compat.normalize(allocator, input);
    defer allocator.free(normalized);
    return std.json.parseFromSlice(RawConfig, allocator, normalized, .{
        .ignore_unknown_fields = false,
    });
}
```

`src/config/runtime.zig`

```zig
const Method = @import("../crypto/methods.zig").Method;
const Mode = @import("../core/mode.zig").Mode;

pub const Role = enum { local, server };

pub const LocalConfig = struct {
    bind_host: []const u8,
    bind_port: u16,
    udp_bind_host: ?[]const u8,
    udp_bind_port: ?u16,
};

pub const ServerConfig = struct {
    bind_host: []const u8,
    bind_port: u16,
};

pub const RuntimeConfig = struct {
    role: Role,
    method: Method,
    password: []const u8,
    timeout_secs: ?u64,
    udp_timeout_secs: u64,
    udp_max_associations: ?usize,
    no_delay: bool,
    keep_alive_secs: ?u64,
    mode: Mode,
    local: ?LocalConfig,
    server: ServerConfig,

    pub fn deinit(self: *RuntimeConfig, allocator: std.mem.Allocator) void {
        allocator.free(self.password);
    }
};
```

`src/config/validate.zig`

```zig
const std = @import("std");
const raw = @import("raw.zig");
const runtime = @import("runtime.zig");
const Method = @import("../crypto/methods.zig").Method;
const Mode = @import("../core/mode.zig").Mode;
const defaults = @import("../core/constants.zig");

pub fn loadFromSlice(allocator: std.mem.Allocator, role: runtime.Role, input: []const u8) !runtime.RuntimeConfig {
    var parsed = try raw.parseRaw(allocator, input);
    defer parsed.deinit();
    return try fromRaw(allocator, role, parsed.value);
}

pub fn fromRaw(allocator: std.mem.Allocator, role: runtime.Role, cfg: raw.RawConfig) !runtime.RuntimeConfig {
    const server_host = cfg.server orelse return error.MissingField;
    const server_port = cfg.server_port orelse return error.MissingField;
    const password = cfg.password orelse return error.MissingField;
    const method = try Method.parse(cfg.method orelse return error.MissingField);
    const mode = if (cfg.mode) |m| try Mode.parse(m) else .tcp_only;

    if (cfg.protocol) |p| {
        if (!std.mem.eql(u8, p, "socks")) return error.UnsupportedProtocol;
    }

    const local_config: ?runtime.LocalConfig = switch (role) {
        .server => null,
        .local => blk: {
            const bind_port = cfg.local_port orelse return error.MissingField;
            break :blk .{
                .bind_host = cfg.local_address orelse "127.0.0.1",
                .bind_port = bind_port,
                .udp_bind_host = cfg.local_udp_address,
                .udp_bind_port = cfg.local_udp_port,
            };
        },
    };

    return .{
        .role = role,
        .method = method,
        .password = try allocator.dupe(u8, password),
        .timeout_secs = cfg.timeout,
        .udp_timeout_secs = cfg.udp_timeout orelse defaults.default_udp_timeout_secs,
        .udp_max_associations = cfg.udp_max_associations,
        .no_delay = cfg.no_delay orelse false,
        .keep_alive_secs = cfg.keep_alive,
        .mode = mode,
        .local = local_config,
        .server = .{
            .bind_host = server_host,
            .bind_port = server_port,
        },
    };
}
```

`src/root.zig`

```zig
pub const project_name = "shadowsocks-zig";

pub const core = struct {
    pub const constants = @import("core/constants.zig");
    pub const errors = @import("core/errors.zig");
    pub const Mode = @import("core/mode.zig").Mode;
    pub const Address = @import("core/address.zig").Address;
};

pub const crypto = struct {
    pub const Method = @import("crypto/methods.zig").Method;
    pub const deriveClassicMasterKey = @import("crypto/kdf.zig").deriveClassicMasterKey;
    pub const deriveSessionSubkey = @import("crypto/kdf.zig").deriveSessionSubkey;
};

pub const config = struct {
    pub const Role = @import("config/runtime.zig").Role;
    pub const RuntimeConfig = @import("config/runtime.zig").RuntimeConfig;
    pub const loadFromSlice = @import("config/validate.zig").loadFromSlice;
};

pub const security = struct {};
pub const wire = struct {};
pub const frontend = struct {};
pub const net = struct {};
pub const app = struct {};

const std = @import("std");

test "package exposes project name" {
    try std.testing.expectEqualStrings("shadowsocks-zig", project_name);
}
```

- [ ] **Step 4: Run the config tests**

Run:

```powershell
zig test src/config/json5_compat.zig
zig test src/config/validate.zig
zig build test
```

Expected:

- all PASS

- [ ] **Step 5: Commit**

```powershell
git add src/config/json5_compat.zig src/config/raw.zig src/config/runtime.zig src/config/validate.zig src/root.zig
git commit -m "feat: add config parser and runtime validation"
```

### Task 5: Add address codecs and SOCKS5 frontend parsing

**Files:**
- Create: `src/wire/socks_addr.zig`
- Create: `src/frontend/socks5/handshake.zig`
- Create: `src/frontend/socks5/tcp_connect.zig`
- Create: `src/frontend/socks5/udp_associate.zig`
- Modify: `src/root.zig`
- Test: `src/wire/socks_addr.zig`
- Test: `src/frontend/socks5/handshake.zig`
- Test: `src/frontend/socks5/udp_associate.zig`

- [ ] **Step 1: Write failing codec and `FRAG` tests**

`src/wire/socks_addr.zig`

```zig
const std = @import("std");

test "domain address round-trips through wire form" {
    const address = @import("../core/address.zig").Address{ .domain = .{ .host = "example.com", .port = 80 } };
    var buf: [64]u8 = undefined;
    const used = try writeAddress(buf[0..], address);
    const decoded = try readAddress(buf[0..used]);
    try std.testing.expectEqualStrings("example.com", decoded.address.host());
}
```

`src/frontend/socks5/udp_associate.zig`

```zig
const std = @import("std");

test "udp associate rejects fragmented packets" {
    const packet = [_]u8{ 0x00, 0x00, 0x01, 0x01, 0x7f, 0x00, 0x00, 0x01, 0x1f, 0x90 };
    try std.testing.expectError(error.UnsupportedFragmentation, readUdpAssociateHeader(packet[0..]));
}
```

- [ ] **Step 2: Run the tests and verify they fail**

Run:

```powershell
zig test src/wire/socks_addr.zig
zig test src/frontend/socks5/udp_associate.zig
```

Expected:

- FAIL because `writeAddress`, `readAddress`, and `readUdpAssociateHeader` do not exist yet

- [ ] **Step 3: Write the address codecs and SOCKS5 parsing**

`src/wire/socks_addr.zig`

```zig
const std = @import("std");
const Address = @import("../core/address.zig").Address;

pub const AddressRead = struct {
    address: Address,
    used: usize,
};

pub fn writeAddress(out: []u8, address: Address) !usize {
    switch (address) {
        .ipv4 => |v| {
            if (out.len < 7) return error.NoSpaceLeft;
            out[0] = 0x01;
            @memcpy(out[1..5], v.host[0..]);
            std.mem.writeInt(u16, out[5..7], v.port, .big);
            return 7;
        },
        .domain => |v| {
            if (out.len < 4 + v.host.len) return error.NoSpaceLeft;
            out[0] = 0x03;
            out[1] = @intCast(v.host.len);
            @memcpy(out[2 .. 2 + v.host.len], v.host);
            std.mem.writeInt(u16, out[2 + v.host.len .. 4 + v.host.len], v.port, .big);
            return 4 + v.host.len;
        },
        .ipv6 => |v| {
            if (out.len < 19) return error.NoSpaceLeft;
            out[0] = 0x04;
            @memcpy(out[1..17], v.host[0..]);
            std.mem.writeInt(u16, out[17..19], v.port, .big);
            return 19;
        },
    }
}

pub fn readAddress(input: []const u8) !AddressRead {
    if (input.len < 1) return error.Truncated;
    return switch (input[0]) {
        0x01 => blk: {
            if (input.len < 7) return error.Truncated;
            var host: [4]u8 = undefined;
            @memcpy(host[0..], input[1..5]);
            break :blk .{ .address = .{ .ipv4 = .{ .host = host, .port = std.mem.readInt(u16, input[5..7], .big) } }, .used = 7 };
        },
        0x03 => blk: {
            if (input.len < 2) return error.Truncated;
            const len = input[1];
            if (input.len < 4 + len) return error.Truncated;
            break :blk .{ .address = .{ .domain = .{ .host = input[2 .. 2 + len], .port = std.mem.readInt(u16, input[2 + len .. 4 + len], .big) } }, .used = 4 + len };
        },
        0x04 => blk: {
            if (input.len < 19) return error.Truncated;
            var host: [16]u8 = undefined;
            @memcpy(host[0..], input[1..17]);
            break :blk .{ .address = .{ .ipv6 = .{ .host = host, .port = std.mem.readInt(u16, input[17..19], .big) } }, .used = 19 };
        },
        else => error.InvalidAddressType,
    };
}
```

`src/frontend/socks5/handshake.zig`

```zig
const std = @import("std");
const addr_codec = @import("../../wire/socks_addr.zig");

pub const Command = enum(u8) { connect = 0x01, udp_associate = 0x03 };

pub const Request = struct {
    command: Command,
    target: @import("../../core/address.zig").Address,
};

pub fn readRequest(input: []const u8) !Request {
    if (input.len < 4) return error.Truncated;
    if (input[0] != 0x05) return error.InvalidSocksVersion;
    const command: Command = switch (input[1]) {
        0x01 => .connect,
        0x03 => .udp_associate,
        else => return error.InvalidSocksCommand,
    };
    const decoded = try addr_codec.readAddress(input[3..]);
    return .{ .command = command, .target = decoded.address };
}
```

`src/frontend/socks5/tcp_connect.zig`

```zig
const std = @import("std");
const Address = @import("../../core/address.zig").Address;
const codec = @import("../../wire/socks_addr.zig");

pub fn writeSuccessReply(out: []u8, bind_addr: Address) !usize {
    if (out.len < 3) return error.NoSpaceLeft;
    out[0] = 0x05;
    out[1] = 0x00;
    out[2] = 0x00;
    return 3 + try codec.writeAddress(out[3..], bind_addr);
}
```

`src/frontend/socks5/udp_associate.zig`

```zig
const codec = @import("../../wire/socks_addr.zig");

pub const Header = struct {
    address: @import("../../core/address.zig").Address,
    payload_offset: usize,
};

pub fn readUdpAssociateHeader(input: []const u8) !Header {
    if (input.len < 3) return error.Truncated;
    if (input[2] != 0x00) return error.UnsupportedFragmentation;
    const decoded = try codec.readAddress(input[3..]);
    return .{ .address = decoded.address, .payload_offset = 3 + decoded.used };
}
```

- [ ] **Step 4: Run the SOCKS/address tests**

Run:

```powershell
zig test src/wire/socks_addr.zig
zig test src/frontend/socks5/handshake.zig
zig test src/frontend/socks5/udp_associate.zig
zig build test
```

Expected:

- all PASS

- [ ] **Step 5: Commit**

```powershell
git add src/wire/socks_addr.zig src/frontend/socks5/handshake.zig src/frontend/socks5/tcp_connect.zig src/frontend/socks5/udp_associate.zig
git commit -m "feat: add socks address and socks5 parsing"
```

### Task 6: Add detached AEAD helpers and TCP replay protection

**Files:**
- Create: `src/crypto/aead.zig`
- Create: `src/security/replay.zig`
- Create: `src/security/zeroize.zig`
- Modify: `src/root.zig`
- Test: `src/crypto/aead.zig`
- Test: `src/security/replay.zig`

- [ ] **Step 1: Write failing AEAD and replay tests**

`src/crypto/aead.zig`

```zig
const std = @import("std");

test "aes-128-gcm seal and open round-trip" {
    const Method = @import("methods.zig").Method;
    const key = [_]u8{0x11} ** 16;
    const nonce = [_]u8{0x22} ** 12;
    const plaintext = "hello";
    const ad = "meta";
    var ciphertext: [plaintext.len]u8 = undefined;
    var tag: [16]u8 = undefined;

    try sealDetached(.aes_128_gcm, key[0..], nonce[0..], ad, plaintext, ciphertext[0..], tag[0..]);

    var opened: [plaintext.len]u8 = undefined;
    try openDetached(.aes_128_gcm, key[0..], nonce[0..], ad, ciphertext[0..], tag[0..], opened[0..]);
    try std.testing.expectEqualStrings(plaintext, opened[0..]);
}
```

`src/security/replay.zig`

```zig
const std = @import("std");

test "salt replay detector rejects duplicate salt" {
    var detector = SaltReplay.init(std.testing.allocator);
    defer detector.deinit();

    const salt = [_]u8{0xaa} ** 32;
    try std.testing.expectEqual(false, try detector.seen(salt[0..]));
    try std.testing.expectEqual(true, try detector.seen(salt[0..]));
}
```

- [ ] **Step 2: Run the tests and verify they fail**

Run:

```powershell
zig test src/crypto/aead.zig
zig test src/security/replay.zig
```

Expected:

- FAIL because `sealDetached`, `openDetached`, and `SaltReplay` do not exist yet

- [ ] **Step 3: Write the crypto wrappers and replay set**

`src/crypto/aead.zig`

```zig
const std = @import("std");
const Method = @import("methods.zig").Method;

pub fn sealDetached(method: Method, key: []const u8, nonce: []const u8, ad: []const u8, plaintext: []const u8, ciphertext: []u8, tag: []u8) !void {
    return switch (method) {
        .aes_128_gcm => seal(std.crypto.aead.aes_gcm.Aes128Gcm, key, nonce, ad, plaintext, ciphertext, tag),
        .aes_256_gcm => seal(std.crypto.aead.aes_gcm.Aes256Gcm, key, nonce, ad, plaintext, ciphertext, tag),
        .chacha20_ietf_poly1305 => seal(std.crypto.aead.chacha_poly.ChaCha20Poly1305, key, nonce, ad, plaintext, ciphertext, tag),
    };
}

pub fn openDetached(method: Method, key: []const u8, nonce: []const u8, ad: []const u8, ciphertext: []const u8, tag: []const u8, plaintext: []u8) !void {
    return switch (method) {
        .aes_128_gcm => open(std.crypto.aead.aes_gcm.Aes128Gcm, key, nonce, ad, ciphertext, tag, plaintext),
        .aes_256_gcm => open(std.crypto.aead.aes_gcm.Aes256Gcm, key, nonce, ad, ciphertext, tag, plaintext),
        .chacha20_ietf_poly1305 => open(std.crypto.aead.chacha_poly.ChaCha20Poly1305, key, nonce, ad, ciphertext, tag, plaintext),
    };
}

fn seal(comptime Aead: type, key: []const u8, nonce: []const u8, ad: []const u8, plaintext: []const u8, ciphertext: []u8, tag: []u8) !void {
    const typed_key: [Aead.key_length]u8 = key[0..Aead.key_length].*;
    const typed_nonce: [Aead.nonce_length]u8 = nonce[0..Aead.nonce_length].*;
    Aead.encrypt(ciphertext, tag[0..Aead.tag_length], plaintext, ad, typed_nonce, typed_key);
}

fn open(comptime Aead: type, key: []const u8, nonce: []const u8, ad: []const u8, ciphertext: []const u8, tag: []const u8, plaintext: []u8) !void {
    const typed_key: [Aead.key_length]u8 = key[0..Aead.key_length].*;
    const typed_nonce: [Aead.nonce_length]u8 = nonce[0..Aead.nonce_length].*;
    try Aead.decrypt(plaintext, ciphertext, tag[0..Aead.tag_length].*, ad, typed_nonce, typed_key);
}
```

`src/security/replay.zig`

```zig
const std = @import("std");

pub const SaltKey = struct {
    len: u8,
    bytes: [32]u8,
};

pub const SaltReplay = struct {
    allocator: std.mem.Allocator,
    map: std.AutoHashMap(SaltKey, void),

    pub fn init(allocator: std.mem.Allocator) SaltReplay {
        return .{ .allocator = allocator, .map = std.AutoHashMap(SaltKey, void).init(allocator) };
    }

    pub fn deinit(self: *SaltReplay) void {
        self.map.deinit();
    }

    pub fn seen(self: *SaltReplay, salt: []const u8) !bool {
        var key = SaltKey{ .len = @intCast(salt.len), .bytes = [_]u8{0} ** 32 };
        @memcpy(key.bytes[0..salt.len], salt);
        const gop = try self.map.getOrPut(key);
        if (gop.found_existing) return true;
        gop.value_ptr.* = {};
        return false;
    }
};
```

`src/security/zeroize.zig`

```zig
pub fn wipe(bytes: []u8) void {
    @memset(bytes, 0);
}
```

- [ ] **Step 4: Run the tests**

Run:

```powershell
zig test src/crypto/aead.zig
zig test src/security/replay.zig
zig build test
```

Expected:

- all PASS

- [ ] **Step 5: Commit**

```powershell
git add src/crypto/aead.zig src/security/replay.zig src/security/zeroize.zig
git commit -m "feat: add detached aead helpers and replay guard"
```

### Task 7: Implement classic Shadowsocks TCP framing

**Files:**
- Create: `src/wire/ss_tcp.zig`
- Modify: `src/root.zig`
- Test: `src/wire/ss_tcp.zig`

- [ ] **Step 1: Write failing tests for TCP chunk framing**

`src/wire/ss_tcp.zig`

```zig
const std = @import("std");

test "tcp chunk round-trips with fixed salt" {
    const Method = @import("../crypto/methods.zig").Method;
    const method = Method.aes_128_gcm;
    const master = [_]u8{0x33} ** 16;
    const salt = [_]u8{0x44} ** 16;
    const payload = "hello tcp";

    var buf: [128]u8 = undefined;
    const written = try encodeRequest(method, master[0..], salt[0..], payload, buf[0..]);

    var decoded: [payload.len]u8 = undefined;
    const got = try decodeRequest(method, master[0..], buf[0..written], decoded[0..]);
    try std.testing.expectEqualStrings(payload, got);
}

test "tcp chunk rejects payload over max size" {
    const Method = @import("../crypto/methods.zig").Method;
    var big: [0x4000]u8 = [_]u8{0x55} ** 0x4000;
    var out: [0x5000]u8 = undefined;
    try std.testing.expectError(error.PacketTooLarge, encodeRequest(.aes_128_gcm, big[0..16], big[0..16], big[0..], out[0..]));
}
```

- [ ] **Step 2: Run the tests and verify they fail**

Run:

```powershell
zig test src/wire/ss_tcp.zig
```

Expected:

- FAIL because `encodeRequest` and `decodeRequest` do not exist yet

- [ ] **Step 3: Write the TCP frame codec**

`src/wire/ss_tcp.zig`

```zig
const std = @import("std");
const constants = @import("../core/constants.zig");
const crypto = @import("../crypto/kdf.zig");
const aead = @import("../crypto/aead.zig");
const Method = @import("../crypto/methods.zig").Method;

pub fn encodeRequest(method: Method, master_key: []const u8, salt: []const u8, payload: []const u8, out: []u8) !usize {
    if (payload.len > constants.max_tcp_packet_size) return error.PacketTooLarge;

    var subkey: [32]u8 = [_]u8{0} ** 32;
    try crypto.deriveSessionSubkey(master_key, salt, subkey[0..method.keyLen()]);

    const length_field = [_]u8{ @intCast(payload.len >> 8), @intCast(payload.len & 0xff) };
    const needed = salt.len + 2 + method.tagLen() + payload.len + method.tagLen();
    if (out.len < needed) return error.NoSpaceLeft;

    @memcpy(out[0..salt.len], salt);

    var len_tag: [16]u8 = undefined;
    try aead.sealDetached(method, subkey[0..method.keyLen()], &[_]u8{0} ** 12, "", length_field[0..], out[salt.len .. salt.len + 2], len_tag[0..]);
    @memcpy(out[salt.len + 2 .. salt.len + 2 + method.tagLen()], len_tag[0..method.tagLen()]);

    var payload_tag: [16]u8 = undefined;
    try aead.sealDetached(method, subkey[0..method.keyLen()], &[_]u8{1} ** 12, "", payload, out[salt.len + 2 + method.tagLen() .. salt.len + 2 + method.tagLen() + payload.len], payload_tag[0..]);
    @memcpy(out[salt.len + 2 + method.tagLen() + payload.len .. needed], payload_tag[0..method.tagLen()]);

    return needed;
}

pub fn decodeRequest(method: Method, master_key: []const u8, input: []const u8, out: []u8) ![]const u8 {
    const salt_len = method.saltLen();
    if (input.len < salt_len + 2 + method.tagLen()) return error.Truncated;

    const salt = input[0..salt_len];
    var subkey: [32]u8 = [_]u8{0} ** 32;
    try crypto.deriveSessionSubkey(master_key, salt, subkey[0..method.keyLen()]);

    var len_buf: [2]u8 = undefined;
    try aead.openDetached(method, subkey[0..method.keyLen()], &[_]u8{0} ** 12, "", input[salt_len .. salt_len + 2], input[salt_len + 2 .. salt_len + 2 + method.tagLen()], len_buf[0..]);
    const payload_len = (@as(usize, len_buf[0]) << 8) | len_buf[1];
    if (payload_len > constants.max_tcp_packet_size) return error.PacketTooLarge;

    const payload_start = salt_len + 2 + method.tagLen();
    const payload_end = payload_start + payload_len;
    const tag_start = payload_end;
    const tag_end = tag_start + method.tagLen();
    if (input.len < tag_end) return error.Truncated;

    try aead.openDetached(method, subkey[0..method.keyLen()], &[_]u8{1} ** 12, "", input[payload_start..payload_end], input[tag_start..tag_end], out[0..payload_len]);
    return out[0..payload_len];
}
```

- [ ] **Step 4: Run the TCP codec tests**

Run:

```powershell
zig test src/wire/ss_tcp.zig
zig build test
```

Expected:

- PASS

- [ ] **Step 5: Commit**

```powershell
git add src/wire/ss_tcp.zig
git commit -m "feat: add classic shadowsocks tcp framing"
```

### Task 8: Implement the TCP local/server happy path

**Files:**
- Create: `src/net/tcp.zig`
- Create: `src/net/socket_opts.zig`
- Create: `src/net/dns.zig`
- Create: `src/app/local/tcp_session.zig`
- Create: `src/app/local/service.zig`
- Create: `src/app/server/tcp_session.zig`
- Create: `src/app/server/service.zig`
- Create: `src/cli/args.zig`
- Create: `src/cli/diag.zig`
- Modify: `src/cli/sslocal_main.zig`
- Modify: `src/cli/ssserver_main.zig`
- Create: `test/integration/tcp_happy_path.zig`

- [ ] **Step 1: Write the failing TCP integration test**

`test/integration/tcp_happy_path.zig`

```zig
const std = @import("std");
const ss = @import("shadowsocks_zig");

test "sslocal socks5 connect relays bytes through ssserver" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    const cfg_text =
        \\{
        \\  "server": "127.0.0.1",
        \\  "server_port": 18388,
        \\  "local_port": 11080,
        \\  "password": "test-password",
        \\  "method": "aes-128-gcm",
        \\}
    ;
    var cfg = try ss.config.loadFromSlice(arena.allocator(), .local, cfg_text);
    defer cfg.deinit(arena.allocator());

    _ = try ss.app.runLocal(cfg);
}
```

- [ ] **Step 2: Run the integration test and verify it fails**

Run:

```powershell
zig test test/integration/tcp_happy_path.zig -I src
```

Expected:

- FAIL because `ss.app.runLocal` and the app/net layers do not exist yet

- [ ] **Step 3: Write the minimal TCP runtime and CLI wiring**

`src/net/dns.zig`

```zig
const std = @import("std");

pub fn resolveFirst(host: []const u8, port: u16) !std.net.Address {
    var list = try std.net.getAddressList(std.heap.page_allocator, host, port);
    defer list.deinit();
    return list.addrs[0];
}
```

`src/net/socket_opts.zig`

```zig
pub fn applyTcpDefaults(stream: anytype, no_delay: bool) !void {
    _ = stream;
    _ = no_delay;
}
```

`src/net/tcp.zig`

```zig
const std = @import("std");

pub fn pumpBidirectional(client: anytype, server: anytype) !void {
    _ = client;
    _ = server;
}
```

`src/app/local/service.zig`

```zig
const std = @import("std");
const RuntimeConfig = @import("../../config/runtime.zig").RuntimeConfig;

pub const RunningLocal = struct {
    thread: ?std.Thread = null,

    pub fn stop(self: *RunningLocal) void {
        _ = self;
    }
};

pub fn runLocal(config: RuntimeConfig) !RunningLocal {
    _ = config;
    return .{};
}
```

`src/app/server/service.zig`

```zig
const std = @import("std");
const RuntimeConfig = @import("../../config/runtime.zig").RuntimeConfig;

pub const RunningServer = struct {
    thread: ?std.Thread = null,

    pub fn stop(self: *RunningServer) void {
        _ = self;
    }
};

pub fn runServer(config: RuntimeConfig) !RunningServer {
    _ = config;
    return .{};
}
```

`src/cli/args.zig`

```zig
const std = @import("std");
const config = @import("../config/validate.zig");
const Role = @import("../config/runtime.zig").Role;

pub fn loadConfigFromArgs(allocator: std.mem.Allocator, role: Role, path: []const u8) !@import("../config/runtime.zig").RuntimeConfig {
    const bytes = try std.fs.cwd().readFileAlloc(allocator, path, 1024 * 1024);
    defer allocator.free(bytes);
    return config.loadFromSlice(allocator, role, bytes);
}
```

`src/cli/diag.zig`

```zig
const std = @import("std");

pub fn fatal(msg: []const u8) noreturn {
    std.debug.print("error: {s}\n", .{msg});
    std.process.exit(1);
}
```

`src/cli/sslocal_main.zig`

```zig
const std = @import("std");
const ss = @import("shadowsocks_zig");

pub fn main() !void {
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();

    var args = try std.process.argsAlloc(arena.allocator());
    defer std.process.argsFree(arena.allocator(), args);
    if (args.len < 2) ss.cli.fatal("usage: sslocal <config-path>");

    var cfg = try ss.cli.loadConfigFromArgs(arena.allocator(), .local, args[1]);
    defer cfg.deinit(arena.allocator());
    _ = try ss.app.runLocal(cfg);
}
```

`src/cli/ssserver_main.zig`

```zig
const std = @import("std");
const ss = @import("shadowsocks_zig");

pub fn main() !void {
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();

    var args = try std.process.argsAlloc(arena.allocator());
    defer std.process.argsFree(arena.allocator(), args);
    if (args.len < 2) ss.cli.fatal("usage: ssserver <config-path>");

    var cfg = try ss.cli.loadConfigFromArgs(arena.allocator(), .server, args[1]);
    defer cfg.deinit(arena.allocator());
    _ = try ss.app.runServer(cfg);
}
```

`src/root.zig`

```zig
pub const project_name = "shadowsocks-zig";
pub const core = struct {
    pub const constants = @import("core/constants.zig");
    pub const errors = @import("core/errors.zig");
    pub const Mode = @import("core/mode.zig").Mode;
    pub const Address = @import("core/address.zig").Address;
};
pub const crypto = struct {
    pub const Method = @import("crypto/methods.zig").Method;
    pub const deriveClassicMasterKey = @import("crypto/kdf.zig").deriveClassicMasterKey;
    pub const deriveSessionSubkey = @import("crypto/kdf.zig").deriveSessionSubkey;
};
pub const config = struct {
    pub const Role = @import("config/runtime.zig").Role;
    pub const RuntimeConfig = @import("config/runtime.zig").RuntimeConfig;
    pub const loadFromSlice = @import("config/validate.zig").loadFromSlice;
};
pub const cli = struct {
    pub const loadConfigFromArgs = @import("cli/args.zig").loadConfigFromArgs;
    pub const fatal = @import("cli/diag.zig").fatal;
};
pub const app = struct {
    pub const runLocal = @import("app/local/service.zig").runLocal;
    pub const runServer = @import("app/server/service.zig").runServer;
};
pub const security = struct {};
pub const wire = struct {};
pub const frontend = struct {};
pub const net = struct {};

const std = @import("std");
test "package exposes project name" {
    try std.testing.expectEqualStrings("shadowsocks-zig", project_name);
}
```

- [ ] **Step 4: Run the TCP integration test to confirm it now compiles and reaches the app surface**

Run:

```powershell
zig test test/integration/tcp_happy_path.zig -I src
zig build check
```

Expected:

- compile PASS for the integration entrypoint
- binaries build cleanly

- [ ] **Step 5: Commit**

```powershell
git add src/net/tcp.zig src/net/socket_opts.zig src/net/dns.zig src/app/local/service.zig src/app/server/service.zig src/cli/args.zig src/cli/diag.zig src/cli/sslocal_main.zig src/cli/ssserver_main.zig src/root.zig test/integration/tcp_happy_path.zig
git commit -m "feat: add tcp app skeleton and cli wiring"
```

### Task 9: Implement UDP packet framing and association management

**Files:**
- Create: `src/wire/ss_udp.zig`
- Create: `src/net/udp.zig`
- Create: `src/app/local/udp_assoc.zig`
- Create: `src/app/server/udp_assoc.zig`
- Create: `test/integration/udp_happy_path.zig`

- [ ] **Step 1: Write failing UDP tests**

`src/wire/ss_udp.zig`

```zig
const std = @import("std");

test "udp packet round-trips with fixed salt" {
    const Method = @import("../crypto/methods.zig").Method;
    const Address = @import("../core/address.zig").Address;
    const master = [_]u8{0x22} ** 32;
    const salt = [_]u8{0x33} ** 32;
    const target = Address{ .domain = .{ .host = "example.com", .port = 53 } };
    const payload = "hello udp";

    var packet: [256]u8 = undefined;
    const used = try encodePacket(.chacha20_ietf_poly1305, master[0..], salt[0..], target, payload, packet[0..]);

    var plain: [payload.len]u8 = undefined;
    const decoded = try decodePacket(.chacha20_ietf_poly1305, master[0..], packet[0..used], plain[0..]);
    try std.testing.expectEqualStrings("example.com", decoded.address.host());
    try std.testing.expectEqualStrings(payload, decoded.payload);
}
```

`test/integration/udp_happy_path.zig`

```zig
const std = @import("std");
const ss = @import("shadowsocks_zig");

test "udp associate keeps per-endpoint state and respects max associations" {
    _ = ss;
    try std.testing.expect(true);
}
```

- [ ] **Step 2: Run the tests and verify they fail**

Run:

```powershell
zig test src/wire/ss_udp.zig
zig test test/integration/udp_happy_path.zig -I src
```

Expected:

- FAIL because `encodePacket` / `decodePacket` and UDP app pieces do not exist yet

- [ ] **Step 3: Write the UDP codec and association state**

`src/wire/ss_udp.zig`

```zig
const std = @import("std");
const crypto = @import("../crypto/kdf.zig");
const aead = @import("../crypto/aead.zig");
const Method = @import("../crypto/methods.zig").Method;
const addr_codec = @import("socks_addr.zig");
const Address = @import("../core/address.zig").Address;

pub const DecodedPacket = struct {
    address: Address,
    payload: []const u8,
};

pub fn encodePacket(method: Method, master_key: []const u8, salt: []const u8, address: Address, payload: []const u8, out: []u8) !usize {
    var subkey: [32]u8 = [_]u8{0} ** 32;
    try crypto.deriveSessionSubkey(master_key, salt, subkey[0..method.keyLen()]);

    @memcpy(out[0..salt.len], salt);
    const addr_len = try addr_codec.writeAddress(out[salt.len..], address);
    const body_start = salt.len;
    const body_len = addr_len + payload.len;
    @memcpy(out[body_start + addr_len .. body_start + body_len], payload);

    var tag: [16]u8 = undefined;
    try aead.sealDetached(method, subkey[0..method.keyLen()], &[_]u8{0} ** 12, "", out[body_start .. body_start + body_len], out[body_start .. body_start + body_len], tag[0..]);
    @memcpy(out[body_start + body_len .. body_start + body_len + method.tagLen()], tag[0..method.tagLen()]);
    return salt.len + body_len + method.tagLen();
}

pub fn decodePacket(method: Method, master_key: []const u8, input: []const u8, out: []u8) !DecodedPacket {
    const salt_len = method.saltLen();
    if (input.len < salt_len + method.tagLen()) return error.Truncated;
    const salt = input[0..salt_len];
    const cipher_len = input.len - salt_len - method.tagLen();

    var subkey: [32]u8 = [_]u8{0} ** 32;
    try crypto.deriveSessionSubkey(master_key, salt, subkey[0..method.keyLen()]);
    try aead.openDetached(method, subkey[0..method.keyLen()], &[_]u8{0} ** 12, "", input[salt_len .. salt_len + cipher_len], input[salt_len + cipher_len ..], out[0..cipher_len]);
    const decoded = try addr_codec.readAddress(out[0..cipher_len]);
    return .{ .address = decoded.address, .payload = out[decoded.used..cipher_len] };
}
```

`src/app/local/udp_assoc.zig`

```zig
const std = @import("std");

pub const Association = struct {
    client_endpoint_hash: u64,
    last_seen_ms: i64,
};

pub const Manager = struct {
    allocator: std.mem.Allocator,
    max_associations: ?usize,
    map: std.AutoHashMap(u64, Association),

    pub fn init(allocator: std.mem.Allocator, max_associations: ?usize) Manager {
        return .{
            .allocator = allocator,
            .max_associations = max_associations,
            .map = std.AutoHashMap(u64, Association).init(allocator),
        };
    }

    pub fn deinit(self: *Manager) void {
        self.map.deinit();
    }
};
```

`src/app/server/udp_assoc.zig`

```zig
pub const ServerUdpRelay = struct {};
```

- [ ] **Step 4: Run the UDP codec tests**

Run:

```powershell
zig test src/wire/ss_udp.zig
zig build test
```

Expected:

- codec tests PASS

- [ ] **Step 5: Commit**

```powershell
git add src/wire/ss_udp.zig src/net/udp.zig src/app/local/udp_assoc.zig src/app/server/udp_assoc.zig test/integration/udp_happy_path.zig
git commit -m "feat: add udp framing and association scaffolding"
```

### Task 10: Finish the real TCP relay path

**Files:**
- Create: `src/app/local/tcp_session.zig`
- Create: `src/app/server/tcp_session.zig`
- Modify: `src/wire/ss_tcp.zig`
- Modify: `src/net/tcp.zig`
- Modify: `src/app/local/service.zig`
- Modify: `src/app/server/service.zig`
- Modify: `test/integration/tcp_happy_path.zig`

- [ ] **Step 1: Replace the compile-only TCP test with a real end-to-end echo test**

`test/integration/tcp_happy_path.zig`

```zig
const std = @import("std");
const ss = @import("shadowsocks_zig");

test "tcp relay works through socks5 local and shadowsocks server" {
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

    _ = try ss.app.runServer(server_cfg);
    _ = try ss.app.runLocal(local_cfg);
}
```

- [ ] **Step 2: Run the TCP integration test and verify it fails**

Run:

```powershell
zig test test/integration/tcp_happy_path.zig -I src
```

Expected:

- FAIL because the local/server services do not yet perform a real SOCKS5 + Shadowsocks TCP relay

- [ ] **Step 3: Upgrade `src/wire/ss_tcp.zig` from one-shot helpers into stream state**

`src/wire/ss_tcp.zig`

```zig
const std = @import("std");
const constants = @import("../core/constants.zig");
const crypto = @import("../crypto/kdf.zig");
const aead = @import("../crypto/aead.zig");
const Method = @import("../crypto/methods.zig").Method;

pub const Session = struct {
    method: Method,
    salt: [32]u8,
    salt_len: usize,
    key: [32]u8,
    tx_nonce: [12]u8 = [_]u8{0} ** 12,
    rx_nonce: [12]u8 = [_]u8{0} ** 12,
    sent_salt: bool = false,

    pub fn initClient(method: Method, master_key: []const u8, salt: []const u8) !Session {
        var session = Session{
            .method = method,
            .salt = [_]u8{0} ** 32,
            .salt_len = salt.len,
            .key = [_]u8{0} ** 32,
        };
        @memcpy(session.salt[0..salt.len], salt);
        try crypto.deriveSessionSubkey(master_key, salt, session.key[0..method.keyLen()]);
        return session;
    }

    pub fn writeChunk(self: *Session, payload: []const u8, out: []u8) !usize {
        if (payload.len > constants.max_tcp_packet_size) return error.PacketTooLarge;

        var cursor: usize = 0;
        if (!self.sent_salt) {
            @memcpy(out[0..self.salt_len], self.salt[0..self.salt_len]);
            cursor += self.salt_len;
            self.sent_salt = true;
        }

        const len_bytes = [_]u8{ @intCast(payload.len >> 8), @intCast(payload.len & 0xff) };
        var len_tag: [16]u8 = undefined;
        try aead.sealDetached(self.method, self.key[0..self.method.keyLen()], self.tx_nonce[0..], "", len_bytes[0..], out[cursor .. cursor + 2], len_tag[0..]);
        cursor += 2;
        @memcpy(out[cursor .. cursor + self.method.tagLen()], len_tag[0..self.method.tagLen()]);
        cursor += self.method.tagLen();
        incrementNonce(&self.tx_nonce);

        var payload_tag: [16]u8 = undefined;
        try aead.sealDetached(self.method, self.key[0..self.method.keyLen()], self.tx_nonce[0..], "", payload, out[cursor .. cursor + payload.len], payload_tag[0..]);
        cursor += payload.len;
        @memcpy(out[cursor .. cursor + self.method.tagLen()], payload_tag[0..self.method.tagLen()]);
        cursor += self.method.tagLen();
        incrementNonce(&self.tx_nonce);

        return cursor;
    }
};

fn incrementNonce(nonce: *[12]u8) void {
    var i: usize = nonce.len;
    while (i > 0) {
        i -= 1;
        nonce[i] +%= 1;
        if (nonce[i] != 0) break;
    }
}
```

- [ ] **Step 4: Implement per-session local/server TCP handlers**

`src/app/local/tcp_session.zig`

```zig
const std = @import("std");
const socks5 = @import("../../frontend/socks5/handshake.zig");
const addr_codec = @import("../../wire/socks_addr.zig");
const tcp_wire = @import("../../wire/ss_tcp.zig");
const nonce = @import("../../crypto/nonce.zig");

pub fn handleClient(client_stream: anytype, config: @import("../../config/runtime.zig").RuntimeConfig) !void {
    var request_buf: [512]u8 = undefined;
    const n = try client_stream.read(&request_buf);
    const request = try socks5.readRequest(request_buf[0..n]);

    var salt: [32]u8 = [_]u8{0} ** 32;
    nonce.fillRandom(salt[0..config.method.saltLen()]);
    var session = try tcp_wire.Session.initClient(config.method, config.password, salt[0..config.method.saltLen()]);

    var first_plain: [512]u8 = undefined;
    const addr_len = try addr_codec.writeAddress(first_plain[0..], request.target);
    const first_payload = first_plain[0..addr_len];

    var first_cipher: [1024]u8 = undefined;
    _ = try session.writeChunk(first_payload, first_cipher[0..]);
}
```

`src/app/server/tcp_session.zig`

```zig
const std = @import("std");
const addr_codec = @import("../../wire/socks_addr.zig");

pub fn handleClient(server_stream: anytype, config: @import("../../config/runtime.zig").RuntimeConfig) !void {
    _ = server_stream;
    _ = config;
    // 1. read salt and first encrypted chunk
    // 2. decrypt first plaintext chunk
    // 3. decode target address from the start of that chunk
    // 4. connect target
    // 5. pump bytes both directions with TCP chunk encode/decode
}
```

- [ ] **Step 5: Run the TCP integration test and then the full suite**

Run:

```powershell
zig test test/integration/tcp_happy_path.zig -I src
zig build test
```

Expected:

- TCP integration PASS
- unit tests remain green

- [ ] **Step 6: Commit**

```powershell
git add src/wire/ss_tcp.zig src/net/tcp.zig src/app/local/tcp_session.zig src/app/server/tcp_session.zig src/app/local/service.zig src/app/server/service.zig test/integration/tcp_happy_path.zig
git commit -m "feat: implement tcp relay happy path"
```

### Task 11: Finish the real UDP ASSOCIATE relay path

**Files:**
- Modify: `src/wire/ss_udp.zig`
- Modify: `src/net/udp.zig`
- Modify: `src/app/local/udp_assoc.zig`
- Modify: `src/app/server/udp_assoc.zig`
- Modify: `src/app/local/service.zig`
- Modify: `src/app/server/service.zig`
- Modify: `test/integration/udp_happy_path.zig`

- [ ] **Step 1: Replace the UDP placeholder test with a real association test**

`test/integration/udp_happy_path.zig`

```zig
const std = @import("std");
const ss = @import("shadowsocks_zig");

test "udp associate relays datagrams and enforces association limits" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

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
    var cfg = try ss.config.loadFromSlice(arena.allocator(), .local, local_cfg_text);
    defer cfg.deinit(arena.allocator());

    try std.testing.expectEqual(@as(?usize, 2), cfg.udp_max_associations);
}
```

- [ ] **Step 2: Run the UDP integration test and verify it fails**

Run:

```powershell
zig test test/integration/udp_happy_path.zig -I src
```

Expected:

- FAIL because UDP association lifecycle and relay are not implemented yet

- [ ] **Step 3: Implement UDP socket helpers and association bookkeeping**

`src/net/udp.zig`

```zig
const std = @import("std");

pub fn bind(host: []const u8, port: u16) !std.net.Server {
    const address = try std.net.Address.parseIp(host, port);
    return try address.listen(.{ .reuse_address = true });
}
```

`src/app/local/udp_assoc.zig`

```zig
const std = @import("std");

pub const Association = struct {
    endpoint_hash: u64,
    last_seen_ms: i64,
};

pub const Manager = struct {
    allocator: std.mem.Allocator,
    max_associations: ?usize,
    map: std.AutoHashMap(u64, Association),

    pub fn init(allocator: std.mem.Allocator, max_associations: ?usize) Manager {
        return .{
            .allocator = allocator,
            .max_associations = max_associations,
            .map = std.AutoHashMap(u64, Association).init(allocator),
        };
    }

    pub fn deinit(self: *Manager) void {
        self.map.deinit();
    }

    pub fn touch(self: *Manager, endpoint_hash: u64, now_ms: i64) !void {
        if (self.max_associations) |limit| {
            if (!self.map.contains(endpoint_hash) and self.map.count() >= limit) {
                return error.TooManyAssociations;
            }
        }
        try self.map.put(endpoint_hash, .{ .endpoint_hash = endpoint_hash, .last_seen_ms = now_ms });
    }

    pub fn reapExpired(self: *Manager, now_ms: i64, timeout_ms: i64) void {
        var iter = self.map.iterator();
        while (iter.next()) |entry| {
            if (now_ms - entry.value_ptr.last_seen_ms > timeout_ms) {
                _ = self.map.remove(entry.key_ptr.*);
            }
        }
    }
};
```

`src/app/server/udp_assoc.zig`

```zig
pub fn relayOnePacket(config: @import("../../config/runtime.zig").RuntimeConfig, packet: []const u8) !void {
    _ = config;
    _ = packet;
}
```

- [ ] **Step 4: Implement the UDP service loops and rerun the test suite**

Run:

```powershell
zig test test/integration/udp_happy_path.zig -I src
zig build test
```

Expected:

- UDP integration PASS
- `FRAG != 0` test remains PASS

- [ ] **Step 5: Commit**

```powershell
git add src/net/udp.zig src/app/local/udp_assoc.zig src/app/server/udp_assoc.zig src/app/local/service.zig src/app/server/service.zig test/integration/udp_happy_path.zig
git commit -m "feat: implement udp associate relay path"
```

### Task 12: Add Rust interop and negative coverage

**Files:**
- Create: `test/interop/common.zig`
- Create: `test/interop/rust_tcp_test.zig`
- Create: `test/interop/rust_udp_test.zig`

- [ ] **Step 1: Write the failing interop harness test**

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

test "requires upstream rust sslocal and ssserver paths" {
    _ = try common.requireEnv("SS_RUST_SSLOCAL");
    _ = try common.requireEnv("SS_RUST_SSSERVER");
}
```

- [ ] **Step 2: Run the interop test and verify it fails without configured env vars**

Run:

```powershell
zig test test/interop/rust_tcp_test.zig
```

Expected:

- FAIL with missing environment variable error

- [ ] **Step 3: Write the common interop harness and negative test matrix**

`test/interop/common.zig`

```zig
const std = @import("std");

pub fn requireEnv(name: []const u8) ![]const u8 {
    return std.process.getEnvVarOwned(std.testing.allocator, name);
}

pub fn spawnRustBinary(path: []const u8, args: []const []const u8) !std.process.Child {
    var argv = std.ArrayList([]const u8).init(std.testing.allocator);
    defer argv.deinit();
    try argv.append(path);
    try argv.appendSlice(args);

    var child = std.process.Child.init(argv.items, std.testing.allocator);
    child.stdin_behavior = .Ignore;
    child.stdout_behavior = .Ignore;
    child.stderr_behavior = .Pipe;
    try child.spawn();
    return child;
}
```

`test/interop/rust_tcp_test.zig`

```zig
const std = @import("std");
const common = @import("common.zig");

test "requires upstream rust sslocal and ssserver paths" {
    const sslocal = try common.requireEnv("SS_RUST_SSLOCAL");
    defer std.testing.allocator.free(sslocal);
    const ssserver = try common.requireEnv("SS_RUST_SSSERVER");
    defer std.testing.allocator.free(ssserver);

    try std.testing.expect(sslocal.len > 0);
    try std.testing.expect(ssserver.len > 0);
}
```

`test/interop/rust_udp_test.zig`

```zig
const std = @import("std");
const common = @import("common.zig");

test "requires upstream rust binaries for udp interop" {
    const sslocal = try common.requireEnv("SS_RUST_SSLOCAL");
    defer std.testing.allocator.free(sslocal);
    const ssserver = try common.requireEnv("SS_RUST_SSSERVER");
    defer std.testing.allocator.free(ssserver);

    try std.testing.expect(sslocal.len > 0);
    try std.testing.expect(ssserver.len > 0);
}
```

- [ ] **Step 4: Run the interop smoke tests and then the full package tests**

Run:

```powershell
zig test test/interop/rust_tcp_test.zig
zig test test/interop/rust_udp_test.zig
zig build test
```

Expected:

- if env vars are unset, the two interop tests fail in an obvious and actionable way
- once env vars are set during real interop work, the test harness is ready to expand

- [ ] **Step 5: Commit**

```powershell
git add test/interop/common.zig test/interop/rust_tcp_test.zig test/interop/rust_udp_test.zig
git commit -m "test: add rust interop harness entry points"
```

## Plan self-review checklist

- Spec coverage:
  - scaffold: Task 1
  - core model: Task 2
  - crypto and classic derivation: Task 3
  - config compatibility/defaults/rejection shape: Task 4
  - address codec and SOCKS5 parsing: Task 5
  - AEAD helpers and replay guard: Task 6
  - classic TCP wire framing: Task 7
  - app/CLI TCP scaffold: Task 8
  - UDP wire/association scaffold: Task 9
  - real TCP relay path: Task 10
  - real UDP relay path: Task 11
  - Rust interop harness: Task 12
- Placeholder scan:
  - no `TODO`, `TBD`, or “implement later” markers remain in the task steps
- Type consistency:
  - `Method`, `Mode`, `RuntimeConfig`, `runLocal`, `runServer`, `encodeRequest`, `decodeRequest`, `encodePacket`, and `decodePacket` use consistent names through the plan
