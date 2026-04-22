const std = @import("std");
const raw = @import("raw.zig");
const runtime = @import("runtime.zig");
const defaults = @import("../core/constants.zig");

pub fn loadFromSlice(allocator: std.mem.Allocator, role: runtime.Role, input: []const u8) !runtime.RuntimeConfig {
    const parsed = try raw.parseRaw(allocator, input);
    defer parsed.deinit();
    return fromRaw(allocator, role, parsed.value);
}

pub fn fromRaw(allocator: std.mem.Allocator, role: runtime.Role, cfg: raw.RawConfig) !runtime.RuntimeConfig {
    const server_host = cfg.server orelse return error.MissingField;
    const server_port = cfg.server_port orelse return error.MissingField;
    const password = cfg.password orelse return error.MissingField;
    const method_text = cfg.method orelse return error.MissingField;

    const method = try runtime.Method.parse(method_text);
    const mode = if (cfg.mode) |mode_text| try runtime.Mode.parse(mode_text) else .tcp_only;

    if (cfg.protocol) |protocol| {
        if (!std.mem.eql(u8, protocol, "socks")) return error.UnsupportedProtocol;
    }

    const runtime_password = try allocator.dupe(u8, password);
    errdefer allocator.free(runtime_password);
    const runtime_server_host = try allocator.dupe(u8, server_host);
    errdefer allocator.free(runtime_server_host);

    const timeout_secs = cfg.timeout;
    const udp_timeout_secs = cfg.udp_timeout orelse defaults.default_udp_timeout_secs;
    const udp_max_associations = cfg.udp_max_associations orelse defaults.default_udp_max_associations;
    const no_delay = cfg.no_delay orelse false;
    const keep_alive_secs = cfg.keep_alive;

    var local_config: ?runtime.LocalConfig = null;
    if (role == .local) {
        const local_port = cfg.local_port orelse return error.MissingField;
        const local_host = try allocator.dupe(u8, cfg.local_address orelse "127.0.0.1");
        errdefer allocator.free(local_host);

        const udp_host = if (cfg.local_udp_address) |address| blk: {
            const dup = try allocator.dupe(u8, address);
            break :blk dup;
        } else null;
        errdefer if (udp_host) |value| allocator.free(value);

        local_config = .{
            .bind_host = local_host,
            .bind_port = local_port,
            .udp_bind_host = udp_host,
            .udp_bind_port = cfg.local_udp_port,
        };
    }

    return .{
        .role = role,
        .method = method,
        .password = runtime_password,
        .timeout_secs = timeout_secs,
        .udp_timeout_secs = udp_timeout_secs,
        .udp_max_associations = udp_max_associations,
        .no_delay = no_delay,
        .keep_alive_secs = keep_alive_secs,
        .mode = mode,
        .local = local_config,
        .server = .{
            .bind_host = runtime_server_host,
            .bind_port = server_port,
        },
    };
}

test "local config defaults mode to tcp_only and bind host to 127.0.0.1 when local_address is omitted" {
    const input =
        \\{
        \\  "server": "127.0.0.1",
        \\  "server_port": 8388,
        \\  "local_port": 1080,
        \\  "password": "test-password",
        \\  "method": "aes-128-gcm",
        \\}
    ;

    var runtime_config = try loadFromSlice(std.testing.allocator, .local, input);
    defer runtime_config.deinit(std.testing.allocator);

    try std.testing.expectEqual(runtime.Mode.tcp_only, runtime_config.mode);
    try std.testing.expect(runtime_config.local != null);
    try std.testing.expectEqualStrings("127.0.0.1", runtime_config.local.?.bind_host);
}

test "server role ignores local-only fields from a shared config and leaves runtime.local = null" {
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

    var runtime_config = try loadFromSlice(std.testing.allocator, .server, input);
    defer runtime_config.deinit(std.testing.allocator);

    try std.testing.expect(runtime_config.local == null);
}
