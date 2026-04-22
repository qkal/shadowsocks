const std = @import("std");
const json5_compat = @import("json5_compat.zig");

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
    const normalized = try json5_compat.normalize(allocator, input);
    defer allocator.free(normalized);
    return try std.json.parseFromSlice(
        RawConfig,
        allocator,
        normalized,
        .{
            .ignore_unknown_fields = false,
            .allocate = .alloc_always,
        },
    );
}
