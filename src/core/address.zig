const std = @import("std");

pub const Address = union(enum) {
    ipv4: struct {
        host: [4]u8,
        port: u16,
    },
    ipv6: struct {
        host: [16]u8,
        port: u16,
    },
    domain: struct {
        host: []const u8,
        port: u16,
    },

    pub fn port(self: Address) u16 {
        return switch (self) {
            .ipv4 => |addr| addr.port,
            .ipv6 => |addr| addr.port,
            .domain => |addr| addr.port,
        };
    }

    pub fn host(self: Address) []const u8 {
        return switch (self) {
            .domain => |addr| addr.host,
            else => unreachable,
        };
    }
};

test "domain address keeps host and port" {
    const addr = Address{ .domain = .{
        .host = "example.com",
        .port = 443,
    } };

    try std.testing.expectEqualStrings("example.com", addr.host());
    try std.testing.expectEqual(@as(u16, 443), addr.port());
}
