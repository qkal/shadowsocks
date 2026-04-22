const std = @import("std");
const Root = @import("root");

const LocalAddress = union(enum) {
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

    pub fn port(self: LocalAddress) u16 {
        return switch (self) {
            .ipv4 => |addr| addr.port,
            .ipv6 => |addr| addr.port,
            .domain => |addr| addr.port,
        };
    }

    pub fn host(self: LocalAddress) []const u8 {
        return switch (self) {
            .domain => |addr| addr.host,
            else => unreachable,
        };
    }
};

pub const Address = if (@hasDecl(Root, "core")) Root.core.Address else LocalAddress;

pub const AddressRead = struct {
    address: Address,
    used: usize,
};

pub fn writeAddress(out: []u8, address: Address) !usize {
    return switch (address) {
        .ipv4 => |addr| encodeIpv4(out, addr.host, addr.port),
        .ipv6 => |addr| encodeIpv6(out, addr.host, addr.port),
        .domain => |addr| encodeDomain(out, addr.host, addr.port),
    };
}

pub fn readAddress(input: []const u8) !AddressRead {
    if (input.len < 1) return error.Truncated;

    return switch (input[0]) {
        0x01 => decodeIpv4(input),
        0x03 => decodeDomain(input),
        0x04 => decodeIpv6(input),
        else => error.InvalidAddressType,
    };
}

fn encodeIpv4(out: []u8, host: [4]u8, port: u16) !usize {
    const needed = 1 + 4 + 2;
    if (out.len < needed) return error.NoSpaceLeft;

    out[0] = 0x01;
    std.mem.copyForwards(u8, out[1..5], &host);
    const port_bytes: *[2]u8 = @ptrCast(out[5..7].ptr);
    std.mem.writeInt(u16, port_bytes, port, .big);
    return needed;
}

fn encodeIpv6(out: []u8, host: [16]u8, port: u16) !usize {
    const needed = 1 + 16 + 2;
    if (out.len < needed) return error.NoSpaceLeft;

    out[0] = 0x04;
    std.mem.copyForwards(u8, out[1..17], &host);
    const port_bytes: *[2]u8 = @ptrCast(out[17..19].ptr);
    std.mem.writeInt(u16, port_bytes, port, .big);
    return needed;
}

fn encodeDomain(out: []u8, host: []const u8, port: u16) !usize {
    if (host.len > std.math.maxInt(u8)) return error.NoSpaceLeft;

    const needed = 1 + 1 + host.len + 2;
    if (out.len < needed) return error.NoSpaceLeft;

    out[0] = 0x03;
    out[1] = @intCast(host.len);
    std.mem.copyForwards(u8, out[2 .. 2 + host.len], host);
    const port_bytes: *[2]u8 = @ptrCast(out[2 + host.len .. needed].ptr);
    std.mem.writeInt(u16, port_bytes, port, .big);
    return needed;
}

fn decodeIpv4(input: []const u8) !AddressRead {
    const needed = 1 + 4 + 2;
    if (input.len < needed) return error.Truncated;

    var host: [4]u8 = undefined;
    std.mem.copyForwards(u8, &host, input[1..5]);
    const port_bytes: *const [2]u8 = @ptrCast(input[5..7].ptr);
    const port = std.mem.readInt(u16, port_bytes, .big);

    return .{
        .address = .{ .ipv4 = .{
            .host = host,
            .port = port,
        } },
        .used = needed,
    };
}

fn decodeIpv6(input: []const u8) !AddressRead {
    const needed = 1 + 16 + 2;
    if (input.len < needed) return error.Truncated;

    var host: [16]u8 = undefined;
    std.mem.copyForwards(u8, &host, input[1..17]);
    const port_bytes: *const [2]u8 = @ptrCast(input[17..19].ptr);
    const port = std.mem.readInt(u16, port_bytes, .big);

    return .{
        .address = .{ .ipv6 = .{
            .host = host,
            .port = port,
        } },
        .used = needed,
    };
}

fn decodeDomain(input: []const u8) !AddressRead {
    if (input.len < 2) return error.Truncated;

    const host_len = @as(usize, input[1]);
    const needed = 1 + 1 + host_len + 2;
    if (input.len < needed) return error.Truncated;

    const host = input[2 .. 2 + host_len];
    const port_bytes: *const [2]u8 = @ptrCast(input[2 + host_len .. needed].ptr);
    const port = std.mem.readInt(u16, port_bytes, .big);

    return .{
        .address = .{ .domain = .{
            .host = host,
            .port = port,
        } },
        .used = needed,
    };
}

test "domain address round-trips through wire form" {
    const address = Address{ .domain = .{
        .host = "example.com",
        .port = 80,
    } };

    var buffer: [32]u8 = undefined;
    const used = try writeAddress(&buffer, address);
    try std.testing.expectEqual(@as(usize, 15), used);

    const decoded = try readAddress(buffer[0..used]);
    try std.testing.expectEqual(@as(usize, used), decoded.used);

    switch (decoded.address) {
        .domain => |decoded_domain| {
            try std.testing.expectEqualStrings("example.com", decoded_domain.host);
            try std.testing.expectEqual(@as(u16, 80), decoded_domain.port);
        },
        else => return error.TestExpectedDomainAddress,
    }
}
