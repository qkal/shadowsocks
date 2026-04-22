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
};

pub const local_socks_addr = struct {
    pub const Address = LocalAddress;

    pub const AddressRead = struct {
        address: LocalAddress,
        used: usize,
    };

    pub fn readAddress(input: []const u8) !AddressRead {
        if (input.len < 1) return error.Truncated;

        return switch (input[0]) {
            0x01 => decodeIpv4(input),
            0x03 => decodeDomain(input),
            0x04 => decodeIpv6(input),
            else => error.InvalidAddressType,
        };
    }

    fn decodeIpv4(input: []const u8) !AddressRead {
        const needed = 1 + 4 + 2;
        if (input.len < needed) return error.Truncated;

        var host: [4]u8 = undefined;
        std.mem.copyForwards(u8, &host, input[1..5]);
        const port_bytes: *const [2]u8 = @ptrCast(input[5..7].ptr);
        const port = std.mem.readInt(u16, port_bytes, .big);
        return .{
            .address = .{ .ipv4 = .{ .host = host, .port = port } },
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
            .address = .{ .ipv6 = .{ .host = host, .port = port } },
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
            .address = .{ .domain = .{ .host = host, .port = port } },
            .used = needed,
        };
    }
};

const socks_addr = if (@hasDecl(Root, "wire")) Root.wire.socks_addr else @This().local_socks_addr;

pub const Address = socks_addr.Address;

pub const Command = enum(u8) {
    connect = 0x01,
    udp_associate = 0x03,
};

pub const Request = struct {
    command: Command,
    target: Address,
};

pub fn readRequest(input: []const u8) !Request {
    if (input.len < 4) return error.Truncated;
    if (input[0] != 0x05) return error.InvalidSocksVersion;
    if (input[2] != 0x00) return error.InvalidReservedField;

    const command = switch (input[1]) {
        0x01 => Command.connect,
        0x03 => Command.udp_associate,
        else => return error.InvalidSocksCommand,
    };

    const target = try socks_addr.readAddress(input[3..]);
    return .{
        .command = command,
        .target = target.address,
    };
}

test "parse SOCKS5 CONNECT request to domain target" {
    const request = [_]u8{
        0x05, 0x01, 0x00, 0x03, 0x0b,
        'e',  'x',  'a',  'm',  'p',
        'l',  'e',  '.',  'c',  'o',
        'm',  0x00, 0x50,
    };

    const parsed = try readRequest(&request);
    try std.testing.expectEqual(Command.connect, parsed.command);

    switch (parsed.target) {
        .domain => |domain| try std.testing.expectEqualStrings("example.com", domain.host),
        else => return error.TestExpectedDomainTarget,
    }
}

test "reject non-zero reserved byte" {
    const request = [_]u8{
        0x05, 0x01, 0x01, 0x03, 0x0b,
        'e',  'x',  'a',  'm',  'p',
        'l',  'e',  '.',  'c',  'o',
        'm',  0x00, 0x50,
    };

    try std.testing.expectError(error.InvalidReservedField, readRequest(&request));
}
