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

pub const Header = struct {
    address: Address,
    payload_offset: usize,
};

pub fn readUdpAssociateHeader(input: []const u8) !Header {
    if (input.len < 3) return error.Truncated;
    if (input[2] != 0) return error.UnsupportedFragmentation;

    const decoded = try socks_addr.readAddress(input[3..]);
    return .{
        .address = decoded.address,
        .payload_offset = 3 + decoded.used,
    };
}

test "udp associate rejects fragmented packets" {
    const packet = [_]u8{
        0x00, 0x00, 0x01, 0x01, 0x7f,
        0x00, 0x00, 0x01, 0x1f, 0x90,
    };

    try std.testing.expectError(error.UnsupportedFragmentation, readUdpAssociateHeader(&packet));
}
