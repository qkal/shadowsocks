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

    pub fn writeAddress(out: []u8, address: LocalAddress) !usize {
        return switch (address) {
            .ipv4 => |addr| encodeIpv4(out, addr.host, addr.port),
            .ipv6 => |addr| encodeIpv6(out, addr.host, addr.port),
            .domain => |addr| encodeDomain(out, addr.host, addr.port),
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
};

const socks_addr = if (@hasDecl(Root, "wire")) Root.wire.socks_addr else @This().local_socks_addr;

pub const Address = socks_addr.Address;

pub fn writeSuccessReply(out: []u8, bind_addr: Address) !usize {
    if (out.len < 3) return error.NoSpaceLeft;

    out[0] = 0x05;
    out[1] = 0x00;
    out[2] = 0x00;

    const used = try socks_addr.writeAddress(out[3..], bind_addr);
    return 3 + used;
}

test "write success reply prefixes socks5 status bytes" {
    const bind_addr = Address{ .domain = .{
        .host = "example.com",
        .port = 80,
    } };

    var buffer: [32]u8 = undefined;
    const used = try writeSuccessReply(&buffer, bind_addr);
    try std.testing.expect(used > 3);
    try std.testing.expectEqual(@as(u8, 0x05), buffer[0]);
    try std.testing.expectEqual(@as(u8, 0x00), buffer[1]);
    try std.testing.expectEqual(@as(u8, 0x00), buffer[2]);
}
