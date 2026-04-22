const std = @import("std");
const socks_addr = @import("../../wire/socks_addr.zig");

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
