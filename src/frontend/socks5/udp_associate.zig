const std = @import("std");
const socks_addr = @import("../../wire/socks_addr.zig");

pub const Address = socks_addr.Address;

pub const Header = struct {
    address: Address,
    payload_offset: usize,
};

pub fn readUdpAssociateHeader(input: []const u8) !Header {
    if (input.len < 3) return error.Truncated;
    if (input[0] != 0 or input[1] != 0) return error.InvalidReservedField;
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

test "udp associate rejects non-zero reserved bytes" {
    const packet = [_]u8{
        0x01, 0x00, 0x00, 0x01, 0x7f,
        0x00, 0x00, 0x01, 0x1f, 0x90,
    };

    try std.testing.expectError(error.InvalidReservedField, readUdpAssociateHeader(&packet));
}
