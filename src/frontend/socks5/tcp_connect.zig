const std = @import("std");
const socks_addr = @import("../../wire/socks_addr.zig");

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
