const std = @import("std");

pub fn resolveFirst(
    allocator: std.mem.Allocator,
    host: []const u8,
    port: u16,
) !std.net.Address {
    var list = try std.net.getAddressList(allocator, host, port);
    defer list.deinit();

    if (list.addrs.len == 0) return error.NoAddressResolved;
    return list.addrs[0];
}
