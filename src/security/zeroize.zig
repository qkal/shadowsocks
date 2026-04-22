const std = @import("std");

pub fn wipe(bytes: []u8) void {
    std.crypto.secureZero(u8, @volatileCast(bytes));
}
