const std = @import("std");

pub fn fillRandom(out: []u8) void {
    std.crypto.random.bytes(out);
}
