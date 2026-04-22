const std = @import("std");

pub const SaltKey = struct {
    len: u8,
    bytes: [32]u8,
};

pub const SaltReplay = struct {
    allocator: std.mem.Allocator,
    entries: std.AutoHashMap(SaltKey, void),

    pub fn init(allocator: std.mem.Allocator) SaltReplay {
        return .{
            .allocator = allocator,
            .entries = std.AutoHashMap(SaltKey, void).init(allocator),
        };
    }

    pub fn deinit(self: *SaltReplay) void {
        self.entries.deinit();
    }

    pub fn seen(self: *SaltReplay, salt: []const u8) !bool {
        if (salt.len > 32) return error.InvalidLength;

        var key = SaltKey{
            .len = @intCast(salt.len),
            .bytes = [_]u8{0} ** 32,
        };
        std.mem.copyForwards(u8, key.bytes[0..salt.len], salt);

        const gop = try self.entries.getOrPut(key);
        if (gop.found_existing) return true;
        gop.value_ptr.* = {};
        return false;
    }
};

test "salt replay detector rejects duplicate salt" {
    var detector = SaltReplay.init(std.testing.allocator);
    defer detector.deinit();

    const salt = [_]u8{0xaa} ** 32;
    try std.testing.expectEqual(false, try detector.seen(salt[0..]));
    try std.testing.expectEqual(true, try detector.seen(salt[0..]));
}
