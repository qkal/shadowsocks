const std = @import("std");

pub const Method = enum {
    aes_128_gcm,
    aes_256_gcm,
    chacha20_ietf_poly1305,

    pub fn parse(text: []const u8) !Method {
        if (std.mem.eql(u8, text, "aes-128-gcm")) return .aes_128_gcm;
        if (std.mem.eql(u8, text, "aes-256-gcm")) return .aes_256_gcm;
        if (std.mem.eql(u8, text, "chacha20-ietf-poly1305")) return .chacha20_ietf_poly1305;
        return error.UnsupportedMethod;
    }

    pub fn keyLen(self: Method) usize {
        return switch (self) {
            .aes_128_gcm => 16,
            .aes_256_gcm => 32,
            .chacha20_ietf_poly1305 => 32,
        };
    }

    pub fn saltLen(self: Method) usize {
        return switch (self) {
            .aes_128_gcm => 16,
            .aes_256_gcm => 32,
            .chacha20_ietf_poly1305 => 32,
        };
    }

    pub fn tagLen(self: Method) usize {
        _ = self;
        return 16;
    }
};

test "parse aes-128-gcm and expose classic AEAD sizes" {
    const method = try Method.parse("aes-128-gcm");
    try std.testing.expectEqual(Method.aes_128_gcm, method);
    try std.testing.expectEqual(@as(usize, 16), method.keyLen());
    try std.testing.expectEqual(@as(usize, 16), method.saltLen());
    try std.testing.expectEqual(@as(usize, 16), method.tagLen());
}
