const std = @import("std");
const Root = @import("root");

const compat = struct {
    pub const constants = struct {
        pub const max_tcp_packet_size: usize = 0x3fff;
    };

    pub const Method = enum {
        aes_128_gcm,
        aes_256_gcm,
        chacha20_ietf_poly1305,

        pub fn keyLen(self: @This()) usize {
            return switch (self) {
                .aes_128_gcm => 16,
                .aes_256_gcm => 32,
                .chacha20_ietf_poly1305 => 32,
            };
        }

        pub fn saltLen(self: @This()) usize {
            return self.keyLen();
        }

        pub fn tagLen(self: @This()) usize {
            _ = self;
            return 16;
        }
    };

    const HmacSha1 = std.crypto.auth.hmac.Hmac(std.crypto.hash.Sha1);
    const HkdfSha1 = std.crypto.kdf.hkdf.Hkdf(HmacSha1);
    const aes_gcm = std.crypto.aead.aes_gcm;
    const chacha_poly = std.crypto.aead.chacha_poly;

    pub fn deriveSessionSubkey(master_key: []const u8, salt: []const u8, out: []u8) !void {
        if (out.len == 0) return;
        const prk = HkdfSha1.extract(salt, master_key);
        HkdfSha1.expand(out, "ss-subkey", prk);
    }

    pub fn sealDetached(
        method: @This().Method,
        key: []const u8,
        nonce: []const u8,
        ad: []const u8,
        plaintext: []const u8,
        ciphertext: []u8,
        tag: []u8,
    ) !void {
        if (ciphertext.len != plaintext.len) return error.InvalidLength;
        switch (method) {
            .aes_128_gcm => try sealDetachedImpl(aes_gcm.Aes128Gcm, key, nonce, ad, plaintext, ciphertext, tag),
            .aes_256_gcm => try sealDetachedImpl(aes_gcm.Aes256Gcm, key, nonce, ad, plaintext, ciphertext, tag),
            .chacha20_ietf_poly1305 => try sealDetachedImpl(chacha_poly.ChaCha20Poly1305, key, nonce, ad, plaintext, ciphertext, tag),
        }
    }

    pub fn openDetached(
        method: @This().Method,
        key: []const u8,
        nonce: []const u8,
        ad: []const u8,
        ciphertext: []const u8,
        tag: []const u8,
        plaintext: []u8,
    ) !void {
        if (plaintext.len != ciphertext.len) return error.InvalidLength;
        switch (method) {
            .aes_128_gcm => try openDetachedImpl(aes_gcm.Aes128Gcm, key, nonce, ad, ciphertext, tag, plaintext),
            .aes_256_gcm => try openDetachedImpl(aes_gcm.Aes256Gcm, key, nonce, ad, ciphertext, tag, plaintext),
            .chacha20_ietf_poly1305 => try openDetachedImpl(chacha_poly.ChaCha20Poly1305, key, nonce, ad, ciphertext, tag, plaintext),
        }
    }

    fn sealDetachedImpl(
        comptime Aead: type,
        key: []const u8,
        nonce: []const u8,
        ad: []const u8,
        plaintext: []const u8,
        ciphertext: []u8,
        tag: []u8,
    ) !void {
        if (key.len != Aead.key_length or nonce.len != Aead.nonce_length or tag.len != Aead.tag_length) {
            return error.InvalidLength;
        }

        var key_buf: [Aead.key_length]u8 = undefined;
        var nonce_buf: [Aead.nonce_length]u8 = undefined;
        var tag_buf: [Aead.tag_length]u8 = undefined;
        defer std.crypto.secureZero(u8, @volatileCast(key_buf[0..]));
        defer std.crypto.secureZero(u8, @volatileCast(nonce_buf[0..]));
        defer std.crypto.secureZero(u8, @volatileCast(tag_buf[0..]));

        std.mem.copyForwards(u8, key_buf[0..], key);
        std.mem.copyForwards(u8, nonce_buf[0..], nonce);

        Aead.encrypt(ciphertext, &tag_buf, plaintext, ad, nonce_buf, key_buf);
        std.mem.copyForwards(u8, tag, tag_buf[0..]);
    }

    fn openDetachedImpl(
        comptime Aead: type,
        key: []const u8,
        nonce: []const u8,
        ad: []const u8,
        ciphertext: []const u8,
        tag: []const u8,
        plaintext: []u8,
    ) !void {
        if (key.len != Aead.key_length or nonce.len != Aead.nonce_length or tag.len != Aead.tag_length) {
            return error.InvalidLength;
        }

        var key_buf: [Aead.key_length]u8 = undefined;
        var nonce_buf: [Aead.nonce_length]u8 = undefined;
        var tag_buf: [Aead.tag_length]u8 = undefined;
        defer std.crypto.secureZero(u8, @volatileCast(key_buf[0..]));
        defer std.crypto.secureZero(u8, @volatileCast(nonce_buf[0..]));
        defer std.crypto.secureZero(u8, @volatileCast(tag_buf[0..]));

        std.mem.copyForwards(u8, key_buf[0..], key);
        std.mem.copyForwards(u8, nonce_buf[0..], nonce);
        std.mem.copyForwards(u8, tag_buf[0..], tag);

        Aead.decrypt(plaintext, ciphertext, tag_buf, ad, nonce_buf, key_buf) catch {
            return error.AuthenticationFailed;
        };
    }
};

const constants = if (@hasDecl(Root, "core")) Root.core.constants else compat.constants;
pub const Method = if (@hasDecl(Root, "crypto")) Root.crypto.Method else compat.Method;
const crypto = if (@hasDecl(Root, "crypto")) Root.crypto else compat;

pub fn encodeRequest(
    method: Method,
    master_key: []const u8,
    salt: []const u8,
    payload: []const u8,
    out: []u8,
) !usize {
    if (master_key.len != method.keyLen() or salt.len != method.saltLen()) return error.InvalidLength;
    if (payload.len > constants.max_tcp_packet_size) return error.PacketTooLarge;

    const tag_len = method.tagLen();
    const needed = salt.len + 2 + tag_len + payload.len + tag_len;
    if (out.len < needed) return error.NoSpaceLeft;

    var subkey: [32]u8 = [_]u8{0} ** 32;
    defer std.crypto.secureZero(u8, @volatileCast(subkey[0..]));
    try crypto.deriveSessionSubkey(master_key, salt, subkey[0..method.keyLen()]);

    std.mem.copyForwards(u8, out[0..salt.len], salt);

    const length_field = [2]u8{
        @intCast((payload.len >> 8) & 0xff),
        @intCast(payload.len & 0xff),
    };

    var length_nonce = [_]u8{0} ** 12;
    var payload_nonce = [_]u8{0} ** 12;
    payload_nonce[0] = 1;

    var length_tag: [16]u8 = undefined;
    try crypto.sealDetached(
        method,
        subkey[0..method.keyLen()],
        length_nonce[0..],
        "",
        length_field[0..],
        out[salt.len .. salt.len + 2],
        length_tag[0..tag_len],
    );
    std.mem.copyForwards(u8, out[salt.len + 2 .. salt.len + 2 + tag_len], length_tag[0..tag_len]);

    const payload_start = salt.len + 2 + tag_len;
    try crypto.sealDetached(
        method,
        subkey[0..method.keyLen()],
        payload_nonce[0..],
        "",
        payload,
        out[payload_start .. payload_start + payload.len],
        out[payload_start + payload.len .. needed],
    );

    return needed;
}

pub fn decodeRequest(
    method: Method,
    master_key: []const u8,
    input: []const u8,
    out: []u8,
) ![]const u8 {
    if (master_key.len != method.keyLen()) return error.InvalidLength;

    const salt_len = method.saltLen();
    const tag_len = method.tagLen();
    if (input.len < salt_len + 2 + tag_len) return error.Truncated;

    const salt = input[0..salt_len];

    var subkey: [32]u8 = [_]u8{0} ** 32;
    defer std.crypto.secureZero(u8, @volatileCast(subkey[0..]));
    try crypto.deriveSessionSubkey(master_key, salt, subkey[0..method.keyLen()]);

    var length_nonce = [_]u8{0} ** 12;
    var payload_nonce = [_]u8{0} ** 12;
    payload_nonce[0] = 1;

    var length_field: [2]u8 = undefined;
    try crypto.openDetached(
        method,
        subkey[0..method.keyLen()],
        length_nonce[0..],
        "",
        input[salt_len .. salt_len + 2],
        input[salt_len + 2 .. salt_len + 2 + tag_len],
        length_field[0..],
    );

    const payload_len = (@as(usize, length_field[0]) << 8) | @as(usize, length_field[1]);
    if (payload_len > constants.max_tcp_packet_size) return error.PacketTooLarge;
    if (out.len < payload_len) return error.NoSpaceLeft;

    const payload_start = salt_len + 2 + tag_len;
    const payload_end = payload_start + payload_len;
    const tag_start = payload_end;
    const tag_end = tag_start + tag_len;
    if (input.len < tag_end) return error.Truncated;

    try crypto.openDetached(
        method,
        subkey[0..method.keyLen()],
        payload_nonce[0..],
        "",
        input[payload_start..payload_end],
        input[tag_start..tag_end],
        out[0..payload_len],
    );

    return out[0..payload_len];
}

test "tcp chunk round-trips with fixed salt" {
    const method = Method.aes_128_gcm;
    const master = [_]u8{0x33} ** 16;
    const salt = [_]u8{0x44} ** 16;
    const payload = "hello tcp";

    var buf: [128]u8 = undefined;
    const written = try encodeRequest(method, master[0..], salt[0..], payload, buf[0..]);

    var decoded: [payload.len]u8 = undefined;
    const got = try decodeRequest(method, master[0..], buf[0..written], decoded[0..]);
    try std.testing.expectEqualStrings(payload, got);
}

test "tcp chunk rejects payload over max size" {
    var big: [0x4000]u8 = [_]u8{0x55} ** 0x4000;
    var out: [0x5000]u8 = undefined;
    try std.testing.expectError(
        error.PacketTooLarge,
        encodeRequest(.aes_128_gcm, big[0..16], big[0..16], big[0..], out[0..]),
    );
}
