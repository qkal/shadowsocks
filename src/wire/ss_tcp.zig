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

pub const Session = struct {
    method: Method,
    master_key: [32]u8 = [_]u8{0} ** 32,
    key: [32]u8 = [_]u8{0} ** 32,
    salt: [32]u8 = [_]u8{0} ** 32,
    salt_len: usize = 0,
    tx_nonce: [12]u8 = [_]u8{0} ** 12,
    rx_nonce: [12]u8 = [_]u8{0} ** 12,
    sent_salt: bool = false,
    received_salt: bool = false,

    pub fn initClient(method: Method, master_key: []const u8, salt: []const u8) !Session {
        if (master_key.len != method.keyLen() or salt.len != method.saltLen()) return error.InvalidLength;

        var self = Session{
            .method = method,
            .salt_len = salt.len,
        };
        std.mem.copyForwards(u8, self.master_key[0..master_key.len], master_key);
        std.mem.copyForwards(u8, self.salt[0..salt.len], salt);
        try crypto.deriveSessionSubkey(master_key, salt, self.key[0..method.keyLen()]);
        return self;
    }

    pub fn initServer(method: Method, master_key: []const u8) !Session {
        if (master_key.len != method.keyLen()) return error.InvalidLength;

        var self = Session{
            .method = method,
        };
        std.mem.copyForwards(u8, self.master_key[0..master_key.len], master_key);
        return self;
    }

    pub fn writeChunk(self: *Session, payload: []const u8, out: []u8) !usize {
        if (payload.len > constants.max_tcp_packet_size) return error.PacketTooLarge;

        const salt_bytes: usize = if (self.sent_salt) 0 else self.salt_len;
        const needed = salt_bytes + encodedChunkLen(self.method, payload.len);
        if (out.len < needed) return error.NoSpaceLeft;

        var next_nonce = self.tx_nonce;
        var cursor: usize = 0;
        if (!self.sent_salt) {
            std.mem.copyForwards(u8, out[0..self.salt_len], self.salt[0..self.salt_len]);
            cursor = self.salt_len;
        }

        cursor += try encodeChunk(
            self.method,
            self.key[0..self.method.keyLen()],
            &next_nonce,
            payload,
            out[cursor..],
        );

        self.tx_nonce = next_nonce;
        self.sent_salt = true;
        return cursor;
    }

    pub fn readChunk(self: *Session, input: []const u8, out: []u8) ![]const u8 {
        var next_key = self.key;
        var next_salt = self.salt;
        var next_salt_len = self.salt_len;
        var next_nonce = self.rx_nonce;
        var next_received_salt = self.received_salt;
        var cursor: usize = 0;

        if (!next_received_salt) {
            next_salt_len = self.method.saltLen();
            if (input.len < next_salt_len) return error.Truncated;

            std.mem.copyForwards(u8, next_salt[0..next_salt_len], input[0..next_salt_len]);
            try crypto.deriveSessionSubkey(
                self.master_key[0..self.method.keyLen()],
                next_salt[0..next_salt_len],
                next_key[0..self.method.keyLen()],
            );

            next_received_salt = true;
            cursor = next_salt_len;
        }

        const plain = try decodeChunk(
            self.method,
            next_key[0..self.method.keyLen()],
            &next_nonce,
            input[cursor..],
            out,
        );

        self.key = next_key;
        self.salt = next_salt;
        self.salt_len = next_salt_len;
        self.rx_nonce = next_nonce;
        self.received_salt = next_received_salt;
        return plain;
    }
};

pub fn encodeRequest(
    method: Method,
    master_key: []const u8,
    salt: []const u8,
    payload: []const u8,
    out: []u8,
) !usize {
    var session = try Session.initClient(method, master_key, salt);
    return session.writeChunk(payload, out);
}

pub fn decodeRequest(
    method: Method,
    master_key: []const u8,
    input: []const u8,
    out: []u8,
) ![]const u8 {
    var session = try Session.initServer(method, master_key);
    return session.readChunk(input, out);
}

fn encodedChunkLen(method: Method, payload_len: usize) usize {
    const tag_len = method.tagLen();
    return 2 + tag_len + payload_len + tag_len;
}

fn encodeChunk(
    method: Method,
    key: []const u8,
    nonce: *[12]u8,
    payload: []const u8,
    out: []u8,
) !usize {
    if (payload.len > constants.max_tcp_packet_size) return error.PacketTooLarge;

    const needed = encodedChunkLen(method, payload.len);
    if (out.len < needed) return error.NoSpaceLeft;

    const tag_len = method.tagLen();
    const length_field = [2]u8{
        @intCast((payload.len >> 8) & 0xff),
        @intCast(payload.len & 0xff),
    };

    var next_nonce = nonce.*;
    try crypto.sealDetached(
        method,
        key,
        next_nonce[0..],
        "",
        length_field[0..],
        out[0..2],
        out[2 .. 2 + tag_len],
    );
    incrementNonce(&next_nonce);

    const payload_start = 2 + tag_len;
    try crypto.sealDetached(
        method,
        key,
        next_nonce[0..],
        "",
        payload,
        out[payload_start .. payload_start + payload.len],
        out[payload_start + payload.len .. needed],
    );
    incrementNonce(&next_nonce);

    nonce.* = next_nonce;
    return needed;
}

fn decodeChunk(
    method: Method,
    key: []const u8,
    nonce: *[12]u8,
    input: []const u8,
    out: []u8,
) ![]const u8 {
    const tag_len = method.tagLen();
    if (input.len < 2 + tag_len) return error.Truncated;

    var next_nonce = nonce.*;
    var length_field: [2]u8 = undefined;
    try crypto.openDetached(
        method,
        key,
        next_nonce[0..],
        "",
        input[0..2],
        input[2 .. 2 + tag_len],
        length_field[0..],
    );
    incrementNonce(&next_nonce);

    const payload_len = (@as(usize, length_field[0]) << 8) | @as(usize, length_field[1]);
    if (payload_len > constants.max_tcp_packet_size) return error.PacketTooLarge;
    if (out.len < payload_len) return error.NoSpaceLeft;

    const payload_start = 2 + tag_len;
    const payload_end = payload_start + payload_len;
    const tag_end = payload_end + tag_len;
    if (input.len < tag_end) return error.Truncated;

    try crypto.openDetached(
        method,
        key,
        next_nonce[0..],
        "",
        input[payload_start..payload_end],
        input[payload_end..tag_end],
        out[0..payload_len],
    );
    incrementNonce(&next_nonce);

    nonce.* = next_nonce;
    return out[0..payload_len];
}

fn incrementNonce(nonce: *[12]u8) void {
    var i: usize = nonce.len;
    while (i > 0) {
        i -= 1;
        nonce[i] +%= 1;
        if (nonce[i] != 0) break;
    }
}

test "client session writes salt once and server session decodes multiple chunks" {
    const method = Method.aes_128_gcm;
    const master = [_]u8{0x11} ** 16;
    const salt = [_]u8{0x22} ** 16;

    var client = try Session.initClient(method, master[0..], salt[0..]);
    var frame_one: [128]u8 = undefined;
    var frame_two: [128]u8 = undefined;
    const used_one = try client.writeChunk("one", frame_one[0..]);
    const used_two = try client.writeChunk("two", frame_two[0..]);

    try std.testing.expectEqual(@as(usize, method.saltLen() + encodedChunkLen(method, 3)), used_one);
    try std.testing.expectEqual(@as(usize, encodedChunkLen(method, 3)), used_two);

    var server = try Session.initServer(method, master[0..]);
    var plain_one: [16]u8 = undefined;
    const got_one = try server.readChunk(frame_one[0..used_one], plain_one[0..]);
    try std.testing.expectEqualStrings("one", got_one);

    var plain_two: [16]u8 = undefined;
    const got_two = try server.readChunk(frame_two[0..used_two], plain_two[0..]);
    try std.testing.expectEqualStrings("two", got_two);
}

test "tcp chunk rejects payload over max size" {
    var big: [0x4000]u8 = [_]u8{0x55} ** 0x4000;
    var out: [0x5000]u8 = undefined;
    try std.testing.expectError(
        error.PacketTooLarge,
        encodeRequest(.aes_128_gcm, big[0..16], big[0..16], big[0..], out[0..]),
    );
}

test "server session preserves state across truncated first chunk" {
    const method = Method.aes_128_gcm;
    const master = [_]u8{0x33} ** 16;
    const salt = [_]u8{0x44} ** 16;

    var client = try Session.initClient(method, master[0..], salt[0..]);
    var frame: [128]u8 = undefined;
    const used = try client.writeChunk("retry", frame[0..]);

    var server = try Session.initServer(method, master[0..]);
    var plain: [16]u8 = undefined;
    try std.testing.expectError(error.Truncated, server.readChunk(frame[0 .. used - 1], plain[0..]));

    const got = try server.readChunk(frame[0..used], plain[0..]);
    try std.testing.expectEqualStrings("retry", got);
}

test "server session preserves state across no-space failure" {
    const method = Method.aes_128_gcm;
    const master = [_]u8{0x55} ** 16;
    const salt = [_]u8{0x66} ** 16;

    var client = try Session.initClient(method, master[0..], salt[0..]);
    var frame: [128]u8 = undefined;
    const used = try client.writeChunk("hello", frame[0..]);

    var server = try Session.initServer(method, master[0..]);
    var too_small: [4]u8 = undefined;
    try std.testing.expectError(error.NoSpaceLeft, server.readChunk(frame[0..used], too_small[0..]));

    var plain: [16]u8 = undefined;
    const got = try server.readChunk(frame[0..used], plain[0..]);
    try std.testing.expectEqualStrings("hello", got);
}

test "server session preserves state across authentication failure" {
    const method = Method.aes_128_gcm;
    const master = [_]u8{0x77} ** 16;
    const salt = [_]u8{0x88} ** 16;

    var client = try Session.initClient(method, master[0..], salt[0..]);
    var frame: [128]u8 = undefined;
    const used = try client.writeChunk("auth", frame[0..]);

    var tampered = frame;
    tampered[used - 1] ^= 0x01;

    var server = try Session.initServer(method, master[0..]);
    var plain: [16]u8 = undefined;
    try std.testing.expectError(error.AuthenticationFailed, server.readChunk(tampered[0..used], plain[0..]));

    const got = try server.readChunk(frame[0..used], plain[0..]);
    try std.testing.expectEqualStrings("auth", got);
}

test "server session rejects oversized decrypted length without consuming state" {
    const method = Method.aes_128_gcm;
    const master = [_]u8{0x99} ** 16;
    const salt = [_]u8{0xaa} ** 16;

    var client = try Session.initClient(method, master[0..], salt[0..]);

    const salt_len = method.saltLen();
    const tag_len = method.tagLen();
    var oversized_frame: [64]u8 = undefined;
    std.mem.copyForwards(u8, oversized_frame[0..salt_len], salt[0..]);
    const oversized_len_field = [2]u8{ 0x40, 0x00 };
    var nonce = [_]u8{0} ** 12;
    try crypto.sealDetached(
        method,
        client.key[0..method.keyLen()],
        nonce[0..],
        "",
        oversized_len_field[0..],
        oversized_frame[salt_len .. salt_len + 2],
        oversized_frame[salt_len + 2 .. salt_len + 2 + tag_len],
    );
    const oversized_used = salt_len + 2 + tag_len;

    var server = try Session.initServer(method, master[0..]);
    var plain: [16]u8 = undefined;
    try std.testing.expectError(error.PacketTooLarge, server.readChunk(oversized_frame[0..oversized_used], plain[0..]));

    var valid_frame: [128]u8 = undefined;
    const valid_used = try client.writeChunk("ok", valid_frame[0..]);
    const got = try server.readChunk(valid_frame[0..valid_used], plain[0..]);
    try std.testing.expectEqualStrings("ok", got);
}
