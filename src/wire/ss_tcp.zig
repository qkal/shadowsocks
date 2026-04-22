const std = @import("std");
const constants = @import("../core/constants.zig");
const kdf = @import("../crypto/kdf.zig");
const aead = @import("../crypto/aead.zig");

pub const Method = @import("../crypto/methods.zig").Method;

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
    try kdf.deriveSessionSubkey(master_key, salt, subkey[0..method.keyLen()]);

    std.mem.copyForwards(u8, out[0..salt.len], salt);

    const length_field = [2]u8{
        @intCast((payload.len >> 8) & 0xff),
        @intCast(payload.len & 0xff),
    };

    var length_nonce = [_]u8{0} ** 12;
    var payload_nonce = [_]u8{0} ** 12;
    payload_nonce[0] = 1;

    var length_tag: [16]u8 = undefined;
    try aead.sealDetached(
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
    try aead.sealDetached(
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
    try kdf.deriveSessionSubkey(master_key, salt, subkey[0..method.keyLen()]);

    var length_nonce = [_]u8{0} ** 12;
    var payload_nonce = [_]u8{0} ** 12;
    payload_nonce[0] = 1;

    var length_field: [2]u8 = undefined;
    try aead.openDetached(
        method,
        subkey[0..method.keyLen()],
        length_nonce[0..],
        "",
        input[salt_len .. salt_len + 2],
        input[salt_len + 2 .. salt_len + 2 + tag_len],
        length_field[0..],
    );

    // Classic Shadowsocks chunk length is a 14-bit big-endian value; the top
    // two bits of the 16-bit length field MUST be zero per the spec.
    if ((length_field[0] & 0xC0) != 0) return error.InvalidChunkLength;

    const payload_len = (@as(usize, length_field[0]) << 8) | @as(usize, length_field[1]);
    if (payload_len > constants.max_tcp_packet_size) return error.PacketTooLarge;
    if (out.len < payload_len) return error.NoSpaceLeft;

    const payload_start = salt_len + 2 + tag_len;
    const payload_end = payload_start + payload_len;
    const tag_start = payload_end;
    const tag_end = tag_start + tag_len;
    if (input.len < tag_end) return error.Truncated;

    try aead.openDetached(
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

test "tcp chunk rejects length field with non-zero top two bits" {
    const method = Method.aes_128_gcm;
    const master = [_]u8{0x77} ** 16;
    const salt = [_]u8{0x88} ** 16;

    // Hand-craft a chunk whose plaintext length field has the top two bits set
    // by encrypting a raw two-byte length of 0xC000 ("1100_0000 0000_0000"),
    // which is over the classic 14-bit limit.
    const tag_len = method.tagLen();
    var subkey: [16]u8 = undefined;
    try kdf.deriveSessionSubkey(master[0..], salt[0..], subkey[0..]);

    var frame: [16 + 2 + 16 + 1 + 16]u8 = undefined;
    std.mem.copyForwards(u8, frame[0..16], salt[0..]);

    const bad_length = [2]u8{ 0xC0, 0x00 };
    var length_nonce = [_]u8{0} ** 12;
    try aead.sealDetached(
        method,
        subkey[0..],
        length_nonce[0..],
        "",
        bad_length[0..],
        frame[16..18],
        frame[18 .. 18 + tag_len],
    );

    // Payload bytes after the length tag don't matter for this test; decodeRequest
    // must reject on the length field before ever touching them.
    const payload_plain = [_]u8{0x00};
    var payload_nonce = [_]u8{0} ** 12;
    payload_nonce[0] = 1;
    try aead.sealDetached(
        method,
        subkey[0..],
        payload_nonce[0..],
        "",
        payload_plain[0..],
        frame[18 + tag_len .. 18 + tag_len + 1],
        frame[18 + tag_len + 1 .. 18 + tag_len + 1 + tag_len],
    );

    var scratch: [1]u8 = undefined;
    try std.testing.expectError(
        error.InvalidChunkLength,
        decodeRequest(method, master[0..], frame[0..], scratch[0..]),
    );
}
