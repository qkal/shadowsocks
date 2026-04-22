const std = @import("std");
const Method = @import("methods.zig").Method;
const aes_gcm = std.crypto.aead.aes_gcm;
const chacha_poly = std.crypto.aead.chacha_poly;

pub const Error = error{
    UnsupportedMethod,
    InvalidLength,
    AuthenticationFailed,
};

pub fn sealDetached(
    method: Method,
    key: []const u8,
    nonce: []const u8,
    ad: []const u8,
    plaintext: []const u8,
    ciphertext: []u8,
    tag: []u8,
) Error!void {
    if (ciphertext.len != plaintext.len) return error.InvalidLength;

    switch (method) {
        .aes_128_gcm => try sealDetachedImpl(aes_gcm.Aes128Gcm, key, nonce, ad, plaintext, ciphertext, tag),
        .aes_256_gcm => try sealDetachedImpl(aes_gcm.Aes256Gcm, key, nonce, ad, plaintext, ciphertext, tag),
        .chacha20_ietf_poly1305 => try sealDetachedImpl(chacha_poly.ChaCha20Poly1305, key, nonce, ad, plaintext, ciphertext, tag),
    }
}

pub fn openDetached(
    method: Method,
    key: []const u8,
    nonce: []const u8,
    ad: []const u8,
    ciphertext: []const u8,
    tag: []const u8,
    plaintext: []u8,
) Error!void {
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
) Error!void {
    if (key.len != Aead.key_length or nonce.len != Aead.nonce_length or tag.len != Aead.tag_length) return error.InvalidLength;

    var key_buf: [Aead.key_length]u8 = undefined;
    var nonce_buf: [Aead.nonce_length]u8 = undefined;
    var tag_buf: [Aead.tag_length]u8 = undefined;

    std.mem.copyForwards(u8, key_buf[0..], key);
    std.mem.copyForwards(u8, nonce_buf[0..], nonce);

    Aead.encrypt(ciphertext, &tag_buf, plaintext, ad, nonce_buf, key_buf);
    std.mem.copyForwards(u8, tag, &tag_buf);
}

fn openDetachedImpl(
    comptime Aead: type,
    key: []const u8,
    nonce: []const u8,
    ad: []const u8,
    ciphertext: []const u8,
    tag: []const u8,
    plaintext: []u8,
) Error!void {
    if (key.len != Aead.key_length or nonce.len != Aead.nonce_length or tag.len != Aead.tag_length) return error.InvalidLength;

    var key_buf: [Aead.key_length]u8 = undefined;
    var nonce_buf: [Aead.nonce_length]u8 = undefined;
    var tag_buf: [Aead.tag_length]u8 = undefined;

    std.mem.copyForwards(u8, key_buf[0..], key);
    std.mem.copyForwards(u8, nonce_buf[0..], nonce);
    std.mem.copyForwards(u8, tag_buf[0..], tag);

    Aead.decrypt(plaintext, ciphertext, tag_buf, ad, nonce_buf, key_buf) catch return error.AuthenticationFailed;
}

test "aes-128-gcm seal/open round-trip" {
    const key = [_]u8{0x11} ** 16;
    const nonce = [_]u8{0x22} ** 12;
    const plaintext = "hello";
    const ad = "meta";

    var ciphertext: [plaintext.len]u8 = undefined;
    var tag: [16]u8 = undefined;
    try sealDetached(.aes_128_gcm, key[0..], nonce[0..], ad[0..], plaintext, ciphertext[0..], tag[0..]);

    var opened: [plaintext.len]u8 = undefined;
    try openDetached(.aes_128_gcm, key[0..], nonce[0..], ad[0..], ciphertext[0..], tag[0..], opened[0..]);
    try std.testing.expectEqualStrings(plaintext, opened[0..]);
}
