const std = @import("std");

pub const ParsedUrl = struct {
    method: []u8,
    password: []u8,
    host: []u8,
    port: u16,
    tag: ?[]u8 = null,

    pub fn deinit(self: *ParsedUrl, allocator: std.mem.Allocator) void {
        allocator.free(self.method);
        allocator.free(self.password);
        allocator.free(self.host);
        if (self.tag) |tag| allocator.free(tag);
    }
};

pub fn parse(allocator: std.mem.Allocator, input: []const u8) !ParsedUrl {
    if (!std.mem.startsWith(u8, input, "ss://")) return error.InvalidScheme;

    const without_scheme = input["ss://".len..];
    const hash_index = std.mem.indexOfScalar(u8, without_scheme, '#');
    const main = if (hash_index) |idx| without_scheme[0..idx] else without_scheme;
    const tag = if (hash_index) |idx| try allocator.dupe(u8, without_scheme[idx + 1 ..]) else null;
    errdefer if (tag) |value| allocator.free(value);

    const at_index = std.mem.indexOfScalar(u8, main, '@') orelse return error.InvalidAuthority;
    const encoded_userinfo = main[0..at_index];
    const host_port = main[at_index + 1 ..];

    const decoded_len = try std.base64.standard.Decoder.calcSizeForSlice(encoded_userinfo);
    const decoded_buf = try allocator.alloc(u8, decoded_len);
    defer allocator.free(decoded_buf);

    try std.base64.standard.Decoder.decode(decoded_buf, encoded_userinfo);
    const decoded = decoded_buf[0..decoded_len];
    const colon_index = std.mem.indexOfScalar(u8, decoded, ':') orelse return error.InvalidUserInfo;
    const last_colon = std.mem.lastIndexOfScalar(u8, host_port, ':') orelse return error.InvalidAuthority;

    return .{
        .method = try allocator.dupe(u8, decoded[0..colon_index]),
        .password = try allocator.dupe(u8, decoded[colon_index + 1 ..]),
        .host = try allocator.dupe(u8, host_port[0..last_colon]),
        .port = try std.fmt.parseInt(u16, host_port[last_colon + 1 ..], 10),
        .tag = tag,
    };
}

test "parse SIP002 URL into method password host port and tag" {
    const url = "ss://YWVzLTEyOC1nY206dGVzdC1wYXNzd29yZA==@127.0.0.1:8388#demo";
    var parsed = try parse(std.testing.allocator, url);
    defer parsed.deinit(std.testing.allocator);

    try std.testing.expectEqualStrings("aes-128-gcm", parsed.method);
    try std.testing.expectEqualStrings("test-password", parsed.password);
    try std.testing.expectEqualStrings("127.0.0.1", parsed.host);
    try std.testing.expectEqual(@as(u16, 8388), parsed.port);
    try std.testing.expectEqualStrings("demo", parsed.tag.?);
}
