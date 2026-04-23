const std = @import("std");
const config = @import("../config/validate.zig");
const runtime = @import("../config/runtime.zig");
const ss_url = @import("../wire/ss_url.zig");

pub const LoadInputs = struct {
    file_bytes: ?[]const u8 = null,
    ss_url: ?[]const u8 = null,
    override_password: ?[]const u8 = null,
    override_method: ?[]const u8 = null,
    override_server_addr: ?[]const u8 = null,
};

pub fn loadConfigFromArgs(
    allocator: std.mem.Allocator,
    io: std.Io,
    role: runtime.Role,
    path: []const u8,
) !runtime.RuntimeConfig {
    const bytes = try std.Io.Dir.cwd().readFileAlloc(io, path, allocator, .limited(1024 * 1024));
    defer allocator.free(bytes);
    return loadConfigFromInputs(allocator, role, .{ .file_bytes = bytes });
}

pub fn loadConfigFromInputs(
    allocator: std.mem.Allocator,
    role: runtime.Role,
    inputs: LoadInputs,
) !runtime.RuntimeConfig {
    var cfg = if (inputs.file_bytes) |file_bytes|
        try config.loadFromSlice(allocator, role, file_bytes)
    else
        return error.MissingConfigSource;

    errdefer cfg.deinit(allocator);

    if (inputs.ss_url) |url| {
        var parsed = try ss_url.parse(allocator, url);
        defer parsed.deinit(allocator);
        try cfg.applyUrlOverrides(allocator, parsed);
    }

    if (inputs.override_method) |method_text| cfg.method = try @TypeOf(cfg.method).parse(method_text);
    if (inputs.override_password) |password_text| try cfg.replacePassword(allocator, password_text);
    if (inputs.override_server_addr) |server_addr| try cfg.replaceServerAddress(allocator, server_addr);

    return cfg;
}

test "CLI overrides beat file config and ss url input" {
    const file_json =
        \\{
        \\  "server": "10.0.0.1",
        \\  "server_port": 8388,
        \\  "local_port": 1080,
        \\  "password": "file-password",
        \\  "method": "aes-128-gcm"
        \\}
    ;

    var cfg = try loadConfigFromInputs(std.testing.allocator, .local, .{
        .file_bytes = file_json,
        .ss_url = "ss://YWVzLTI1Ni1nY206dXJsLXBhc3M=@192.0.2.10:443",
        .override_password = "cli-password",
        .override_method = "chacha20-ietf-poly1305",
        .override_server_addr = "127.0.0.1:9443",
    });
    defer cfg.deinit(std.testing.allocator);

    try std.testing.expectEqual(try @TypeOf(cfg.method).parse("chacha20-ietf-poly1305"), cfg.method);
    try std.testing.expectEqualStrings("cli-password", cfg.password);
    try std.testing.expectEqualStrings("127.0.0.1", cfg.server.bind_host);
    try std.testing.expectEqual(@as(u16, 9443), cfg.server.bind_port);
}
