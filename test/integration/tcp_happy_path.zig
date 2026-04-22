const std = @import("std");
const ss = @import("shadowsocks_zig");

test "sslocal socks5 connect relays bytes through ssserver" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    const cfg_text =
        \\{
        \\  "server": "127.0.0.1",
        \\  "server_port": 18388,
        \\  "local_port": 11080,
        \\  "password": "test-password",
        \\  "method": "aes-128-gcm",
        \\}
    ;

    var cfg = try ss.config.loadFromSlice(arena.allocator(), .local, cfg_text);
    defer cfg.deinit(arena.allocator());

    _ = try ss.app.runLocal(cfg);
}
