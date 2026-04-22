const std = @import("std");
const ss = @import("shadowsocks_zig");

// Placeholder integration test: the TCP relay is not implemented yet, so this
// test currently just exercises the config → `runLocal` path end-to-end to
// make sure the CLI glue compiles and links. Once the accept loop and session
// pump land, this file should grow a real loopback sslocal ↔ ssserver test.
test "sslocal accepts a loaded config without crashing" {
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
