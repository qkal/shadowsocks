const std = @import("std");
const ss = @import("shadowsocks_zig");

const tcp = ss.net.tcp;

test "sslocal relays socks5 tcp through ssserver to a tcp echo target" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    const server_cfg_text =
        \\{
        \\  "server": "127.0.0.1",
        \\  "server_port": 18388,
        \\  "password": "test-password",
        \\  "method": "aes-128-gcm",
        \\  "mode": "tcp_only"
        \\}
    ;
    const local_cfg_text =
        \\{
        \\  "server": "127.0.0.1",
        \\  "server_port": 18388,
        \\  "local_port": 11080,
        \\  "password": "test-password",
        \\  "method": "aes-128-gcm",
        \\  "mode": "tcp_only"
        \\}
    ;

    var server_cfg = try ss.config.loadFromSlice(arena.allocator(), .server, server_cfg_text);
    defer server_cfg.deinit(arena.allocator());
    var local_cfg = try ss.config.loadFromSlice(arena.allocator(), .local, local_cfg_text);
    defer local_cfg.deinit(arena.allocator());

    var running_server = try ss.app.runServer(server_cfg);
    defer running_server.stop();
    var running_local = try ss.app.runLocal(local_cfg);
    defer running_local.stop();

    try expectSocks5Echo("127.0.0.1", 11080, 19090, "hello through zig");
}

test "ssserver preserves payload bytes in first shadowsocks tcp chunk" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    const server_cfg_text =
        \\{
        \\  "server": "127.0.0.1",
        \\  "server_port": 18389,
        \\  "password": "test-password",
        \\  "method": "aes-128-gcm",
        \\  "mode": "tcp_only"
        \\}
    ;

    var server_cfg = try ss.config.loadFromSlice(arena.allocator(), .server, server_cfg_text);
    defer server_cfg.deinit(arena.allocator());

    var running_server = try ss.app.runServer(server_cfg);
    defer running_server.stop();

    try expectDirectShadowsocksEcho("127.0.0.1", 18389, 19091, "first payload survives");
}

fn expectSocks5Echo(proxy_host: []const u8, proxy_port: u16, target_port: u16, payload: []const u8) !void {
    var listener = try tcp.listenIp("127.0.0.1", target_port);
    defer tcp.deinitServer(&listener);

    const echo_thread = try std.Thread.spawn(.{}, runEchoOnce, .{ &listener, payload });
    defer echo_thread.join();

    const proxy = try tcp.connectHost(proxy_host, proxy_port);
    defer tcp.close(proxy);

    try tcp.writeAll(proxy, &[_]u8{ 0x05, 0x01, 0x00 });

    var greeting_reply: [2]u8 = undefined;
    try tcp.readExact(proxy, &greeting_reply);
    try std.testing.expectEqualSlices(u8, &[_]u8{ 0x05, 0x00 }, &greeting_reply);

    const connect_request = [_]u8{
        0x05,                                0x01,                         0x00, 0x01,
        127,                                 0,                            0,    1,
        @intCast((target_port >> 8) & 0xff), @intCast(target_port & 0xff),
    };
    try tcp.writeAll(proxy, &connect_request);

    var connect_reply: [10]u8 = undefined;
    try tcp.readExact(proxy, &connect_reply);
    try std.testing.expectEqual(@as(u8, 0x05), connect_reply[0]);
    try std.testing.expectEqual(@as(u8, 0x00), connect_reply[1]);

    try tcp.writeAll(proxy, payload);
    tcp.shutdownSend(proxy);

    var echoed: [128]u8 = undefined;
    const echoed_n = try tcp.read(proxy, &echoed);
    try std.testing.expectEqualStrings(payload, echoed[0..echoed_n]);
}

fn expectDirectShadowsocksEcho(server_host: []const u8, server_port: u16, target_port: u16, payload: []const u8) !void {
    var listener = try tcp.listenIp("127.0.0.1", target_port);
    defer tcp.deinitServer(&listener);

    const echo_thread = try std.Thread.spawn(.{}, runEchoOnce, .{ &listener, payload });
    defer echo_thread.join();

    const server = try tcp.connectHost(server_host, server_port);
    defer tcp.close(server);

    const method = ss.wire.ss_tcp.Method.aes_128_gcm;
    var master_key = [_]u8{0} ** 32;
    try ss.crypto.deriveClassicMasterKey("test-password", master_key[0..method.keyLen()]);

    var salt = [_]u8{0x42} ** 32;
    var outbound = try ss.wire.ss_tcp.Session.initClient(
        method,
        master_key[0..method.keyLen()],
        salt[0..method.saltLen()],
    );
    var inbound = tcp.EncryptedReader.init(
        try ss.wire.ss_tcp.Session.initServer(method, master_key[0..method.keyLen()]),
    );

    var first_plain: [ss.core.constants.max_tcp_packet_size]u8 = undefined;
    const target = ss.wire.socks_addr.Address{ .ipv4 = .{
        .host = .{ 127, 0, 0, 1 },
        .port = target_port,
    } };
    const address_len = try ss.wire.socks_addr.writeAddress(&first_plain, target);
    @memcpy(first_plain[address_len .. address_len + payload.len], payload);

    var frame: [1024]u8 = undefined;
    const frame_len = try outbound.writeChunk(first_plain[0 .. address_len + payload.len], &frame);
    try tcp.writeAll(server, frame[0..frame_len]);
    tcp.shutdownSend(server);

    var echoed: [128]u8 = undefined;
    const plain = (try inbound.nextPlain(server, &echoed)) orelse return error.EndOfStream;
    try std.testing.expectEqualStrings(payload, plain);
}

fn runEchoOnce(listener: *tcp.Server, expected: []const u8) !void {
    const accepted = try tcp.accept(listener);
    defer tcp.close(accepted);

    var buf: [128]u8 = undefined;
    const n = try tcp.read(accepted, &buf);
    try std.testing.expectEqualStrings(expected, buf[0..n]);
    try tcp.writeAll(accepted, buf[0..n]);
}
