const std = @import("std");
const RuntimeConfig = @import("../../config/runtime.zig").RuntimeConfig;
const tcp = @import("../../net/tcp.zig");
const socket_opts = @import("../../net/socket_opts.zig");
const kdf = @import("../../crypto/kdf.zig");
const socks5 = @import("../../frontend/socks5/handshake.zig");
const tcp_connect = @import("../../frontend/socks5/tcp_connect.zig");
const tcp_wire = @import("../../wire/ss_tcp.zig");

pub const LocalTcpSession = struct {
    pub fn handleClient(client: tcp.Stream, config: RuntimeConfig) !void {
        defer tcp.close(client);
        return LocalTcpSession.handleClientBorrowed(client, config);
    }

    pub fn handleClientBorrowed(client: tcp.Stream, config: RuntimeConfig) !void {
        try socket_opts.applyTcpDefaults(client, config.no_delay);

        try negotiateNoAuth(client);

        var request_buf: [512]u8 = undefined;
        const request = try readSocksRequest(client, request_buf[0..]);
        if (request.command != .connect) return error.UnsupportedSocksCommand;

        const upstream = try tcp.connectHost(config.server.bind_host, config.server.bind_port);
        defer tcp.close(upstream);
        try socket_opts.applyTcpDefaults(upstream, config.no_delay);

        const method = toWireMethod(config.method);
        const master_key = try deriveMasterKey(config, method);
        var outbound_session = try initClientSession(method, master_key[0..method.keyLen()]);
        var inbound_reader = tcp.EncryptedReader.init(
            try tcp_wire.Session.initServer(method, master_key[0..method.keyLen()]),
        );

        var first_plain: [512]u8 = undefined;
        const addr_len = try writeAddress(first_plain[0..], request.target);

        var first_frame: [1024]u8 = undefined;
        const first_used = try outbound_session.writeChunk(first_plain[0..addr_len], first_frame[0..]);
        try tcp.writeAll(upstream, first_frame[0..first_used]);

        var reply_buf: [64]u8 = undefined;
        const reply_len = try tcp_connect.writeSuccessReply(reply_buf[0..], .{
            .ipv4 = .{ .host = .{ 0, 0, 0, 0 }, .port = 0 },
        });
        try tcp.writeAll(client, reply_buf[0..reply_len]);

        try tcp.pumpShadowsocksBidirectional(client, upstream, &inbound_reader, &outbound_session);
    }
};

pub fn handleClient(client: tcp.Stream, config: RuntimeConfig) !void {
    return LocalTcpSession.handleClient(client, config);
}

pub fn handleClientBorrowed(client: tcp.Stream, config: RuntimeConfig) !void {
    return LocalTcpSession.handleClientBorrowed(client, config);
}

fn negotiateNoAuth(client: tcp.Stream) !void {
    var header: [2]u8 = undefined;
    try tcp.readExact(client, &header);
    if (header[0] != 0x05) return error.InvalidSocksVersion;

    const method_count = @as(usize, header[1]);
    var methods: [255]u8 = undefined;
    try tcp.readExact(client, methods[0..method_count]);

    var supports_no_auth = false;
    for (methods[0..method_count]) |method| {
        if (method == 0x00) {
            supports_no_auth = true;
            break;
        }
    }
    if (!supports_no_auth) return error.NoAcceptableAuthenticationMethod;

    try tcp.writeAll(client, &[_]u8{ 0x05, 0x00 });
}

fn readSocksRequest(client: tcp.Stream, out: []u8) !socks5.Request {
    if (out.len < 4) return error.NoSpaceLeft;
    try tcp.readExact(client, out[0..4]);

    const used = switch (out[3]) {
        0x01 => blk: {
            const total = 4 + 4 + 2;
            if (out.len < total) return error.NoSpaceLeft;
            try tcp.readExact(client, out[4..total]);
            break :blk total;
        },
        0x04 => blk: {
            const total = 4 + 16 + 2;
            if (out.len < total) return error.NoSpaceLeft;
            try tcp.readExact(client, out[4..total]);
            break :blk total;
        },
        0x03 => blk: {
            if (out.len < 5) return error.NoSpaceLeft;
            try tcp.readExact(client, out[4..5]);
            const host_len = @as(usize, out[4]);
            const total = 4 + 1 + host_len + 2;
            if (out.len < total) return error.NoSpaceLeft;
            try tcp.readExact(client, out[5..total]);
            break :blk total;
        },
        else => return error.InvalidAddressType,
    };

    return socks5.readRequest(out[0..used]);
}

fn deriveMasterKey(config: RuntimeConfig, method: tcp_wire.Method) ![32]u8 {
    var master_key = [_]u8{0} ** 32;
    try kdf.deriveClassicMasterKey(config.password, master_key[0..method.keyLen()]);
    return master_key;
}

fn initClientSession(method: tcp_wire.Method, master_key: []const u8) !tcp_wire.Session {
    var salt: [32]u8 = undefined;
    tcp.io().random(salt[0..method.saltLen()]);
    return tcp_wire.Session.initClient(
        method,
        master_key,
        salt[0..method.saltLen()],
    );
}

fn toWireMethod(method: anytype) tcp_wire.Method {
    return switch (method) {
        .aes_128_gcm => .aes_128_gcm,
        .aes_256_gcm => .aes_256_gcm,
        .chacha20_ietf_poly1305 => .chacha20_ietf_poly1305,
    };
}

fn writeAddress(out: []u8, address: anytype) !usize {
    return switch (address) {
        .ipv4 => |addr| writeIpv4(out, addr.host, addr.port),
        .ipv6 => |addr| writeIpv6(out, addr.host, addr.port),
        .domain => |addr| writeDomain(out, addr.host, addr.port),
    };
}

fn writeIpv4(out: []u8, host: [4]u8, port: u16) !usize {
    const needed = 1 + 4 + 2;
    if (out.len < needed) return error.NoSpaceLeft;
    out[0] = 0x01;
    std.mem.copyForwards(u8, out[1..5], &host);
    const port_bytes: *[2]u8 = @ptrCast(out[5..7].ptr);
    std.mem.writeInt(u16, port_bytes, port, .big);
    return needed;
}

fn writeIpv6(out: []u8, host: [16]u8, port: u16) !usize {
    const needed = 1 + 16 + 2;
    if (out.len < needed) return error.NoSpaceLeft;
    out[0] = 0x04;
    std.mem.copyForwards(u8, out[1..17], &host);
    const port_bytes: *[2]u8 = @ptrCast(out[17..19].ptr);
    std.mem.writeInt(u16, port_bytes, port, .big);
    return needed;
}

fn writeDomain(out: []u8, host: []const u8, port: u16) !usize {
    if (host.len > std.math.maxInt(u8)) return error.NoSpaceLeft;
    const needed = 1 + 1 + host.len + 2;
    if (out.len < needed) return error.NoSpaceLeft;
    out[0] = 0x03;
    out[1] = @intCast(host.len);
    std.mem.copyForwards(u8, out[2 .. 2 + host.len], host);
    const port_bytes: *[2]u8 = @ptrCast(out[2 + host.len .. needed].ptr);
    std.mem.writeInt(u16, port_bytes, port, .big);
    return needed;
}
