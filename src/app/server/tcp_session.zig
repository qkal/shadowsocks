const std = @import("std");
const RuntimeConfig = @import("../../config/runtime.zig").RuntimeConfig;
const tcp = @import("../../net/tcp.zig");
const constants = @import("../../core/constants.zig");
const socket_opts = @import("../../net/socket_opts.zig");
const kdf = @import("../../crypto/kdf.zig");
const addr_codec = @import("../../wire/socks_addr.zig");
const tcp_wire = @import("../../wire/ss_tcp.zig");

pub const ServerTcpSession = struct {
    pub fn handleClient(client: tcp.Stream, config: RuntimeConfig) !void {
        defer tcp.close(client);
        return ServerTcpSession.handleClientBorrowed(client, config);
    }

    pub fn handleClientBorrowed(client: tcp.Stream, config: RuntimeConfig) !void {
        try socket_opts.applyTcpDefaults(client, config.no_delay);

        const method = toWireMethod(config.method);
        const master_key = try deriveMasterKey(config, method);
        var inbound_reader = tcp.EncryptedReader.init(
            try tcp_wire.Session.initServer(method, master_key[0..method.keyLen()]),
        );

        var first_plain_buf: [constants.max_tcp_packet_size]u8 = undefined;
        const first_plain = (try inbound_reader.nextPlain(client, first_plain_buf[0..])) orelse {
            return error.EndOfStream;
        };
        const decoded = try addr_codec.readAddress(first_plain);

        const target = try tcp.connectTarget(decoded.address);
        defer tcp.close(target);
        try socket_opts.applyTcpDefaults(target, config.no_delay);

        if (first_plain.len > decoded.used) {
            try tcp.writeAll(target, first_plain[decoded.used..]);
        }

        var outbound_session = try initClientSession(method, master_key[0..method.keyLen()]);
        try tcp.pumpShadowsocksBidirectional(target, client, &inbound_reader, &outbound_session);
    }
};

pub fn handleClient(client: tcp.Stream, config: RuntimeConfig) !void {
    return ServerTcpSession.handleClient(client, config);
}

pub fn handleClientBorrowed(client: tcp.Stream, config: RuntimeConfig) !void {
    return ServerTcpSession.handleClientBorrowed(client, config);
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
