const std = @import("std");
const constants = @import("../core/constants.zig");
const ss_tcp = @import("../wire/ss_tcp.zig");
const Address = @import("../wire/socks_addr.zig").Address;

pub const net = std.Io.net;
pub const Stream = net.Stream;
pub const Server = net.Server;

const relay_buffer_len = 64 * 1024;

pub fn io() std.Io {
    return std.Io.Threaded.global_single_threaded.io();
}

pub const EncryptedReader = struct {
    session: ss_tcp.Session,
    buffered_len: usize = 0,
    buffer: [relay_buffer_len]u8 = undefined,

    pub fn init(session: ss_tcp.Session) EncryptedReader {
        return .{ .session = session };
    }

    pub fn nextPlain(self: *EncryptedReader, stream: Stream, out: []u8) !?[]const u8 {
        while (true) {
            if (self.buffered_len > 0) {
                const had_salt = self.session.received_salt;
                if (self.session.readChunk(self.buffer[0..self.buffered_len], out)) |plain| {
                    const used = frameLen(self.session.method, plain.len, had_salt);
                    consumeBuffered(self, used);
                    return plain;
                } else |err| switch (err) {
                    error.Truncated => {},
                    else => return err,
                }
            }

            if (self.buffered_len == self.buffer.len) return error.NoSpaceLeft;

            const n = read(stream, self.buffer[self.buffered_len..]) catch |err| {
                if (isClosedError(err)) {
                    return if (self.buffered_len == 0) null else error.Truncated;
                }
                return err;
            };
            if (n == 0) return if (self.buffered_len == 0) null else error.Truncated;
            self.buffered_len += n;
        }
    }
};

pub fn listenIp(host: []const u8, port: u16) !Server {
    var address = try net.IpAddress.parse(host, port);
    return address.listen(io(), .{ .reuse_address = true });
}

pub fn connectHost(host: []const u8, port: u16) !Stream {
    var address = net.IpAddress.parse(host, port) catch {
        const host_name = try net.HostName.init(host);
        return host_name.connect(io(), port, .{ .mode = .stream, .protocol = .tcp });
    };
    return address.connect(io(), .{ .mode = .stream, .protocol = .tcp });
}

pub fn connectTarget(target: Address) !Stream {
    return switch (target) {
        .domain => |domain| try connectHost(domain.host, domain.port),
        .ipv4 => |ipv4| blk: {
            var address = net.IpAddress{ .ip4 = .{ .bytes = ipv4.host, .port = ipv4.port } };
            break :blk try address.connect(io(), .{ .mode = .stream, .protocol = .tcp });
        },
        .ipv6 => |ipv6| blk: {
            var address = net.IpAddress{ .ip6 = .{ .bytes = ipv6.host, .port = ipv6.port } };
            break :blk try address.connect(io(), .{ .mode = .stream, .protocol = .tcp });
        },
    };
}

pub fn close(stream: Stream) void {
    stream.close(io());
}

pub fn shutdown(stream: Stream) void {
    stream.shutdown(io(), .both) catch {};
}

pub fn shutdownSend(stream: Stream) void {
    stream.shutdown(io(), .send) catch {};
}

pub fn accept(server: *Server) !Stream {
    return server.accept(io());
}

pub fn deinitServer(server: *Server) void {
    server.deinit(io());
}

pub fn read(stream: Stream, out: []u8) !usize {
    var buffers = [_][]u8{out};
    return io().vtable.netRead(io().userdata, stream.socket.handle, buffers[0..]);
}

pub fn readExact(stream: Stream, out: []u8) !void {
    var cursor: usize = 0;
    while (cursor < out.len) {
        const n = try read(stream, out[cursor..]);
        if (n == 0) return error.EndOfStream;
        cursor += n;
    }
}

pub fn writeAll(stream: Stream, bytes: []const u8) !void {
    var cursor: usize = 0;
    while (cursor < bytes.len) {
        const chunks = [_][]const u8{bytes[cursor..]};
        const n = try io().vtable.netWrite(io().userdata, stream.socket.handle, "", chunks[0..], 1);
        if (n == 0) return error.WriteFailed;
        cursor += n;
    }
}

pub fn pumpBidirectional(client: Stream, server: Stream) !void {
    const forward = try std.Thread.spawn(.{}, copyLoopWorker, .{ client, server });

    copyLoop(server, client) catch |err| {
        shutdown(client);
        shutdown(server);
        forward.join();
        return err;
    };
    shutdownSend(client);

    forward.join();
}

pub fn pumpShadowsocksBidirectional(
    plain_stream: Stream,
    ss_stream: Stream,
    inbound_reader: *EncryptedReader,
    outbound_session: *ss_tcp.Session,
) !void {
    const forward = try std.Thread.spawn(.{}, relayPlainToShadowsocksWorker, .{
        plain_stream,
        ss_stream,
        outbound_session,
    });

    relayShadowsocksToPlain(inbound_reader, ss_stream, plain_stream) catch |err| {
        shutdown(plain_stream);
        shutdown(ss_stream);
        forward.join();
        return err;
    };
    shutdownSend(plain_stream);

    forward.join();
}

fn copyLoopWorker(reader_stream: Stream, writer_stream: Stream) void {
    copyLoop(reader_stream, writer_stream) catch {};
    shutdownSend(writer_stream);
}

fn relayPlainToShadowsocksWorker(
    plain_stream: Stream,
    ss_stream: Stream,
    outbound_session: *ss_tcp.Session,
) void {
    relayPlainToShadowsocks(plain_stream, ss_stream, outbound_session) catch {};
    shutdownSend(ss_stream);
}

fn copyLoop(reader_stream: Stream, writer_stream: Stream) !void {
    var buf: [16 * 1024]u8 = undefined;
    while (true) {
        const n = read(reader_stream, &buf) catch |err| {
            if (isClosedError(err)) break;
            return err;
        };
        if (n == 0) break;

        writeAll(writer_stream, buf[0..n]) catch |err| {
            if (isClosedError(err)) break;
            return err;
        };
    }
}

fn relayPlainToShadowsocks(
    plain_stream: Stream,
    ss_stream: Stream,
    outbound_session: *ss_tcp.Session,
) !void {
    var plain_buf: [constants.max_tcp_packet_size]u8 = undefined;
    var frame_buf: [relay_buffer_len]u8 = undefined;

    while (true) {
        const n = read(plain_stream, &plain_buf) catch |err| {
            if (isClosedError(err)) break;
            return err;
        };
        if (n == 0) break;

        const used = try outbound_session.writeChunk(plain_buf[0..n], frame_buf[0..]);
        writeAll(ss_stream, frame_buf[0..used]) catch |err| {
            if (isClosedError(err)) break;
            return err;
        };
    }
}

fn relayShadowsocksToPlain(
    inbound_reader: *EncryptedReader,
    ss_stream: Stream,
    plain_stream: Stream,
) !void {
    var plain_buf: [constants.max_tcp_packet_size]u8 = undefined;

    while (true) {
        const maybe_plain = try inbound_reader.nextPlain(ss_stream, plain_buf[0..]);
        const plain = maybe_plain orelse break;

        writeAll(plain_stream, plain) catch |err| {
            if (isClosedError(err)) break;
            return err;
        };
    }
}

fn frameLen(method: ss_tcp.Method, payload_len: usize, had_salt: bool) usize {
    return (if (had_salt) @as(usize, 0) else method.saltLen()) + encodedChunkLen(method, payload_len);
}

fn encodedChunkLen(method: ss_tcp.Method, payload_len: usize) usize {
    const tag_len = method.tagLen();
    return 2 + tag_len + payload_len + tag_len;
}

fn consumeBuffered(reader: *EncryptedReader, used: usize) void {
    std.debug.assert(used <= reader.buffered_len);

    const remaining = reader.buffered_len - used;
    if (remaining > 0) {
        std.mem.copyForwards(u8, reader.buffer[0..remaining], reader.buffer[used..reader.buffered_len]);
    }
    reader.buffered_len = remaining;
}

fn isClosedError(err: anyerror) bool {
    return switch (err) {
        error.BrokenPipe,
        error.ConnectionAborted,
        error.ConnectionResetByPeer,
        error.NetworkDown,
        error.SocketUnconnected,
        => true,
        else => false,
    };
}
