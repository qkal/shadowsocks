const std = @import("std");
const runtime = @import("../../config/runtime.zig");
const RuntimeConfig = runtime.RuntimeConfig;
const tcp = @import("../../net/tcp.zig");
const tcp_session = @import("tcp_session.zig");

const service_allocator = std.heap.page_allocator;

const ServiceState = struct {
    config: RuntimeConfig,
    stop_requested: std.atomic.Value(bool) = .init(false),
    mutex: std.Io.Mutex = .init,
    sessions: std.array_list.Managed(*ClientSession),

    fn deinit(self: *ServiceState) void {
        self.config.deinit(service_allocator);
        self.sessions.deinit();
    }
};

const ClientSession = struct {
    stream: tcp.Stream,
    config: RuntimeConfig,
    active: std.atomic.Value(bool) = .init(true),
    thread: ?std.Thread = null,

    fn deinit(self: *ClientSession) void {
        self.config.deinit(service_allocator);
    }
};

pub const RunningServer = struct {
    thread: ?std.Thread = null,
    state: ?*ServiceState = null,

    pub fn stop(self: *RunningServer) void {
        const state = self.state orelse return;
        if (!state.stop_requested.load(.acquire)) {
            state.stop_requested.store(true, .release);
            wakeListener(state.config.server.bind_host, state.config.server.bind_port);
        }

        if (self.thread) |thread| thread.join();
        shutdownSessions(state);
        joinSessions(state);
        state.deinit();
        service_allocator.destroy(state);
        self.* = .{};
    }
};

pub fn runServer(config: RuntimeConfig) !RunningServer {
    var state = try service_allocator.create(ServiceState);
    errdefer service_allocator.destroy(state);

    state.* = .{
        .config = try cloneRuntimeConfig(config),
        .stop_requested = .init(false),
        .sessions = std.array_list.Managed(*ClientSession).init(service_allocator),
    };
    errdefer state.deinit();

    var listener = try tcp.listenIp(state.config.server.bind_host, state.config.server.bind_port);
    errdefer tcp.deinitServer(&listener);

    const thread = try std.Thread.spawn(.{}, acceptLoop, .{ state, listener });
    return .{
        .thread = thread,
        .state = state,
    };
}

fn acceptLoop(state: *ServiceState, listener: tcp.Server) void {
    var server = listener;
    defer {
        reapInactiveSessions(state);
        tcp.deinitServer(&server);
    }

    while (true) {
        reapInactiveSessions(state);

        const accepted = tcp.accept(&server) catch {
            if (state.stop_requested.load(.acquire)) break;
            break;
        };

        if (state.stop_requested.load(.acquire)) {
            tcp.close(accepted);
            break;
        }

        spawnSession(state, accepted) catch {
            tcp.close(accepted);
        };
    }
}

fn reapInactiveSessions(state: *ServiceState) void {
    state.mutex.lockUncancelable(tcp.io());
    defer state.mutex.unlock(tcp.io());

    var index: usize = 0;
    while (index < state.sessions.items.len) {
        const session = state.sessions.items[index];
        if (session.active.load(.acquire)) {
            index += 1;
            continue;
        }

        _ = state.sessions.swapRemove(index);
        state.mutex.unlock(tcp.io());

        if (session.thread) |thread| thread.join();
        session.deinit();
        service_allocator.destroy(session);

        state.mutex.lockUncancelable(tcp.io());
    }
}

fn sessionMain(session: *ClientSession) void {
    defer {
        session.active.store(false, .release);
        tcp.close(session.stream);
    }
    tcp_session.handleClientBorrowed(session.stream, session.config) catch {};
}

fn spawnSession(state: *ServiceState, stream: tcp.Stream) !void {
    var session = try service_allocator.create(ClientSession);
    errdefer service_allocator.destroy(session);

    session.* = .{
        .stream = stream,
        .config = try cloneRuntimeConfig(state.config),
        .active = .init(true),
        .thread = null,
    };
    errdefer session.deinit();

    state.mutex.lockUncancelable(tcp.io());
    defer state.mutex.unlock(tcp.io());
    try state.sessions.append(session);

    session.thread = std.Thread.spawn(.{}, sessionMain, .{session}) catch |err| {
        _ = state.sessions.pop();
        return err;
    };
}

fn shutdownSessions(state: *ServiceState) void {
    state.mutex.lockUncancelable(tcp.io());
    defer state.mutex.unlock(tcp.io());
    for (state.sessions.items) |session| {
        if (session.active.load(.acquire)) tcp.shutdown(session.stream);
    }
}

fn joinSessions(state: *ServiceState) void {
    state.mutex.lockUncancelable(tcp.io());
    const sessions = state.sessions.items;
    state.mutex.unlock(tcp.io());

    for (sessions) |session| {
        if (session.thread) |thread| thread.join();
        session.deinit();
        service_allocator.destroy(session);
    }
    state.sessions.clearRetainingCapacity();
}

fn wakeListener(host: []const u8, port: u16) void {
    const wake_host = if (std.mem.eql(u8, host, "0.0.0.0"))
        "127.0.0.1"
    else if (std.mem.eql(u8, host, "::"))
        "::1"
    else
        host;

    const stream = tcp.connectHost(wake_host, port) catch return;
    tcp.close(stream);
}

fn cloneRuntimeConfig(config: RuntimeConfig) !RuntimeConfig {
    const password = try service_allocator.dupe(u8, config.password);
    errdefer service_allocator.free(password);

    const server_host = try service_allocator.dupe(u8, config.server.bind_host);
    errdefer service_allocator.free(server_host);

    var local: ?runtime.LocalConfig = null;
    if (config.local) |src_local| {
        const bind_host = try service_allocator.dupe(u8, src_local.bind_host);
        errdefer service_allocator.free(bind_host);

        const udp_bind_host = if (src_local.udp_bind_host) |udp_host|
            try service_allocator.dupe(u8, udp_host)
        else
            null;
        errdefer if (udp_bind_host) |host| service_allocator.free(host);

        local = .{
            .bind_host = bind_host,
            .bind_port = src_local.bind_port,
            .udp_bind_host = udp_bind_host,
            .udp_bind_port = src_local.udp_bind_port,
        };
    }

    return .{
        .role = config.role,
        .method = config.method,
        .password = password,
        .timeout_secs = config.timeout_secs,
        .udp_timeout_secs = config.udp_timeout_secs,
        .udp_max_associations = config.udp_max_associations,
        .no_delay = config.no_delay,
        .keep_alive_secs = config.keep_alive_secs,
        .mode = config.mode,
        .local = local,
        .server = .{
            .bind_host = server_host,
            .bind_port = config.server.bind_port,
        },
    };
}
