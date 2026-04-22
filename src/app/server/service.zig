const std = @import("std");
const RuntimeConfig = @import("../../config/runtime.zig").RuntimeConfig;

// Stub skeleton. The real accept loop, per-connection session, and shutdown
// handling are not wired yet — `runServer` just returns an empty handle so the
// CLI and integration tests can exercise config loading end-to-end without
// blocking on a real listener.
pub const RunningServer = struct {
    thread: ?std.Thread = null,

    // TODO: signal the accept loop and join the worker thread once it exists.
    pub fn stop(self: *RunningServer) void {
        self.thread = null;
    }
};

pub fn runServer(config: RuntimeConfig) !RunningServer {
    _ = config;
    return .{};
}
