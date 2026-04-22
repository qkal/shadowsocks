const std = @import("std");
const RuntimeConfig = @import("../../config/runtime.zig").RuntimeConfig;

// Stub skeleton. The real accept loop, per-connection session, and shutdown
// handling are not wired yet — `runLocal` just returns an empty handle so the
// CLI and integration tests can exercise config loading end-to-end without
// blocking on a real listener.
pub const RunningLocal = struct {
    thread: ?std.Thread = null,

    // TODO: signal the accept loop and join the worker thread once it exists.
    pub fn stop(self: *RunningLocal) void {
        self.thread = null;
    }
};

pub fn runLocal(config: RuntimeConfig) !RunningLocal {
    _ = config;
    return .{};
}
