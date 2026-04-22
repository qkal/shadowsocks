const std = @import("std");
const RuntimeConfig = @import("../../config/runtime.zig").RuntimeConfig;

pub const RunningServer = struct {
    thread: ?std.Thread = null,

    pub fn stop(self: *RunningServer) void {
        self.thread = null;
    }
};

pub fn runServer(config: RuntimeConfig) !RunningServer {
    _ = config;
    return .{};
}
