const std = @import("std");
const RuntimeConfig = @import("../../config/runtime.zig").RuntimeConfig;

pub const RunningLocal = struct {
    thread: ?std.Thread = null,

    pub fn stop(self: *RunningLocal) void {
        self.thread = null;
    }
};

pub fn runLocal(config: RuntimeConfig) !RunningLocal {
    _ = config;
    return .{};
}
