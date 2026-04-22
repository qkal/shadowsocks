const std = @import("std");
const config = @import("../config/validate.zig");
const Role = @import("../config/runtime.zig").Role;
const RuntimeConfig = @import("../config/runtime.zig").RuntimeConfig;

pub fn loadConfigFromArgs(
    allocator: std.mem.Allocator,
    io: std.Io,
    role: Role,
    path: []const u8,
) !RuntimeConfig {
    const bytes = try std.Io.Dir.cwd().readFileAlloc(io, path, allocator, .limited(1024 * 1024));
    defer allocator.free(bytes);
    return config.loadFromSlice(allocator, role, bytes);
}
