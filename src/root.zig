pub const project_name = "shadowsocks-zig";

pub const core = struct {};
pub const config = struct {};
pub const crypto = struct {};
pub const security = struct {};
pub const wire = struct {};
pub const frontend = struct {};
pub const net = struct {};
pub const app = struct {};

const std = @import("std");

test "package exposes project name" {
    try std.testing.expectEqualStrings("shadowsocks-zig", project_name);
}
