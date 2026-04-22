const std = @import("std");
const ss = @import("shadowsocks_zig");

pub fn main() !void {
    std.debug.print("{s} ssserver bootstrap\n", .{ss.project_name});
}
