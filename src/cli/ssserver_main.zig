const std = @import("std");
const ss = @import("shadowsocks_zig");
pub const config = ss.config;
pub const wire = ss.wire;

pub fn main(init: std.process.Init) !void {
    var args = try std.process.Args.iterateAllocator(init.minimal.args, init.gpa);
    defer args.deinit();

    _ = args.next();
    const config_path = args.next() orelse ss.cli.fatal("usage: ssserver <config-path>");

    var cfg = try ss.cli.loadConfigFromArgs(init.gpa, init.io, .server, config_path);
    defer cfg.deinit(init.gpa);

    _ = try ss.app.runServer(cfg);
}
