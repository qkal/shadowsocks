const std = @import("std");
const ss = @import("shadowsocks_zig");

pub fn main(init: std.process.Init) !void {
    var args = try std.process.Args.iterateAllocator(init.minimal.args, init.gpa);
    defer args.deinit();

    _ = args.next();
    const config_path = args.next() orelse ss.cli.fatal("usage: sslocal <config-path>");

    var cfg = try ss.cli.loadConfigFromArgs(init.gpa, init.io, .local, config_path);
    defer cfg.deinit(init.gpa);

    var running = try ss.app.runLocal(cfg);
    defer running.stop();

    while (true) try std.Io.sleep(init.io, .fromSeconds(3600), .awake);
}
