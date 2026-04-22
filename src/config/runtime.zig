const std = @import("std");

pub const Mode = @import("../core/mode.zig").Mode;
pub const Method = @import("../crypto/methods.zig").Method;

pub const Role = enum {
    local,
    server,
};

pub const LocalConfig = struct {
    bind_host: []u8,
    bind_port: u16,
    udp_bind_host: ?[]u8 = null,
    udp_bind_port: ?u16 = null,
};

pub const ServerConfig = struct {
    bind_host: []u8,
    bind_port: u16,
};

pub const RuntimeConfig = struct {
    role: Role,
    method: Method,
    password: []u8,
    timeout_secs: ?u64,
    udp_timeout_secs: u64,
    udp_max_associations: usize,
    no_delay: bool,
    keep_alive_secs: ?u64,
    mode: Mode,
    local: ?LocalConfig,
    server: ServerConfig,

    pub fn deinit(self: *RuntimeConfig, allocator: std.mem.Allocator) void {
        allocator.free(self.password);
        if (self.local) |*local| {
            allocator.free(local.bind_host);
            if (local.udp_bind_host) |udp_bind_host| allocator.free(udp_bind_host);
        }
        allocator.free(self.server.bind_host);
    }
};
