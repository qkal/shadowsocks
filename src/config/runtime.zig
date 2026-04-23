const std = @import("std");

const root = @import("root");

const compat = struct {
    pub const Mode = enum {
        tcp_only,
        tcp_and_udp,

        pub fn parse(text: []const u8) !@This() {
            if (std.mem.eql(u8, text, "tcp_only")) return .tcp_only;
            if (std.mem.eql(u8, text, "tcp_and_udp")) return .tcp_and_udp;
            return error.InvalidMode;
        }
    };

    pub const Method = enum {
        aes_128_gcm,
        aes_256_gcm,
        chacha20_ietf_poly1305,

        pub fn parse(text: []const u8) !@This() {
            if (std.mem.eql(u8, text, "aes-128-gcm")) return .aes_128_gcm;
            if (std.mem.eql(u8, text, "aes-256-gcm")) return .aes_256_gcm;
            if (std.mem.eql(u8, text, "chacha20-ietf-poly1305")) return .chacha20_ietf_poly1305;
            return error.UnsupportedMethod;
        }
    };
};

pub const Mode = if (@hasDecl(root, "core")) root.core.Mode else compat.Mode;

pub const Method = if (@hasDecl(root, "crypto")) root.crypto.Method else compat.Method;

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

    pub fn applyUrlOverrides(self: *RuntimeConfig, allocator: std.mem.Allocator, parsed: anytype) !void {
        const new_host = try allocator.dupe(u8, parsed.host);
        errdefer allocator.free(new_host);
        const new_password = try allocator.dupe(u8, parsed.password);
        errdefer allocator.free(new_password);
        const new_method = try Method.parse(parsed.method);

        allocator.free(self.password);
        self.password = new_password;
        allocator.free(self.server.bind_host);
        self.server.bind_host = new_host;
        self.server.bind_port = parsed.port;
        self.method = new_method;
    }

    pub fn replacePassword(self: *RuntimeConfig, allocator: std.mem.Allocator, password_text: []const u8) !void {
        const new_password = try allocator.dupe(u8, password_text);
        allocator.free(self.password);
        self.password = new_password;
    }

    pub fn replaceServerAddress(self: *RuntimeConfig, allocator: std.mem.Allocator, input: []const u8) !void {
        const colon = std.mem.lastIndexOfScalar(u8, input, ':') orelse return error.InvalidServerAddress;
        const new_host = try allocator.dupe(u8, input[0..colon]);
        errdefer allocator.free(new_host);

        const new_port = try std.fmt.parseInt(u16, input[colon + 1 ..], 10);

        allocator.free(self.server.bind_host);
        self.server.bind_host = new_host;
        self.server.bind_port = new_port;
    }
};
