pub const project_name = "shadowsocks-zig";

pub const core = struct {
    pub const constants = @import("core/constants.zig");
    pub const errors = @import("core/errors.zig");
    pub const Mode = @import("core/mode.zig").Mode;
    pub const Address = @import("core/address.zig").Address;
};
pub const config = struct {
    pub const Role = @import("config/runtime.zig").Role;
    pub const RuntimeConfig = @import("config/runtime.zig").RuntimeConfig;
    pub const loadFromSlice = @import("config/validate.zig").loadFromSlice;
};
pub const crypto = struct {
    pub const Method = @import("crypto/methods.zig").Method;
    pub const deriveClassicMasterKey = @import("crypto/kdf.zig").deriveClassicMasterKey;
    pub const deriveSessionSubkey = @import("crypto/kdf.zig").deriveSessionSubkey;
};
pub const security = struct {};
pub const wire = struct {
    pub const socks_addr = @import("wire/socks_addr.zig");
};
pub const frontend = struct {
    pub const socks5 = struct {
        pub const handshake = @import("frontend/socks5/handshake.zig");
        pub const tcp_connect = @import("frontend/socks5/tcp_connect.zig");
        pub const udp_associate = @import("frontend/socks5/udp_associate.zig");
    };
};
pub const net = struct {};
pub const app = struct {};

const std = @import("std");

test "package exposes project name" {
    try std.testing.expectEqualStrings("shadowsocks-zig", project_name);
}
