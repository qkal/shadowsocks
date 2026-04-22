pub const project_name = "shadowsocks-zig";

pub const core = struct {
    pub const constants = @import("core/constants.zig");
    pub const errors = @import("core/errors.zig");
    pub const Mode = @import("core/mode.zig").Mode;
    pub const Address = @import("core/address.zig").Address;
};
pub const config = struct {};
pub const crypto = struct {
    pub const Method = @import("crypto/methods.zig").Method;
    pub const deriveClassicMasterKey = @import("crypto/kdf.zig").deriveClassicMasterKey;
    pub const deriveSessionSubkey = @import("crypto/kdf.zig").deriveSessionSubkey;
};
pub const security = struct {};
pub const wire = struct {};
pub const frontend = struct {};
pub const net = struct {};
pub const app = struct {};

const std = @import("std");

test "package exposes project name" {
    try std.testing.expectEqualStrings("shadowsocks-zig", project_name);
}
