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
pub const cli = struct {
    pub const loadConfigFromArgs = @import("cli/args.zig").loadConfigFromArgs;
    pub const fatal = @import("cli/diag.zig").fatal;
};
pub const crypto = struct {
    pub const Method = @import("crypto/methods.zig").Method;
    pub const aead = @import("crypto/aead.zig");
    pub const sealDetached = aead.sealDetached;
    pub const openDetached = aead.openDetached;
    pub const deriveClassicMasterKey = @import("crypto/kdf.zig").deriveClassicMasterKey;
    pub const deriveSessionSubkey = @import("crypto/kdf.zig").deriveSessionSubkey;
};
pub const security = struct {
    pub const replay = @import("security/replay.zig");
    pub const SaltKey = replay.SaltKey;
    pub const SaltReplay = replay.SaltReplay;
    pub const zeroize = @import("security/zeroize.zig");
    pub const wipe = zeroize.wipe;
};
pub const wire = struct {
    pub const socks_addr = @import("wire/socks_addr.zig");
    pub const ss_tcp = @import("wire/ss_tcp.zig");
};
pub const frontend = struct {
    pub const socks5 = struct {
        pub const handshake = @import("frontend/socks5/handshake.zig");
        pub const tcp_connect = @import("frontend/socks5/tcp_connect.zig");
        pub const udp_associate = @import("frontend/socks5/udp_associate.zig");
    };
};
pub const net = struct {
    pub const dns = @import("net/dns.zig");
    pub const socket_opts = @import("net/socket_opts.zig");
    pub const tcp = @import("net/tcp.zig");
};
pub const app = struct {
    pub const local = struct {
        pub const tcp_session = @import("app/local/tcp_session.zig");
        pub const service = @import("app/local/service.zig");
    };
    pub const server = struct {
        pub const tcp_session = @import("app/server/tcp_session.zig");
        pub const service = @import("app/server/service.zig");
    };
    pub const runLocal = local.service.runLocal;
    pub const runServer = server.service.runServer;
};

const std = @import("std");

test "package exposes project name" {
    try std.testing.expectEqualStrings("shadowsocks-zig", project_name);
}
