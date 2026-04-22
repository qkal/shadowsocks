const std = @import("std");

pub const Mode = enum {
    tcp_only,
    tcp_and_udp,

    pub fn parse(text: []const u8) !Mode {
        if (std.mem.eql(u8, text, "tcp_only")) return .tcp_only;
        if (std.mem.eql(u8, text, "tcp_and_udp")) return .tcp_and_udp;
        return error.InvalidMode;
    }

    pub fn enablesTcp(self: Mode) bool {
        _ = self;
        return true;
    }

    pub fn enablesUdp(self: Mode) bool {
        return self == .tcp_and_udp;
    }
};

test "parse tcp_only and tcp_and_udp" {
    try std.testing.expectEqual(Mode.tcp_only, try Mode.parse("tcp_only"));
    try std.testing.expectEqual(Mode.tcp_and_udp, try Mode.parse("tcp_and_udp"));
}
