const std = @import("std");

const socks_addr = @import("../../wire/socks_addr.zig");

pub const Address = socks_addr.Address;

pub fn writeSuccessReply(out: []u8, bind_addr: Address) !usize {
    if (out.len < 3) return error.NoSpaceLeft;

    out[0] = 0x05;
    out[1] = 0x00;
    out[2] = 0x00;

    const used = try socks_addr.writeAddress(out[3..], bind_addr);
    return 3 + used;
}
