pub fn wipe(bytes: []u8) void {
    @memset(bytes, 0);
}
