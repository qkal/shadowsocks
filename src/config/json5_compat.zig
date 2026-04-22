const std = @import("std");

pub fn normalize(allocator: std.mem.Allocator, input: []const u8) ![]u8 {
    var out = try std.ArrayList(u8).initCapacity(allocator, input.len);
    defer out.deinit(allocator);

    var i: usize = 0;
    var in_string = false;
    var escaped = false;
    var in_line_comment = false;
    var pending_comma = false;
    var comma_ws = try std.ArrayList(u8).initCapacity(allocator, input.len);
    defer comma_ws.deinit(allocator);

    while (i < input.len) : (i += 1) {
        const c = input[i];

        if (in_line_comment) {
            if (c == '\n') {
                in_line_comment = false;
                if (pending_comma) {
                    try comma_ws.append(allocator, c);
                } else {
                    try out.append(allocator, c);
                }
            }
            continue;
        }

        if (in_string) {
            if (pending_comma) {
                try out.append(allocator, ',');
                try out.appendSlice(allocator, comma_ws.items);
                comma_ws.clearRetainingCapacity();
                pending_comma = false;
            }
            try out.append(allocator, c);
            if (escaped) {
                escaped = false;
            } else if (c == '\\') {
                escaped = true;
            } else if (c == '"') {
                in_string = false;
            }
            continue;
        }

        if (pending_comma) {
            switch (c) {
                ' ', '\t', '\r', '\n' => {
                    try comma_ws.append(allocator, c);
                    continue;
                },
                '}', ']' => {
                    try out.appendSlice(allocator, comma_ws.items);
                    comma_ws.clearRetainingCapacity();
                    pending_comma = false;
                    try out.append(allocator, c);
                    continue;
                },
                '/' => {
                    if (i + 1 < input.len and input[i + 1] == '/') {
                        in_line_comment = true;
                        i += 1;
                        continue;
                    }
                },
                else => {},
            }

            try out.append(allocator, ',');
            try out.appendSlice(allocator, comma_ws.items);
            comma_ws.clearRetainingCapacity();
            pending_comma = false;
        }

        switch (c) {
            '"' => {
                in_string = true;
                try out.append(allocator, c);
            },
            '/' => {
                if (i + 1 < input.len and input[i + 1] == '/') {
                    in_line_comment = true;
                    i += 1;
                } else {
                    try out.append(allocator, c);
                }
            },
            ',' => {
                pending_comma = true;
            },
            else => {
                try out.append(allocator, c);
            },
        }
    }

    if (pending_comma) {
        try out.append(allocator, ',');
        try out.appendSlice(allocator, comma_ws.items);
    }

    return try out.toOwnedSlice(allocator);
}

test "normalize strips line comments and trailing commas from a small JSON object" {
    const input =
        \\{
        \\  // comment before server
        \\  "server": "127.0.0.1",
        \\  "server_port": 8388,
        \\  "local_port": 1080,
        \\}
    ;
    const expected =
        \\{
        \\  
        \\  "server": "127.0.0.1",
        \\  "server_port": 8388,
        \\  "local_port": 1080
        \\}
    ;

    const normalized = try normalize(std.testing.allocator, input);
    defer std.testing.allocator.free(normalized);
    try std.testing.expectEqualStrings(expected, normalized);
}
