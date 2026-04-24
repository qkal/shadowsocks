const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const pkg = b.addModule("shadowsocks_zig", .{
        .root_source_file = b.path("src/root.zig"),
        .target = target,
        .optimize = optimize,
    });

    const sslocal = b.addExecutable(.{
        .name = "sslocal",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/cli/sslocal_main.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{.{ .name = "shadowsocks_zig", .module = pkg }},
        }),
    });
    const ssserver = b.addExecutable(.{
        .name = "ssserver",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/cli/ssserver_main.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{.{ .name = "shadowsocks_zig", .module = pkg }},
        }),
    });

    b.installArtifact(sslocal);
    b.installArtifact(ssserver);

    const pkg_tests = b.addTest(.{ .root_module = pkg });
    const run_pkg_tests = b.addRunArtifact(pkg_tests);

    const tcp_integration_tests = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("test/integration/tcp_happy_path.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{.{ .name = "shadowsocks_zig", .module = pkg }},
        }),
    });
    const run_tcp_integration_tests = b.addRunArtifact(tcp_integration_tests);

    const test_step = b.step("test", "Run package tests");
    test_step.dependOn(&run_pkg_tests.step);
    test_step.dependOn(&run_tcp_integration_tests.step);

    const check_step = b.step("check", "Build sslocal and ssserver");
    check_step.dependOn(&sslocal.step);
    check_step.dependOn(&ssserver.step);

    const sslocal_step = b.step("sslocal", "Build sslocal");
    sslocal_step.dependOn(&sslocal.step);

    const ssserver_step = b.step("ssserver", "Build ssserver");
    ssserver_step.dependOn(&ssserver.step);
}
