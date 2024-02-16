const std = @import("std");

pub fn build(b: *std.Build) void {
    _ = b.addModule("zigscan", .{
        .root_source_file = .{ .path = "src/zigscan.zig" },
    });

    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const exe = b.addExecutable(.{
        .name = "bench",
        .root_source_file = .{ .path = "src/bench.zig" },
        .target = target,
        .optimize = optimize,
    });

    const tests = b.addTest(.{
        .root_source_file = .{ .path = "src/zigscan.zig" },
        .target = target,
        .optimize = optimize,
    });

    const run_tests = b.addRunArtifact(tests);
    const test_step = b.step("test", "Run tests");
    test_step.dependOn(&run_tests.step);

    const run = b.addRunArtifact(exe);
    const run_step = b.step("run", "Run benchmark");
    run_step.dependOn(&run.step);
}
