const std = @import("std");
const testing = std.testing;
const curve = std.crypto.ecc.Curve25519;
const CompressedScalar = curve.scalar.CompressedScalar;
const Scalar = curve.scalar.Scalar;

test {
    const skip = [_][]const u8{
        "random_scalar",
        "hash_to_scalar",
        "generate_keys",
        "check_key",
        "secret_key_to_public_key",
    };
    const hexToBytes = std.fmt.hexToBytes;
    const filename = "tests.txt";
    var file = try std.fs.cwd().openFile(filename, .{});
    defer file.close();
    var buf_reader = std.io.bufferedReader(file.reader());
    var in_stream = buf_reader.reader();
    var buf: [64 * 1024]u8 = undefined;
    while (try in_stream.readUntilDelimiterOrEof(&buf, '\n')) |line| {
        if (std.mem.startsWith(u8, line, "check_scalar")) {
            var splitted = std.mem.splitScalar(u8, line, ' ');
            _ = splitted.next().?;
            var scalar: CompressedScalar = undefined;
            _ = try hexToBytes(&scalar, splitted.next().?);
            var expected: bool = undefined;
            if (std.mem.eql(u8, splitted.next().?, "true")) {
                expected = true;
            } else {
                expected = false;
            }
            curve.scalar.rejectNonCanonical(scalar) catch {
                try testing.expectEqual(expected, false);
            };
        }
        for (skip) |s| {
            if (std.mem.startsWith(u8, line, s)) {
                continue;
            }
        }
    }
}
