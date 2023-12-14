const std = @import("std");
const testing = std.testing;
const curve = std.crypto.ecc.Curve25519;
const CompressedScalar = curve.scalar.CompressedScalar;
const Scalar = curve.scalar.Scalar;

fn ge_double_scalarmult_base_vartime(
    k1: CompressedScalar,
    public: CompressedScalar,
    k2: CompressedScalar,
) CompressedScalar {
    const tmp_a = curve.scalar.mul(k1, public);
    const tmp_b = try curve.basePoint.mul(k2);
    return std.crypto.ecc.Edwards25519.scalar.add(tmp_a, tmp_b);
}

fn ge_double_scalarmult_vartime(
    k1: CompressedScalar,
    public: CompressedScalar,
    k2: CompressedScalar,
    image: CompressedScalar,
) CompressedScalar {
    const tmp_a = curve.scalar.mul(k1, public);
    const tmp_b = try curve.scalar.mul(k2, image);
    return std.crypto.ecc.Edwards25519.scalar.add(tmp_a, tmp_b);
}

fn generate_ring_signature(
    allocator: std.mem.Allocator,
    prefix: [32]u8,
    image: [32]u8,
    pubs_count: usize,
    pubs: [][32]u8,
    secret: [32]u8,
    secret_index: usize,
    out: []u8,
) ![]u8 {
    var aba = try allocator.alloc(CompressedScalar, pubs_count);
    defer allocator.free(aba);
    var abb = try allocator.alloc(CompressedScalar, pubs_count);
    defer allocator.free(abb);
    for (0..pubs.len) |i| {
        var tmp2: CompressedScalar = undefined;
        var tmp3: CompressedScalar = undefined;
        if (i == secret_index) {
            const k = curve.scalar.random();
            tmp3 = try curve.basePoint.mul(k);
            aba[i] = tmp3.toBytes();
            tmp3 = curve.fromBytes(pubs[i]);
            abb[i] = curve.scalar.mul(k, tmp3.toBytes());
        } else {
            const k1 = curve.scalar.random();
            const k2 = curve.scalar.random();
            tmp2 = ge_double_scalarmult_base_vartime(k1, pubs[i], k2);
            aba[i] = tmp2;
            tmp3 = pubs[i];
        }
    }
    _ = secret;
    _ = prefix;
    _ = image;
    return out[0..5];
}

test {
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
        if (std.mem.startsWith(u8, line, "generate_ring_signature")) {
            var splitted = std.mem.splitScalar(u8, line, ' ');
            _ = splitted.next().?;
            var prefix: [32]u8 = undefined;
            _ = try hexToBytes(&prefix, splitted.next().?);
            var image: [32]u8 = undefined;
            _ = try hexToBytes(&image, splitted.next().?);
            const pubs: usize = try std.fmt.parseInt(
                usize,
                splitted.next().?,
                10,
            );
            var arr = std.ArrayList([32]u8).init(testing.allocator);
            defer arr.deinit();
            for (0..pubs) |_| {
                var b: [32]u8 = undefined;
                _ = try hexToBytes(&b, splitted.next().?);
                try arr.append(b);
            }
            var secret: [32]u8 = undefined;
            _ = try hexToBytes(&secret, splitted.next().?);
            const secret_index: usize = try std.fmt.parseInt(
                usize,
                splitted.next().?,
                10,
            );
            var signature: [1024 * 128]u8 = undefined;
            const signature_slice = try hexToBytes(
                &signature,
                splitted.next().?,
            );
            _ = signature_slice;
            var actual_signature: [1024 * 128]u8 = undefined;
            const actual_signature_slice = try generate_ring_signature(
                testing.allocator,
                prefix,
                image,
                pubs,
                arr.allocatedSlice(),
                secret,
                secret_index,
                &actual_signature,
            );
            std.debug.print("{s}\n", .{
                std.fmt.fmtSliceHexLower(actual_signature_slice),
            });
        }
    }
}
