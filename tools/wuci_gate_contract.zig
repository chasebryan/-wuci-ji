const std = @import("std");

const Allocator = std.mem.Allocator;
const Io = std.Io;
const Sha256 = std.crypto.hash.sha2.Sha256;

const contract_schema = "wuci-gate-receipt-contract-v1";
const max_file_size = 16 * 1024 * 1024;
const max_process_output = 4 * 1024 * 1024;

const field_labels = [_][]const u8{
    "schema",
    "action",
    "artifact-sha256",
    "authorization-message-sha256",
    "receipt-sha256",
    "artifact-manifest-sha256",
    "group-public-key",
    "group-commitment",
    "challenge",
    "signature-commitment",
    "signature-scalar",
};

const private_markers = [_][]const u8{
    "group_secret",
    "share",
    "hiding",
    "binding",
    "hiding_nonce",
    "binding_nonce",
    "signature_share",
};

const Args = struct {
    command: []const u8,
    bin: []const u8 = "build/wuci-ji",
    artifact: []const u8 = "",
    receipt: []const u8 = "",
    contract: []const u8 = "",
    keyfile: ?[]const u8 = null,
    out: ?[]const u8 = null,
    runner: ?[]const u8 = null,
    env_runner: ?[]const u8 = null,
    quiet: bool = false,
};

const Contract = struct {
    values: [field_labels.len][]const u8,

    fn action(self: Contract) []const u8 {
        return self.values[1];
    }

    fn artifactSha256(self: Contract) []const u8 {
        return self.values[2];
    }

    fn authorizationMessageSha256(self: Contract) []const u8 {
        return self.values[3];
    }

    fn receiptSha256(self: Contract) []const u8 {
        return self.values[4];
    }

    fn artifactManifestSha256(self: Contract) []const u8 {
        return self.values[5];
    }

    fn groupPublicKey(self: Contract) []const u8 {
        return self.values[6];
    }

    fn groupCommitment(self: Contract) []const u8 {
        return self.values[7];
    }

    fn challenge(self: Contract) []const u8 {
        return self.values[8];
    }

    fn signatureCommitment(self: Contract) []const u8 {
        return self.values[9];
    }

    fn signatureScalar(self: Contract) []const u8 {
        return self.values[10];
    }
};

const ProcessOutput = struct {
    stdout: []u8,
    stderr: []u8,
};

pub fn main(init: std.process.Init) !void {
    const gpa = init.gpa;
    const io = init.io;
    var stdout_buffer: [256]u8 = undefined;
    var stdout_writer = Io.File.stdout().writer(io, &stdout_buffer);
    const stdout = &stdout_writer.interface;

    var args = parseArgs(gpa, init.minimal.args) catch |err| {
        usage();
        return err;
    };
    args.env_runner = init.environ_map.get("WUCI_JI_RUNNER");

    if (std.mem.eql(u8, args.command, "verify")) {
        try runVerify(gpa, io, stdout, args, false);
        return;
    }
    if (std.mem.eql(u8, args.command, "emit")) {
        try runEmit(gpa, io, stdout, args);
        return;
    }
    if (std.mem.eql(u8, args.command, "open")) {
        try runVerify(gpa, io, stdout, args, true);
        return;
    }

    usage();
    return error.UnsupportedCommand;
}

fn parseArgs(gpa: Allocator, process_args: std.process.Args) !Args {
    var argv = try std.process.Args.Iterator.initAllocator(process_args, gpa);
    defer argv.deinit();

    _ = argv.next() orelse return error.MissingArgv0;
    const command = argv.next() orelse return error.MissingCommand;
    var parsed = Args{ .command = command };

    while (argv.next()) |arg| {
        if (std.mem.eql(u8, arg, "--bin")) {
            parsed.bin = argv.next() orelse return error.MissingValue;
        } else if (std.mem.eql(u8, arg, "--artifact")) {
            parsed.artifact = argv.next() orelse return error.MissingValue;
        } else if (std.mem.eql(u8, arg, "--receipt")) {
            parsed.receipt = argv.next() orelse return error.MissingValue;
        } else if (std.mem.eql(u8, arg, "--contract")) {
            parsed.contract = argv.next() orelse return error.MissingValue;
        } else if (std.mem.eql(u8, arg, "--keyfile")) {
            parsed.keyfile = argv.next() orelse return error.MissingValue;
        } else if (std.mem.eql(u8, arg, "--out")) {
            parsed.out = argv.next() orelse return error.MissingValue;
        } else if (std.mem.eql(u8, arg, "--runner")) {
            parsed.runner = argv.next() orelse return error.MissingValue;
        } else if (std.mem.eql(u8, arg, "--quiet")) {
            parsed.quiet = true;
        } else {
            return error.UnknownArgument;
        }
    }

    if (parsed.artifact.len == 0 or parsed.receipt.len == 0 or parsed.contract.len == 0) {
        return error.MissingRequiredArgument;
    }
    if (std.mem.eql(u8, parsed.command, "open") and (parsed.keyfile == null or parsed.out == null)) {
        return error.OpenRequiresKeyfileAndOut;
    }
    return parsed;
}

fn usage() void {
    std.debug.print(
        \\usage: wuci_gate_contract <emit|verify|open> --bin <wuci-ji> --artifact <artifact> --receipt <receipt-json> --contract <flat-contract> [--runner <runner>] [--keyfile <key> --out <path>]
        \\
    , .{});
}

fn runEmit(gpa: Allocator, io: Io, stdout: *Io.Writer, args: Args) !void {
    const receipt_text = try readFile(gpa, io, args.receipt);
    defer gpa.free(receipt_text);

    try requireJsonString(receipt_text, "schema", "wuci-frost-authorization-v1");
    try requireJsonString(receipt_text, "suite", "FROST-secp256k1-SHA256-v1");
    try requireJsonString(receipt_text, "mode", "deterministic-2of2-fixture");
    try requireJsonBool(receipt_text, "production", false);

    const receipt_action = try jsonString(receipt_text, "action");
    if (!isAllowedAction(receipt_action)) return error.UnsupportedAction;

    const artifact_manifest_sha256 = try jsonString(receipt_text, "artifact_manifest_sha256");
    const authorization_message_sha256 = try jsonString(receipt_text, "authorization_message_sha256");
    const group_public_key = try jsonString(receipt_text, "group_public_key");
    const group_commitment = try jsonString(receipt_text, "group_commitment");
    const challenge_value = try jsonString(receipt_text, "challenge");
    const signature_commitment = try jsonString(receipt_text, "signature_commitment");
    const signature_scalar = try jsonString(receipt_text, "signature_scalar");
    const verification = try jsonString(receipt_text, "verification");

    try expectEqual(verification, "valid", error.ReceiptNotMarkedValid);
    try expectEqual(group_commitment, signature_commitment, error.SignatureCommitmentMismatch);

    const artifact_data = try readFile(gpa, io, args.artifact);
    defer gpa.free(artifact_data);
    const artifact_hash = sha256Hex(artifact_data);
    const receipt_hash = sha256Hex(receipt_text);

    const manifest = try runWuci(gpa, io, args, &.{ "manifest-file", args.artifact }, null);
    defer freeProcessOutput(gpa, manifest);
    const manifest_hash = sha256Hex(manifest.stdout);
    try expectEqual(artifact_manifest_sha256, manifest_hash[0..], error.ManifestHashMismatch);

    const warrant = try runWuci(gpa, io, args, &.{ "warrant-message-file", receipt_action, args.artifact }, null);
    defer freeProcessOutput(gpa, warrant);
    const warrant_hash = sha256Hex(warrant.stdout);
    try expectEqual(authorization_message_sha256, warrant_hash[0..], error.AuthorizationMessageHashMismatch);

    const challenge = try runWuci(
        gpa,
        io,
        args,
        &.{ "frost-secp256k1-challenge", group_commitment, group_public_key },
        warrant.stdout,
    );
    defer freeProcessOutput(gpa, challenge);
    const challenge_text = std.mem.trim(u8, challenge.stdout, " \n\r\t");
    try expectEqual(challenge_value, challenge_text, error.ChallengeMismatch);

    const verify = try runWuciRaw(
        gpa,
        io,
        args,
        &.{ "frost-secp256k1-verify", signature_commitment, group_public_key, signature_scalar, challenge_value },
        null,
    );
    defer freeRunResult(gpa, verify);
    const verify_exited_zero = switch (verify.term) {
        .exited => |code| code == 0,
        else => false,
    };
    if (!verify_exited_zero) return error.InvalidSignature;
    const verify_text = std.mem.trim(u8, verify.stdout, " \n\r\t");
    try expectEqual(verify_text, "valid", error.InvalidSignature);

    const contract_text = try std.fmt.allocPrint(
        gpa,
        "schema: {s}\n" ++
            "action: {s}\n" ++
            "artifact-sha256: {s}\n" ++
            "authorization-message-sha256: {s}\n" ++
            "receipt-sha256: {s}\n" ++
            "artifact-manifest-sha256: {s}\n" ++
            "group-public-key: {s}\n" ++
            "group-commitment: {s}\n" ++
            "challenge: {s}\n" ++
            "signature-commitment: {s}\n" ++
            "signature-scalar: {s}\n",
        .{
            contract_schema,
            receipt_action,
            artifact_hash,
            authorization_message_sha256,
            receipt_hash,
            artifact_manifest_sha256,
            group_public_key,
            group_commitment,
            challenge_value,
            signature_commitment,
            signature_scalar,
        },
    );
    defer gpa.free(contract_text);
    _ = try parseContract(contract_text);

    try writeNewFile(io, args.contract, contract_text);
    if (!args.quiet) {
        try stdout.print("contract: {s}\n", .{args.contract});
        try stdout.print("action: {s}\n", .{receipt_action});
        try stdout.print("artifact-sha256: {s}\n", .{artifact_hash});
        try stdout.print("authorization-message-sha256: {s}\n", .{authorization_message_sha256});
        try stdout.print("receipt-sha256: {s}\n", .{receipt_hash});
        try stdout.flush();
    }
}

fn runVerify(gpa: Allocator, io: Io, stdout: *Io.Writer, args: Args, do_open: bool) !void {
    const contract_text = try readFile(gpa, io, args.contract);
    defer gpa.free(contract_text);
    const contract = try parseContract(contract_text);

    try compareHash(gpa, io, args.artifact, contract.artifactSha256(), "artifact-sha256");
    try compareHash(gpa, io, args.receipt, contract.receiptSha256(), "receipt-sha256");

    const manifest = try runWuci(gpa, io, args, &.{ "manifest-file", args.artifact }, null);
    defer freeProcessOutput(gpa, manifest);
    try compareHashBytes(manifest.stdout, contract.artifactManifestSha256(), "artifact-manifest-sha256");

    const warrant = try runWuci(
        gpa,
        io,
        args,
        &.{ "warrant-message-file", contract.action(), args.artifact },
        null,
    );
    defer freeProcessOutput(gpa, warrant);
    try compareHashBytes(warrant.stdout, contract.authorizationMessageSha256(), "authorization-message-sha256");

    const challenge = try runWuci(
        gpa,
        io,
        args,
        &.{ "frost-secp256k1-challenge", contract.groupCommitment(), contract.groupPublicKey() },
        warrant.stdout,
    );
    defer freeProcessOutput(gpa, challenge);
    const challenge_text = std.mem.trim(u8, challenge.stdout, " \n\r\t");
    if (!std.mem.eql(u8, challenge_text, contract.challenge())) {
        return error.ChallengeMismatch;
    }

    const verify = try runWuciRaw(
        gpa,
        io,
        args,
        &.{
            "frost-secp256k1-verify",
            contract.signatureCommitment(),
            contract.groupPublicKey(),
            contract.signatureScalar(),
            contract.challenge(),
        },
        null,
    );
    defer freeRunResult(gpa, verify);
    const verify_exited_zero = switch (verify.term) {
        .exited => |code| code == 0,
        else => false,
    };
    if (!verify_exited_zero) {
        return error.InvalidSignature;
    }
    const verify_text = std.mem.trim(u8, verify.stdout, " \n\r\t");
    if (!std.mem.eql(u8, verify_text, "valid")) {
        return error.InvalidSignature;
    }

    if (do_open) {
        const opened = try runWuci(
            gpa,
            io,
            args,
            &.{ "open-file-keyfile", args.keyfile.?, args.artifact, args.out.? },
            null,
        );
        defer freeProcessOutput(gpa, opened);
        if (opened.stdout.len != 0) return error.UnexpectedOpenOutput;
    }

    try stdout.writeAll("valid\n");
    try stdout.flush();
}

fn parseContract(text: []const u8) !Contract {
    if (text.len == 0) return error.EmptyContract;
    for (text) |byte| {
        if (byte > 0x7f) return error.NonAsciiContract;
        if (byte == '\r') return error.ContractContainsCr;
    }
    if (text[text.len - 1] != '\n') return error.MissingTrailingNewline;
    if (text.len >= 2 and text[text.len - 2] == '\n') return error.ExtraTrailingNewline;
    for (private_markers) |marker| {
        if (std.mem.indexOf(u8, text, marker) != null) return error.PrivateMaterialMarker;
    }

    var values: [field_labels.len][]const u8 = undefined;
    var index: usize = 0;
    var lines = std.mem.splitScalar(u8, text[0 .. text.len - 1], '\n');
    while (lines.next()) |line| {
        if (index >= field_labels.len) return error.UnexpectedFieldCount;
        const label = field_labels[index];
        if (!std.mem.startsWith(u8, line, label)) return error.NonCanonicalFieldOrder;
        if (line.len < label.len + 2 or line[label.len] != ':' or line[label.len + 1] != ' ') {
            return error.MalformedContractLine;
        }
        const value = line[label.len + 2 ..];
        if (value.len == 0) return error.EmptyContractField;
        values[index] = value;
        index += 1;
    }
    if (index != field_labels.len) return error.UnexpectedFieldCount;

    const contract = Contract{ .values = values };
    try validateContract(contract);
    return contract;
}

fn validateContract(contract: Contract) !void {
    if (!std.mem.eql(u8, contract.values[0], contract_schema)) return error.UnsupportedSchema;
    if (!isAllowedAction(contract.action())) return error.UnsupportedAction;

    inline for (.{ 2, 3, 4, 5, 8, 10 }) |index| {
        if (!isLowerHex(contract.values[index], 64)) return error.InvalidHex64;
    }
    inline for (.{ 6, 7, 9 }) |index| {
        if (!isLowerHex(contract.values[index], 66)) return error.InvalidCompressedSec1;
        if (!std.mem.eql(u8, contract.values[index][0..2], "02") and
            !std.mem.eql(u8, contract.values[index][0..2], "03"))
        {
            return error.InvalidCompressedSec1;
        }
    }
    if (!std.mem.eql(u8, contract.signatureCommitment(), contract.groupCommitment())) {
        return error.SignatureCommitmentMismatch;
    }
}

fn isAllowedAction(value: []const u8) bool {
    return std.mem.eql(u8, value, "open") or
        std.mem.eql(u8, value, "release") or
        std.mem.eql(u8, value, "trust") or
        std.mem.eql(u8, value, "publish");
}

fn isLowerHex(value: []const u8, expected_len: usize) bool {
    if (value.len != expected_len) return false;
    for (value) |byte| {
        if (!((byte >= '0' and byte <= '9') or (byte >= 'a' and byte <= 'f'))) return false;
    }
    return true;
}

fn sha256Hex(data: []const u8) [64]u8 {
    var digest: [Sha256.digest_length]u8 = undefined;
    Sha256.hash(data, &digest, .{});
    return std.fmt.bytesToHex(digest, .lower);
}

fn jsonString(text: []const u8, key: []const u8) ![]const u8 {
    const needle = try std.fmt.allocPrint(std.heap.smp_allocator, "\"{s}\": \"", .{key});
    defer std.heap.smp_allocator.free(needle);
    const start = std.mem.indexOf(u8, text, needle) orelse return error.JsonStringMissing;
    const value_start = start + needle.len;
    const value_rel_end = std.mem.indexOfScalar(u8, text[value_start..], '"') orelse return error.JsonStringUnterminated;
    const value = text[value_start .. value_start + value_rel_end];
    if (value.len == 0) return error.JsonStringEmpty;
    return value;
}

fn requireJsonString(text: []const u8, key: []const u8, value: []const u8) !void {
    try expectEqual(try jsonString(text, key), value, error.JsonBindingMismatch);
}

fn requireJsonBool(text: []const u8, key: []const u8, value: bool) !void {
    const literal = if (value) "false" else "true";
    const wanted = if (value) "true" else "false";
    _ = literal;
    const needle = try std.fmt.allocPrint(std.heap.smp_allocator, "\"{s}\": {s}", .{ key, wanted });
    defer std.heap.smp_allocator.free(needle);
    if (std.mem.indexOf(u8, text, needle) == null) return error.JsonBindingMismatch;
}

fn expectEqual(actual: []const u8, expected: []const u8, err: anyerror) !void {
    if (!std.mem.eql(u8, actual, expected)) return err;
}

fn compareHash(gpa: Allocator, io: Io, path: []const u8, expected: []const u8, context: []const u8) !void {
    const data = try readFile(gpa, io, path);
    defer gpa.free(data);
    try compareHashBytes(data, expected, context);
}

fn compareHashBytes(data: []const u8, expected: []const u8, context: []const u8) !void {
    var digest: [Sha256.digest_length]u8 = undefined;
    Sha256.hash(data, &digest, .{});
    const actual = std.fmt.bytesToHex(digest, .lower);
    if (!std.mem.eql(u8, actual[0..], expected)) {
        std.debug.print("{s} mismatch\n", .{context});
        return error.HashMismatch;
    }
}

fn readFile(gpa: Allocator, io: Io, path: []const u8) ![]u8 {
    return try Io.Dir.cwd().readFileAlloc(io, path, gpa, .limited(max_file_size));
}

fn writeNewFile(io: Io, path: []const u8, data: []const u8) !void {
    try Io.Dir.cwd().writeFile(io, .{
        .sub_path = path,
        .data = data,
        .flags = .{
            .exclusive = true,
            .permissions = @enumFromInt(0o600),
        },
    });
}

fn runWuci(
    gpa: Allocator,
    io: Io,
    args: Args,
    wuci_args: []const []const u8,
    stdin_data: ?[]const u8,
) !ProcessOutput {
    const result = try runWuciRaw(gpa, io, args, wuci_args, stdin_data);
    errdefer freeRunResult(gpa, result);

    switch (result.term) {
        .exited => |code| {
            if (code != 0) {
                std.debug.print("wuci command failed: {s}\n", .{std.mem.trim(u8, result.stderr, " \n\r\t")});
                return error.WuciCommandFailed;
            }
        },
        else => return error.WuciCommandTerminated,
    }

    return .{ .stdout = result.stdout, .stderr = result.stderr };
}

fn runWuciRaw(
    gpa: Allocator,
    io: Io,
    args: Args,
    wuci_args: []const []const u8,
    stdin_data: ?[]const u8,
) !std.process.RunResult {
    var argv: std.ArrayList([]const u8) = .empty;
    defer argv.deinit(gpa);

    try appendRunner(gpa, &argv, args);
    try argv.append(gpa, args.bin);
    try argv.appendSlice(gpa, wuci_args);

    const result = if (stdin_data) |input|
        try runProcessWithStdin(gpa, io, argv.items, input)
    else
        try std.process.run(gpa, io, .{
            .argv = argv.items,
            .stdout_limit = .limited(max_process_output),
            .stderr_limit = .limited(max_process_output),
        });
    return result;
}

fn runProcessWithStdin(
    gpa: Allocator,
    io: Io,
    argv: []const []const u8,
    input: []const u8,
) !std.process.RunResult {
    var child = try std.process.spawn(io, .{
        .argv = argv,
        .stdin = .pipe,
        .stdout = .pipe,
        .stderr = .pipe,
    });
    defer child.kill(io);

    try child.stdin.?.writeStreamingAll(io, input);
    child.stdin.?.close(io);
    child.stdin = null;

    var multi_reader_buffer: Io.File.MultiReader.Buffer(2) = undefined;
    var multi_reader: Io.File.MultiReader = undefined;
    multi_reader.init(gpa, io, multi_reader_buffer.toStreams(), &.{ child.stdout.?, child.stderr.? });
    defer multi_reader.deinit();

    const stdout_reader = multi_reader.reader(0);
    const stderr_reader = multi_reader.reader(1);

    while (multi_reader.fill(64, .none)) |_| {
        if (stdout_reader.buffered().len > max_process_output) return error.StreamTooLong;
        if (stderr_reader.buffered().len > max_process_output) return error.StreamTooLong;
    } else |err| switch (err) {
        error.EndOfStream => {},
        else => |e| return e,
    }

    try multi_reader.checkAnyError();
    const term = try child.wait(io);

    const stdout_slice = try multi_reader.toOwnedSlice(0);
    errdefer gpa.free(stdout_slice);

    const stderr_slice = try multi_reader.toOwnedSlice(1);
    errdefer gpa.free(stderr_slice);

    return .{
        .term = term,
        .stdout = stdout_slice,
        .stderr = stderr_slice,
    };
}

fn appendRunner(gpa: Allocator, argv: *std.ArrayList([]const u8), args: Args) !void {
    if (args.runner) |runner| {
        if (runner.len != 0) try argv.append(gpa, runner);
        return;
    }
    if (args.env_runner) |env_runner| {
        var parts = std.mem.tokenizeAny(u8, env_runner, " \t\r\n");
        while (parts.next()) |part| {
            try argv.append(gpa, part);
        }
    }
}

fn freeProcessOutput(gpa: Allocator, output: ProcessOutput) void {
    gpa.free(output.stdout);
    gpa.free(output.stderr);
}

fn freeRunResult(gpa: Allocator, output: std.process.RunResult) void {
    gpa.free(output.stdout);
    gpa.free(output.stderr);
}
