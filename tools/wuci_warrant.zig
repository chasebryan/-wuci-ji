const std = @import("std");

const Allocator = std.mem.Allocator;
const Io = std.Io;
const Sha256 = std.crypto.hash.sha2.Sha256;

const max_process_output = 4 * 1024 * 1024;
const max_file_size = 1024 * 1024;

const suite = "FROST-secp256k1-SHA256-v1";
const mode = "deterministic-2of2-fixture";
const transcript_schema = "wuci-frost-transcript-v1";
const auth_message_schema = "wuci-frost-authorization-message-v1";
const receipt_schema = "wuci-frost-authorization-v1";
const fixture_warning = "NON-PRODUCTION deterministic fixture material only; do not use for real signatures.";
const group_public_key = "022f8bde4d1a07209355b4a7250a5c5128e88b84bddc619ab7cba8d569b240efe4";

const zero1 = "0000000000000000000000000000000000000000000000000000000000000001";
const zero2 = "0000000000000000000000000000000000000000000000000000000000000002";
const zero3 = "0000000000000000000000000000000000000000000000000000000000000003";
const zero4 = "0000000000000000000000000000000000000000000000000000000000000004";
const zero5 = "0000000000000000000000000000000000000000000000000000000000000005";
const share1 = "000000000000000000000000000000000000000000000000000000000000000c";
const share2 = "0000000000000000000000000000000000000000000000000000000000000013";

const Args = struct {
    bin: []const u8 = "build/wuci-ji",
    artifact: []const u8 = "",
    action: []const u8 = "",
    print_auth_message: bool = false,
    print_transcript_manifest: bool = false,
    transcript_manifest: []const u8 = "",
    update_transcript_manifest: bool = false,
    receipt: []const u8 = "",
    runner: ?[]const u8 = null,
    env_runner: ?[]const u8 = null,
};

const ProcessOutput = struct {
    stdout: []u8,
    stderr: []u8,
};

const Manifest = struct {
    text: []u8,
    version: []const u8,
    algorithm: []const u8,
    header_length: []const u8,
    key_id: []const u8,
    artifact_sha256: []const u8,
    ciphertext_length: []const u8,
    ciphertext_sha256: []const u8,
    nonce: []const u8,
    tag: []const u8,

    fn deinit(self: Manifest, gpa: Allocator) void {
        gpa.free(self.text);
    }
};

const Authorization = struct {
    manifest: Manifest,
    message: []u8,
    manifest_sha256: [64]u8,
    message_sha256: [64]u8,

    fn deinit(self: Authorization, gpa: Allocator) void {
        self.manifest.deinit(gpa);
        gpa.free(self.message);
    }
};

const Transcript = struct {
    d1: []const u8,
    e1: []const u8,
    d2: []const u8,
    e2: []const u8,
    commitment_hash: []u8,
    message_hash: []u8,
    rho1: []u8,
    rho2: []u8,
    group_commitment: []const u8,
    challenge: []u8,
    lagrange1: []u8,
    lagrange2: []u8,

    fn deinit(self: Transcript, gpa: Allocator) void {
        gpa.free(self.d1);
        gpa.free(self.e1);
        gpa.free(self.d2);
        gpa.free(self.e2);
        gpa.free(self.commitment_hash);
        gpa.free(self.message_hash);
        gpa.free(self.rho1);
        gpa.free(self.rho2);
        gpa.free(self.group_commitment);
        gpa.free(self.challenge);
        gpa.free(self.lagrange1);
        gpa.free(self.lagrange2);
    }
};

const Signature = struct {
    z1: []u8,
    z2: []u8,
    signature_commitment: []const u8,
    signature_scalar: []const u8,
    verification: []u8,

    fn deinit(self: Signature, gpa: Allocator) void {
        gpa.free(self.z1);
        gpa.free(self.z2);
        gpa.free(self.signature_commitment);
        gpa.free(self.signature_scalar);
        gpa.free(self.verification);
    }
};

pub fn main(init: std.process.Init) !void {
    const gpa = init.gpa;
    const io = init.io;
    var stdout_buffer: [4096]u8 = undefined;
    var stdout_writer = Io.File.stdout().writer(io, &stdout_buffer);
    const stdout = &stdout_writer.interface;

    var args = parseArgs(gpa, init.minimal.args) catch |err| {
        usage();
        return err;
    };
    args.env_runner = init.environ_map.get("WUCI_JI_RUNNER");

    try validateArgs(args);
    const auth = try buildAuthorization(gpa, io, args);
    defer auth.deinit(gpa);

    if (args.print_auth_message) {
        try stdout.writeAll(auth.message);
        try stdout.flush();
        return;
    }

    const transcript = try buildTranscript(gpa, io, args, auth.message);
    defer transcript.deinit(gpa);
    const transcript_text = try formatTranscript(gpa, auth.message, transcript, false);
    defer gpa.free(transcript_text);

    if (args.print_transcript_manifest) {
        try stdout.writeAll(transcript_text);
        try stdout.flush();
        return;
    }

    if (args.transcript_manifest.len == 0 or args.receipt.len == 0) return error.MissingReceiptModeArgument;
    const supplied_transcript = try readFile(gpa, io, args.transcript_manifest);
    defer gpa.free(supplied_transcript);
    if (!std.mem.eql(u8, supplied_transcript, transcript_text)) return error.TranscriptManifestMismatch;

    const signature = try signTranscript(gpa, io, args, transcript);
    defer signature.deinit(gpa);
    if (args.update_transcript_manifest) {
        const spent_transcript = try formatTranscript(gpa, auth.message, transcript, true);
        defer gpa.free(spent_transcript);
        try replaceFile(gpa, io, args.transcript_manifest, spent_transcript);
    }
    const receipt_text = try formatReceipt(gpa, auth, transcript, signature, args.action);
    defer gpa.free(receipt_text);
    try writeNewFile(io, args.receipt, receipt_text);
}

fn parseArgs(gpa: Allocator, process_args: std.process.Args) !Args {
    var argv = try std.process.Args.Iterator.initAllocator(process_args, gpa);
    defer argv.deinit();

    _ = argv.next() orelse return error.MissingArgv0;
    var args = Args{};
    while (argv.next()) |arg| {
        if (std.mem.eql(u8, arg, "--bin")) {
            args.bin = argv.next() orelse return error.MissingValue;
        } else if (std.mem.eql(u8, arg, "--artifact")) {
            args.artifact = argv.next() orelse return error.MissingValue;
        } else if (std.mem.eql(u8, arg, "--action")) {
            args.action = argv.next() orelse return error.MissingValue;
        } else if (std.mem.eql(u8, arg, "--print-auth-message")) {
            args.print_auth_message = true;
        } else if (std.mem.eql(u8, arg, "--print-transcript-manifest")) {
            args.print_transcript_manifest = true;
        } else if (std.mem.eql(u8, arg, "--transcript-manifest")) {
            args.transcript_manifest = argv.next() orelse return error.MissingValue;
        } else if (std.mem.eql(u8, arg, "--update-transcript-manifest")) {
            args.update_transcript_manifest = true;
        } else if (std.mem.eql(u8, arg, "--receipt")) {
            args.receipt = argv.next() orelse return error.MissingValue;
        } else if (std.mem.eql(u8, arg, "--runner")) {
            args.runner = argv.next() orelse return error.MissingValue;
        } else {
            return error.UnknownArgument;
        }
    }
    return args;
}

fn usage() void {
    std.debug.print(
        \\usage: wuci-warrant --bin <wuci-ji> --artifact <artifact> --action <open|release> --print-transcript-manifest
        \\       wuci-warrant --bin <wuci-ji> --artifact <artifact> --action <open|release> --transcript-manifest <path> --update-transcript-manifest --receipt <path>
        \\
    , .{});
}

fn validateArgs(args: Args) !void {
    if (args.artifact.len == 0) return error.MissingArtifact;
    if (!std.mem.eql(u8, args.action, "open") and !std.mem.eql(u8, args.action, "release")) {
        return error.UnsupportedAction;
    }
    const mode_count: u8 = @intFromBool(args.print_auth_message) + @intFromBool(args.print_transcript_manifest) + @intFromBool(args.receipt.len != 0);
    if (mode_count != 1) return error.InvalidMode;
    if (args.update_transcript_manifest and args.receipt.len == 0) return error.UpdateRequiresReceipt;
}

fn buildAuthorization(gpa: Allocator, io: Io, args: Args) !Authorization {
    const manifest_output = try runWuci(gpa, io, args, &.{ "manifest-file", args.artifact }, null);
    defer freeProcessOutput(gpa, manifest_output);
    const manifest = try parseManifest(gpa, manifest_output.stdout);

    const warrant = try runWuci(gpa, io, args, &.{ "warrant-message-file", args.action, args.artifact }, null);
    errdefer freeProcessOutput(gpa, warrant);
    const prefix = "artifact-manifest:\n";
    if (!std.mem.endsWith(u8, warrant.stdout, manifest.text)) return error.WarrantManifestMismatch;
    if (warrant.stdout.len < manifest.text.len + prefix.len) return error.WarrantManifestMismatch;
    const prefix_start = warrant.stdout.len - manifest.text.len - prefix.len;
    if (!std.mem.eql(u8, warrant.stdout[prefix_start .. prefix_start + prefix.len], prefix)) {
        return error.WarrantManifestMismatch;
    }

    return .{
        .manifest = manifest,
        .message = warrant.stdout,
        .manifest_sha256 = sha256Hex(manifest.text),
        .message_sha256 = sha256Hex(warrant.stdout),
    };
}

fn parseManifest(gpa: Allocator, text: []const u8) !Manifest {
    if (text.len == 0 or text[text.len - 1] != '\n') return error.InvalidManifest;
    const copy = try gpa.dupe(u8, text);
    errdefer gpa.free(copy);
    return .{
        .text = copy,
        .version = try manifestValue(copy, "version"),
        .algorithm = try manifestValue(copy, "algorithm"),
        .header_length = try manifestValue(copy, "header-length"),
        .key_id = try manifestValue(copy, "key-id"),
        .artifact_sha256 = try manifestValue(copy, "artifact-sha256"),
        .ciphertext_length = try manifestValue(copy, "ciphertext-length"),
        .ciphertext_sha256 = try manifestValue(copy, "ciphertext-sha256"),
        .nonce = try manifestValue(copy, "nonce"),
        .tag = try manifestValue(copy, "tag"),
    };
}

fn manifestValue(text: []const u8, label: []const u8) ![]const u8 {
    var lines = std.mem.splitScalar(u8, text[0 .. text.len - 1], '\n');
    while (lines.next()) |line| {
        if (std.mem.startsWith(u8, line, label) and line.len > label.len + 2 and line[label.len] == ':' and line[label.len + 1] == ' ') {
            return line[label.len + 2 ..];
        }
    }
    return error.MissingManifestField;
}

fn buildTranscript(gpa: Allocator, io: Io, args: Args, message: []const u8) !Transcript {
    const commit1 = try runWuci(gpa, io, args, &.{ "frost-secp256k1-commit", zero2, zero3 }, null);
    defer freeProcessOutput(gpa, commit1);
    const d1 = try labelValue(commit1.stdout, "hiding_nonce_commitment");
    const e1 = try labelValue(commit1.stdout, "binding_nonce_commitment");

    const commit2 = try runWuci(gpa, io, args, &.{ "frost-secp256k1-commit", zero4, zero5 }, null);
    defer freeProcessOutput(gpa, commit2);
    const d2 = try labelValue(commit2.stdout, "hiding_nonce_commitment");
    const e2 = try labelValue(commit2.stdout, "binding_nonce_commitment");

    const commitment_hash = try runScalar(gpa, io, args, &.{ "frost-secp256k1-commitment-hash", zero1, d1, e1, zero2, d2, e2 }, null);
    errdefer gpa.free(commitment_hash);
    const message_hash = try runScalar(gpa, io, args, &.{"frost-secp256k1-h4"}, message);
    errdefer gpa.free(message_hash);
    const rho1 = try runScalar(gpa, io, args, &.{ "frost-secp256k1-binding-factor", group_public_key, message_hash, commitment_hash, zero1 }, null);
    errdefer gpa.free(rho1);
    const rho2 = try runScalar(gpa, io, args, &.{ "frost-secp256k1-binding-factor", group_public_key, message_hash, commitment_hash, zero2 }, null);
    errdefer gpa.free(rho2);

    const group = try runWuci(gpa, io, args, &.{ "frost-secp256k1-group-commitment", zero1, d1, e1, rho1, zero2, d2, e2, rho2 }, null);
    defer freeProcessOutput(gpa, group);
    const group_commitment = try labelValue(group.stdout, "group_commitment");
    const challenge = try runScalar(gpa, io, args, &.{ "frost-secp256k1-challenge", group_commitment, group_public_key }, message);
    errdefer gpa.free(challenge);
    const lagrange1 = try runScalar(gpa, io, args, &.{ "frost-secp256k1-lagrange", zero1, zero1, zero2 }, null);
    errdefer gpa.free(lagrange1);
    const lagrange2 = try runScalar(gpa, io, args, &.{ "frost-secp256k1-lagrange", zero2, zero1, zero2 }, null);
    errdefer gpa.free(lagrange2);

    return .{
        .d1 = try gpa.dupe(u8, d1),
        .e1 = try gpa.dupe(u8, e1),
        .d2 = try gpa.dupe(u8, d2),
        .e2 = try gpa.dupe(u8, e2),
        .commitment_hash = commitment_hash,
        .message_hash = message_hash,
        .rho1 = rho1,
        .rho2 = rho2,
        .group_commitment = try gpa.dupe(u8, group_commitment),
        .challenge = challenge,
        .lagrange1 = lagrange1,
        .lagrange2 = lagrange2,
    };
}

fn signTranscript(gpa: Allocator, io: Io, args: Args, transcript: Transcript) !Signature {
    const z1 = try runScalar(gpa, io, args, &.{ "frost-secp256k1-signing-share", zero2, zero3, transcript.rho1, transcript.lagrange1, share1, transcript.challenge }, null);
    errdefer gpa.free(z1);
    const z2 = try runScalar(gpa, io, args, &.{ "frost-secp256k1-signing-share", zero4, zero5, transcript.rho2, transcript.lagrange2, share2, transcript.challenge }, null);
    errdefer gpa.free(z2);
    const aggregate = try runWuci(gpa, io, args, &.{ "frost-secp256k1-aggregate", transcript.group_commitment, z1, z2 }, null);
    defer freeProcessOutput(gpa, aggregate);
    const signature_commitment = try labelValue(aggregate.stdout, "signature_commitment");
    const signature_scalar = try labelValue(aggregate.stdout, "signature_scalar");
    if (!std.mem.eql(u8, signature_commitment, transcript.group_commitment)) return error.SignatureCommitmentMismatch;
    const verification = try runScalar(gpa, io, args, &.{ "frost-secp256k1-verify", signature_commitment, group_public_key, signature_scalar, transcript.challenge }, null);
    errdefer gpa.free(verification);
    if (!std.mem.eql(u8, verification, "valid")) return error.SignatureVerificationFailed;
    return .{
        .z1 = z1,
        .z2 = z2,
        .signature_commitment = try gpa.dupe(u8, signature_commitment),
        .signature_scalar = try gpa.dupe(u8, signature_scalar),
        .verification = verification,
    };
}

fn formatTranscript(gpa: Allocator, message: []const u8, transcript: Transcript, emitted: bool) ![]u8 {
    const message_hex = try allocHex(gpa, message);
    defer gpa.free(message_hex);
    return try std.fmt.allocPrint(gpa,
        \\{{
        \\  "challenge": "{s}",
        \\  "commitment_hash": "{s}",
        \\  "group_commitment": "{s}",
        \\  "group_public_key": "{s}",
        \\  "message_hash": "{s}",
        \\  "message_hex": "{s}",
        \\  "mode": "{s}",
        \\  "production": false,
        \\  "schema": "{s}",
        \\  "signers": [
        \\    {{
        \\      "binding_factor": "{s}",
        \\      "binding_nonce_commitment": "{s}",
        \\      "hiding_nonce_commitment": "{s}",
        \\      "id": "{s}",
        \\      "lagrange": "{s}"
        \\    }},
        \\    {{
        \\      "binding_factor": "{s}",
        \\      "binding_nonce_commitment": "{s}",
        \\      "hiding_nonce_commitment": "{s}",
        \\      "id": "{s}",
        \\      "lagrange": "{s}"
        \\    }}
        \\  ],
        \\  "signing_shares_emitted": {},
        \\  "suite": "{s}",
        \\  "warning": "{s}"
        \\}}
        \\
    , .{
        transcript.challenge,
        transcript.commitment_hash,
        transcript.group_commitment,
        group_public_key,
        transcript.message_hash,
        message_hex,
        mode,
        transcript_schema,
        transcript.rho1,
        transcript.e1,
        transcript.d1,
        zero1,
        transcript.lagrange1,
        transcript.rho2,
        transcript.e2,
        transcript.d2,
        zero2,
        transcript.lagrange2,
        emitted,
        suite,
        fixture_warning,
    });
}

fn formatReceipt(gpa: Allocator, auth: Authorization, transcript: Transcript, signature: Signature, action: []const u8) ![]u8 {
    return try std.fmt.allocPrint(gpa,
        \\{{
        \\  "action": "{s}",
        \\  "artifact_manifest": {{
        \\    "algorithm": "{s}",
        \\    "artifact_sha256": "{s}",
        \\    "ciphertext_length": "{s}",
        \\    "ciphertext_sha256": "{s}",
        \\    "header_length": "{s}",
        \\    "key_id": "{s}",
        \\    "nonce": "{s}",
        \\    "tag": "{s}",
        \\    "version": "{s}"
        \\  }},
        \\  "artifact_manifest_sha256": "{s}",
        \\  "authorization_message_schema": "{s}",
        \\  "authorization_message_sha256": "{s}",
        \\  "challenge": "{s}",
        \\  "group_commitment": "{s}",
        \\  "group_public_key": "{s}",
        \\  "mode": "{s}",
        \\  "production": false,
        \\  "schema": "{s}",
        \\  "signature_commitment": "{s}",
        \\  "signature_scalar": "{s}",
        \\  "suite": "{s}",
        \\  "verification": "{s}",
        \\  "warning": "{s}"
        \\}}
        \\
    , .{
        action,
        auth.manifest.algorithm,
        auth.manifest.artifact_sha256,
        auth.manifest.ciphertext_length,
        auth.manifest.ciphertext_sha256,
        auth.manifest.header_length,
        auth.manifest.key_id,
        auth.manifest.nonce,
        auth.manifest.tag,
        auth.manifest.version,
        auth.manifest_sha256[0..],
        auth_message_schema,
        auth.message_sha256[0..],
        transcript.challenge,
        transcript.group_commitment,
        group_public_key,
        mode,
        receipt_schema,
        signature.signature_commitment,
        signature.signature_scalar,
        suite,
        signature.verification,
        fixture_warning,
    });
}

fn runScalar(gpa: Allocator, io: Io, args: Args, wuci_args: []const []const u8, stdin_data: ?[]const u8) ![]u8 {
    const result = try runWuci(gpa, io, args, wuci_args, stdin_data);
    defer freeProcessOutput(gpa, result);
    return try gpa.dupe(u8, std.mem.trim(u8, result.stdout, " \n\r\t"));
}

fn labelValue(text: []const u8, label: []const u8) ![]const u8 {
    var lines = std.mem.splitScalar(u8, text, '\n');
    while (lines.next()) |line| {
        if (line.len == 0) continue;
        if (std.mem.startsWith(u8, line, label) and line.len > label.len + 2 and line[label.len] == ':' and line[label.len + 1] == ' ') {
            return line[label.len + 2 ..];
        }
    }
    return error.MissingLabel;
}

fn sha256Hex(data: []const u8) [64]u8 {
    var digest: [Sha256.digest_length]u8 = undefined;
    Sha256.hash(data, &digest, .{});
    return std.fmt.bytesToHex(digest, .lower);
}

fn allocHex(gpa: Allocator, data: []const u8) ![]u8 {
    const table = "0123456789abcdef";
    const out = try gpa.alloc(u8, data.len * 2);
    for (data, 0..) |byte, index| {
        out[index * 2] = table[byte >> 4];
        out[index * 2 + 1] = table[byte & 0x0f];
    }
    return out;
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

fn replaceFile(gpa: Allocator, io: Io, path: []const u8, data: []const u8) !void {
    const tmp = try std.fmt.allocPrint(gpa, "{s}.tmp", .{path});
    defer gpa.free(tmp);
    try writeNewFile(io, tmp, data);
    errdefer Io.Dir.cwd().deleteFile(io, tmp) catch {};
    try Io.Dir.cwd().rename(tmp, Io.Dir.cwd(), path, io);
}

fn runWuci(gpa: Allocator, io: Io, args: Args, wuci_args: []const []const u8, stdin_data: ?[]const u8) !ProcessOutput {
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

fn runWuciRaw(gpa: Allocator, io: Io, args: Args, wuci_args: []const []const u8, stdin_data: ?[]const u8) !std.process.RunResult {
    var argv: std.ArrayList([]const u8) = .empty;
    defer argv.deinit(gpa);
    try appendRunner(gpa, &argv, args);
    try argv.append(gpa, args.bin);
    try argv.appendSlice(gpa, wuci_args);
    if (stdin_data) |input| {
        return try runProcessWithStdin(gpa, io, argv.items, input);
    }
    return try std.process.run(gpa, io, .{
        .argv = argv.items,
        .stdout_limit = .limited(max_process_output),
        .stderr_limit = .limited(max_process_output),
    });
}

fn runProcessWithStdin(gpa: Allocator, io: Io, argv: []const []const u8, input: []const u8) !std.process.RunResult {
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
