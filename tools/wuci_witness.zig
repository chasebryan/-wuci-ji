const std = @import("std");

const Allocator = std.mem.Allocator;
const Io = std.Io;
const Sha256 = std.crypto.hash.sha2.Sha256;

const max_file_size = 16 * 1024 * 1024;
const max_process_output = 4 * 1024 * 1024;

const bundle_schema = "wuci-publish-bundle-v1";
const index_schema = "wuci-publish-index-v1";
const attestation_schema = "wuci-witness-attestation-v1";
const contract_schema = "wuci-gate-receipt-contract-v1";
const authority_schema = "wuci-authority-root-v1";
const frost_suite = "FROST-secp256k1-SHA256-v1";
const release_action = "release";
const release_anchor_sha256 = "d50c0be237fadddc4f22c69d912567b318cd235b2b4bd0aeff851b54d126ae1f";
const fixture_group_public_key = "022f8bde4d1a07209355b4a7250a5c5128e88b84bddc619ab7cba8d569b240efe4";

const public_files = [_][]const u8{
    "wuci-ji.self.wj",
    "manifest.txt",
    "warrant-message.txt",
    "release-receipt.json",
    "receipt-contract.txt",
    "authority-root.txt",
    "release-decision.txt",
    "publish-index.txt",
    "attestation.json",
};

const forbidden_files = [_][]const u8{
    "artifact.key",
    "opened-wuci-ji",
    "auth-transcript.json",
    "release-transcript.json",
};

const index_labels = [_][]const u8{
    "schema",
    "artifact-sha256",
    "manifest-sha256",
    "warrant-message-sha256",
    "release-receipt-sha256",
    "receipt-contract-sha256",
    "authority-root-sha256",
    "release-decision-sha256",
    "release-authority-group-public-key",
};

const authority_labels = [_][]const u8{
    "schema",
    "suite",
    "production",
    "authority-id",
    "group-public-key",
    "allow-open",
    "allow-release",
    "allow-trust",
    "allow-publish",
};

const contract_labels = [_][]const u8{
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

const decision_labels = [_][]const u8{
    "authorized",
    "action",
    "artifact-sha256",
};

const Args = struct {
    command: []const u8,
    bundle: []const u8 = "",
    bin: []const u8 = "build/wuci-ji",
    runner: ?[]const u8 = null,
    env_runner: ?[]const u8 = null,
};

const BundlePaths = struct {
    artifact: []u8,
    manifest: []u8,
    warrant_message: []u8,
    release_receipt: []u8,
    receipt_contract: []u8,
    authority_root: []u8,
    release_decision: []u8,
    publish_index: []u8,
    attestation: []u8,

    fn deinit(self: BundlePaths, gpa: Allocator) void {
        gpa.free(self.artifact);
        gpa.free(self.manifest);
        gpa.free(self.warrant_message);
        gpa.free(self.release_receipt);
        gpa.free(self.receipt_contract);
        gpa.free(self.authority_root);
        gpa.free(self.release_decision);
        gpa.free(self.publish_index);
        gpa.free(self.attestation);
    }
};

const BundleData = struct {
    artifact: []u8,
    manifest: []u8,
    warrant_message: []u8,
    release_receipt: []u8,
    receipt_contract: []u8,
    authority_root: []u8,
    release_decision: []u8,
    publish_index: []u8,
    attestation: []u8,

    fn deinit(self: BundleData, gpa: Allocator) void {
        gpa.free(self.artifact);
        gpa.free(self.manifest);
        gpa.free(self.warrant_message);
        gpa.free(self.release_receipt);
        gpa.free(self.receipt_contract);
        gpa.free(self.authority_root);
        gpa.free(self.release_decision);
        gpa.free(self.publish_index);
        gpa.free(self.attestation);
    }
};

const Hashes = struct {
    artifact: [64]u8,
    manifest: [64]u8,
    warrant_message: [64]u8,
    release_receipt: [64]u8,
    receipt_contract: [64]u8,
    authority_root: [64]u8,
    release_decision: [64]u8,
    publish_index: [64]u8,
};

const Parsed = struct {
    index: [index_labels.len][]const u8,
    authority: [authority_labels.len][]const u8,
    contract: [contract_labels.len][]const u8,
    decision: [decision_labels.len][]const u8,
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

    if (std.mem.eql(u8, args.command, "index")) {
        try runIndex(gpa, io, stdout, args);
        return;
    }
    if (std.mem.eql(u8, args.command, "attest")) {
        try runAttest(gpa, io, stdout, args);
        return;
    }
    if (std.mem.eql(u8, args.command, "verify")) {
        try runVerify(gpa, io, stdout, args);
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
        } else if (std.mem.eql(u8, arg, "--bundle")) {
            parsed.bundle = argv.next() orelse return error.MissingValue;
        } else if (std.mem.eql(u8, arg, "--runner")) {
            parsed.runner = argv.next() orelse return error.MissingValue;
        } else if (arg.len > 0 and arg[0] == '-') {
            return error.UnknownArgument;
        } else if (parsed.bundle.len == 0) {
            parsed.bundle = arg;
        } else {
            return error.UnexpectedArgument;
        }
    }

    if (parsed.bundle.len == 0) return error.MissingBundle;
    return parsed;
}

fn usage() void {
    std.debug.print(
        \\usage: wuci-witness index <bundle> [--bin <wuci-ji>] [--runner <runner>]
        \\       wuci-witness attest <bundle> [--bin <wuci-ji>] [--runner <runner>]
        \\       wuci-witness verify <bundle> [--bin <wuci-ji>] [--runner <runner>]
        \\       wuci-witness index --bundle <bundle> [--bin <wuci-ji>] [--runner <runner>]
        \\       wuci-witness attest --bundle <bundle> [--bin <wuci-ji>] [--runner <runner>]
        \\       wuci-witness verify --bundle <bundle> [--bin <wuci-ji>] [--runner <runner>]
        \\
    , .{});
}

fn runIndex(gpa: Allocator, io: Io, stdout: *Io.Writer, args: Args) !void {
    try assertPublicProfile(io, args.bundle, false, false);
    const paths = try bundlePaths(gpa, args.bundle);
    defer paths.deinit(gpa);

    const index_text = try buildIndexText(gpa, io, args, paths);
    defer gpa.free(index_text);
    try writeNewFile(io, paths.publish_index, index_text);

    try stdout.print("wrote publish index: {s}\n", .{paths.publish_index});
    try stdout.flush();
}

fn runAttest(gpa: Allocator, io: Io, stdout: *Io.Writer, args: Args) !void {
    try assertPublicProfile(io, args.bundle, true, false);
    const paths = try bundlePaths(gpa, args.bundle);
    defer paths.deinit(gpa);

    const expected_index = try buildIndexText(gpa, io, args, paths);
    defer gpa.free(expected_index);
    const actual_index = try readFile(gpa, io, paths.publish_index);
    defer gpa.free(actual_index);
    try expectEqual(actual_index, expected_index, error.PublishIndexMismatch);
    const index = try parseFlat(index_labels, actual_index);

    const hashes = Hashes{
        .artifact = try sha256File(gpa, io, paths.artifact),
        .manifest = try sha256File(gpa, io, paths.manifest),
        .warrant_message = try sha256File(gpa, io, paths.warrant_message),
        .release_receipt = try sha256File(gpa, io, paths.release_receipt),
        .receipt_contract = try sha256File(gpa, io, paths.receipt_contract),
        .authority_root = try sha256File(gpa, io, paths.authority_root),
        .release_decision = try sha256File(gpa, io, paths.release_decision),
        .publish_index = try sha256File(gpa, io, paths.publish_index),
    };

    const decision_text = try readFile(gpa, io, paths.release_decision);
    defer gpa.free(decision_text);
    const decision = try parseFlat(decision_labels, decision_text);
    try validateDecision(decision, hashes.artifact[0..]);

    const verifier_hash = try sha256File(gpa, io, args.bin);
    const attestation = try formatAttestationJson(gpa, hashes, index, decision, verifier_hash[0..]);
    defer gpa.free(attestation);
    try writeNewFile(io, paths.attestation, attestation);

    try stdout.print("wrote witness attestation: {s}\n", .{paths.attestation});
    try stdout.flush();
}

fn runVerify(gpa: Allocator, io: Io, stdout: *Io.Writer, args: Args) !void {
    try assertPublicProfile(io, args.bundle, true, true);

    const paths = try bundlePaths(gpa, args.bundle);
    defer paths.deinit(gpa);

    const data = try readBundleData(gpa, io, paths);
    defer data.deinit(gpa);

    const hashes = Hashes{
        .artifact = sha256Hex(data.artifact),
        .manifest = sha256Hex(data.manifest),
        .warrant_message = sha256Hex(data.warrant_message),
        .release_receipt = sha256Hex(data.release_receipt),
        .receipt_contract = sha256Hex(data.receipt_contract),
        .authority_root = sha256Hex(data.authority_root),
        .release_decision = sha256Hex(data.release_decision),
        .publish_index = sha256Hex(data.publish_index),
    };

    const parsed = Parsed{
        .index = try parseFlat(index_labels, data.publish_index),
        .authority = try parseFlat(authority_labels, data.authority_root),
        .contract = try parseFlat(contract_labels, data.receipt_contract),
        .decision = try parseFlat(decision_labels, data.release_decision),
    };

    try validateIndex(parsed.index, hashes);
    try validateAuthority(parsed.authority, hashes.authority_root[0..]);
    try validateContract(parsed.contract, hashes, parsed.authority[4]);
    try validateDecision(parsed.decision, hashes.artifact[0..]);
    try validateReceiptJson(data.release_receipt, hashes, parsed.contract);

    try compareWuciOutput(gpa, io, args, &.{ "manifest-file", paths.artifact }, data.manifest, "manifest-file");
    try compareWuciOutput(
        gpa,
        io,
        args,
        &.{ "warrant-message-file", release_action, paths.artifact },
        data.warrant_message,
        "warrant-message-file",
    );
    try compareWuciOutput(gpa, io, args, &.{ "authority-root-verify", paths.authority_root }, "valid\n", "authority-root-verify");
    try compareWuciOutput(
        gpa,
        io,
        args,
        &.{ "release-authorized-rooted", paths.authority_root, paths.artifact, paths.receipt_contract },
        data.release_decision,
        "release-authorized-rooted",
    );

    try validateAttestationJson(data.attestation, hashes, parsed.index, parsed.authority[4], parsed.decision);

    try stdout.writeAll("valid witness bundle\n");
    try stdout.flush();
}

fn bundlePaths(gpa: Allocator, bundle: []const u8) !BundlePaths {
    return .{
        .artifact = try joinPath(gpa, bundle, "wuci-ji.self.wj"),
        .manifest = try joinPath(gpa, bundle, "manifest.txt"),
        .warrant_message = try joinPath(gpa, bundle, "warrant-message.txt"),
        .release_receipt = try joinPath(gpa, bundle, "release-receipt.json"),
        .receipt_contract = try joinPath(gpa, bundle, "receipt-contract.txt"),
        .authority_root = try joinPath(gpa, bundle, "authority-root.txt"),
        .release_decision = try joinPath(gpa, bundle, "release-decision.txt"),
        .publish_index = try joinPath(gpa, bundle, "publish-index.txt"),
        .attestation = try joinPath(gpa, bundle, "attestation.json"),
    };
}

fn joinPath(gpa: Allocator, parent: []const u8, child: []const u8) ![]u8 {
    if (parent.len != 0 and parent[parent.len - 1] == '/') {
        return try std.fmt.allocPrint(gpa, "{s}{s}", .{ parent, child });
    }
    return try std.fmt.allocPrint(gpa, "{s}/{s}", .{ parent, child });
}

fn readBundleData(gpa: Allocator, io: Io, paths: BundlePaths) !BundleData {
    return .{
        .artifact = try readFile(gpa, io, paths.artifact),
        .manifest = try readFile(gpa, io, paths.manifest),
        .warrant_message = try readFile(gpa, io, paths.warrant_message),
        .release_receipt = try readFile(gpa, io, paths.release_receipt),
        .receipt_contract = try readFile(gpa, io, paths.receipt_contract),
        .authority_root = try readFile(gpa, io, paths.authority_root),
        .release_decision = try readFile(gpa, io, paths.release_decision),
        .publish_index = try readFile(gpa, io, paths.publish_index),
        .attestation = try readFile(gpa, io, paths.attestation),
    };
}

fn assertPublicProfile(io: Io, bundle: []const u8, require_index: bool, require_attestation: bool) !void {
    var dir = try Io.Dir.cwd().openDir(io, bundle, .{ .iterate = true });
    defer dir.close(io);

    var seen: [public_files.len]bool = @splat(false);
    var iter = dir.iterate();
    while (try iter.next(io)) |entry| {
        if (entry.kind != .file) return error.PublicBundleEntryNotFile;
        if (indexOf(forbidden_files, entry.name) != null) return error.PrivateFilePresent;
        const index = indexOf(public_files, entry.name) orelse return error.UnexpectedPublicBundleFile;
        if (index == 7 and !require_index) return error.UnexpectedPublicBundleFile;
        if (index == 8 and !require_attestation) return error.UnexpectedPublicBundleFile;
        if (seen[index]) return error.DuplicatePublicBundleFile;
        seen[index] = true;
    }
    for (seen, 0..) |found, index| {
        const required = index < 7 or (index == 7 and require_index) or (index == 8 and require_attestation);
        if (required and !found) return error.MissingPublicBundleFile;
    }
}

fn indexOf(comptime list: anytype, value: []const u8) ?usize {
    for (list, 0..) |item, index| {
        if (std.mem.eql(u8, item, value)) return index;
    }
    return null;
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

fn sha256File(gpa: Allocator, io: Io, path: []const u8) ![64]u8 {
    const data = try readFile(gpa, io, path);
    defer gpa.free(data);
    return sha256Hex(data);
}

fn sha256Hex(data: []const u8) [64]u8 {
    var digest: [Sha256.digest_length]u8 = undefined;
    Sha256.hash(data, &digest, .{});
    return std.fmt.bytesToHex(digest, .lower);
}

fn buildIndexText(gpa: Allocator, io: Io, args: Args, paths: BundlePaths) ![]u8 {
    const data = try readCoreData(gpa, io, paths);
    defer data.deinit(gpa);

    var hashes: Hashes = undefined;
    hashes.artifact = sha256Hex(data.artifact);
    hashes.manifest = sha256Hex(data.manifest);
    hashes.warrant_message = sha256Hex(data.warrant_message);
    hashes.release_receipt = sha256Hex(data.release_receipt);
    hashes.receipt_contract = sha256Hex(data.receipt_contract);
    hashes.authority_root = sha256Hex(data.authority_root);
    hashes.release_decision = sha256Hex(data.release_decision);

    const authority = try parseFlat(authority_labels, data.authority_root);
    const contract = try parseFlat(contract_labels, data.receipt_contract);
    const decision = try parseFlat(decision_labels, data.release_decision);
    try validateAuthority(authority, hashes.authority_root[0..]);
    try validateContract(contract, hashes, authority[4]);
    try validateDecision(decision, hashes.artifact[0..]);
    try validateReceiptJson(data.release_receipt, hashes, contract);

    try compareWuciOutput(gpa, io, args, &.{ "manifest-file", paths.artifact }, data.manifest, "manifest-file");
    try compareWuciOutput(
        gpa,
        io,
        args,
        &.{ "warrant-message-file", release_action, paths.artifact },
        data.warrant_message,
        "warrant-message-file",
    );
    try compareWuciOutput(gpa, io, args, &.{ "authority-root-verify", paths.authority_root }, "valid\n", "authority-root-verify");
    try compareWuciOutput(
        gpa,
        io,
        args,
        &.{ "release-authorized-rooted", paths.authority_root, paths.artifact, paths.receipt_contract },
        data.release_decision,
        "release-authorized-rooted",
    );

    return try formatFlat(gpa, index_labels, .{
        index_schema,
        hashes.artifact[0..],
        hashes.manifest[0..],
        hashes.warrant_message[0..],
        hashes.release_receipt[0..],
        hashes.receipt_contract[0..],
        hashes.authority_root[0..],
        hashes.release_decision[0..],
        authority[4],
    });
}

const CoreData = struct {
    artifact: []u8,
    manifest: []u8,
    warrant_message: []u8,
    release_receipt: []u8,
    receipt_contract: []u8,
    authority_root: []u8,
    release_decision: []u8,

    fn deinit(self: CoreData, gpa: Allocator) void {
        gpa.free(self.artifact);
        gpa.free(self.manifest);
        gpa.free(self.warrant_message);
        gpa.free(self.release_receipt);
        gpa.free(self.receipt_contract);
        gpa.free(self.authority_root);
        gpa.free(self.release_decision);
    }
};

fn readCoreData(gpa: Allocator, io: Io, paths: BundlePaths) !CoreData {
    return .{
        .artifact = try readFile(gpa, io, paths.artifact),
        .manifest = try readFile(gpa, io, paths.manifest),
        .warrant_message = try readFile(gpa, io, paths.warrant_message),
        .release_receipt = try readFile(gpa, io, paths.release_receipt),
        .receipt_contract = try readFile(gpa, io, paths.receipt_contract),
        .authority_root = try readFile(gpa, io, paths.authority_root),
        .release_decision = try readFile(gpa, io, paths.release_decision),
    };
}

fn formatFlat(gpa: Allocator, comptime labels: anytype, fields: [labels.len][]const u8) ![]u8 {
    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(gpa);
    inline for (labels, 0..) |label, index| {
        try out.appendSlice(gpa, label);
        try out.appendSlice(gpa, ": ");
        try out.appendSlice(gpa, fields[index]);
        try out.append(gpa, '\n');
    }
    return try out.toOwnedSlice(gpa);
}

fn formatAttestationJson(
    gpa: Allocator,
    hashes: Hashes,
    index: [index_labels.len][]const u8,
    decision: [decision_labels.len][]const u8,
    verifier_hash: []const u8,
) ![]u8 {
    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(gpa);

    try appendFmt(gpa, &out,
        \\{{
        \\  "action": "release",
        \\  "boundary": {{
        \\    "assembly_owned_surfaces": [
        \\      "manifest-file",
        \\      "warrant-message-file",
        \\      "authority-root-verify",
        \\      "release-authorized-rooted"
        \\    ],
        \\    "authority_anchor": "authority/wuci-release-root.fixture.txt",
        \\    "authority_anchor_sha256": "{s}",
        \\    "authority_schema": "wuci-authority-root-v1",
        \\    "bundle_schema": "wuci-publish-bundle-v1",
        \\    "contract_schema": "wuci-gate-receipt-contract-v1",
        \\    "gate_enforcement": "assembly-rooted-release-contract",
        \\    "index_schema": "wuci-publish-index-v1",
        \\    "non_goals": [
        \\      "Do not require or accept a decryption key in the public witness bundle.",
        \\      "Do not open the sealed artifact.",
        \\      "Do not parse receipt JSON in assembly.",
        \\      "Do not accept arbitrary signer material.",
        \\      "Do not accept trust bits or reserved publish bits yet."
        \\    ],
        \\    "public_profile_excludes": [
        \\      "artifact.key",
        \\      "auth-transcript.json",
        \\      "opened-wuci-ji",
        \\      "release-transcript.json"
        \\    ]
        \\  }},
        \\  "bundle_schema": "wuci-publish-bundle-v1",
        \\  "checks": {{
        \\    "forbidden_private_files_absent": true,
        \\    "manifest_matches_assembly": true,
        \\    "public_bundle_profile": true,
        \\    "publish_index_matches_bundle": true,
        \\    "release_authority_allows_release": true,
        \\    "release_authority_is_committed_anchor": true,
        \\    "release_authority_matches_contract": true,
        \\    "release_decision_matches_assembly": true,
        \\    "release_receipt_contract_matches_receipt": true,
        \\    "release_warrant_message_matches_assembly": true,
        \\    "rooted_release_check": true,
        \\    "witness_bundle_complete": true
        \\  }},
        \\  "fixture_authority": true,
        \\  "paths": {{
        \\    "attestation": "attestation.json",
        \\    "authority_root": "authority-root.txt",
        \\    "manifest": "manifest.txt",
        \\    "publish_index": "publish-index.txt",
        \\    "receipt_contract": "receipt-contract.txt",
        \\    "release_decision": "release-decision.txt",
        \\    "release_receipt": "release-receipt.json",
        \\    "sealed_artifact": "wuci-ji.self.wj",
        \\    "warrant_message": "warrant-message.txt"
        \\  }},
        \\  "production": false,
        \\  "publish_index": {{
        \\    "artifact-sha256": "{s}",
        \\    "authority-root-sha256": "{s}",
        \\    "manifest-sha256": "{s}",
        \\    "receipt-contract-sha256": "{s}",
        \\    "release-authority-group-public-key": "{s}",
        \\    "release-decision-sha256": "{s}",
        \\    "release-receipt-sha256": "{s}",
        \\    "schema": "{s}",
        \\    "warrant-message-sha256": "{s}"
        \\  }},
        \\  "publish_index_matches_bundle": true,
        \\  "quantum_safe": false,
        \\  "release_authority_group_public_key": "{s}",
        \\  "release_authority_root_sha256": "{s}",
        \\  "release_contract_sha256": "{s}",
        \\  "release_decision": {{
        \\    "action": "{s}",
        \\    "artifact-sha256": "{s}",
        \\    "authorized": "{s}"
        \\  }},
        \\  "release_decision_sha256": "{s}",
        \\  "rooted_release_check": true,
        \\  "runtime_sandbox_enforced": false,
        \\  "schema": "wuci-witness-attestation-v1",
        \\  "sha256": {{
        \\    "authority_root": "{s}",
        \\    "manifest": "{s}",
        \\    "publish_index": "{s}",
        \\    "receipt_contract": "{s}",
        \\    "release_decision": "{s}",
        \\    "release_receipt": "{s}",
        \\    "sealed_artifact": "{s}",
        \\    "warrant_message": "{s}"
        \\  }},
        \\  "summary": "Wuci-ji release witness bundle was verified from the public files only: the release authority root is pinned, the assembly rooted release decision is reproducible, and no key or opened binary is present.",
        \\  "trust_level": "test-only",
        \\  "verifier_binary_sha256": "{s}",
        \\  "witness_bundle_complete": true
        \\}}
        \\
    , .{
        release_anchor_sha256,
        index[1],
        index[6],
        index[2],
        index[5],
        index[8],
        index[7],
        index[4],
        index[0],
        index[3],
        index[8],
        hashes.authority_root[0..],
        hashes.receipt_contract[0..],
        decision[1],
        decision[2],
        decision[0],
        hashes.release_decision[0..],
        hashes.authority_root[0..],
        hashes.manifest[0..],
        hashes.publish_index[0..],
        hashes.receipt_contract[0..],
        hashes.release_decision[0..],
        hashes.release_receipt[0..],
        hashes.artifact[0..],
        hashes.warrant_message[0..],
        verifier_hash,
    });
    return try out.toOwnedSlice(gpa);
}

fn appendFmt(gpa: Allocator, out: *std.ArrayList(u8), comptime fmt: []const u8, args: anytype) !void {
    const text = try std.fmt.allocPrint(gpa, fmt, args);
    defer gpa.free(text);
    try out.appendSlice(gpa, text);
}

fn parseFlat(comptime labels: anytype, text: []const u8) ![labels.len][]const u8 {
    if (text.len == 0) return error.EmptyFlatFile;
    for (text) |byte| {
        if (byte > 0x7f) return error.NonAsciiFlatFile;
        if (byte == '\r') return error.FlatFileContainsCr;
    }
    if (text[text.len - 1] != '\n') return error.MissingTrailingNewline;
    if (text.len >= 2 and text[text.len - 2] == '\n') return error.ExtraTrailingNewline;

    var values: [labels.len][]const u8 = undefined;
    var index: usize = 0;
    var lines = std.mem.splitScalar(u8, text[0 .. text.len - 1], '\n');
    while (lines.next()) |line| {
        if (index >= labels.len) return error.UnexpectedFieldCount;
        const label = labels[index];
        if (!std.mem.startsWith(u8, line, label)) return error.NonCanonicalFieldOrder;
        if (line.len < label.len + 2 or line[label.len] != ':' or line[label.len + 1] != ' ') {
            return error.MalformedFlatLine;
        }
        const value = line[label.len + 2 ..];
        if (value.len == 0) return error.EmptyFlatField;
        values[index] = value;
        index += 1;
    }
    if (index != labels.len) return error.UnexpectedFieldCount;
    return values;
}

fn validateIndex(index: [index_labels.len][]const u8, hashes: Hashes) !void {
    try expectEqual(index[0], index_schema, error.UnsupportedIndexSchema);
    try expectHex64(index[1], hashes.artifact[0..], "artifact-sha256");
    try expectHex64(index[2], hashes.manifest[0..], "manifest-sha256");
    try expectHex64(index[3], hashes.warrant_message[0..], "warrant-message-sha256");
    try expectHex64(index[4], hashes.release_receipt[0..], "release-receipt-sha256");
    try expectHex64(index[5], hashes.receipt_contract[0..], "receipt-contract-sha256");
    try expectHex64(index[6], hashes.authority_root[0..], "authority-root-sha256");
    try expectHex64(index[7], hashes.release_decision[0..], "release-decision-sha256");
    try requireCompressedSec1(index[8], "release-authority-group-public-key");
    try expectEqual(index[8], fixture_group_public_key, error.IndexGroupKeyMismatch);
}

fn validateAuthority(authority: [authority_labels.len][]const u8, authority_hash: []const u8) !void {
    try expectEqual(authority[0], authority_schema, error.UnsupportedAuthoritySchema);
    try expectEqual(authority[1], frost_suite, error.UnsupportedAuthoritySuite);
    try expectEqual(authority[2], "false", error.ProductionAuthorityRoot);
    try requireHex(authority[3], 64, "authority-id");
    try requireCompressedSec1(authority[4], "group-public-key");
    try expectEqual(authority[4], fixture_group_public_key, error.AuthorityGroupKeyMismatch);
    try expectEqual(authority[5], "false", error.ReleaseAuthorityAllowsOpen);
    try expectEqual(authority[6], "true", error.ReleaseAuthorityDisallowsRelease);
    try expectEqual(authority[7], "false", error.AuthorityAllowsTrust);
    try expectEqual(authority[8], "false", error.AuthorityAllowsPublish);
    try expectEqual(authority_hash, release_anchor_sha256, error.AuthorityNotCommittedReleaseAnchor);

    var group_bytes: [33]u8 = undefined;
    _ = try std.fmt.hexToBytes(&group_bytes, authority[4]);
    const authority_id = sha256Hex(group_bytes[0..]);
    try expectEqual(authority[3], authority_id[0..], error.AuthorityIdMismatch);
}

fn validateContract(
    contract: [contract_labels.len][]const u8,
    hashes: Hashes,
    authority_group_key: []const u8,
) !void {
    try expectEqual(contract[0], contract_schema, error.UnsupportedContractSchema);
    try expectEqual(contract[1], release_action, error.ContractActionNotRelease);
    try expectHex64(contract[2], hashes.artifact[0..], "artifact-sha256");
    try expectHex64(contract[3], hashes.warrant_message[0..], "authorization-message-sha256");
    try expectHex64(contract[4], hashes.release_receipt[0..], "receipt-sha256");
    try expectHex64(contract[5], hashes.manifest[0..], "artifact-manifest-sha256");
    try requireCompressedSec1(contract[6], "group-public-key");
    try requireCompressedSec1(contract[7], "group-commitment");
    try requireHex(contract[8], 64, "challenge");
    try requireCompressedSec1(contract[9], "signature-commitment");
    try requireHex(contract[10], 64, "signature-scalar");
    try expectEqual(contract[6], authority_group_key, error.ContractAuthorityGroupKeyMismatch);
    try expectEqual(contract[7], contract[9], error.SignatureCommitmentMismatch);
}

fn validateDecision(decision: [decision_labels.len][]const u8, artifact_hash: []const u8) !void {
    try expectEqual(decision[0], "true", error.ReleaseDecisionNotAuthorized);
    try expectEqual(decision[1], release_action, error.ReleaseDecisionActionMismatch);
    try expectEqual(decision[2], artifact_hash, error.ReleaseDecisionArtifactMismatch);
}

fn validateReceiptJson(
    receipt: []const u8,
    hashes: Hashes,
    contract: [contract_labels.len][]const u8,
) !void {
    try requireJsonString(receipt, "action", release_action);
    try requireJsonString(receipt, "artifact_manifest_sha256", hashes.manifest[0..]);
    try requireJsonString(receipt, "authorization_message_sha256", hashes.warrant_message[0..]);
    try requireJsonString(receipt, "group_public_key", contract[6]);
    try requireJsonString(receipt, "group_commitment", contract[7]);
    try requireJsonString(receipt, "challenge", contract[8]);
    try requireJsonString(receipt, "signature_commitment", contract[9]);
    try requireJsonString(receipt, "signature_scalar", contract[10]);
}

fn validateAttestationJson(
    attestation: []const u8,
    hashes: Hashes,
    index: [index_labels.len][]const u8,
    authority_group_key: []const u8,
    decision: [decision_labels.len][]const u8,
) !void {
    try requireJsonString(attestation, "schema", attestation_schema);
    try requireJsonString(attestation, "bundle_schema", bundle_schema);
    try requireJsonString(attestation, "action", release_action);
    try requireJsonBool(attestation, "production", false);
    try requireJsonBool(attestation, "rooted_release_check", true);
    try requireJsonBool(attestation, "witness_bundle_complete", true);
    try requireJsonBool(attestation, "publish_index_matches_bundle", true);

    try requireJsonString(attestation, "release_authority_root_sha256", hashes.authority_root[0..]);
    try requireJsonString(attestation, "release_authority_group_public_key", authority_group_key);
    try requireJsonString(attestation, "release_contract_sha256", hashes.receipt_contract[0..]);
    try requireJsonString(attestation, "release_decision_sha256", hashes.release_decision[0..]);

    try requireJsonString(attestation, "artifact-sha256", index[1]);
    try requireJsonString(attestation, "manifest-sha256", index[2]);
    try requireJsonString(attestation, "warrant-message-sha256", index[3]);
    try requireJsonString(attestation, "release-receipt-sha256", index[4]);
    try requireJsonString(attestation, "receipt-contract-sha256", index[5]);
    try requireJsonString(attestation, "authority-root-sha256", index[6]);
    try requireJsonString(attestation, "release-decision-sha256", index[7]);
    try requireJsonString(attestation, "release-authority-group-public-key", index[8]);

    try requireJsonString(attestation, "sealed_artifact", hashes.artifact[0..]);
    try requireJsonString(attestation, "manifest", hashes.manifest[0..]);
    try requireJsonString(attestation, "warrant_message", hashes.warrant_message[0..]);
    try requireJsonString(attestation, "release_receipt", hashes.release_receipt[0..]);
    try requireJsonString(attestation, "receipt_contract", hashes.receipt_contract[0..]);
    try requireJsonString(attestation, "authority_root", hashes.authority_root[0..]);
    try requireJsonString(attestation, "release_decision", hashes.release_decision[0..]);
    try requireJsonString(attestation, "publish_index", hashes.publish_index[0..]);

    try requireJsonString(attestation, "authorized", decision[0]);
    try requireJsonString(attestation, "artifact-sha256", decision[2]);

    try requireJsonBool(attestation, "public_bundle_profile", true);
    try requireJsonBool(attestation, "forbidden_private_files_absent", true);
    try requireJsonBool(attestation, "manifest_matches_assembly", true);
    try requireJsonBool(attestation, "release_warrant_message_matches_assembly", true);
    try requireJsonBool(attestation, "release_receipt_contract_matches_receipt", true);
    try requireJsonBool(attestation, "release_authority_is_committed_anchor", true);
    try requireJsonBool(attestation, "release_authority_allows_release", true);
    try requireJsonBool(attestation, "release_authority_matches_contract", true);
    try requireJsonBool(attestation, "release_decision_matches_assembly", true);
}

fn requireJsonString(text: []const u8, key: []const u8, value: []const u8) !void {
    const snippet = try std.fmt.allocPrint(std.heap.smp_allocator, "\"{s}\": \"{s}\"", .{ key, value });
    defer std.heap.smp_allocator.free(snippet);
    if (std.mem.indexOf(u8, text, snippet) == null) {
        std.debug.print("missing JSON binding: {s}\n", .{key});
        return error.JsonBindingMissing;
    }
}

fn requireJsonBool(text: []const u8, key: []const u8, value: bool) !void {
    const literal = if (value) "true" else "false";
    const snippet = try std.fmt.allocPrint(std.heap.smp_allocator, "\"{s}\": {s}", .{ key, literal });
    defer std.heap.smp_allocator.free(snippet);
    if (std.mem.indexOf(u8, text, snippet) == null) {
        std.debug.print("missing JSON binding: {s}\n", .{key});
        return error.JsonBindingMissing;
    }
}

fn expectHex64(actual: []const u8, expected: []const u8, context: []const u8) !void {
    try requireHex(actual, 64, context);
    try expectEqual(actual, expected, error.HashMismatch);
}

fn requireHex(value: []const u8, expected_len: usize, context: []const u8) !void {
    if (value.len != expected_len or !isLowerHex(value)) {
        std.debug.print("{s} must be lowercase hex length {d}\n", .{ context, expected_len });
        return error.InvalidHex;
    }
}

fn requireCompressedSec1(value: []const u8, context: []const u8) !void {
    try requireHex(value, 66, context);
    if (!std.mem.eql(u8, value[0..2], "02") and !std.mem.eql(u8, value[0..2], "03")) {
        return error.InvalidCompressedSec1;
    }
}

fn isLowerHex(value: []const u8) bool {
    for (value) |byte| {
        if (!((byte >= '0' and byte <= '9') or (byte >= 'a' and byte <= 'f'))) return false;
    }
    return true;
}

fn expectEqual(actual: []const u8, expected: []const u8, err: anyerror) !void {
    if (!std.mem.eql(u8, actual, expected)) return err;
}

fn compareWuciOutput(
    gpa: Allocator,
    io: Io,
    args: Args,
    wuci_args: []const []const u8,
    expected: []const u8,
    context: []const u8,
) !void {
    const output = try runWuci(gpa, io, args, wuci_args);
    defer freeProcessOutput(gpa, output);
    if (!std.mem.eql(u8, output.stdout, expected)) {
        std.debug.print("{s} output mismatch\n", .{context});
        return error.WuciOutputMismatch;
    }
}

fn runWuci(
    gpa: Allocator,
    io: Io,
    args: Args,
    wuci_args: []const []const u8,
) !ProcessOutput {
    var argv: std.ArrayList([]const u8) = .empty;
    defer argv.deinit(gpa);

    try appendRunner(gpa, &argv, args);
    try argv.append(gpa, args.bin);
    try argv.appendSlice(gpa, wuci_args);

    const result = try std.process.run(gpa, io, .{
        .argv = argv.items,
        .stdout_limit = .limited(max_process_output),
        .stderr_limit = .limited(max_process_output),
    });
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
