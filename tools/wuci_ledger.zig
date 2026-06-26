const std = @import("std");

const Allocator = std.mem.Allocator;
const Io = std.Io;
const Sha256 = std.crypto.hash.sha2.Sha256;

const max_file_size = 1024 * 1024;
const entry_schema = "wuci-ledger-entry-v1";
const head_schema = "wuci-ledger-head-v1";
const inclusion_schema = "wuci-ledger-inclusion-proof-v1";
const consistency_schema = "wuci-ledger-consistency-proof-v1";
const zero64 = "0000000000000000000000000000000000000000000000000000000000000000";
const index_schema = "wuci-publish-index-v1";

const entry_labels = [_][]const u8{
    "schema",
    "sequence",
    "artifact-sha256",
    "manifest-sha256",
    "warrant-message-sha256",
    "release-receipt-sha256",
    "receipt-contract-sha256",
    "authority-root-sha256",
    "release-decision-sha256",
    "attestation-sha256",
    "release-authority-group-public-key",
};

const head_labels = [_][]const u8{
    "schema",
    "tree-size",
    "root-hash",
    "previous-tree-size",
    "previous-root-hash",
    "entry-hash",
};

const inclusion_labels = [_][]const u8{
    "schema",
    "tree-size",
    "leaf-index",
    "leaf-hash",
    "root-hash",
    "path-count",
};

const consistency_labels = [_][]const u8{
    "schema",
    "first-size",
    "first-root-hash",
    "second-size",
    "second-root-hash",
    "path-count",
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

const witness_public_files = [_][]const u8{
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

const witness_forbidden_files = [_][]const u8{
    "artifact.key",
    "opened-wuci-ji",
    "auth-transcript.json",
    "release-transcript.json",
};

const Args = struct {
    command: []const u8,
    ledger: []const u8 = "build/wuci-ledger",
    witness_bundle: []const u8 = "",
    out: []const u8 = "",
    entry: []const u8 = "",
    proof: []const u8 = "",
    head: []const u8 = "",
    from_head: []const u8 = "",
    to_head: []const u8 = "",
    sequence: ?usize = null,
    force: bool = false,
};

const LedgerPaths = struct {
    entries: []u8,
    heads: []u8,
    latest_entry: []u8,
    latest_head: []u8,
    previous_head: []u8,
    lock: []u8,

    fn deinit(self: LedgerPaths, gpa: Allocator) void {
        gpa.free(self.entries);
        gpa.free(self.heads);
        gpa.free(self.latest_entry);
        gpa.free(self.latest_head);
        gpa.free(self.previous_head);
        gpa.free(self.lock);
    }
};

const Entry = struct {
    text: []u8,
    fields: [entry_labels.len][]const u8,
    leaf: [32]u8,
    entry_hash: [64]u8,

    fn deinit(self: Entry, gpa: Allocator) void {
        gpa.free(self.text);
    }
};

const ProofPath = struct {
    hashes: [][32]u8,

    fn deinit(self: ProofPath, gpa: Allocator) void {
        gpa.free(self.hashes);
    }
};

pub fn main(init: std.process.Init) !void {
    const gpa = init.gpa;
    const io = init.io;
    var stdout_buffer: [256]u8 = undefined;
    var stdout_writer = Io.File.stdout().writer(io, &stdout_buffer);
    const stdout = &stdout_writer.interface;

    const args = parseArgs(gpa, init.minimal.args) catch |err| {
        usage();
        return err;
    };

    if (std.mem.eql(u8, args.command, "init")) {
        try runInit(gpa, io, stdout, args);
        return;
    }
    if (std.mem.eql(u8, args.command, "append")) {
        try runAppend(gpa, io, stdout, args);
        return;
    }
    if (std.mem.eql(u8, args.command, "prove-inclusion")) {
        try runProveInclusion(gpa, io, stdout, args);
        return;
    }
    if (std.mem.eql(u8, args.command, "verify-inclusion")) {
        try runVerifyInclusion(gpa, io, stdout, args);
        return;
    }
    if (std.mem.eql(u8, args.command, "prove-consistency")) {
        try runProveConsistency(gpa, io, stdout, args);
        return;
    }
    if (std.mem.eql(u8, args.command, "verify-consistency")) {
        try runVerifyConsistency(gpa, io, stdout, args);
        return;
    }
    if (std.mem.eql(u8, args.command, "verify-history")) {
        try runVerifyHistory(gpa, io, stdout, args.ledger);
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
        if (std.mem.eql(u8, arg, "--ledger")) {
            parsed.ledger = argv.next() orelse return error.MissingValue;
        } else if (std.mem.eql(u8, arg, "--witness-bundle")) {
            parsed.witness_bundle = argv.next() orelse return error.MissingValue;
        } else if (std.mem.eql(u8, arg, "--sequence")) {
            parsed.sequence = try parseDecimal(argv.next() orelse return error.MissingValue, "sequence");
        } else if (std.mem.eql(u8, arg, "--out")) {
            parsed.out = argv.next() orelse return error.MissingValue;
        } else if (std.mem.eql(u8, arg, "--entry")) {
            parsed.entry = argv.next() orelse return error.MissingValue;
        } else if (std.mem.eql(u8, arg, "--proof")) {
            parsed.proof = argv.next() orelse return error.MissingValue;
        } else if (std.mem.eql(u8, arg, "--head")) {
            parsed.head = argv.next() orelse return error.MissingValue;
        } else if (std.mem.eql(u8, arg, "--from-head")) {
            parsed.from_head = argv.next() orelse return error.MissingValue;
        } else if (std.mem.eql(u8, arg, "--to-head")) {
            parsed.to_head = argv.next() orelse return error.MissingValue;
        } else if (std.mem.eql(u8, arg, "--force")) {
            parsed.force = true;
        } else if (std.mem.eql(u8, arg, "--bin")) {
            _ = argv.next() orelse return error.MissingValue;
        } else if (arg.len > 0 and arg[0] == '-') {
            return error.UnknownArgument;
        } else {
            parsed.ledger = arg;
        }
    }
    return parsed;
}

fn usage() void {
    std.debug.print(
        \\usage: wuci-ledger init [--ledger <ledger-dir>]
        \\       wuci-ledger append [--ledger <ledger-dir>] --witness-bundle <bundle>
        \\       wuci-ledger prove-inclusion [--ledger <ledger-dir>] --sequence <n> --out <proof>
        \\       wuci-ledger verify-inclusion --entry <entry> --proof <proof> --head <head>
        \\       wuci-ledger prove-consistency [--ledger <ledger-dir>] --from-head <old> --to-head <new> --out <proof>
        \\       wuci-ledger verify-consistency --proof <proof>
        \\       wuci-ledger verify-history [--ledger <ledger-dir>]
        \\       wuci-ledger verify-history <ledger-dir>
        \\
    , .{});
}

fn runInit(gpa: Allocator, io: Io, stdout: *Io.Writer, args: Args) !void {
    const paths = try ledgerPaths(gpa, args.ledger);
    defer paths.deinit(gpa);

    if (args.force) {
        Io.Dir.cwd().deleteTree(io, args.ledger) catch {};
    } else {
        try assertLedgerMissingOrEmpty(io, args.ledger);
    }

    try Io.Dir.cwd().createDirPath(io, paths.entries);
    try Io.Dir.cwd().createDirPath(io, paths.heads);

    const head_text = try initHead(gpa);
    defer gpa.free(head_text);
    try writeNewFile(io, paths.latest_head, head_text);
    const head0_name = try fileNameForHead(gpa, 0);
    defer gpa.free(head0_name);
    const head0_path = try joinPath(gpa, paths.heads, head0_name);
    defer gpa.free(head0_path);
    try writeNewFile(io, head0_path, head_text);

    try stdout.print("initialized WUCI-LEDGER: {s}\nledger head: {s}\n", .{ args.ledger, paths.latest_head });
    try stdout.flush();
}

fn runAppend(gpa: Allocator, io: Io, stdout: *Io.Writer, args: Args) !void {
    if (args.witness_bundle.len == 0) return error.MissingWitnessBundle;
    const paths = try ledgerPaths(gpa, args.ledger);
    defer paths.deinit(gpa);

    try writeNewFile(io, paths.lock, "");
    defer Io.Dir.cwd().deleteFile(io, paths.lock) catch {};

    const old_head_text = try readFile(gpa, io, paths.latest_head);
    defer gpa.free(old_head_text);
    const old_head = try parseHead(old_head_text);
    const old_size = try parseDecimal(old_head[1], "tree-size");

    const old_entries = try loadEntries(gpa, io, paths, old_size);
    defer freeEntries(gpa, old_entries);
    if (old_entries.len != old_size) return error.LedgerEntryCountMismatch;

    const entry_text = try deriveEntryFromBundle(gpa, io, args.witness_bundle, old_size);
    defer gpa.free(entry_text);

    const entry_name = try fileNameForEntry(gpa, old_size);
    defer gpa.free(entry_name);
    const entry_path = try joinPath(gpa, paths.entries, entry_name);
    defer gpa.free(entry_path);
    try writeNewFile(io, entry_path, entry_text);
    try replaceFile(gpa, io, paths.latest_entry, entry_text);

    const entries = try loadEntries(gpa, io, paths, old_size + 1);
    defer freeEntries(gpa, entries);
    const root_hex = hex32(merkleRoot(entries));
    const entry_hash = sha256Hex(entry_text);
    const new_size_text = try std.fmt.allocPrint(gpa, "{d}", .{old_size + 1});
    defer gpa.free(new_size_text);
    const new_head_text = try formatHead(gpa, .{
        head_schema,
        new_size_text,
        root_hex[0..],
        old_head[1],
        old_head[2],
        entry_hash[0..],
    });
    defer gpa.free(new_head_text);

    try replaceFile(gpa, io, paths.previous_head, old_head_text);
    try replaceFile(gpa, io, paths.latest_head, new_head_text);
    const head_name = try fileNameForHead(gpa, old_size + 1);
    defer gpa.free(head_name);
    const head_path = try joinPath(gpa, paths.heads, head_name);
    defer gpa.free(head_path);
    try writeNewFile(io, head_path, new_head_text);

    try stdout.print("appended WUCI-LEDGER entry: {d}\nledger entry: {s}\nledger head: {s}\n", .{ old_size, paths.latest_entry, paths.latest_head });
    try stdout.flush();
}

fn runProveInclusion(gpa: Allocator, io: Io, stdout: *Io.Writer, args: Args) !void {
    const sequence = args.sequence orelse return error.MissingSequence;
    if (args.out.len == 0) return error.MissingOutput;
    const paths = try ledgerPaths(gpa, args.ledger);
    defer paths.deinit(gpa);

    const latest_text = try readFile(gpa, io, paths.latest_head);
    defer gpa.free(latest_text);
    const latest = try parseHead(latest_text);
    const size = try parseDecimal(latest[1], "tree-size");
    if (sequence >= size) return error.InclusionSequenceOutsideTree;

    const entries = try loadEntries(gpa, io, paths, size);
    defer freeEntries(gpa, entries);
    const root_hex = hex32(merkleRoot(entries));
    try expectEqual(latest[2], root_hex[0..], error.HeadRootMismatch);

    var path: std.ArrayList([32]u8) = .empty;
    defer path.deinit(gpa);
    try appendInclusionPath(gpa, &path, entries, sequence);

    const leaf_hex = hex32(entries[sequence].leaf);
    const index_text = try std.fmt.allocPrint(gpa, "{d}", .{sequence});
    defer gpa.free(index_text);
    const proof_text = try formatProof(gpa, inclusion_labels, .{
        inclusion_schema,
        latest[1],
        index_text,
        leaf_hex[0..],
        root_hex[0..],
        "",
    }, path.items);
    defer gpa.free(proof_text);
    try writeNewFile(io, args.out, proof_text);

    try stdout.print("wrote inclusion proof: {s}\n", .{args.out});
    try stdout.flush();
}

fn runVerifyInclusion(gpa: Allocator, io: Io, stdout: *Io.Writer, args: Args) !void {
    if (args.entry.len == 0 or args.proof.len == 0 or args.head.len == 0) return error.MissingArgument;

    const entry_text = try readFile(gpa, io, args.entry);
    defer gpa.free(entry_text);
    const entry = try parseEntry(entry_text);

    const proof_text = try readFile(gpa, io, args.proof);
    defer gpa.free(proof_text);
    const proof = try parseProof(gpa, inclusion_labels, proof_text, inclusion_schema);
    defer proof.deinit(gpa);

    const head_text = try readFile(gpa, io, args.head);
    defer gpa.free(head_text);
    const head = try parseHead(head_text);

    const size = try parseDecimal(proof.fields[1], "tree-size");
    const index = try parseDecimal(proof.fields[2], "leaf-index");
    if (try parseDecimal(entry[1], "sequence") != index) return error.EntrySequenceMismatch;
    try expectEqual(head[1], proof.fields[1], error.InclusionHeadTreeSizeMismatch);
    try expectEqual(head[2], proof.fields[4], error.InclusionHeadRootMismatch);

    const leaf = ledgerLeaf(entry_text);
    const leaf_hex = hex32(leaf);
    try expectEqual(proof.fields[3], leaf_hex[0..], error.InclusionLeafHashMismatch);

    const root = try rootFromInclusion(leaf, index, size, proof.hashes);
    const root_hex = hex32(root);
    try expectEqual(proof.fields[4], root_hex[0..], error.InclusionRootMismatch);

    try stdout.print("valid inclusion proof: {s}\n", .{args.proof});
    try stdout.flush();
}

fn runProveConsistency(gpa: Allocator, io: Io, stdout: *Io.Writer, args: Args) !void {
    if (args.from_head.len == 0 or args.to_head.len == 0 or args.out.len == 0) return error.MissingArgument;
    const paths = try ledgerPaths(gpa, args.ledger);
    defer paths.deinit(gpa);

    const first_text = try readFile(gpa, io, args.from_head);
    defer gpa.free(first_text);
    const first = try parseHead(first_text);
    const second_text = try readFile(gpa, io, args.to_head);
    defer gpa.free(second_text);
    const second = try parseHead(second_text);
    const first_size = try parseDecimal(first[1], "first tree-size");
    const second_size = try parseDecimal(second[1], "second tree-size");
    if (first_size > second_size) return error.ConsistencyRangeInvalid;

    const entries = try loadEntries(gpa, io, paths, second_size);
    defer freeEntries(gpa, entries);
    const first_root_hex = hex32(merkleRoot(entries[0..first_size]));
    const second_root_hex = hex32(merkleRoot(entries));
    try expectEqual(first[2], first_root_hex[0..], error.FirstHeadRootMismatch);
    try expectEqual(second[2], second_root_hex[0..], error.SecondHeadRootMismatch);

    var path: std.ArrayList([32]u8) = .empty;
    defer path.deinit(gpa);
    try appendConsistencyPath(gpa, &path, entries, first_size, true);

    const proof_text = try formatProof(gpa, consistency_labels, .{
        consistency_schema,
        first[1],
        first_root_hex[0..],
        second[1],
        second_root_hex[0..],
        "",
    }, path.items);
    defer gpa.free(proof_text);
    try writeNewFile(io, args.out, proof_text);

    try stdout.print("wrote consistency proof: {s}\n", .{args.out});
    try stdout.flush();
}

fn runVerifyConsistency(gpa: Allocator, io: Io, stdout: *Io.Writer, args: Args) !void {
    if (args.proof.len == 0) return error.MissingProof;
    const proof_text = try readFile(gpa, io, args.proof);
    defer gpa.free(proof_text);
    const proof = try parseProof(gpa, consistency_labels, proof_text, consistency_schema);
    defer proof.deinit(gpa);

    const first_size = try parseDecimal(proof.fields[1], "first-size");
    const first_root = try hexToBytes32(proof.fields[2]);
    const second_size = try parseDecimal(proof.fields[3], "second-size");
    const second_root = try hexToBytes32(proof.fields[4]);
    if (first_size > second_size) return error.ConsistencyRangeInvalid;

    if (first_size == 0) {
        if (proof.hashes.len != 0) return error.EmptyConsistencyPathNotEmpty;
        const empty = emptyRoot();
        if (!std.mem.eql(u8, empty[0..], first_root[0..])) return error.EmptyConsistencyRootMismatch;
    } else if (first_size == second_size) {
        if (proof.hashes.len != 0) return error.SameSizeConsistencyPathNotEmpty;
        if (!std.mem.eql(u8, first_root[0..], second_root[0..])) return error.SameSizeConsistencyRootMismatch;
    } else {
        const roots = try consistencyRootsFromProof(first_size, second_size, first_root, proof.hashes);
        if (!std.mem.eql(u8, roots.old[0..], first_root[0..])) return error.ConsistencyFirstRootMismatch;
        if (!std.mem.eql(u8, roots.new[0..], second_root[0..])) return error.ConsistencySecondRootMismatch;
    }

    try stdout.print("valid consistency proof: {s}\n", .{args.proof});
    try stdout.flush();
}

fn runVerifyHistory(gpa: Allocator, io: Io, stdout: *Io.Writer, ledger: []const u8) !void {
    const paths = try ledgerPaths(gpa, ledger);
    defer paths.deinit(gpa);

    const latest_text = try readFile(gpa, io, paths.latest_head);
    defer gpa.free(latest_text);
    const latest = try parseHead(latest_text);
    const size = try parseDecimal(latest[1], "tree-size");

    try assertDirectoryExact(io, paths.entries, size, fileNameForEntry);
    try assertDirectoryExact(io, paths.heads, size + 1, fileNameForHead);

    var entries: std.ArrayList(Entry) = .empty;
    defer {
        for (entries.items) |entry| entry.deinit(gpa);
        entries.deinit(gpa);
    }

    var index: usize = 0;
    while (index < size) : (index += 1) {
        const name = try fileNameForEntry(gpa, index);
        defer gpa.free(name);
        const path = try joinPath(gpa, paths.entries, name);
        defer gpa.free(path);
        const text = try readFile(gpa, io, path);
        const fields = try parseEntry(text);
        if (try parseDecimal(fields[1], "sequence") != index) return error.EntrySequenceMismatch;
        const canonical_entry = try formatEntry(gpa, fields);
        defer gpa.free(canonical_entry);
        try expectEqual(text, canonical_entry, error.EntryNotCanonical);
        const leaf = ledgerLeaf(text);
        const entry_hash = sha256Hex(text);
        try entries.append(gpa, .{
            .text = text,
            .fields = fields,
            .leaf = leaf,
            .entry_hash = entry_hash,
        });
    }

    var previous_root_hex: [64]u8 = undefined;
    @memcpy(previous_root_hex[0..], zero64);
    var previous_head_text: ?[]u8 = null;
    defer if (previous_head_text) |text| gpa.free(text);

    index = 0;
    while (index <= size) : (index += 1) {
        const name = try fileNameForHead(gpa, index);
        defer gpa.free(name);
        const path = try joinPath(gpa, paths.heads, name);
        defer gpa.free(path);
        const head_text = try readFile(gpa, io, path);
        defer gpa.free(head_text);

        const head = try parseHead(head_text);
        if (try parseDecimal(head[1], "tree-size") != index) return error.HeadTreeSizeMismatch;
        const canonical_head = try formatHead(gpa, head);
        defer gpa.free(canonical_head);
        try expectEqual(head_text, canonical_head, error.HeadNotCanonical);

        const root = merkleRoot(entries.items[0..index]);
        const root_hex = hex32(root);
        try expectEqual(head[2], root_hex[0..], error.HeadRootMismatch);

        if (index == 0) {
            try expectEqual(head[3], "0", error.EmptyHeadPreviousSizeMismatch);
            try expectEqual(head[4], zero64, error.EmptyHeadPreviousRootMismatch);
            try expectEqual(head[5], zero64, error.EmptyHeadEntryHashMismatch);
        } else {
            const previous_size = try parseDecimal(head[3], "previous-tree-size");
            if (previous_size != index - 1) return error.HeadPreviousSizeMismatch;
            try expectEqual(head[4], previous_root_hex[0..], error.HeadPreviousRootMismatch);
            try expectEqual(head[5], entries.items[index - 1].entry_hash[0..], error.HeadEntryHashMismatch);
        }

        @memcpy(previous_root_hex[0..], root_hex[0..]);

        if (index + 1 == size) {
            if (previous_head_text) |old| gpa.free(old);
            previous_head_text = try gpa.dupe(u8, head_text);
        }

        if (index == size) {
            try expectEqual(head_text, latest_text, error.LatestHeadMismatch);
        }
    }

    if (size > 0) {
        const prev = previous_head_text orelse return error.MissingPreviousHead;
        const previous_text = try readFile(gpa, io, paths.previous_head);
        defer gpa.free(previous_text);
        try expectEqual(previous_text, prev, error.PreviousHeadMismatch);

        const latest_entry = try readFile(gpa, io, paths.latest_entry);
        defer gpa.free(latest_entry);
        try expectEqual(latest_entry, entries.items[size - 1].text, error.LatestEntryMismatch);
    }

    try stdout.print("valid ledger history: {s}\n", .{ledger});
    try stdout.flush();
}

fn ledgerPaths(gpa: Allocator, ledger: []const u8) !LedgerPaths {
    return .{
        .entries = try joinPath(gpa, ledger, "entries"),
        .heads = try joinPath(gpa, ledger, "heads"),
        .latest_entry = try joinPath(gpa, ledger, "ledger-entry.txt"),
        .latest_head = try joinPath(gpa, ledger, "ledger-head.txt"),
        .previous_head = try joinPath(gpa, ledger, "previous-ledger-head.txt"),
        .lock = try joinPath(gpa, ledger, ".wuci-ledger.lock"),
    };
}

fn joinPath(gpa: Allocator, parent: []const u8, child: []const u8) ![]u8 {
    if (parent.len != 0 and parent[parent.len - 1] == '/') {
        return try std.fmt.allocPrint(gpa, "{s}{s}", .{ parent, child });
    }
    return try std.fmt.allocPrint(gpa, "{s}/{s}", .{ parent, child });
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

fn assertLedgerMissingOrEmpty(io: Io, ledger: []const u8) !void {
    var dir = Io.Dir.cwd().openDir(io, ledger, .{ .iterate = true }) catch |err| switch (err) {
        error.FileNotFound => return,
        else => |e| return e,
    };
    defer dir.close(io);
    var iter = dir.iterate();
    if (try iter.next(io) != null) return error.LedgerDirectoryNotEmpty;
}

fn initHead(gpa: Allocator) ![]u8 {
    const root_hex = hex32(emptyRoot());
    return try formatHead(gpa, .{ head_schema, "0", root_hex[0..], "0", zero64, zero64 });
}

fn loadEntries(gpa: Allocator, io: Io, paths: LedgerPaths, size: usize) ![]Entry {
    try assertDirectoryExact(io, paths.entries, size, fileNameForEntry);

    var entries: std.ArrayList(Entry) = .empty;
    errdefer {
        for (entries.items) |entry| entry.deinit(gpa);
        entries.deinit(gpa);
    }

    var index: usize = 0;
    while (index < size) : (index += 1) {
        const name = try fileNameForEntry(gpa, index);
        defer gpa.free(name);
        const path = try joinPath(gpa, paths.entries, name);
        defer gpa.free(path);
        const text = try readFile(gpa, io, path);
        const fields = try parseEntry(text);
        if (try parseDecimal(fields[1], "sequence") != index) return error.EntrySequenceMismatch;
        const canonical_entry = try formatEntry(gpa, fields);
        defer gpa.free(canonical_entry);
        try expectEqual(text, canonical_entry, error.EntryNotCanonical);
        try entries.append(gpa, .{
            .text = text,
            .fields = fields,
            .leaf = ledgerLeaf(text),
            .entry_hash = sha256Hex(text),
        });
    }
    return try entries.toOwnedSlice(gpa);
}

fn freeEntries(gpa: Allocator, entries: []Entry) void {
    for (entries) |entry| entry.deinit(gpa);
    gpa.free(entries);
}

fn deriveEntryFromBundle(gpa: Allocator, io: Io, bundle: []const u8, sequence: usize) ![]u8 {
    try assertWitnessProfile(io, bundle);

    const artifact_path = try joinPath(gpa, bundle, "wuci-ji.self.wj");
    defer gpa.free(artifact_path);
    const manifest_path = try joinPath(gpa, bundle, "manifest.txt");
    defer gpa.free(manifest_path);
    const warrant_path = try joinPath(gpa, bundle, "warrant-message.txt");
    defer gpa.free(warrant_path);
    const receipt_path = try joinPath(gpa, bundle, "release-receipt.json");
    defer gpa.free(receipt_path);
    const contract_path = try joinPath(gpa, bundle, "receipt-contract.txt");
    defer gpa.free(contract_path);
    const authority_path = try joinPath(gpa, bundle, "authority-root.txt");
    defer gpa.free(authority_path);
    const decision_path = try joinPath(gpa, bundle, "release-decision.txt");
    defer gpa.free(decision_path);
    const index_path = try joinPath(gpa, bundle, "publish-index.txt");
    defer gpa.free(index_path);
    const attestation_path = try joinPath(gpa, bundle, "attestation.json");
    defer gpa.free(attestation_path);

    const index_text = try readFile(gpa, io, index_path);
    defer gpa.free(index_text);
    const index_fields = try parseIndex(index_text);

    try compareFileHash(gpa, io, artifact_path, index_fields[1]);
    try compareFileHash(gpa, io, manifest_path, index_fields[2]);
    try compareFileHash(gpa, io, warrant_path, index_fields[3]);
    try compareFileHash(gpa, io, receipt_path, index_fields[4]);
    try compareFileHash(gpa, io, contract_path, index_fields[5]);
    try compareFileHash(gpa, io, authority_path, index_fields[6]);
    try compareFileHash(gpa, io, decision_path, index_fields[7]);

    const attestation = try readFile(gpa, io, attestation_path);
    defer gpa.free(attestation);
    const attestation_hash = sha256Hex(attestation);
    const sequence_text = try std.fmt.allocPrint(gpa, "{d}", .{sequence});
    defer gpa.free(sequence_text);

    return try formatEntry(gpa, .{
        entry_schema,
        sequence_text,
        index_fields[1],
        index_fields[2],
        index_fields[3],
        index_fields[4],
        index_fields[5],
        index_fields[6],
        index_fields[7],
        attestation_hash[0..],
        index_fields[8],
    });
}

fn assertWitnessProfile(io: Io, bundle: []const u8) !void {
    var dir = try Io.Dir.cwd().openDir(io, bundle, .{ .iterate = true });
    defer dir.close(io);

    var seen: [witness_public_files.len]bool = @splat(false);
    var iter = dir.iterate();
    while (try iter.next(io)) |entry| {
        if (entry.kind != .file) return error.WitnessBundleEntryNotFile;
        if (indexOf(witness_forbidden_files, entry.name) != null) return error.WitnessPrivateFilePresent;
        const index = indexOf(witness_public_files, entry.name) orelse return error.UnexpectedWitnessBundleFile;
        if (seen[index]) return error.DuplicateWitnessBundleFile;
        seen[index] = true;
    }
    for (seen) |found| {
        if (!found) return error.MissingWitnessBundleFile;
    }
}

fn indexOf(comptime list: anytype, value: []const u8) ?usize {
    for (list, 0..) |item, index| {
        if (std.mem.eql(u8, item, value)) return index;
    }
    return null;
}

fn parseIndex(text: []const u8) ![index_labels.len][]const u8 {
    const fields = try parseFlat(index_labels, text, index_schema);
    inline for (1..8) |field_index| {
        try requireHex(fields[field_index], 64);
    }
    try requireHex(fields[8], 66);
    if (!std.mem.eql(u8, fields[8][0..2], "02") and !std.mem.eql(u8, fields[8][0..2], "03")) {
        return error.InvalidCompressedSec1;
    }
    return fields;
}

fn compareFileHash(gpa: Allocator, io: Io, path: []const u8, expected: []const u8) !void {
    const bytes = try readFile(gpa, io, path);
    defer gpa.free(bytes);
    const actual = sha256Hex(bytes);
    try expectEqual(actual[0..], expected, error.HashMismatch);
}

fn assertDirectoryExact(
    io: Io,
    path: []const u8,
    expected_count: usize,
    nameFn: fn (Allocator, usize) anyerror![]u8,
) !void {
    var arena_instance = std.heap.ArenaAllocator.init(std.heap.smp_allocator);
    defer arena_instance.deinit();
    const arena = arena_instance.allocator();

    var seen = try arena.alloc(bool, expected_count);
    @memset(seen, false);

    var dir = try Io.Dir.cwd().openDir(io, path, .{ .iterate = true });
    defer dir.close(io);

    var count: usize = 0;
    var iter = dir.iterate();
    while (try iter.next(io)) |entry| {
        if (entry.kind != .file) return error.LedgerDirectoryEntryNotFile;
        count += 1;
        var matched = false;
        var index: usize = 0;
        while (index < expected_count) : (index += 1) {
            const expected = try nameFn(arena, index);
            if (std.mem.eql(u8, entry.name, expected)) {
                if (seen[index]) return error.DuplicateLedgerFile;
                seen[index] = true;
                matched = true;
                break;
            }
        }
        if (!matched) return error.UnexpectedLedgerFile;
    }
    if (count != expected_count) return error.MissingLedgerFile;
    for (seen) |item| {
        if (!item) return error.MissingLedgerFile;
    }
}

fn fileNameForEntry(gpa: Allocator, sequence: usize) ![]u8 {
    return try std.fmt.allocPrint(gpa, "{d:0>20}.txt", .{sequence});
}

fn fileNameForHead(gpa: Allocator, size: usize) ![]u8 {
    return try std.fmt.allocPrint(gpa, "{d:0>20}.txt", .{size});
}

fn parseEntry(text: []const u8) ![entry_labels.len][]const u8 {
    const fields = try parseFlat(entry_labels, text, entry_schema);
    _ = try parseDecimal(fields[1], "sequence");
    inline for (2..10) |field_index| {
        try requireHex(fields[field_index], 64);
    }
    try requireHex(fields[10], 66);
    if (!std.mem.eql(u8, fields[10][0..2], "02") and !std.mem.eql(u8, fields[10][0..2], "03")) {
        return error.InvalidCompressedSec1;
    }
    return fields;
}

fn parseHead(text: []const u8) ![head_labels.len][]const u8 {
    const fields = try parseFlat(head_labels, text, head_schema);
    const tree_size = try parseDecimal(fields[1], "tree-size");
    const previous_size = try parseDecimal(fields[3], "previous-tree-size");
    if (tree_size == 0) {
        if (previous_size != 0) return error.EmptyHeadPreviousSizeMismatch;
        try expectLiteral(fields[5], zero64, error.EmptyHeadEntryHashMismatch);
    } else if (previous_size >= tree_size) {
        return error.HeadPreviousSizeMismatch;
    }
    try requireHex(fields[2], 64);
    try requireHex(fields[4], 64);
    try requireHex(fields[5], 64);
    return fields;
}

fn parseFlat(comptime labels: anytype, text: []const u8, schema: []const u8) ![labels.len][]const u8 {
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
    try expectLiteral(values[0], schema, error.UnsupportedSchema);
    return values;
}

fn formatEntry(gpa: Allocator, fields: [entry_labels.len][]const u8) ![]u8 {
    return try formatFlat(gpa, entry_labels, fields);
}

fn formatHead(gpa: Allocator, fields: [head_labels.len][]const u8) ![]u8 {
    return try formatFlat(gpa, head_labels, fields);
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

fn formatProof(
    gpa: Allocator,
    comptime labels: anytype,
    fields: [labels.len][]const u8,
    path: []const [32]u8,
) ![]u8 {
    var values = fields;
    const path_count = try std.fmt.allocPrint(gpa, "{d}", .{path.len});
    defer gpa.free(path_count);
    values[labels.len - 1] = path_count;

    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(gpa);
    inline for (labels, 0..) |label, index| {
        try out.appendSlice(gpa, label);
        try out.appendSlice(gpa, ": ");
        try out.appendSlice(gpa, values[index]);
        try out.append(gpa, '\n');
    }
    try out.appendSlice(gpa, "path:\n");
    for (path) |hash| {
        const hash_hex = hex32(hash);
        try out.appendSlice(gpa, hash_hex[0..]);
        try out.append(gpa, '\n');
    }
    return try out.toOwnedSlice(gpa);
}

fn ParsedProof(comptime count: comptime_int) type {
    return struct {
        fields: [count][]const u8,
        hashes: [][32]u8,

        fn deinit(self: @This(), gpa: Allocator) void {
            gpa.free(self.hashes);
        }
    };
}

fn parseProof(
    gpa: Allocator,
    comptime labels: anytype,
    text: []const u8,
    schema: []const u8,
) !ParsedProof(labels.len) {
    if (text.len == 0) return error.EmptyFlatFile;
    for (text) |byte| {
        if (byte > 0x7f) return error.NonAsciiFlatFile;
        if (byte == '\r') return error.FlatFileContainsCr;
    }
    if (text[text.len - 1] != '\n') return error.MissingTrailingNewline;
    if (text.len >= 2 and text[text.len - 2] == '\n') return error.ExtraTrailingNewline;

    var values: [labels.len][]const u8 = undefined;
    var lines = std.mem.splitScalar(u8, text[0 .. text.len - 1], '\n');
    inline for (labels, 0..) |label, index| {
        const line = lines.next() orelse return error.ProofTruncated;
        if (!std.mem.startsWith(u8, line, label)) return error.NonCanonicalFieldOrder;
        if (line.len < label.len + 2 or line[label.len] != ':' or line[label.len + 1] != ' ') {
            return error.MalformedFlatLine;
        }
        const value = line[label.len + 2 ..];
        if (value.len == 0) return error.EmptyFlatField;
        values[index] = value;
    }
    try expectEqual(values[0], schema, error.UnsupportedSchema);
    const path_header = lines.next() orelse return error.ProofMissingPath;
    try expectEqual(path_header, "path:", error.ProofMissingPath);
    const path_count = try parseDecimal(values[labels.len - 1], "path-count");
    var path = try gpa.alloc([32]u8, path_count);
    errdefer gpa.free(path);
    var index: usize = 0;
    while (index < path_count) : (index += 1) {
        const line = lines.next() orelse return error.ProofPathTooShort;
        path[index] = try hexToBytes32(line);
    }
    if (lines.next() != null) return error.ProofPathTooLong;
    return .{ .fields = values, .hashes = path };
}

fn appendInclusionPath(
    gpa: Allocator,
    path: *std.ArrayList([32]u8),
    entries: []const Entry,
    index: usize,
) !void {
    if (index >= entries.len) return error.InclusionSequenceOutsideTree;
    if (entries.len == 1) return;
    const k = splitPower(entries.len);
    if (index < k) {
        try appendInclusionPath(gpa, path, entries[0..k], index);
        try path.append(gpa, merkleRoot(entries[k..]));
    } else {
        try appendInclusionPath(gpa, path, entries[k..], index - k);
        try path.append(gpa, merkleRoot(entries[0..k]));
    }
}

fn appendConsistencyPath(
    gpa: Allocator,
    path: *std.ArrayList([32]u8),
    entries: []const Entry,
    first_size: usize,
    seed: bool,
) !void {
    const second_size = entries.len;
    if (first_size > second_size) return error.ConsistencyRangeInvalid;
    if (first_size == 0) return;
    if (first_size == second_size) {
        if (!seed) try path.append(gpa, merkleRoot(entries));
        return;
    }
    const k = splitPower(second_size);
    if (first_size <= k) {
        try appendConsistencyPath(gpa, path, entries[0..k], first_size, seed);
        try path.append(gpa, merkleRoot(entries[k..]));
    } else {
        try appendConsistencyPath(gpa, path, entries[k..], first_size - k, false);
        try path.append(gpa, merkleRoot(entries[0..k]));
    }
}

fn rootFromInclusion(leaf: [32]u8, index: usize, size: usize, path: []const [32]u8) ![32]u8 {
    if (size == 0 or index >= size) return error.InclusionSequenceOutsideTree;
    if (size == 1) {
        if (path.len != 0) return error.InclusionPathTooLong;
        return leaf;
    }
    if (path.len == 0) return error.InclusionPathTooShort;
    const k = splitPower(size);
    const sibling = path[path.len - 1];
    const rest = path[0 .. path.len - 1];
    if (index < k) {
        return ledgerNode(try rootFromInclusion(leaf, index, k, rest), sibling);
    }
    return ledgerNode(sibling, try rootFromInclusion(leaf, index - k, size - k, rest));
}

const ConsistencyRoots = struct {
    old: [32]u8,
    new: [32]u8,
};

const ConsistencyRec = struct {
    old: [32]u8,
    new: [32]u8,
    consumed: usize,
};

fn consistencyRootsFromProof(
    first_size: usize,
    second_size: usize,
    first_root: [32]u8,
    path: []const [32]u8,
) !ConsistencyRoots {
    const result = try consistencyRec(first_size, second_size, first_root, path, true, 0);
    if (result.consumed != path.len) return error.ConsistencyPathTooLong;
    return .{ .old = result.old, .new = result.new };
}

fn consistencyRec(
    local_first: usize,
    local_second: usize,
    first_root: [32]u8,
    path: []const [32]u8,
    seed: bool,
    offset: usize,
) !ConsistencyRec {
    if (local_first == local_second) {
        if (seed) return .{ .old = first_root, .new = first_root, .consumed = offset };
        if (offset >= path.len) return error.ConsistencyPathTooShort;
        const value = path[offset];
        return .{ .old = value, .new = value, .consumed = offset + 1 };
    }
    const k = splitPower(local_second);
    if (local_first <= k) {
        const left = try consistencyRec(local_first, k, first_root, path, seed, offset);
        if (left.consumed >= path.len) return error.ConsistencyPathTooShort;
        const right = path[left.consumed];
        return .{
            .old = left.old,
            .new = ledgerNode(left.new, right),
            .consumed = left.consumed + 1,
        };
    }

    const right = try consistencyRec(local_first - k, local_second - k, first_root, path, false, offset);
    if (right.consumed >= path.len) return error.ConsistencyPathTooShort;
    const left_hash = path[right.consumed];
    return .{
        .old = ledgerNode(left_hash, right.old),
        .new = ledgerNode(left_hash, right.new),
        .consumed = right.consumed + 1,
    };
}

fn hexToBytes32(value: []const u8) ![32]u8 {
    try requireHex(value, 64);
    var out: [32]u8 = undefined;
    _ = try std.fmt.hexToBytes(&out, value);
    return out;
}

fn parseDecimal(value: []const u8, context: []const u8) !usize {
    if (value.len == 0) return error.InvalidDecimal;
    if (value.len > 1 and value[0] == '0') return error.DecimalLeadingZero;
    var result: usize = 0;
    for (value) |byte| {
        if (byte < '0' or byte > '9') {
            std.debug.print("{s} must be decimal\n", .{context});
            return error.InvalidDecimal;
        }
        result = try std.math.mul(usize, result, 10);
        result = try std.math.add(usize, result, byte - '0');
    }
    return result;
}

fn requireHex(value: []const u8, expected_len: usize) !void {
    if (value.len != expected_len) return error.InvalidHex;
    for (value) |byte| {
        if (!((byte >= '0' and byte <= '9') or (byte >= 'a' and byte <= 'f'))) {
            return error.InvalidHex;
        }
    }
}

fn expectLiteral(actual: []const u8, expected: []const u8, err: anyerror) !void {
    if (!std.mem.eql(u8, actual, expected)) return err;
}

fn expectEqual(actual: []const u8, expected: []const u8, err: anyerror) !void {
    if (!std.mem.eql(u8, actual, expected)) return err;
}

fn sha256Hex(data: []const u8) [64]u8 {
    var digest: [Sha256.digest_length]u8 = undefined;
    Sha256.hash(data, &digest, .{});
    return std.fmt.bytesToHex(digest, .lower);
}

fn ledgerLeaf(entry: []const u8) [32]u8 {
    var digest: [Sha256.digest_length]u8 = undefined;
    var hasher = Sha256.init(.{});
    hasher.update(&.{0});
    hasher.update(entry);
    hasher.final(&digest);
    return digest;
}

fn ledgerNode(left: [32]u8, right: [32]u8) [32]u8 {
    var digest: [Sha256.digest_length]u8 = undefined;
    var hasher = Sha256.init(.{});
    hasher.update(&.{1});
    hasher.update(left[0..]);
    hasher.update(right[0..]);
    hasher.final(&digest);
    return digest;
}

fn emptyRoot() [32]u8 {
    var digest: [Sha256.digest_length]u8 = undefined;
    Sha256.hash("", &digest, .{});
    return digest;
}

fn merkleRoot(entries: []const Entry) [32]u8 {
    if (entries.len == 0) return emptyRoot();
    if (entries.len == 1) return entries[0].leaf;
    const k = splitPower(entries.len);
    return ledgerNode(
        merkleRoot(entries[0..k]),
        merkleRoot(entries[k..]),
    );
}

fn splitPower(size: usize) usize {
    return @as(usize, 1) << @intCast(std.math.log2_int(usize, size - 1));
}

fn hex32(digest: [32]u8) [64]u8 {
    return std.fmt.bytesToHex(digest, .lower);
}
