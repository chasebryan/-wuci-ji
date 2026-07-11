import { link, mkdtemp, mkdir, rm, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { pathToFileURL } from "node:url";
import { describe, expect, it } from "vitest";
import {
  assertBundleSourceMetadata,
  assertCleanSourceSnapshot,
  assertCurrentCleanSource,
  assertReleaseBuildToolchain,
  assertSameBytes,
  assertValidKeyring,
  buildSourceClosure,
  collectRegularFiles,
  normalizeGitRepositoryUrl,
  sha256
} from "./release-manifest-lib.mjs";

describe("release manifest filesystem boundary", () => {
  it("pins the production Bottle build toolchain exactly", () => {
    expect(() => assertReleaseBuildToolchain("v22.23.1", "npm@11.8.0")).not.toThrow();
    expect(() => assertReleaseBuildToolchain("v24.0.0", "npm@11.8.0")).toThrow(
      /Production Bottle builds require/
    );
    expect(() => assertReleaseBuildToolchain("v22.23.1", "npm@11.9.0")).toThrow(
      /Production Bottle builds require/
    );
  });

  it("rejects symbolic links and multiply linked files", async () => {
    const directory = await mkdtemp(join(tmpdir(), "daylight-release-files-"));
    try {
      const root = pathToFileURL(`${directory}/`);
      const regular = join(directory, "regular.txt");
      await writeFile(regular, "public artifact\n", "utf8");
      await symlink(regular, join(directory, "linked.txt"));
      await expect(collectRegularFiles(root)).rejects.toThrow(/symbolic link/);

      await rm(join(directory, "linked.txt"));
      await link(regular, join(directory, "hardlinked.txt"));
      await expect(collectRegularFiles(root)).rejects.toThrow(/multiple hard links/);
    } finally {
      await rm(directory, { recursive: true, force: true });
    }
  });

  it("hashes an explicit source closure deterministically and detects byte changes", async () => {
    const directory = await mkdtemp(join(tmpdir(), "daylight-release-closure-"));
    try {
      await mkdir(join(directory, "worker"));
      await writeFile(join(directory, "worker", "a.ts"), "export const a = 1;\n", "utf8");
      await writeFile(join(directory, "worker", "b.ts"), "export const b = 2;\n", "utf8");
      const root = pathToFileURL(`${directory}/`);
      const paths = ["worker/b.ts", "worker/a.ts"];
      const first = await buildSourceClosure(root, paths);
      const second = await buildSourceClosure(root, paths);
      expect(second).toEqual(first);
      expect(first.files.map((file) => file.path)).toEqual([...paths].sort());

      await writeFile(join(directory, "worker", "b.ts"), "export const b = 3;\n", "utf8");
      const changed = await buildSourceClosure(root, paths);
      expect(changed.sha256).not.toBe(first.sha256);
    } finally {
      await rm(directory, { recursive: true, force: true });
    }
  });

  it("requires source and built keyring bytes to match exactly", () => {
    expect(() => assertSameBytes(Buffer.from("same"), Buffer.from("same"), "Keyring")).not.toThrow();
    expect(() => assertSameBytes(Buffer.from("source"), Buffer.from("built"), "Keyring")).toThrow(
      /byte-for-byte identical/
    );
  });

  it("rejects stale or dirty production source bindings", () => {
    const commit = "a".repeat(40);
    const manifest = {
      schema: "nsm.daylight-bottle.release-manifest.v1",
      source: {
        repository: "https://github.com/chasebryan/-wuci-ji",
        commit,
        treeState: "clean"
      }
    };
    const repository = "https://github.com/chasebryan/-wuci-ji";
    expect(() => assertCleanSourceSnapshot(manifest, commit, "", repository)).not.toThrow();
    expect(() => assertCurrentCleanSource(manifest, commit, "", repository, commit)).not.toThrow();
    expect(() =>
      assertCurrentCleanSource(manifest, "b".repeat(40), "", repository, commit)
    ).toThrow(/canonical origin/);
    expect(() =>
      assertCurrentCleanSource(manifest, commit, " M worker/index.ts", repository, commit)
    ).toThrow(
      /canonical origin/
    );
    expect(() =>
      assertCurrentCleanSource(
        { ...manifest, source: { ...manifest.source, treeState: "dirty" } },
        commit,
        "",
        repository,
        commit
      )
    ).toThrow(/canonical origin/);
    expect(() =>
      assertCurrentCleanSource(manifest, commit, "", "https://github.com/example/fork", commit)
    ).toThrow(/canonical origin/);
    expect(() =>
      assertCurrentCleanSource(manifest, commit, "", repository, "b".repeat(40))
    ).toThrow(/origin\/main/);
  });

  it("normalizes supported GitHub origin URL forms without attributing unknown origins", () => {
    expect(normalizeGitRepositoryUrl("git@github.com:chasebryan/-wuci-ji.git")).toBe(
      "https://github.com/chasebryan/-wuci-ji"
    );
    expect(normalizeGitRepositoryUrl("ssh://git@github.com/chasebryan/-wuci-ji.git")).toBe(
      "https://github.com/chasebryan/-wuci-ji"
    );
    expect(normalizeGitRepositoryUrl("https://github.com/example/fork.git")).toBe(
      "https://github.com/example/fork"
    );
    expect(normalizeGitRepositoryUrl("https://git.example.com/example/fork.git")).toBeUndefined();
  });

  it("allows unknown source identity for portable bundle checks but rejects malformed metadata", () => {
    const commit = "a".repeat(40);
    expect(() =>
      assertBundleSourceMetadata({
        repository: "https://github.com/chasebryan/-wuci-ji",
        commit,
        treeState: "clean"
      })
    ).not.toThrow();
    expect(() =>
      assertBundleSourceMetadata({ repository: "unknown", commit: "unknown", treeState: "unknown" })
    ).not.toThrow();
    expect(() =>
      assertBundleSourceMetadata({ repository: undefined, commit, treeState: "clean" })
    ).toThrow(/source metadata/);
    expect(() =>
      assertBundleSourceMetadata({
        repository: "git@github.com:chasebryan/-wuci-ji.git",
        commit,
        treeState: "clean"
      })
    ).toThrow(/source metadata/);
    expect(() =>
      assertBundleSourceMetadata({ repository: "unknown", commit: "not-a-commit", treeState: "clean" })
    ).toThrow(/source metadata/);
  });

  it("matches runtime keyring validation without rejecting public keyname words", () => {
    const keyname = "secret.agent";
    const publicRecipient = `age1${"q".repeat(58)}`;
    const fingerprint = `sha256:${sha256(
      Buffer.from(`nsm.daylight-bottle.key.v1\n${keyname}\n${publicRecipient}`)
    )}`;
    const record = {
      schema: "nsm.daylight-bottle.key.v1",
      keyname,
      publicRecipient,
      fingerprint,
      createdAt: "2026-07-07T00:00:00.000Z",
      status: "active"
    };
    const keyring = {
      schema: "nsm.daylight-bottle.keyring.v1",
      updatedAt: "2026-07-07T00:00:00.000Z",
      keys: [record]
    };

    expect(assertValidKeyring(keyring)).toBe(keyring);
    expect(() => assertValidKeyring({ ...keyring, updatedAt: "2026-07-07" })).toThrow(
      /canonical UTC/
    );
    expect(() =>
      assertValidKeyring({ ...keyring, keys: [{ ...record, keyname: "Secret.Agent" }] })
    ).toThrow(/not canonical/);
    expect(() =>
      assertValidKeyring({ ...keyring, keys: [{ ...record, publicRecipient: "not-age" }] })
    ).toThrow(/age public recipient/);
    expect(() =>
      assertValidKeyring({ ...keyring, keys: [{ ...record, privateIdentity: "must-not-appear" }] })
    ).toThrow(/unexpected field privateIdentity/);
    expect(() =>
      assertValidKeyring({ ...keyring, keys: [{ ...record, fingerprint: "sha256:not-hex" }] })
    ).toThrow(/invalid fingerprint/);
    expect(() =>
      assertValidKeyring({
        ...keyring,
        keys: [{ ...record, fingerprint: `sha256:${"a".repeat(64)}` }]
      })
    ).toThrow(/fingerprint mismatch/);
    expect(() =>
      assertValidKeyring({ ...keyring, keys: [{ ...record, createdAt: "2026-07-07" }] })
    ).toThrow(/canonical UTC/);
    expect(() => {
      const missingCreatedAt = { ...record };
      delete missingCreatedAt.createdAt;
      return assertValidKeyring({ ...keyring, keys: [missingCreatedAt] });
    }).toThrow(/missing field createdAt/);
    expect(() => assertValidKeyring({ ...keyring, keys: [record, record] })).toThrow(
      /duplicate fingerprint/
    );
    expect(() =>
      assertValidKeyring({
        ...keyring,
        keys: [
          record,
          {
            ...record,
            publicRecipient: `age1${"r".repeat(58)}`,
            fingerprint: `sha256:${sha256(
              Buffer.from(`nsm.daylight-bottle.key.v1\n${keyname}\nage1${"r".repeat(58)}`)
            )}`
          }
        ]
      })
    ).toThrow(/multiple active records/);
  });
});
