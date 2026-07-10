#!/usr/bin/env python3
from __future__ import annotations

import argparse
import os
import tempfile
from pathlib import Path

import sys


REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "tools"))

import wuci_safeio


def assert_fails(fn, context: str) -> None:
    try:
        fn()
    except wuci_safeio.SafeIOError:
        return
    raise AssertionError(context)


def main() -> None:
    parser = argparse.ArgumentParser(description="Check WUCI safe I/O helpers.")
    parser.add_argument("--quiet", action="store_true", help="suppress summary")
    args = parser.parse_args()

    with tempfile.TemporaryDirectory() as temp_dir:
        tmp = Path(temp_dir)
        output = tmp / "out.txt"
        wuci_safeio.write_new_text(output, "hello\n", "test output")
        assert output.read_text(encoding="ascii") == "hello\n"
        assert_fails(
            lambda: wuci_safeio.write_new_text(output, "again\n", "test output"),
            "safe write must refuse overwrite",
        )

        target = tmp / "target.txt"
        target.write_text("target\n", encoding="ascii")
        symlink = tmp / "link.txt"
        symlink.symlink_to(target)
        assert_fails(
            lambda: wuci_safeio.write_new_text(symlink, "x\n", "symlink output"),
            "safe write must refuse symlink target",
        )
        assert_fails(
            lambda: wuci_safeio.read_regular_bytes(symlink, "symlink input"),
            "safe read must refuse symlink",
        )
        assert_fails(
            lambda: wuci_safeio.read_regular_bytes(tmp, "directory input"),
            "safe read must refuse directory",
        )
        assert list(wuci_safeio.iter_regular_chunks(target, "chunked input", chunk_size=3)) == [b"tar", b"get", b"\n"]

        mutation_target = tmp / "mutation-target.txt"
        mutation_target.write_text("original\n", encoding="ascii")
        original_read = wuci_safeio.os.read
        mutated = False

        def mutate_during_read(fd: int, size: int) -> bytes:
            nonlocal mutated
            data = original_read(fd, size)
            if data and not mutated:
                mutated = True
                mutation_target.write_text("mutated!\n", encoding="ascii")
            return data

        wuci_safeio.os.read = mutate_during_read
        try:
            assert_fails(
                lambda: wuci_safeio.read_regular_bytes(mutation_target, "mutating input"),
                "safe read must reject a file changed through its open descriptor",
            )
        finally:
            wuci_safeio.os.read = original_read

        chunk_mutation_target = tmp / "chunk-mutation-target.txt"
        chunk_mutation_target.write_text("original\n", encoding="ascii")
        mutated = False

        def mutate_chunked_read(fd: int, size: int) -> bytes:
            nonlocal mutated
            data = original_read(fd, size)
            if data and not mutated:
                mutated = True
                chunk_mutation_target.write_text("mutated!\n", encoding="ascii")
            return data

        wuci_safeio.os.read = mutate_chunked_read
        try:
            assert_fails(
                lambda: list(wuci_safeio.iter_regular_chunks(
                    chunk_mutation_target,
                    "mutating chunked input",
                    chunk_size=3,
                )),
                "chunked safe read must reject a file changed before exhaustion",
            )
        finally:
            wuci_safeio.os.read = original_read

        path_swap_target = tmp / "path-swap-target.txt"
        path_swap_target.write_text("path one\n", encoding="ascii")
        path_swap_replacement = tmp / "path-swap-replacement.txt"
        path_swap_replacement.write_text("path two\n", encoding="ascii")
        swapped = False

        def swap_path_during_read(fd: int, size: int) -> bytes:
            nonlocal swapped
            data = original_read(fd, size)
            if data and not swapped:
                swapped = True
                os.replace(path_swap_replacement, path_swap_target)
            return data

        wuci_safeio.os.read = swap_path_during_read
        try:
            assert_fails(
                lambda: wuci_safeio.read_regular_bytes(path_swap_target, "path-swapped input"),
                "safe read must reject a path swapped after opening",
            )
        finally:
            wuci_safeio.os.read = original_read

        original_open = wuci_safeio.os.open
        open_mutation_target = tmp / "open-mutation-target.txt"
        open_mutation_target.write_text("original\n", encoding="ascii")
        opened_after_mutation = False

        def mutate_before_open(path: str | os.PathLike[str], flags: int, *args: int) -> int:
            nonlocal opened_after_mutation
            if Path(path) == open_mutation_target and not opened_after_mutation:
                opened_after_mutation = True
                open_mutation_target.write_text("mutated!\n", encoding="ascii")
            return original_open(path, flags, *args)

        wuci_safeio.os.open = mutate_before_open
        try:
            assert_fails(
                lambda: wuci_safeio.read_regular_bytes(open_mutation_target, "open-mutated input"),
                "safe read must reject same-inode mutation between lstat and open",
            )
        finally:
            wuci_safeio.os.open = original_open

        chunk_open_mutation_target = tmp / "chunk-open-mutation-target.txt"
        chunk_open_mutation_target.write_text("original\n", encoding="ascii")
        opened_after_mutation = False

        def mutate_before_chunk_open(path: str | os.PathLike[str], flags: int, *args: int) -> int:
            nonlocal opened_after_mutation
            if Path(path) == chunk_open_mutation_target and not opened_after_mutation:
                opened_after_mutation = True
                chunk_open_mutation_target.write_text("mutated!\n", encoding="ascii")
            return original_open(path, flags, *args)

        wuci_safeio.os.open = mutate_before_chunk_open
        try:
            assert_fails(
                lambda: list(wuci_safeio.iter_regular_chunks(
                    chunk_open_mutation_target,
                    "open-mutated chunked input",
                    chunk_size=3,
                )),
                "chunked safe read must reject same-inode mutation between lstat and open",
            )
        finally:
            wuci_safeio.os.open = original_open

        large = tmp / "large.txt"
        large.write_text("abcdef", encoding="ascii")
        assert_fails(
            lambda: wuci_safeio.read_regular_bytes(large, "large input", max_bytes=3),
            "safe read must enforce max bytes",
        )

        keyfile = tmp / "artifact.key"
        keyfile.write_text(("11" * 32) + "\n", encoding="ascii")
        keyfile.chmod(0o644)
        assert_fails(
            lambda: wuci_safeio.reject_group_world_readable(keyfile, "keyfile"),
            "strict keyfile check must reject group/world readable files",
        )
        keyfile.chmod(0o600)
        wuci_safeio.reject_group_world_readable(keyfile, "keyfile")

        hardlink = tmp / "hardlink.txt"
        os.link(target, hardlink)
        assert_fails(
            lambda: wuci_safeio.read_regular_bytes(
                hardlink,
                "hardlinked input",
                reject_hardlink=True,
            ),
            "strict safe read must reject hardlinks",
        )

        json_file = tmp / "duplicate.json"
        json_file.write_text('{"schema":"x","schema":"y"}\n', encoding="utf-8")
        assert_fails(
            lambda: wuci_safeio.read_regular_json(json_file, "duplicate JSON"),
            "safe JSON read must reject duplicate object keys",
        )

        real_parent = tmp / "real-parent"
        real_parent.mkdir()
        parent_link = tmp / "parent-link"
        parent_link.symlink_to(real_parent, target_is_directory=True)
        assert_fails(
            lambda: wuci_safeio.write_new_text(parent_link / "child.txt", "x\n", "symlink parent output"),
            "safe write must refuse symlink parent directories",
        )

    if not args.quiet:
        print("wuci safeio: PASS")


if __name__ == "__main__":
    main()
