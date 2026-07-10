#!/usr/bin/env python3
from __future__ import annotations

import copy
import sys
import tempfile
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))

from tools import site_dist


def must_fail(function, expected: str) -> None:
    try:
        function()
    except ValueError as error:
        assert expected in str(error), error
        return
    raise AssertionError(f"expected ValueError containing {expected!r}")


def main() -> None:
    assert site_dist.public_route_aliases("public-page.html") == {
        "/public-page",
        "/public-page.html",
    }
    assert site_dist.public_route_aliases("docs/index.html") == {
        "/docs/",
        "/docs/index.html",
    }
    source_files = site_dist.collect_regular_tree(site_dist.SOURCE_ROOT)
    clean_url_collision = dict(source_files)
    clean_url_collision["public-page.html"] = b"<!doctype html><title>public</title>"
    clean_url_collision["_redirects"] += (
        b"\n/public-page https://github.com/chasebryan/-wuci-ji 302\n"
    )
    must_fail(
        lambda: site_dist.build_inventory(clean_url_collision),
        "redirect-shadowed site sources",
    )

    wildcard_collision = dict(source_files)
    wildcard_collision["_redirects"] += b"\n/assets/* / 302\n"
    must_fail(
        lambda: site_dist.build_inventory(wildcard_collision),
        "redirect-shadowed site sources",
    )

    with tempfile.TemporaryDirectory() as temporary:
        output = Path(temporary) / "site-dist"
        inventory = site_dist.build_site_dist(site_dist.SOURCE_ROOT, output)
        staged = site_dist.collect_regular_tree(output)
        site_dist.validate_inventory(inventory, staged)

        assert inventory["publicFileCount"] == len(inventory["publicFiles"])
        assert inventory["publicBytes"] == sum(
            record["bytes"] for record in inventory["publicFiles"]
        )
        assert set(site_dist.EXCLUDED_SOURCE_FILES).isdisjoint(staged)
        assert set(site_dist.CONFIG_FILES).issubset(staged)
        assert site_dist.INVENTORY_NAME in staged

        records = {record["path"]: record for record in inventory["publicFiles"]}
        assert records["ai-scoring-integrity.html"]["urlPath"] == "/ai-scoring-integrity"
        assert records["assets/wuci-ji-systems-hero.jpg"]["mediaType"] == "image/jpeg"
        assert records["404.html"] == site_dist.public_file_record(
            "404.html", staged["404.html"]
        )

        missing_inventory = copy.deepcopy(inventory)
        missing_inventory["publicFiles"] = [
            record
            for record in missing_inventory["publicFiles"]
            if record["path"] != "ai-scoring-integrity.html"
        ]
        missing_inventory["publicFileCount"] -= 1
        missing_inventory["publicBytes"] -= records["ai-scoring-integrity.html"]["bytes"]
        missing_staged = dict(staged)
        missing_staged[site_dist.INVENTORY_NAME] = site_dist.inventory_bytes(
            missing_inventory
        )
        must_fail(
            lambda: site_dist.validate_inventory(missing_inventory, missing_staged),
            "tree mismatch",
        )

        extra_inventory = copy.deepcopy(inventory)
        extra_inventory["publicFiles"].append(
            {
                "path": "extra.bin",
                "urlPath": "/extra.bin",
                "status": 200,
                "mediaType": "application/octet-stream",
                "bytes": 1,
                "sha256": "0" * 64,
            }
        )
        extra_inventory["publicFileCount"] += 1
        extra_inventory["publicBytes"] += 1
        extra_staged = dict(staged)
        extra_staged[site_dist.INVENTORY_NAME] = site_dist.inventory_bytes(extra_inventory)
        must_fail(
            lambda: site_dist.validate_inventory(extra_inventory, extra_staged),
            "bytes or route do not match",
        )

        substituted = dict(staged)
        substituted["ai-scoring-integrity.html"] += b"substituted"
        must_fail(
            lambda: site_dist.validate_inventory(inventory, substituted),
            "bytes or route do not match",
        )

    must_fail(
        lambda: site_dist.media_type_for_path("assets/unknown.bin"),
        "no explicit safe MIME contract",
    )

    with tempfile.TemporaryDirectory() as temporary:
        root = Path(temporary)
        (root / "too-large.txt").write_bytes(
            b"x" * (site_dist.MAX_SITE_FILE_BYTES + 1)
        )
        must_fail(lambda: site_dist.collect_regular_tree(root), "entry exceeds")

    with tempfile.TemporaryDirectory() as temporary:
        root = Path(temporary)
        original_total = site_dist.MAX_SITE_TOTAL_BYTES
        try:
            site_dist.MAX_SITE_TOTAL_BYTES = 10
            (root / "a.txt").write_bytes(b"a" * 6)
            (root / "b.txt").write_bytes(b"b" * 6)
            must_fail(lambda: site_dist.collect_regular_tree(root), "aggregate budget")
        finally:
            site_dist.MAX_SITE_TOTAL_BYTES = original_total

    print("site dist: PASS")


if __name__ == "__main__":
    main()
