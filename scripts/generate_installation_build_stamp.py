#!/usr/bin/env python3
"""Generate fixed Engram launcher build inputs after final memory signing.

This records product bytes only. Neither this header nor its provenance record
is installation enrollment, child retirement, or permission to open a store.
No compiler, signing tool, executable, database, or manifest is run here.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import stat

MAXIMUM_EXECUTABLE_BYTES = 1024 * 1024 * 1024


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def stable_metadata(value: os.stat_result) -> tuple[int, ...]:
    return (value.st_dev, value.st_ino, value.st_mode, value.st_uid,
            value.st_nlink, value.st_size, value.st_mtime_ns, value.st_ctime_ns)


def signed_input_facts(memory: Path, leaf: str = "memory") -> dict[str, object]:
    # The caller's packaging pipeline owns final signing; this function does
    # not infer signature validity or origin merely by hashing arbitrary bytes.
    require(leaf in {"memory", "memory-installation-launcher"} and memory.name == leaf,
            "a fixed Engram sibling executable is required")
    descriptor = os.open(memory, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        before = os.fstat(descriptor)
        require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1
                and before.st_mode & 0o111 != 0 and before.st_mode & 0o6022 == 0,
                "memory must be a regular single-link executable with controlled permissions")
        require(0 < before.st_size <= MAXIMUM_EXECUTABLE_BYTES,
                "memory is outside the executable size bound")
        named_before = memory.lstat()
        require(stable_metadata(named_before) == stable_metadata(before),
                "memory name changed before hashing")
        digest = hashlib.sha256()
        consumed = 0
        while consumed < before.st_size:
            block = os.read(descriptor, min(64 * 1024, before.st_size - consumed))
            require(bool(block), "memory ended before its observed size")
            consumed += len(block)
            digest.update(block)
        require(not os.read(descriptor, 1), "memory grew during hashing")
        after = os.fstat(descriptor)
        named = memory.lstat()
        require(stable_metadata(before) == stable_metadata(after)
                and stable_metadata(after) == stable_metadata(named),
                "memory changed during final-byte observation")
        return {"leaf": leaf, "bytes": consumed, "sha256": digest.hexdigest(),
                "observedDevice": before.st_dev, "observedInode": before.st_ino}
    finally:
        os.close(descriptor)


def header_bytes(source_revision: str, core_revision: str, facts: dict[str, object]) -> bytes:
    require(bool(re.fullmatch(r"[0-9a-f]{40}", source_revision)),
            "full frozen Engram source revision required")
    require(bool(re.fullmatch(r"[0-9a-f]{40}", core_revision)),
            "full frozen Core source revision required")
    digest = facts["sha256"]
    require(isinstance(digest, str) and bool(re.fullmatch(r"[0-9a-f]{64}", digest)),
            "exact final-byte digest required")
    require(facts["leaf"] == "memory", "arbitrary executable names are not supported")
    literal = ", ".join(f"0x{digest[i:i+2]}" for i in range(0, 64, 2))
    return ("#pragma once\n#include <array>\n#include <cstdint>\n#include <string_view>\n"
            "// Product-byte constraints only; no registration or store authority.\n"
            "namespace lattice::detail::ordinary_installation::engram_build_stamp {\n"
            "inline constexpr bool available = true;\n"
            'inline constexpr std::string_view product = "engram";\n'
            f'inline constexpr std::string_view source_revision = "{source_revision}";\n'
            f'inline constexpr std::string_view core_revision = "{core_revision}";\n'
            'inline constexpr std::string_view initializer_leaf = "memory";\n'
            f"inline constexpr std::array<std::uint8_t, 32> initializer_sha256{{{literal}}};\n"
            "}\n").encode()


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--final-memory", type=Path, required=True)
    parser.add_argument("--source-revision", required=True)
    parser.add_argument("--core-revision", required=True)
    parser.add_argument("--output-header", type=Path, required=True)
    parser.add_argument("--output-provenance", type=Path, required=True)
    args = parser.parse_args()
    require(args.output_header.resolve() != args.output_provenance.resolve(),
            "header and provenance outputs must differ")
    facts = signed_input_facts(args.final_memory)
    header = header_bytes(args.source_revision, args.core_revision, facts)
    # These exclusive outputs are build artifacts, not an installed catalog.
    # A partial pair is an explicit build failure and cannot be reused.
    with args.output_header.open("xb") as output:
        output.write(header)
    provenance = {"schemaVersion": 1, "product": "engram",
                  "sourceRevision": args.source_revision, "coreRevision": args.core_revision, "initializer": facts,
                  "headerSHA256": hashlib.sha256(header).hexdigest(),
                  "isRegistration": False,
                  "requiresFinalLauncherProvenance": True,
                  "requiresActualRetainedControllerClosure": True}
    with args.output_provenance.open("x", encoding="utf-8") as output:
        output.write(json.dumps(provenance, indent=2, sort_keys=True) + "\n")


if __name__ == "__main__":
    main()
