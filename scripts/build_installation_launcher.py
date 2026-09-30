#!/usr/bin/env python3
"""Build the fixed native Engram launcher after memory's final signing.

This packaging tool runs a compiler when invoked by the release pipeline. It
never enrolls an installation or opens a store. Exact Package.resolved source
and the final memory bytes are build inputs, not runtime authority.
"""
from __future__ import annotations
import argparse
import json
from pathlib import Path
import re
import subprocess
from generate_installation_build_stamp import header_bytes, signed_input_facts, require

SOURCES = ("main.cpp", "owned_launch.cpp", "installation_manifest.cpp",
           "installation_cohort.cpp", "installation_files.cpp", "installation_seed.cpp",
           "store_admission.cpp", "engram_product_installer.cpp")


def git(root: Path, *arguments: str) -> str:
    return subprocess.run(["git", "-C", str(root), *arguments], check=True,
                          capture_output=True, text=True, timeout=60).stdout.strip()


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--final-cli-directory", type=Path, required=True)
    parser.add_argument("--build-directory", type=Path, required=True)
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    source_revision = git(root, "rev-parse", "HEAD")
    require(bool(re.fullmatch(r"[0-9a-f]{40}", source_revision)), "exact source revision required")
    require(not git(root, "status", "--porcelain", "--untracked-files=no"), "Engram source must be clean")
    resolved_bytes = (root / "Package.resolved").read_bytes()
    pins = [pin for pin in json.loads(resolved_bytes)["pins"] if pin["identity"] == "latticecore"]
    require(len(pins) == 1 and pins[0]["location"] == "https://github.com/jsflax/LatticeCore.git",
            "the fixed resolved Core dependency is required")
    core_revision = pins[0]["state"]["revision"]
    candidates = [p for p in (root / ".build/checkouts").iterdir() if p.name.lower() == "latticecore"]
    require(len(candidates) == 1, "exact resolved Core checkout is required")
    core = candidates[0]
    require(git(core, "rev-parse", "HEAD") == core_revision
            and not git(core, "status", "--porcelain"), "Core checkout differs from its resolved revision")
    core_tree = git(core, "rev-parse", "HEAD^{tree}")
    source_dir = core / "Tools/LatticeInstallationLauncher"
    require(all((source_dir / name).is_file() for name in SOURCES), "resolved Core lacks the reviewed installer graph")
    cli = args.final_cli_directory.resolve()
    require(cli.is_dir(), "final CLI directory must exist")
    output = cli / "memory-installation-launcher"
    require(not output.exists() and not output.is_symlink(), "launcher output must be new")
    # Exclusive build directory prevents accidentally reusing a stamp generated
    # before a later signing operation. Any partial build remains a failure.
    args.build_directory.mkdir(parents=True, exist_ok=False)
    build = args.build_directory.resolve()
    facts = signed_input_facts(cli / "memory")
    header = header_bytes(source_revision, core_revision, facts)
    stamp = build / "engram_build_stamp.generated.hpp"
    stamp.write_bytes(header)
    provenance = {"schemaVersion": 1, "product": "engram", "sourceRevision": source_revision,
                  "coreRevision": core_revision, "coreTree": core_tree, "initializer": facts,
                  "isRegistration": False, "requiresFinalLauncherProvenance": True}
    (build / "build-inputs.json").write_text(json.dumps(provenance, indent=2) + "\n")
    # A direct eight-TU native link graph: no Swift manifest, app initialization,
    # LatticeCore library, SQLite or process-global application service.
    command = ["xcrun", "--sdk", "macosx", "clang++", "-std=c++20", "-O2", "-pthread",
               f'-DLATTICE_ENGRAM_BUILD_STAMP_HEADER="{stamp}"',
               *[str(source_dir / name) for name in SOURCES], "-o", str(output)]
    subprocess.run(command, check=True, timeout=600)
    require(signed_input_facts(cli / "memory") == facts, "memory changed during launcher build")
    require((root / "Package.resolved").read_bytes() == resolved_bytes
            and git(core, "rev-parse", "HEAD") == core_revision
            and not git(core, "status", "--porcelain"), "source binding changed during launcher build")
    # Signing the output and writing final provenance are later explicit steps.


if __name__ == "__main__":
    main()
