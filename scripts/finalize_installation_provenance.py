#!/usr/bin/env python3
"""Record both final signed sibling executables; never grant store authority."""
from __future__ import annotations
import argparse
import hashlib
import json
from pathlib import Path
import re
import struct
from generate_installation_build_stamp import signed_input_facts, require


def encode_provenance(source_revision: str, core_revision: str,
                      initializer: dict[str, object], launcher: dict[str, object]) -> bytes:
    require(bool(re.fullmatch(r"[0-9a-f]{40}", source_revision))
            and bool(re.fullmatch(r"[0-9a-f]{40}", core_revision)), "exact frozen revisions required")
    require(initializer["leaf"] == "memory" and launcher["leaf"] == "memory-installation-launcher",
            "fixed sibling names required")
    for facts in (initializer, launcher):
        require(isinstance(facts["sha256"], str) and bool(re.fullmatch(r"[0-9a-f]{64}", facts["sha256"])),
                "exact final-byte digest required")
    result = (b"LATPKG1\0" + struct.pack("<QQ", 1, 1) + bytes.fromhex(source_revision)
              + bytes.fromhex(core_revision) + bytes.fromhex(initializer["sha256"])
              + bytes.fromhex(launcher["sha256"]))
    require(len(result) == 128, "fixed package record size required")
    return result


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--final-cli-directory", type=Path, required=True)
    parser.add_argument("--build-inputs", type=Path, required=True)
    args = parser.parse_args()
    cli = args.final_cli_directory
    inputs = json.loads(args.build_inputs.read_text())
    require(inputs["schemaVersion"] == 1 and inputs["product"] == "engram"
            and inputs["isRegistration"] is False, "build input provenance required")
    memory = signed_input_facts(cli / "memory")
    require(memory == inputs["initializer"], "memory was modified or signed again after stamping")
    launcher = signed_input_facts(cli / "memory-installation-launcher", "memory-installation-launcher")
    record = encode_provenance(inputs["sourceRevision"], inputs["coreRevision"], memory, launcher)
    with (cli / "engram-installation.provenance").open("xb") as target:
        target.write(record)
    receipt = {**inputs, "launcher": launcher, "packageRecordSHA256": hashlib.sha256(record).hexdigest(),
               "finalByteObservationOnly": True, "signatureValidityInferred": False,
               "requiresActualRetainedControllerClosure": True}
    with (cli / "engram-installation-provenance.json").open("x", encoding="utf-8") as target:
        target.write(json.dumps(receipt, indent=2, sort_keys=True) + "\n")
    require(signed_input_facts(cli / "memory") == memory
            and signed_input_facts(cli / "memory-installation-launcher", "memory-installation-launcher") == launcher,
            "final executable changed during provenance publication")


if __name__ == "__main__":
    main()
