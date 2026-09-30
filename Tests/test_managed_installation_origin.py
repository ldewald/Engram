"""Hosted real-product qualification; never a stand-in seed child or DB mock.

Not part of ordinary unit-test discovery acceptance. Qualification must provide
an exact already-built/signed CLI artifact and its frozen Engram/Core revisions.
A missing artifact is a skip and does not qualify any installer capability.
This file has not been executed by source preparation.
"""
from __future__ import annotations
import hashlib
import json
import os
from pathlib import Path
import shutil
import signal
import struct
import subprocess
import tempfile
import unittest


def digest(path: Path) -> str:
    value = hashlib.sha256()
    with path.open("rb") as source:
        for block in iter(lambda: source.read(64 * 1024), b""):
            value.update(block)
    return value.hexdigest()


class ActualManagedInstallationOrigin(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        names = ("ENGRAM_INSTALLATION_CLI", "ENGRAM_INSTALLATION_EVIDENCE",
                 "ENGRAM_INSTALLATION_SOURCE", "ENGRAM_INSTALLATION_CORE")
        if any(not os.environ.get(name) for name in names):
            raise unittest.SkipTest("exact real product artifact and source binding unavailable")
        cls.cli = Path(os.environ[names[0]]).resolve(strict=True)
        cls.evidence = Path(os.environ[names[1]]).resolve(strict=True)
        cls.source = os.environ[names[2]]
        cls.core = os.environ[names[3]]
        cls.launcher = cls.cli / "memory-installation-launcher"
        cls.provenance = json.loads((cls.cli / "engram-installation-provenance.json").read_text())
        assert cls.provenance["sourceRevision"] == cls.source
        assert cls.provenance["coreRevision"] == cls.core
        assert cls.provenance["product"] == "engram" and cls.provenance["isRegistration"] is False
        assert digest(cls.launcher) == cls.provenance["launcher"]["sha256"]
        assert digest(cls.cli / "memory") == cls.provenance["initializer"]["sha256"]
        assert digest(cls.cli / "engram-installation.provenance") == cls.provenance["packageRecordSHA256"]
        record = (cls.cli / "engram-installation.provenance").read_bytes()
        assert len(record) == 128 and record[:24] == b"LATPKG1\0" + struct.pack("<QQ", 1, 1)
        assert record[24:44] == bytes.fromhex(cls.source) and record[44:64] == bytes.fromhex(cls.core)
        assert record[64:96].hex() == digest(cls.cli / "memory")
        assert record[96:128].hex() == digest(cls.launcher)

    def setUp(self) -> None:
        # Evidence is retained on success/failure. In particular a timed-out
        # owned process never causes its files to be removed underneath it.
        self.root = Path(tempfile.mkdtemp(prefix=self._testMethodName + "-", dir=self.evidence))
        self.parent = self.root / "installations"
        self.parent.mkdir(mode=0o700)
        self.calls = 0

    def invoke(self, launcher: Path | None = None, leaf: str = "owned") -> tuple[int, bytes, int]:
        self.calls += 1
        stem = self.root / f"command-{self.calls}"
        with stem.with_suffix(".stdout").open("xb") as out, stem.with_suffix(".stderr").open("xb") as err:
            process = subprocess.Popen([str(launcher or self.launcher), "create-engram", str(self.parent), leaf],
                                       stdout=out, stderr=err, start_new_session=True)
            try:
                status = process.wait(timeout=40)  # native operation retains its original30-second budget
            except subprocess.TimeoutExpired:
                # This guardian owns the newly created process group. Failure
                # cleanup is negative evidence, never a successful native join.
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                joined = False
                try:
                    process.wait(timeout=5)
                    joined = True
                except subprocess.TimeoutExpired:
                    pass
                stem.with_suffix(".timeout.json").write_text(json.dumps({"timeout": True,
                    "parentPID": process.pid, "actualParentReaped": joined,
                    "descendantsProvenRetired": False, "qualified": False}) + "\n")
                self.fail("real product deadline expired; failure custody and files retained")
        output_path = stem.with_suffix(".stdout")
        self.assertLessEqual(output_path.stat().st_size, 1024 * 1024)
        return status, output_path.read_bytes(), process.pid

    def changed_package(self) -> Path:
        target = self.root / "package"
        target.mkdir(mode=0o700)
        # Negative pre-child fixtures need no runtime resources. Both binaries
        # are still copies of the exact product; no fixture binary can register.
        for leaf in ("memory", "memory-installation-launcher", "engram-installation.provenance"):
            shutil.copy2(self.cli / leaf, target / leaf)
        return target

    def test_actual_product_registers_exact_closed_origin(self) -> None:
        status, output, parent_pid = self.invoke()
        self.assertEqual(status, 0)
        self.assertEqual(output.splitlines()[-1:], [b"registered-unadopted-origin"])
        directory = self.parent / "owned"
        main = directory / "data/memory.sqlite"
        with main.open("rb") as source:
            self.assertEqual(source.read(16), b"SQLite format 3\0")
        origin = (directory / "origin.v1").read_bytes()
        anchor = (self.parent / "owned.origin").read_bytes()
        self.assertEqual(len(origin), 256)
        self.assertEqual(len(anchor), 320)
        self.assertEqual(origin[:16], b"LATORG1\0" + struct.pack("<Q", 1))
        self.assertEqual(anchor[:16], b"LATREG1\0" + struct.pack("<Q", 1))
        origin_stat = (directory / "origin.v1").stat()
        self.assertEqual(struct.unpack_from("<QQ", anchor, 16), (origin_stat.st_dev, origin_stat.st_ino))
        self.assertEqual(anchor[32:64], hashlib.sha256(origin).digest())
        self.assertEqual(anchor[64:], origin)
        catalog = (directory / "catalog.v1").read_bytes()
        self.assertEqual(origin[64:96], hashlib.sha256(catalog).digest())
        self.assertEqual(origin[96:128].hex(), self.provenance["packageRecordSHA256"])
        self.assertEqual(origin[128:168].decode(), self.source)
        self.assertEqual(origin[168:208].decode(), self.core)
        child_pid, recorded_parent = struct.unpack_from("<QQ", origin, 208)
        self.assertGreater(child_pid, 0)
        self.assertEqual(recorded_parent, parent_pid)
        self.assertEqual(struct.unpack_from("<Q", origin, 240)[0], 0)
        admission = (directory / "control/admission.v1").read_bytes()
        self.assertEqual(len(admission), 256)
        self.assertEqual(admission[24], 1)  # unadopted, never an app-open grant
        self.assertEqual(admission[32:48], origin[16:32])
        self.assertEqual(admission[80:96], bytes(16))
        self.assertEqual(struct.unpack_from("<QQ", admission, 96), (main.stat().st_dev, main.stat().st_ino))
        self.assertEqual(hashlib.sha256(admission[:224]).digest(), admission[224:])
        gate = (directory / "launch.v1").read_bytes()
        self.assertEqual(struct.unpack_from("<Q", gate, 24)[0], 3)  # durably terminal, never reopened
        # A second actual invocation cannot relearn/repair this registered origin.
        retained = {p: (p.stat().st_ino, digest(p)) for p in
                    (directory / "origin.v1", self.parent / "owned.origin", directory / "catalog.v1",
                     directory / "control/admission.v1", directory / "launch.v1", main)}
        status, _, _ = self.invoke()
        self.assertNotEqual(status, 0)
        self.assertEqual(retained, {p: (p.stat().st_ino, digest(p)) for p in retained})

    def test_unstamped_core_launcher_cannot_register(self) -> None:
        value = os.environ.get("ENGRAM_UNSTAMPED_INSTALLER")
        if not value:
            self.skipTest("default Core executable not supplied; unstamped refusal remains unqualified")
        launcher = Path(value).resolve(strict=True)
        self.assertNotEqual(digest(launcher), digest(self.launcher))
        self.assertNotEqual(self.invoke(launcher)[0], 0)
        self.assertEqual(list(self.parent.iterdir()), [])

    def test_actual_package_rejects_changed_memory_before_namespace_creation(self) -> None:
        package = self.changed_package()
        with (package / "memory").open("ab") as output:
            output.write(b"changed-after-signing")
        self.assertNotEqual(self.invoke(package / "memory-installation-launcher")[0], 0)
        self.assertEqual(list(self.parent.iterdir()), [])

    def test_actual_package_rejects_current_provenance_revision_replacement(self) -> None:
        package = self.changed_package()
        record = bytearray((package / "engram-installation.provenance").read_bytes())
        record[24] ^= 1
        (package / "engram-installation.provenance").write_bytes(record)
        self.assertNotEqual(self.invoke(package / "memory-installation-launcher")[0], 0)
        self.assertEqual(list(self.parent.iterdir()), [])

    def test_actual_package_rejects_initializer_symlink_before_child(self) -> None:
        package = self.changed_package()
        (package / "memory").unlink()
        (package / "memory").symlink_to(self.cli / "memory")
        self.assertNotEqual(self.invoke(package / "memory-installation-launcher")[0], 0)
        self.assertEqual(list(self.parent.iterdir()), [])

    def test_existing_namespace_never_becomes_registration(self) -> None:
        directory = self.parent / "owned"
        directory.mkdir(mode=0o700)
        marker = directory / "legacy-marker"
        marker.write_bytes(b"existing ordinary namespace must remain untouched")
        before = (marker.stat().st_ino, digest(marker))
        self.assertNotEqual(self.invoke()[0], 0)
        self.assertEqual((marker.stat().st_ino, digest(marker)), before)
        self.assertEqual([p.name for p in directory.iterdir()], ["legacy-marker"])
        self.assertFalse((self.parent / "owned.origin").exists())

    def test_external_anchor_collision_preserves_original_failure_and_bytes(self) -> None:
        existing = self.parent / "owned.origin"
        existing.write_bytes(b"preexisting separate registration must not be replaced")
        before = (existing.stat().st_ino, digest(existing))
        status, output, _ = self.invoke()
        self.assertNotEqual(status, 0)
        self.assertNotIn(b"registered-unadopted-origin", output.splitlines())
        self.assertEqual((existing.stat().st_ino, digest(existing)), before)
        # Even if all child work completed, failed anchor publication cannot
        # qualify registration or clear the actual closed launch fence.
        gate = self.parent / "owned/launch.v1"
        self.assertTrue(gate.exists())
        self.assertEqual(struct.unpack_from("<Q", gate.read_bytes(), 24)[0], 3)


if __name__ == "__main__":
    unittest.main()
