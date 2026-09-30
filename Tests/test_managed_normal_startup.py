"""Hosted actual-product normal MCP qualification; source preparation never runs it.

Requires the same exact signed artifact/source binding as the origin suite.
Timeouts, missing artifacts and cleanup uncertainty never qualify startup.
These tests use public MCP operations against the actual packaged memory binary.
They do not manufacture a native context, receipt, journal success or child exit.
"""
from __future__ import annotations
import hashlib
import fcntl
import json
import os
import pwd
from pathlib import Path
import selectors
import signal
import struct
import subprocess
import time
import unittest
import test_managed_installation_origin as origin


class ActualManagedNormalStartup(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        origin.ActualManagedInstallationOrigin.setUpClass.__func__(cls)
        account_home = Path(pwd.getpwuid(os.geteuid()).pw_dir)
        if cls.cli != account_home / ".claude/bin" or not (account_home / ".claude/installation/managed-package.v1").is_file():
            raise unittest.SkipTest("actual authorized fixed-root installation unavailable; normal startup remains unqualified")

    def setUp(self) -> None:
        origin.ActualManagedInstallationOrigin.setUp(self)

    def start(self, *, direct: bool = False, leaf: str = "owned"):
        command = ([str(self.cli / "memory"), "--lattice-managed-mcp-v1"] if direct else
                   [str(self.launcher), "create-and-run-engram-mcp", str(self.parent), leaf])
        self.stderr = (self.root / "normal.stderr").open("xb")
        self.raw = (self.root / "normal.stdout").open("xb")
        self.transcript = (self.root / "mcp-transcript.jsonl").open("x")
        environment = dict(os.environ)
        # This inherited path cannot become authority or cause a legacy open.
        self.legacy = self.root / "must-not-open.sqlite"
        environment["CLAUDE_MEMORY_DB"] = str(self.legacy)
        environment["CLAUDE_SESSION_ID"] = "managed-normal-qualification"
        self.process = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            stderr=self.stderr, start_new_session=True, env=environment, close_fds=True)
        self.selector = selectors.DefaultSelector()
        self.selector.register(self.process.stdout, selectors.EVENT_READ)
        os.set_blocking(self.process.stdout.fileno(), False)
        self.buffer = bytearray()
        self.total = 0
        self.next_id = 1
        self.finished = False
        self.addCleanup(self.cleanup)

    def send(self, method: str, params=None, *, notification=False):
        request = {"jsonrpc": "2.0", "method": method}
        if params is not None:
            request["params"] = params
        number = None
        if not notification:
            number = self.next_id
            self.next_id += 1
            request["id"] = number
        self.transcript.write(json.dumps({"direction": "request", "message": request}) + "\n")
        self.transcript.flush()
        self.process.stdin.write(json.dumps(request).encode() + b"\n")
        self.process.stdin.flush()
        return number

    def response(self, number: int, end: float):
        while time.monotonic() < end:
            while b"\n" in self.buffer:
                line, _, tail = self.buffer.partition(b"\n")
                self.buffer[:] = tail
                if not line:
                    continue
                # Non-JSON stdout or a different response is preserved and
                # rejected, rather than skipped as a successful MCP reply.
                message = json.loads(line)
                self.transcript.write(json.dumps({"direction": "response", "message": message}) + "\n")
                self.transcript.flush()
                if "id" not in message:
                    continue
                self.assertEqual(message["id"], number)
                self.assertNotIn("error", message)
                self.assertLess(time.monotonic(), end, "actual MCP reply was not observed by its fixed deadline")
                return message["result"]
            remaining = end - time.monotonic()
            if remaining <= 0:
                break
            events = self.selector.select(remaining)
            if not events:
                continue
            chunk = os.read(self.process.stdout.fileno(), 65536)
            self.assertTrue(chunk, "actual MCP closed before its response")
            self.raw.write(chunk)
            self.raw.flush()
            self.total += len(chunk)
            self.assertLessEqual(self.total, 1024 * 1024)
            self.buffer.extend(chunk)
        self.fail("actual MCP observation exceeded its original fixed deadline")

    def call(self, name: str, arguments: dict):
        number = self.send("tools/call", {"name": name, "arguments": arguments})
        result = self.response(number, time.monotonic() + 10)
        self.assertFalse(result.get("isError", False), result)
        return "\n".join(item.get("text", "") for item in result.get("content", []) if item.get("type") == "text")

    def invoke_refused(self, *, launcher: Path | None = None):
        """An actual new issuer must fail before launching any managed role."""
        self.calls += 1
        stem = self.root / f"normal-refusal-{self.calls}"
        with stem.with_suffix(".stdout").open("xb") as out, stem.with_suffix(".stderr").open("xb") as err:
            process = subprocess.Popen([str(launcher or self.launcher), "create-and-run-engram-mcp",
                str(self.parent), "owned"], stdin=subprocess.DEVNULL, stdout=out, stderr=err,
                start_new_session=True, close_fds=True)
            try:
                status = process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                # The timeout remains the assertion failure. This separate
                # cleanup only observes the directly owned process and never
                # qualifies any descendant or repairs an unknown origin.
                if process.poll() is None:
                    process.kill()
                try:
                    process.wait(timeout=5)
                    reaped = True
                except subprocess.TimeoutExpired:
                    reaped = False
                stem.with_suffix(".timeout.json").write_text(json.dumps({"originalTimeout": True,
                    "launcherPID": process.pid, "launcherReaped": reaped,
                    "normalChildCompletionProven": False, "qualified": False}) + "\n")
                self.fail("actual normal issuer refusal exceeded its fixed deadline")
        self.assertEqual(status, 74)
        self.assertEqual(stem.with_suffix(".stdout").read_bytes(), b"")

    def finish(self):
        self.process.stdin.close()
        # Separate normal shutdown/reap observation, not added to any prior
        # response deadline and never used to forgive a timed-out assertion.
        status = self.process.wait(timeout=10)
        self.assertEqual(status, 0)
        self.finished = True
        directory = self.parent / "owned"
        gate = (directory / "normal-runtime/launch.v1").read_bytes()
        self.assertEqual(struct.unpack_from("<Q", gate, 24)[0], 3)
        # Actual registry terminal records contain the exact owned child and
        # raw wait status; marker output alone is insufficient.
        self.assertEqual(len(gate), 208)
        self.assertEqual(gate[:16], b"LATCOH1\0" + struct.pack("<Q", 1))
        self.assertEqual(hashlib.sha256(gate[:-32]).digest(), gate[-32:])
        self.assertEqual(struct.unpack_from("<Q", gate, 80)[0], self.process.pid)
        self.assertEqual(struct.unpack_from("<Q", gate, 112)[0], 0)  # no newly owned data namespaces
        self.assertEqual(struct.unpack_from("<Q", gate, 120)[0], 1)  # one actual normal child
        self.assertEqual(struct.unpack_from("<Q", gate, 128)[0], 2)  # actual terminal, never pending
        child_pid, parent_pid, birth_major, _ = struct.unpack_from("<QQQQ", gate, 136)
        self.assertGreater(child_pid, 0)
        self.assertGreater(birth_major, 0)
        self.assertEqual(parent_pid, self.process.pid)
        self.assertEqual(struct.unpack_from("<Q", gate, 168)[0], 0)  # actual wait status
        self.assertFalse(self.legacy.exists())
        (self.root / "normal-completion.json").write_text(json.dumps({"launcherPID": self.process.pid,
            "launcherReaped": True, "launcherExit": status, "durableNormalGateSHA256": hashlib.sha256(gate).hexdigest(),
            "mcpRepliesObserved": self.next_id - 1, "qualifiedByMarkersAlone": False}) + "\n")

    def cleanup(self):
        if getattr(self, "finished", False):
            self.selector.close()
            self.process.stdout.close()
            self.stderr.close()
            self.raw.close()
            self.transcript.close()
            return
        process = getattr(self, "process", None)
        if process is None:
            return
        if process.stdin and not process.stdin.closed:
            process.stdin.close()
        # Popen is the exclusive reaper for this actual child. A terminal poll
        # reaps it and forbids subsequent signaling. No remembered group is
        # signaled after leader custody has been released.
        status = process.poll()
        signaled = False
        if status is None:
            process.send_signal(signal.SIGTERM)
            signaled = True
        try:
            status = process.wait(timeout=5)
            joined = True
        except subprocess.TimeoutExpired:
            process.kill()
            try:
                status = process.wait(timeout=5)
                joined = True
            except subprocess.TimeoutExpired:
                status = None
                joined = False
        (self.root / "failure-cleanup.json").write_text(json.dumps({"launcherPID": process.pid,
            "signaledWhileOwned": signaled, "actualLauncherReaped": joined, "launcherExit": status,
            "normalChildCompletionProven": False, "qualified": False}) + "\n")
        self.selector.close()
        process.stdout.close()
        self.stderr.close()
        self.raw.close()
        self.transcript.close()

    def test_actual_managed_mcp_keeps_original_schema_and_committed_checkpoint_behavior(self):
        self.assertEqual(list(self.parent.iterdir()), [])
        self.assertFalse((self.parent / "owned/data/sync").exists())
        self.start()
        request = self.send("initialize", {"protocolVersion": "2025-03-26", "capabilities": {},
            "clientInfo": {"name": "managed-normal-qualification", "version": "1"}})
        # Native seed and context handshakes each retain their original30-second
        # limit. This outer60-second startup guardian does not alter either.
        initialized = self.response(request, time.monotonic() + 60)
        self.assertEqual(initialized["serverInfo"]["name"], "memory")
        self.send("notifications/initialized", notification=True)
        title = "actual managed ordinary checkpoint"
        created = self.call("checkpoint", {"title": title, "project": "managed-normal", "plan": "retain native context"})
        self.assertIn(title, created)
        observed = self.call("list_tasks", {"project": "managed-normal", "limit": 10})
        self.assertIn(title, observed)
        directory = self.parent / "owned"
        admission = (directory / "control/admission.v1").read_bytes()
        self.assertEqual(admission[8], 2)
        self.assertEqual(admission[24], 3)
        self.assertNotEqual(admission[176:192], bytes(16))
        self.assertEqual(hashlib.sha256(admission[:224]).digest(), admission[224:])
        generation = os.open(directory / "control/generation.lock", os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
        self.addCleanup(os.close, generation)
        generation_stat = os.fstat(generation)
        self.assertEqual((generation_stat.st_dev, generation_stat.st_ino), struct.unpack_from("<QQ", admission, 160))
        with self.assertRaises(BlockingIOError):
            fcntl.flock(generation, fcntl.LOCK_EX | fcntl.LOCK_NB)
        original_gate = (directory / "launch.v1").read_bytes()
        self.assertEqual(struct.unpack_from("<Q", original_gate, 24)[0], 3)
        self.finish()
        retired = (directory / "control/admission.v1").read_bytes()
        self.assertEqual(retired[24], 2)
        self.assertEqual(retired[176:192], admission[176:192])
        self.assertEqual(retired[32:80], admission[32:80])
        self.assertEqual(retired[96:176], admission[96:176])
        # Real process exit and exact child reaping must release its actual
        # generation hold. This is not permission to adopt or reopen the store.
        fcntl.flock(generation, fcntl.LOCK_EX | fcntl.LOCK_NB)
        fcntl.flock(generation, fcntl.LOCK_UN)
        # A successful past launch is historical evidence, never authority for
        # a new controller to resume the retired generation.
        retained = {path: (path.stat().st_ino, origin.digest(path)) for path in (
            directory / "data/memory.sqlite", directory / "control/admission.v1",
            directory / "origin.v1", directory / "catalog.v1", directory / "launch.v1",
            directory / "normal-runtime/launch.v1", self.parent / "owned.origin")}
        self.invoke_refused()
        self.assertEqual(retained, {path: (path.stat().st_ino, origin.digest(path)) for path in retained})

    def test_direct_normal_flag_and_environment_cannot_issue_context_or_open_store(self):
        self.start(direct=True)
        self.process.stdin.close()
        status = self.process.wait(timeout=10)
        self.assertEqual(status, 74)
        self.assertFalse(self.legacy.exists())
        self.assertEqual(list(self.parent.iterdir()), [])
        self.finished = True

    def test_separate_restarted_issuer_cannot_admit_a_registered_unadopted_origin(self):
        status, output, _ = origin.ActualManagedInstallationOrigin.invoke(self)
        self.assertEqual(status, 0)
        self.assertEqual(output.splitlines()[-1:], [b"registered-unadopted-origin"])
        directory = self.parent / "owned"
        record = (directory / "control/admission.v1").read_bytes()
        self.assertEqual(record[8], 1)
        self.assertEqual(record[24], 1)
        retained = {path: (path.stat().st_ino, origin.digest(path)) for path in (
            directory / "data/memory.sqlite", directory / "control/admission.v1",
            directory / "origin.v1", directory / "catalog.v1", directory / "launch.v1", self.parent / "owned.origin")}
        self.invoke_refused()
        self.assertEqual(retained, {path: (path.stat().st_ino, origin.digest(path)) for path in retained})
        self.assertFalse((directory / "normal-runtime").exists())

    def test_missing_installed_provenance_cannot_create_a_normal_origin(self):
        package = origin.ActualManagedInstallationOrigin.changed_package(self)
        (package / "engram-installation.provenance").unlink()
        self.invoke_refused(launcher=package / "memory-installation-launcher")
        self.assertEqual(list(self.parent.iterdir()), [])

    def test_stale_installed_provenance_cannot_create_a_normal_origin(self):
        package = origin.ActualManagedInstallationOrigin.changed_package(self)
        record = bytearray((package / "engram-installation.provenance").read_bytes())
        record[24] ^= 1
        (package / "engram-installation.provenance").write_bytes(record)
        self.invoke_refused(launcher=package / "memory-installation-launcher")
        self.assertEqual(list(self.parent.iterdir()), [])

    def test_self_consistent_copied_package_cannot_enroll_itself(self):
        package = origin.ActualManagedInstallationOrigin.changed_package(self)
        # All exact signed bytes and their existing self-consistent package
        # record are present. The independent installed-root identity differs.
        self.assertEqual(origin.digest(package / "memory"), self.provenance["initializer"]["sha256"])
        self.assertEqual(origin.digest(package / "memory-installation-launcher"), self.provenance["launcher"]["sha256"])
        self.invoke_refused(launcher=package / "memory-installation-launcher")
        self.assertEqual(list(self.parent.iterdir()), [])


if __name__ == "__main__":
    unittest.main()
