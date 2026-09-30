"""Metadata/verbose-input regressions; never build, launch or enroll a product."""
import hashlib
from pathlib import Path
import shlex
import tempfile
import unittest

from managed_startup_qualification import (compiler_inputs, graph_nodes,
                                           launcher_compiler_inputs, parse_json,
                                           read_regular)


class PrivateManagedQualificationTests(unittest.TestCase):
    def test_duplicate_metadata_cannot_replace_the_first_binding(self):
        with self.assertRaises(ValueError):
            parse_json(b'{"core":{"commit":"first","commit":"replacement"}}')

    def test_empty_source_is_observable_but_empty_metadata_is_refused(self):
        root = Path.home() / "localdev"
        root.mkdir(exist_ok=True)
        with tempfile.TemporaryDirectory(prefix="managed-source-test-", dir=root) as directory:
            source = Path(directory) / "empty"
            source.touch()
            self.assertEqual(read_regular(source, 1, allow_empty=True), b"")
            with self.assertRaises(ValueError):
                read_regular(source, 1)

    def test_symlink_input_is_refused_before_regular_file_read(self):
        root = Path.home() / "localdev"
        root.mkdir(exist_ok=True)
        with tempfile.TemporaryDirectory(prefix="managed-source-test-", dir=root) as directory:
            source, alias = Path(directory) / "source", Path(directory) / "alias"
            source.write_bytes(b"bounded")
            alias.symlink_to(source)
            with self.assertRaises(ValueError):
                read_regular(alias, 8)

    def test_conflicting_repeated_graph_identity_is_refused(self):
        first = {"identity": "lattice", "path": "/fixed", "url": "https://example.invalid/lattice", "version": "unspecified"}
        duplicate = dict(first)
        self.assertEqual(set(graph_nodes({"dependencies": [first, duplicate]})), {"lattice"})
        duplicate["path"] = "/replacement"
        with self.assertRaises(ValueError):
            graph_nodes({"dependencies": [first, duplicate]})

    def test_native_memory_input_requires_actual_compile_not_driver_echo(self):
        source = "/fixed/Sources/LatticeCore/src/lattice.cpp"
        expected = {source: hashlib.sha256(b"source").hexdigest()}
        with self.assertRaises(ValueError):
            compiler_inputs(f"echo {source}\n".encode(), expected)
        proof = compiler_inputs(shlex.join(["/usr/bin/clang", "-c", source, "-o", "/fixed/object.o"]).encode(), expected)
        self.assertEqual(proof[source], {"sha256": expected[source], "actualCommandCount": 1})

    def test_native_memory_input_cannot_be_substituted_by_another_graph(self):
        source = "/fixed/Sources/LatticeCore/src/lattice.cpp"
        other = "/other/Sources/LatticeCore/src/lattice.cpp"
        with self.assertRaises(ValueError):
            compiler_inputs(f"/usr/bin/clang -c {other} -o /fixed/object.o\n".encode(), {source: "frozen"})

    def test_response_file_does_not_prove_memory_compiler_inputs(self):
        source = "/fixed/Sources/LatticeCore/src/lattice.cpp"
        with self.assertRaises(ValueError):
            compiler_inputs(f"/usr/bin/clang @hidden -c {source}\n".encode(), {source: "frozen"})

    def test_all_nine_actual_launcher_frontends_are_required(self):
        expected = {f"/fixed/Tools/LatticeInstallationLauncher/unit{index}.cpp": f"digest{index}" for index in range(9)}
        lines = [shlex.join(["/usr/bin/clang", "-cc1", "-emit-obj", "-o", f"/fixed/unit{index}.o", "-x", "c++", source])
                 for index, source in enumerate(expected)]
        proof = launcher_compiler_inputs("\n".join(lines).encode(), expected)
        self.assertEqual(proof, {source: {"sha256": digest, "actualCommandCount": 1} for source, digest in expected.items()})
        with self.assertRaises(ValueError):
            launcher_compiler_inputs("\n".join(lines[:-1]).encode(), expected)

    def test_launcher_driver_echo_and_response_file_do_not_prove_frontend_execution(self):
        source = "/fixed/Tools/LatticeInstallationLauncher/main.cpp"
        expected = {source: "frozen"}
        for line in (f"/usr/bin/clang++ -v {source}",
                     f"/usr/bin/clang -cc1 -emit-obj @hidden -x c++ {source}"):
            with self.subTest(line=line), self.assertRaises(ValueError):
                launcher_compiler_inputs(line.encode(), expected)


if __name__ == "__main__":
    unittest.main()
