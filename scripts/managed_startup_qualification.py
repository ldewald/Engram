"""Private source/build binding for hosted managed-startup qualification.

This module never publishes installed state, launches a product, or issues an
ordinary context. It authenticates an explicitly edited build graph and the
closed build inputs before the existing final-byte launcher packaging step.
The hosted command owner and independent collector must also verify the saved
command/graph provenance; decoded receipt fields alone are not qualification.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
import shlex
import stat

from generate_installation_build_stamp import require, stable_metadata

MAXIMUM_METADATA = 16 * 1024 * 1024
MAXIMUM_SOURCE = 64 * 1024 * 1024
MAXIMUM_BUILD_LOG = 256 * 1024 * 1024
MAXIMUM_COMMAND_LINE = 1024 * 1024
PROFILE = "scripts/managed-startup-qualification.json"


def read_regular(path: Path, maximum: int, *, allow_empty: bool = False) -> bytes:
    require(path.is_absolute() and path.resolve(strict=True) == path,
            "private qualification input path must be canonical")
    fd = os.open(path, os.O_RDONLY | os.O_NONBLOCK | os.O_CLOEXEC | os.O_NOFOLLOW)
    try:
        before = os.fstat(fd)
        require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1
                and (0 if allow_empty else 1) <= before.st_size <= maximum,
                "private input is not a bounded regular file")
        require(stable_metadata(path.lstat()) == stable_metadata(before), "private input naming changed")
        result = bytearray()
        while len(result) < before.st_size:
            part = os.read(fd, min(64 * 1024, before.st_size - len(result)))
            require(bool(part), "private input ended early")
            result.extend(part)
        require(not os.read(fd, 1) and stable_metadata(os.fstat(fd)) == stable_metadata(before)
                and stable_metadata(path.lstat()) == stable_metadata(before), "private input changed")
        return bytes(result)
    finally:
        os.close(fd)


def parse_json(raw: bytes):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            require(key not in result, "duplicate qualification metadata key")
            result[key] = value
        return result
    return json.loads(raw, object_pairs_hook=unique)


def url_key(value: str) -> str:
    return value.rstrip("/").removesuffix(".git").lower()


def authenticate_source_bytes(repository: Path, git) -> str:
    """Do not rely on index/status flags as a substitute for actual source."""
    records = git(repository, "ls-tree", "-rz", "HEAD").split("\0")
    digest = hashlib.sha256()
    for record in filter(None, records):
        metadata, name = record.split("\t", 1)
        mode, kind, oid = metadata.split()
        require(kind == "blob" and mode in {"100644", "100755", "120000"}, "unsupported source entry")
        path = repository / name
        raw = os.fsencode(os.readlink(path)) if mode == "120000" else read_regular(path, MAXIMUM_SOURCE, allow_empty=True)
        require(hashlib.sha1(b"blob " + str(len(raw)).encode() + b"\0" + raw).hexdigest() == oid,
                "physical source bytes differ from the exact frozen tree")
        digest.update(record.encode() + b"\0" + hashlib.sha256(raw).digest())
    return digest.hexdigest()


def graph_nodes(graph: dict) -> dict:
    stack, found, visited = [(graph, 0)], {}, 0
    while stack:
        node, depth = stack.pop()
        visited += 1
        require(type(node) is dict and depth <= 64 and visited <= 4096,
                "effective graph exceeds its fixed bounds")
        children = node.get("dependencies", [])
        require(type(children) is list, "effective graph children must be an array")
        if depth:
            identity = node.get("identity", node.get("name", "")).lower()
            require(bool(re.fullmatch(r"[a-z0-9_.-]+", identity)), "invalid effective dependency identity")
            signature = {key: node.get(key) for key in ("path", "url", "version")}
            require(identity not in found or signature == found[identity],
                    "one effective dependency has conflicting paths or versions")
            found[identity] = signature
        stack.extend((child, depth + 1) for child in children)
    return found


def compiler_inputs(raw: bytes, expected: dict[str, str]) -> dict:
    """Observe direct verbose compiler inputs; reject uncertain matching lines."""
    observed = {path: 0 for path in expected}
    for line in raw.splitlines():
        mentioned = [path for path in expected if os.fsencode(path) in line]
        core_markers = (b"/Sources/LatticeCore/src/", b"/Sources/LatticeSwiftCppBridge/src/",
                        b"/Sources/LatticeInstallationChannel/src/")
        if not mentioned and not any(marker in line for marker in core_markers):
            continue
        require(len(line) <= MAXIMUM_COMMAND_LINE, "matching compiler line exceeds the bound")
        try:
            argv = shlex.split(line.decode("utf-8"))
        except (UnicodeDecodeError, ValueError) as error:
            raise ValueError("matching compiler input line is not unambiguous") from error
        if not argv or Path(argv[0]).name not in {"clang", "clang++", "swift-frontend"} or "-c" not in argv:
            continue
        require(not any(a.startswith("@") or a in {";", "&&", "||", "|", ">", ">>", "2>", "2>&1"} for a in argv),
                "matching compiler command uses an unproved response file or shell composition")
        if Path(argv[0]).name in {"clang", "clang++"}:
            require(argv.count("-c") == 1 and argv.index("-c") + 1 < len(argv), "ambiguous native compiler input")
            inputs = [argv[argv.index("-c") + 1]]
            if any(marker.decode() in inputs[0] for marker in core_markers):
                require(inputs[0] in expected, "compiler consumed native source outside the exact private graph")
        else:
            require("-frontend" in argv, "Swift input is not a direct frontend invocation")
            inputs = [arg for arg in argv if arg.endswith(".swift")]
        for path in mentioned:
            if path in inputs:
                observed[path] += 1
    require(all(observed.values()), "actual compiler inputs are missing from the closed verbose build")
    return {path: {"sha256": expected[path], "actualCommandCount": count} for path, count in observed.items()}


def launcher_compiler_inputs(raw: bytes, expected: dict[str, str]) -> dict:
    """Observe all nine direct clang frontend inputs in the private -v link."""
    observed = {path: 0 for path in expected}
    for line in raw.splitlines():
        if not any(os.fsencode(path) in line for path in expected):
            continue
        require(len(line) <= MAXIMUM_COMMAND_LINE, "launcher compiler line exceeds the bound")
        try:
            argv = shlex.split(line.decode("utf-8"))
        except (UnicodeDecodeError, ValueError) as error:
            raise ValueError("launcher compiler input line is not unambiguous") from error
        if not argv or Path(argv[0]).name not in {"clang", "clang++"} or "-cc1" not in argv:
            continue
        require(not any(a.startswith("@") or a in {";", "&&", "||", "|", ">", ">>", "2>", "2>&1"} for a in argv),
                "launcher compiler input uses an unproved response file or shell composition")
        require(argv.count("-cc1") == 1 and "-emit-obj" in argv
                and argv.count("-x") == 1 and argv[argv.index("-x") + 1:] == ["c++", argv[-1]]
                and argv[-1] in expected, "launcher frontend input is not the fixed direct C++ source")
        observed[argv[-1]] += 1
    require(all(observed.values()), "actual launcher compiler inputs are missing")
    return {path: {"sha256": expected[path], "actualCommandCount": count} for path, count in observed.items()}


def validate_private_inputs(root: Path, git) -> tuple[Path, dict]:
    root = root.resolve(strict=True)
    require(root.name == "engram", "private checkout must use the fixed engram child path")
    workspace = root.parent
    allowed = (Path.home() / "localdev").resolve(strict=True)
    require(workspace.is_relative_to(allowed) and workspace != allowed,
            "private qualification workspace must be inside localdev")
    profile_raw = read_regular(root / PROFILE, MAXIMUM_METADATA)
    profile = parse_json(profile_raw)
    require(set(profile) == {"schemaVersion", "scope", "core", "sdk", "publicEngramResolvedSHA256",
                             "sdkResolvedSHA256", "supplementalPins", "runtimeAuthority"}
            and profile["schemaVersion"] == 1 and profile["runtimeAuthority"] is False
            and profile["scope"] == "private-new-origin-primary-mcp-qualification",
            "exact private source profile required")
    original_raw = read_regular(root / "Package.resolved", MAXIMUM_METADATA)
    require(hashlib.sha256(original_raw).hexdigest() == profile["publicEngramResolvedSHA256"],
            "public Engram lock must be restored byte exactly before packaging")
    entries = parse_json(original_raw)["pins"] + profile["supplementalPins"]
    pins = {entry["identity"]: entry for entry in entries}
    require(len(pins) == len(entries) == 48, "complete fixed private dependency set required")
    overrides, physical_sources = {}, {"engram": authenticate_source_bytes(root, git)}
    for identity, key, leaf in (("lattice", "sdk", "lattice"), ("latticecore", "core", "LatticeCore")):
        binding = profile[key]
        require(set(binding) == {"commit", "tree"} and all(type(value) is str and re.fullmatch(r"[0-9a-f]{40}", value)
                for value in binding.values()), "exact private source identity required")
        path = workspace / leaf
        require(path.resolve(strict=True) == path and path.is_dir(), "private source checkout path is not canonical")
        require(git(path, "rev-parse", "HEAD", "HEAD^{tree}").splitlines() == [binding["commit"], binding["tree"]]
                and not git(path, "status", "--porcelain", "--untracked-files=all"), "private source checkout changed")
        overrides[identity] = path
        physical_sources[identity] = authenticate_source_bytes(path, git)
    sdk = overrides["lattice"]
    require(hashlib.sha256(read_regular(sdk / "Package.resolved", MAXIMUM_METADATA)).hexdigest()
            == profile["sdkResolvedSHA256"], "public SDK lock changed")
    sdk_binding = parse_json(read_regular(sdk / "Scripts/development-core.json", MAXIMUM_METADATA))
    require(sdk_binding["coreCommit"] == profile["core"]["commit"]
            and sdk_binding["coreTree"] == profile["core"]["tree"], "SDK private Core pair differs")
    receipts = workspace / "managed-startup-receipts"
    graph_raw = read_regular(receipts / "effective-graph-before.json", MAXIMUM_METADATA)
    graph = parse_json(graph_raw)
    require(graph.get("path") == str(root) and graph.get("identity", graph.get("name", "")).lower() == "engram",
            "effective dependency graph must belong to the exact Engram checkout")
    nodes = graph_nodes(graph)
    state_raw = read_regular(root / ".build/workspace-state.json", MAXIMUM_METADATA)
    dependencies = parse_json(state_raw)["object"]["dependencies"]
    states = {entry["packageRef"]["identity"]: entry for entry in dependencies}
    require(len(states) == len(dependencies) and set(states) == set(nodes) == set(pins),
            "effective graph and workspace must contain exactly the complete private pin set")
    graph_rows = []
    for identity in sorted(pins):
        pin, node, entry = pins[identity], nodes[identity], states[identity]
        path = Path(node["path"])
        require(path.is_absolute() and path.resolve(strict=True) == path, "dependency path is not canonical")
        require(url_key(entry["packageRef"]["location"]) == url_key(pin["location"]), "dependency origin differs")
        if identity in overrides:
            require(path == overrides[identity] and entry["state"]["name"] == "edited",
                    "both exact private dependencies must be explicit edits")
            revision = profile["sdk" if identity == "lattice" else "core"]["commit"]
        else:
            relative = Path(entry["subpath"])
            require(not relative.is_absolute() and ".." not in relative.parts, "dependency subpath escapes checkout root")
            checkout_state = entry["state"]["checkoutState"]
            require(set(checkout_state) <= {"revision", "version", "branch"}
                    and all(checkout_state.get(key) == pin["state"].get(key) for key in ("revision", "version", "branch")),
                    "non-private checkout revision, version or branch changed")
            require(path == root / ".build/checkouts" / relative and entry["state"]["name"] == "sourceControlCheckout"
                    and url_key(node["url"]) == url_key(pin["location"]), "non-private dependency changed")
            revision = pin["state"]["revision"]
        require(git(path, "rev-parse", "HEAD") == revision
                and not git(path, "status", "--porcelain", "--untracked-files=all"), "effective checkout is not exact clean source")
        graph_rows.append({"identity": identity, "revision": revision, "path": str(path)})
    command_raw = read_regular(receipts / "build-memory-command.json", MAXIMUM_METADATA)
    command = parse_json(command_raw)
    require(command["label"] == "build-memory" and command["started"] is True and command["exitCode"] == 0
            and command["success"] is True and command["groupGone"] is True and command["leaderReaped"] is True,
            "actual memory build command must close successfully before packaging")
    require(command["engramCommit"] == git(root, "rev-parse", "HEAD")
            and command["sdkCommit"] == profile["sdk"]["commit"]
            and command["coreCommit"] == profile["core"]["commit"], "closed memory build source binding differs")
    require(command["cwd"] == str(root) and command["argv"] == [
            "swift", "build", "--force-resolved-versions", "-c", "release", "--product", "Engram", "-j", "2", "-v"],
            "closed memory build must be the fixed verbose release product command")
    log = read_regular(workspace / "private/managed-startup-build.log", MAXIMUM_BUILD_LOG)
    require(len(log) == command["logBytes"] and hashlib.sha256(log).hexdigest() == command["logSHA256"],
            "closed memory build log differs from its command receipt")
    core = overrides["latticecore"]
    source_paths = [core / name for name in git(core, "ls-files", "-z").split("\0")
                    if name.endswith(".cpp") and name.startswith(("Sources/LatticeCore/src/",
                       "Sources/LatticeSwiftCppBridge/src/", "Sources/LatticeInstallationChannel/src/"))]
    source_paths += [sdk / p for p in ("Sources/Lattice/Lattice.swift", "Sources/Lattice/OrdinaryInstallationContext.swift",
                    "Sources/LatticeInstallation/LatticeInstallationInitializer.swift",
                    "Sources/LatticeInstallation/LatticeInstallationNormalStartup.swift")]
    source_paths.append(root / "Sources/Engram/main.swift")
    expected = {str(path): hashlib.sha256(read_regular(path, MAXIMUM_METADATA)).hexdigest() for path in source_paths}
    proof = compiler_inputs(log, expected)
    require(not git(root, "status", "--porcelain", "--untracked-files=no"), "strict clean Engram source required")
    return core, {"profileSHA256": hashlib.sha256(profile_raw).hexdigest(), "profileScope": profile["scope"],
                  "sdkCommit": profile["sdk"]["commit"], "sdkTree": profile["sdk"]["tree"],
                  "effectiveGraphSHA256": hashlib.sha256(graph_raw).hexdigest(), "effectiveDependencies": graph_rows,
                  "workspaceStateSHA256": hashlib.sha256(state_raw).hexdigest(),
                  "physicalSourceManifests": physical_sources,
                  "buildCommandSHA256": hashlib.sha256(command_raw).hexdigest(), "buildLogSHA256": command["logSHA256"],
                  "compilerInputs": proof, "runtimeAuthority": False,
                  "independentHostedCommandAndCollectorVerificationRequired": True}
