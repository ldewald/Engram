#!/bin/bash
set -e

INSTALL_DIR="$HOME/.claude/bin"
REPO="jsflax/Engram"

# Explicit new-origin operation. It runs before cleanup, downloads, MCP
# registration, daemons or any ordinary store open. Existing/partial namespaces
# and unstamped packages are refused by the retained native controller. This
# does not migrate a legacy store or claim custody of GUI/host processes.
if [ "${1:-}" = "--create-managed-origin" ]; then
    if [ "$#" -ne 3 ] || [ ! -x "$INSTALL_DIR/memory-installation-launcher" ] || \
       [ ! -f "$INSTALL_DIR/engram-installation.provenance" ]; then
        echo "Managed origin unavailable: exact installed launcher and parent/name are required." >&2
        exit 64
    fi
    exec "$INSTALL_DIR/memory-installation-launcher" create-engram "$2" "$3"
fi

# One supported normal path: a new primary-only origin and its live MCP child.
# The native controller independently checks the OS-account installation
# authority before creating anything; this argument grants no authority.
if [ "${1:-}" = "--create-and-run-managed-mcp" ]; then
    if [ "$#" -ne 3 ]; then
        echo "Managed MCP startup requires a new parent/name." >&2
        exit 64
    fi
    exec "$INSTALL_DIR/memory-installation-launcher" create-and-run-engram-mcp "$2" "$3"
fi

EXPECTED_INSTALL_DIR="$(python3 -c 'import os,pwd; print(pwd.getpwuid(os.geteuid()).pw_dir + "/.claude/bin")')"
if [ "$INSTALL_DIR" != "$EXPECTED_INSTALL_DIR" ]; then
    echo "Installation requires the OS account home; an overridden HOME cannot publish managed authority." >&2
    exit 64
fi

echo "Engram Installer"
echo "================"
echo ""
echo "Tip: For a GUI with automatic updates, download Engram.dmg from:"
echo "  https://github.com/$REPO/releases/latest"
echo ""

# Clean old install
rm -f "$INSTALL_DIR/memory"
rm -f "$INSTALL_DIR/memory-hooks"
rm -f "$INSTALL_DIR/memory-sync"
rm -rf "$INSTALL_DIR/Engram_EngramKit.bundle"
rm -rf "$INSTALL_DIR/swift-transformers_Hub.bundle"
rm -rf "$INSTALL_DIR/SwiftLM_SwiftLM.bundle"
mkdir -p "$INSTALL_DIR"

if [ "$1" = "--from-source" ]; then
    SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
    REPO_DIR="$(dirname "$SCRIPT_DIR")"
    echo "Building from source: $REPO_DIR"
    cd "$REPO_DIR" && swift build -c release
    cp .build/release/Engram "$INSTALL_DIR/memory"
    cp .build/release/EngramHooks "$INSTALL_DIR/memory-hooks"
    cp .build/release/EngramDaemon "$INSTALL_DIR/memory-sync"
    cp -R .build/release/Engram_EngramKit.bundle "$INSTALL_DIR/"
    cp -R .build/release/swift-transformers_Hub.bundle "$INSTALL_DIR/"
    cp -R .build/release/SwiftLM_SwiftLM.bundle "$INSTALL_DIR/"
    bash "$REPO_DIR/scripts/package_codex_learner.sh" "$INSTALL_DIR/codex"
    # Re-sign binaries — linker-signed ad-hoc binaries can be rejected by macOS Taskgated
    codesign --force --sign - "$INSTALL_DIR/memory"
    codesign --force --sign - "$INSTALL_DIR/memory-hooks"
    codesign --force --sign - "$INSTALL_DIR/memory-sync"
    # Product-byte stamp follows memory's last signing operation. This does
    # not enroll existing stores or authorize normal managed application opens.
    rm -f "$INSTALL_DIR/memory-installation-launcher" "$INSTALL_DIR/engram-installation.provenance" \
        "$INSTALL_DIR/engram-installation-provenance.json"
    INSTALLER_BUILD="$REPO_DIR/.build/installation-launcher-$(date +%s)-$$"
    python3 -B "$REPO_DIR/scripts/build_installation_launcher.py" \
        --final-cli-directory "$INSTALL_DIR" --build-directory "$INSTALLER_BUILD"
    codesign --force --sign - "$INSTALL_DIR/memory-installation-launcher"
    python3 -B "$REPO_DIR/scripts/finalize_installation_provenance.py" \
        --final-cli-directory "$INSTALL_DIR" --build-inputs "$INSTALLER_BUILD/build-inputs.json"
else
    echo "Downloading latest release..."
    DOWNLOAD_URL=$(curl -sL "https://api.github.com/repos/$REPO/releases/latest" \
        | grep '"browser_download_url"' \
        | grep -F '/engram-macos-arm64.tar.gz"' \
        | head -1 \
        | cut -d'"' -f4)

    if [ -z "$DOWNLOAD_URL" ]; then
        echo "Error: No release found. Use --from-source to build locally."
        exit 1
    fi

    echo "From: $DOWNLOAD_URL"
    curl -sL "$DOWNLOAD_URL" | tar xz -C "$INSTALL_DIR"
    # Preserve release signatures: the sync daemon needs its Developer ID
    # identity for keychain access when launched without a visible prompt.
fi

# Publish outside the package only as part of this authorized installation.
# Normal launcher/receiver paths never invoke the publisher or repair state.
# Keep the exact publisher in the trusted installer stream: curl-to-bash
# has no adjacent checkout helper and must not load code from the offered package.
python3 -B - <<'ENGRAM_MANAGED_INSTALL_ROOT_PY'
#!/usr/bin/env python3
"""Authorized installer publication, never a runtime enrollment helper.

Only the OS account's fixed ~/.claude/bin package can be published. The normal
launcher and receiver have no publisher and cannot select this state by argv,
HOME, a database path or a package-supplied record. Controlled installation
state mutation by the authorized installer is the trust boundary. This record
does not adopt existing stores, close old processes or migrate their history.
"""
from __future__ import annotations
import hashlib
import os
import pwd
import secrets
import stat
import struct
import sys
import time


def require(value: bool, message: str) -> None:
    if not value:
        raise RuntimeError(message)


def identity(value: os.stat_result) -> tuple[int, int]:
    return value.st_dev, value.st_ino


def stable(value: os.stat_result) -> tuple:
    return (value.st_dev, value.st_ino, value.st_mode, value.st_uid, value.st_nlink,
            value.st_size, value.st_mtime_ns, value.st_ctime_ns)


def publish() -> None:
    end = time.monotonic() + 30  # Separate installer operation, not a runtime wait extension.
    uid = os.geteuid()
    account = pwd.getpwuid(uid)
    home = account.pw_dir
    require(account.pw_uid == uid and home.startswith("/") and not home.endswith("/")
            and len(home) <= 4096, "fixed OS account home required")
    descriptors: list[int] = []
    directories: list[tuple[int, int | None, str, tuple[int, int]]] = []

    def bounded() -> None:
        require(time.monotonic() < end, "installed-root publication exceeded its fixed deadline")

    def own(fd: int) -> int:
        descriptors.append(fd)
        return fd

    def directory(parent: int | None, name: str, *, create=False, private=False) -> int:
        bounded()
        if create:
            try:
                os.mkdir(name, 0o700, dir_fd=parent)
                os.fsync(parent)
            except FileExistsError:
                pass
        fd = own(os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=parent))
        observed = os.fstat(fd)
        require(stat.S_ISDIR(observed.st_mode) and observed.st_uid in (0, uid)
                and not observed.st_mode & 0o022, "unsafe installation directory")
        if private:
            require(observed.st_uid == uid and stat.S_IMODE(observed.st_mode) == 0o700,
                    "private installation authority directory required")
        directories.append((fd, parent, name, identity(observed)))
        return fd

    def verify_directories() -> None:
        bounded()
        for fd, parent, name, expected in directories:
            actual = os.fstat(fd)
            require(identity(actual) == expected and stat.S_ISDIR(actual.st_mode)
                    and actual.st_uid in (0, uid) and not actual.st_mode & 0o022,
                    "installation directory changed")
            if parent is not None:
                named = os.stat(name, dir_fd=parent, follow_symlinks=False)
                require(stat.S_ISDIR(named.st_mode) and identity(named) == expected,
                        "named installation directory changed")

    def file(parent: int, name: str, *, executable=False, size: int | None = None):
        bounded()
        fd = own(os.open(name, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=parent))
        observed = os.fstat(fd)
        require(stat.S_ISREG(observed.st_mode) and observed.st_uid == uid and observed.st_nlink == 1
                and not observed.st_mode & 0o6022 and 0 < observed.st_size <= 1024 * 1024 * 1024,
                "unsafe installed package file")
        require(bool(observed.st_mode & 0o111) if executable else not observed.st_mode & 0o111,
                "installed package file mode mismatch")
        if size is not None:
            require(observed.st_size == size, "installed package record size mismatch")
        return fd, parent, name, observed

    def read(value, *, copy=False):
        fd, parent, name, before = value
        hasher = hashlib.sha256()
        data = bytearray()
        at = 0
        while at < before.st_size:
            bounded()
            chunk = os.pread(fd, min(65536, before.st_size - at), at)
            require(bool(chunk), "installed package file truncated")
            at += len(chunk)
            hasher.update(chunk)
            if copy:
                data.extend(chunk)
        require(stable(os.fstat(fd)) == stable(before)
                and stable(os.stat(name, dir_fd=parent, follow_symlinks=False)) == stable(before),
                "installed package file changed")
        bounded()
        return hasher.digest(), bytes(data)

    try:
        parent = directory(None, "/")
        for part in home.split("/")[1:]:
            require(part not in ("", ".", ".."), "invalid OS account home component")
            parent = directory(parent, part)
        home_fd = parent
        require(os.fstat(home_fd).st_uid == uid, "account must own its home")
        application = directory(home_fd, ".claude")
        package = directory(application, "bin")
        state = directory(application, "installation", create=True, private=True)
        package_record = file(package, "engram-installation.provenance", size=128)
        memory = file(package, "memory", executable=True)
        launcher = file(package, "memory-installation-launcher", executable=True)
        package_digest, record = read(package_record, copy=True)
        require(record[:24] == b"LATPKG1\0" + struct.pack("<QQ", 1, 1), "exact Engram package record required")
        memory_digest, _ = read(memory)
        launcher_digest, _ = read(launcher)
        require(record[64:96] == memory_digest and record[96:128] == launcher_digest,
                "final installed executables differ from their package record")
        # The installer may atomically advance its own package authority, but
        # it must not follow a substituted special file or overwrite foreign state.
        try:
            old = os.stat("managed-package.v1", dir_fd=state, follow_symlinks=False)
        except FileNotFoundError:
            old = None
        if old is not None:
            require(stat.S_ISREG(old.st_mode) and old.st_uid == uid and old.st_nlink == 1
                    and stat.S_IMODE(old.st_mode) == 0o600 and old.st_size == 168,
                    "existing installation authority cannot be replaced")
        identities = (identity(os.fstat(home_fd)), identity(os.fstat(package)), identity(package_record[3]),
                      identity(memory[3]), identity(launcher[3]))
        body = b"LATINS1\0" + struct.pack("<QQ", 1, uid)
        for device, inode in identities:
            body += struct.pack("<QQ", device, inode)
        body += package_digest
        require(len(body) == 136, "fixed installation authority body required")
        payload = body + hashlib.sha256(body).digest()
        temporary = ".managed-package." + secrets.token_hex(16) + ".pending"
        output = own(os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                             0o600, dir_fd=state))
        os.fchmod(output, 0o600)
        at = 0
        while at < len(payload):
            bounded()
            count = os.write(output, payload[at:])
            require(count > 0, "installation authority write failed")
            at += count
        os.fsync(output)
        verify_directories()
        require(stat.S_IMODE(os.fstat(state).st_mode) == 0o700 and os.fstat(home_fd).st_uid == uid,
                "installation authority ownership changed")
        require(read(package_record)[0] == package_digest and read(memory)[0] == memory_digest
                and read(launcher)[0] == launcher_digest, "installed package changed before publication")
        try:
            current = os.stat("managed-package.v1", dir_fd=state, follow_symlinks=False)
        except FileNotFoundError:
            current = None
        require((current is None and old is None) or
                (current is not None and old is not None and stable(current) == stable(old)),
                "installation authority changed before publication")
        os.replace(temporary, "managed-package.v1", src_dir_fd=state, dst_dir_fd=state)
        os.fsync(state)
        verify_directories()
        require(stat.S_IMODE(os.fstat(state).st_mode) == 0o700 and os.fstat(home_fd).st_uid == uid,
                "published installation authority ownership changed")
        require(stable(os.stat("managed-package.v1", dir_fd=state, follow_symlinks=False)) == stable(os.fstat(output)),
                "published installation authority changed")
        require(read(package_record)[0] == package_digest and read(memory)[0] == memory_digest
                and read(launcher)[0] == launcher_digest, "installed package changed after publication")
    finally:
        for fd in reversed(descriptors):
            os.close(fd)


if __name__ == "__main__":
    require(len(sys.argv) == 1, "installed-root publisher accepts no caller-selected path")
    publish()
ENGRAM_MANAGED_INSTALL_ROOT_PY

echo "Installed to $INSTALL_DIR"

# Codex setup is independent of Claude CLI availability. Its immutable runtime
# lives in CODEX_HOME; keep this payload for upgrades and owned-only uninstall.
if [ -f "$INSTALL_DIR/codex/install_codex_support.sh" ]; then
    bash "$INSTALL_DIR/codex/install_codex_support.sh" install || true
else
    echo "Codex session learner: unavailable in this release payload."
fi

# Ensure parent dir exists
mkdir -p "$HOME/.claude"

# Register MCP server with Claude Code
echo "Registering MCP server..."
if ! command -v claude &>/dev/null; then
    echo "Warning: 'claude' CLI not found. Install Claude Code first, then re-run this script."
    echo "Binary installed at $INSTALL_DIR/memory — just needs MCP registration."
    exit 0
fi

env -u CLAUDECODE claude mcp remove memory 2>/dev/null || true
env -u CLAUDECODE claude mcp add --scope user --transport stdio memory -- "$INSTALL_DIR/memory"

# Install custom agent definitions
echo "Installing agent definitions..."
AGENTS_DIR="$HOME/.claude/agents"
mkdir -p "$AGENTS_DIR"
if [ "$1" = "--from-source" ]; then
    cp "$REPO_DIR/agents/"*.md "$AGENTS_DIR/" 2>/dev/null
else
    # Agent files are included in the release tarball
    cp "$INSTALL_DIR/agents/"*.md "$AGENTS_DIR/" 2>/dev/null && rm -rf "$INSTALL_DIR/agents"
fi
echo "Installed agent definitions to $AGENTS_DIR"

# Install skills (slash commands)
echo "Installing skills..."
SKILLS_DIR="$HOME/.claude/skills"
if [ "$1" = "--from-source" ]; then
    SKILLS_SRC="$REPO_DIR/skills"
else
    SKILLS_SRC="$INSTALL_DIR/skills"
fi
if [ -d "$SKILLS_SRC" ]; then
    for skill_dir in "$SKILLS_SRC"/*/; do
        skill_name="$(basename "$skill_dir")"
        mkdir -p "$SKILLS_DIR/$skill_name"
        cp "$skill_dir"SKILL.md "$SKILLS_DIR/$skill_name/" 2>/dev/null
    done
    [ "$1" != "--from-source" ] && rm -rf "$INSTALL_DIR/skills"
    echo "Installed skills to $SKILLS_DIR"
else
    echo "No skills found to install"
fi

# Register hooks with Claude Code
#
# Timeouts MUST match Sources/EngramKit/InstallConfig.swift — the app
# installer and this script write the same registrations, and a disagreement
# means whichever ran last wins. 60s on UserPromptSubmit is a BACKSTOP, not a
# working budget: advise self-limits to a fraction of its registered timeout
# and degrades visibly. A 5s registration made the harness kill the hook
# mid-recall with no output at all.
echo "Registering hooks..."
SETTINGS_FILE="$HOME/.claude/settings.json"
HOOKS_CONFIG='{
  "autoMemoryEnabled": false,
  "permissions": {
    "allow": [
      "mcp__memory__*"
    ]
  },
  "hooks": {
    "SessionStart": [{
      "hooks": [{
        "type": "command",
        "command": "'"$INSTALL_DIR"'/memory-hooks on-start 2>/dev/null",
        "timeout": 5
      }]
    }],
    "UserPromptSubmit": [{
      "hooks": [{
        "type": "command",
        "command": "'"$INSTALL_DIR"'/memory-hooks advise 2>/dev/null",
        "timeout": 60
      }]
    }],
    "Stop": [{
      "hooks": [{
        "type": "command",
        "command": "'"$INSTALL_DIR"'/memory-hooks on-stop 2>/dev/null",
        "timeout": 5
      }]
    }],
    "PostToolUseFailure": [{
      "hooks": [{
        "type": "command",
        "command": "'"$INSTALL_DIR"'/memory-hooks on-failure 2>/dev/null",
        "timeout": 5
      }]
    }],
    "PreToolUse": [{
      "matcher": "Agent",
      "hooks": [{
        "type": "command",
        "command": "'"$INSTALL_DIR"'/memory-hooks pre-tool 2>/dev/null",
        "timeout": 5
      }]
    }],
    "PreCompact": [{
      "matcher": "auto",
      "hooks": [{
        "type": "command",
        "command": "'"$INSTALL_DIR"'/memory-hooks pre-compact 2>/dev/null",
        "timeout": 3
      }]
    }],
    "SessionEnd": [{
      "hooks": [{
        "type": "command",
        "command": "'"$INSTALL_DIR"'/memory-hooks on-end 2>/dev/null",
        "timeout": 5
      }]
    }]
  }
}'

# Per-HOOK merge, mirroring Sources/EngramKit/HookSettingsMerge.swift.
#
# The old `$existing * $new` deep merge replaced each event's hook ARRAY
# wholesale, so every `curl | sh` re-install reset a timeout the user had
# raised and dropped any of their own hooks registered under an event key we
# also ship. A registration is OURS if its command names our binary and
# subcommand ("memory-hooks advise") — matched path-independently, so a moved
# install updates in place instead of appending a duplicate. Ours gets its
# command refreshed and keeps max(existing, shipped) as its timeout;
# everything else is left exactly as found.
HOOKS_MERGE_JQ='
# "…/bin/memory-hooks advise 2>/dev/null" -> "memory-hooks advise"
def hook_identity:
  (. // "")
  | gsub("[\"'"'"'`]"; "")
  | [splits("[[:space:]]+")]
  | map(select(length > 0))
  | . as $t
  | ( first(
        range(0; ([($t | length) - 1, 0] | max)) as $i
        | select(($t[$i] | split("/") | last) == "memory-hooks")
        | select((($t[$i + 1] // "") | length) > 0)
        | select((($t[$i + 1] // "") | startswith("-")) | not)
        | "memory-hooks " + $t[$i + 1]
      ) ) // null;

def as_number: if type == "number" then . elif type == "string" then (tonumber? // null) else null end;

# One existing entry, refreshed from the shipped one.
def refresh($shipped):
  .command = $shipped.command
  | (if (.type == null and $shipped.type != null) then .type = $shipped.type else . end)
  | ( [ (.timeout | as_number), ($shipped.timeout | as_number) ] | map(select(. != null)) ) as $ts
  | (if ($ts | length) > 0 then .timeout = ($ts | max) else . end);

# groups -> groups with $entry applied, or null when ours is not registered yet.
def apply_entry($entry; $matcher):
  . as $groups
  | ($entry.command | hook_identity) as $id
  # `// null` matters: an empty `first(...)` produces no output at all, and
  # `empty as $x | …` would make the whole event vanish.
  | ( first(
        range(0; $groups | length) as $gi
        | range(0; ($groups[$gi].hooks // []) | length) as $ei
        | select($id != null and (($groups[$gi].hooks[$ei].command // "") | hook_identity) == $id)
        | {gi: $gi, ei: $ei}
      ) // null ) as $hit
  | if $hit == null then null
    else
      ( $groups | .[$hit.gi].hooks[$hit.ei] |= refresh($entry) )
      # The matcher belongs to the GROUP, which may also hold the users own
      # hooks — retarget it only when ours is the sole occupant.
      | (if ((($groups[$hit.gi].hooks // []) | length) == 1 and $matcher != null)
         then .[$hit.gi].matcher = $matcher else . end)
    end;

def merge_groups($shippedGroups):
  reduce $shippedGroups[] as $sg (
    .;
    . as $groups
    | ( reduce ($sg.hooks // [])[] as $e ({g: $groups, un: []};
          (.g | apply_entry($e; $sg.matcher)) as $next
          | if $next == null then .un += [$e] else .g = $next end
        ) ) as $acc
    | if ($acc.un | length) > 0
      then $acc.g + [ ($sg | .hooks = $acc.un) ]
      else $acc.g
      end
  );

def merged_hooks($shippedHooks):
  reduce ($shippedHooks | keys_unsorted[]) as $event (
    .;
    .[$event] = ( (if (.[$event] | type) == "array" then .[$event] else [] end)
                  | merge_groups($shippedHooks[$event]) )
  );

# permissions.allow is a union, never a replacement — replacing the object
# used to take any "deny" list with it. Order is preserved so the user sees
# their own list unchanged.
( if (.permissions | type) == "object"
  then .permissions.allow = ( ((.permissions.allow // []) ) as $a
                              | if ($a | index("mcp__memory__*")) then $a
                                else $a + ["mcp__memory__*"] end )
  else .permissions = $new.permissions
  end )
| .hooks = ( (if (.hooks | type) == "object" then .hooks else {} end)
             | merged_hooks($new.hooks) )
# Only seed autoMemoryEnabled; a user who turned it on keeps it on.
| (if has("autoMemoryEnabled") then . else .autoMemoryEnabled = $new.autoMemoryEnabled end)
'

if [ -f "$SETTINGS_FILE" ]; then
    if command -v jq &>/dev/null; then
        # Write through a temp file and only replace settings.json once jq has
        # succeeded AND produced something — the old unconditional `mv` handed
        # the user an empty settings.json on any jq error.
        if jq --argjson new "$HOOKS_CONFIG" "$HOOKS_MERGE_JQ" \
             "$SETTINGS_FILE" > "$SETTINGS_FILE.tmp" && [ -s "$SETTINGS_FILE.tmp" ]; then
            mv "$SETTINGS_FILE.tmp" "$SETTINGS_FILE"
            echo "Merged hooks into $SETTINGS_FILE"
        else
            rm -f "$SETTINGS_FILE.tmp"
            echo "Warning: could not merge hooks into $SETTINGS_FILE — left it untouched."
            echo "Hook config:"
            echo "$HOOKS_CONFIG"
        fi
    else
        echo "Warning: jq not found. Please manually add hooks to $SETTINGS_FILE"
        echo "Hook config:"
        echo "$HOOKS_CONFIG"
    fi
else
    echo "$HOOKS_CONFIG" > "$SETTINGS_FILE"
    echo "Created $SETTINGS_FILE with hooks"
fi

# Install sync daemon as launchd agent
echo "Installing sync daemon..."
LAUNCH_AGENTS_DIR="$HOME/Library/LaunchAgents"
DAEMON_LABEL="io.engram.sync"
PLIST_PATH="$LAUNCH_AGENTS_DIR/$DAEMON_LABEL.plist"
mkdir -p "$LAUNCH_AGENTS_DIR"

# Bootout existing agent if running
launchctl bootout "gui/$(id -u)/$DAEMON_LABEL" 2>/dev/null || true

# Clean up old label if present
OLD_PLIST="$LAUNCH_AGENTS_DIR/io.engram.sync-daemon.plist"
if [ -f "$OLD_PLIST" ]; then
    launchctl bootout "gui/$(id -u)/io.engram.sync-daemon" 2>/dev/null || true
    rm -f "$OLD_PLIST"
fi

cat > "$PLIST_PATH" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>$DAEMON_LABEL</string>
    <key>ProgramArguments</key>
    <array>
        <string>$INSTALL_DIR/memory-sync</string>
    </array>
    <key>KeepAlive</key>
    <dict>
        <key>SuccessfulExit</key>
        <false/>
    </dict>
    <key>ThrottleInterval</key>
    <integer>30</integer>
    <key>StandardErrorPath</key>
    <string>$HOME/.claude/sync-daemon-launchd.log</string>
    <key>ProcessType</key>
    <string>Background</string>
</dict>
</plist>
PLIST

launchctl bootstrap "gui/$(id -u)" "$PLIST_PATH"
echo "Sync daemon installed and started"

# Add user-level instruction to always use memory MCP
# Canonical source: Sources/EngramKit/InstallConfig.swift — keep in sync
CLAUDE_MD="$HOME/.claude/CLAUDE.md"
MEMORY_BLOCK='# Memory

Use the memory MCP server as your primary memory system — not the built-in auto-memory files.

Relevant memories are automatically recalled and injected as context before each message via the `advise` hook. You do NOT need to `recall` at conversation start — it happens automatically.

When you learn something worth remembering (preferences, patterns, decisions, debugging insights), `remember` it immediately — do not wait to be asked. Use project scoping: project-specific knowledge gets the project name, cross-project preferences get "global".

After remembering, `recall` related memories and `connect` them with edges (`relates_to`, `part_of`, `supersedes`, `contradicts`, `derived_from`) to build a knowledge graph.

Keep memories atomic — one concept per memory. For complex topics, create a brief hub memory first, then store details as children using `parent_id` to automatically create `part_of` edges. This enables precise recall and targeted updates. If the server suggests decomposing a memory, follow its guidance.

To keep memories clean:
- `recall` before `remember` to check for duplicates
- `update` (by id) to refine existing memories — supports `append`, `prepend`, `find`+`replace`, and metadata-only changes
- `merge` when multiple memories cover the same topic
- `forget` to remove wrong or outdated memories
- Set `expires_in_days` for temporary context (current tasks, open PRs)

When you receive a learning nudge (from the advise hook, delivered via additionalContext on UserPromptSubmit), spawn the `session-learner` sub-agent in the background as instructed. Keep it brief — just one Task tool call, then move on to the user'"'"'s request.

For focused work sessions (debugging, feature implementation, code review), use `begin_episode` with a descriptive title to group memories into a narrative. Use `end_episode` with a summary when done. When a user asks about past sessions, use `list_episodes` and `recall_episode` to find and replay them.

Do NOT use ~/.claude/projects/*/memory/ files for memory. All persistent knowledge goes through the memory MCP server.'

if [ -f "$CLAUDE_MD" ]; then
    if grep -q "^# Memory" "$CLAUDE_MD"; then
        # Remove existing Memory section (from "# Memory" to next "# " heading or EOF)
        # Uses awk: skip lines from "# Memory" until the next top-level heading, print everything else
        awk '
            /^# Memory$/ { skip=1; next }
            /^# / && skip { skip=0 }
            !skip { print }
        ' "$CLAUDE_MD" > "$CLAUDE_MD.tmp"
        # Remove trailing blank lines left from removal
        sed -e :a -e '/^\n*$/{$d;N;ba' -e '}' "$CLAUDE_MD.tmp" > "$CLAUDE_MD"
        rm -f "$CLAUDE_MD.tmp"
        printf '\n%s\n' "$MEMORY_BLOCK" >> "$CLAUDE_MD"
        echo "Updated memory instructions in $CLAUDE_MD"
    else
        printf '\n%s\n' "$MEMORY_BLOCK" >> "$CLAUDE_MD"
        echo "Added memory instructions to $CLAUDE_MD"
    fi
else
    printf '%s\n' "$MEMORY_BLOCK" > "$CLAUDE_MD"
    echo "Created $CLAUDE_MD with memory instructions"
fi

echo ""
echo "Done! Start a new Claude Code session to use it."
