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
