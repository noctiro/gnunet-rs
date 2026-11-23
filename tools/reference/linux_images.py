"""Capture executable file images for a live, owned Linux child."""

from contextlib import nullcontext
import hashlib
import os
from pathlib import Path
import stat
import tempfile


MAP_BYTES = 1024 * 1024
IMAGE_COUNT = 128
CAPTURE_BYTES = 512 * 1024 * 1024
READ_BYTES = 1024 * 1024


def identity(info):
    return os.major(info.st_dev), os.minor(info.st_dev), info.st_ino


def file_state(info):
    return identity(info), info.st_size, info.st_mtime_ns, info.st_ctime_ns


def executable_mappings(data):
    """Return a bounded set of file-backed executable map identities and paths."""
    images = {}
    for line in data.split(b"\n"):
        if not line:
            continue
        fields = line.split(None, 5)
        if len(fields) < 5 or len(fields[1]) != 4:
            raise ValueError("malformed Linux process maps")
        inode = int(fields[4])
        if inode == 0 or fields[1][2] != ord("x"):
            continue
        if (len(fields) != 6 or not fields[5].startswith(b"/")
                or fields[5].startswith(b"//") or b".." in fields[5].split(b"/")):
            raise ValueError("executable map has no absolute file path")
        major, minor = fields[3].split(b":")
        key = int(major, 16), int(minor, 16), inode
        images.setdefault(key, fields[5])
        if len(images) > IMAGE_COUNT:
            raise ValueError("Linux executable mapping count exceeded")
    return images


def mappings(process):
    with os.fdopen(os.open("maps", os.O_RDONLY, dir_fd=process), "rb") as stream:
        data = stream.read(MAP_BYTES + 1)
    if len(data) > MAP_BYTES or (data and not data.endswith(b"\n")):
        raise ValueError("Linux process maps exceeded the capture bound or were incomplete")
    return executable_mappings(data)


def open_mapped(root, path, expected):
    # Qualify the name without opening a replacement special file. Reopen
    # that same held object for content, even if its path later changes.
    fd = os.open(path[1:], os.O_PATH | os.O_NOFOLLOW, dir_fd=root)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or identity(info) != expected:
            raise ValueError("mapped image no longer names the original file")
        return os.fdopen(os.open(f"/proc/self/fd/{fd}", os.O_RDONLY), "rb")
    finally:
        os.close(fd)


class Images:
    """One content-addressed store for native observations in a new run directory."""

    def __init__(self, output):
        self.output = Path(output)
        self.directory = self.output / "runtime-images"
        self.directory.mkdir()
        self.retained_bytes = 0
        self.retained = {}

    def _retain(self, stream, expected, remaining):
        before = os.fstat(stream.fileno())
        if not stat.S_ISREG(before.st_mode) or identity(before) != expected:
            raise ValueError("mapped image no longer names the original file")
        count = before.st_size
        if not 0 < count <= remaining:
            raise ValueError("Linux executable images exceeded the capture byte bound")

        state = file_state(before)
        known = self.retained.get(state)
        writer = (tempfile.NamedTemporaryFile(dir=self.directory) if known is None
                  else nullcontext())
        digest = hashlib.sha256()
        with writer as temporary:
            remaining = count
            while remaining:
                chunk = stream.read(min(remaining, READ_BYTES))
                if not chunk:
                    raise ValueError("mapped image shrank while reading")
                digest.update(chunk)
                if temporary is not None:
                    temporary.write(chunk)
                remaining -= len(chunk)
            if stream.read(1) or file_state(os.fstat(stream.fileno())) != state:
                raise ValueError("mapped image changed while reading")
            value = digest.hexdigest()
            destination = self.directory / value
            if temporary is None:
                if value != known or not destination.is_file():
                    raise ValueError("retained executable image changed between observations")
            elif not destination.exists():
                if self.retained_bytes + count > CAPTURE_BYTES:
                    raise ValueError("retained Linux executable images exceeded the run byte bound")
                temporary.flush()
                os.link(temporary.name, destination)
                self.retained_bytes += count
            self.retained[state] = value
        return {"path": destination.relative_to(self.output).as_posix(), "sha256": value}, count

    def capture(self, child, executable):
        """Observe the executable and file-backed code at one live instant."""
        if child.poll() is not None:
            raise ValueError("owned child exited before image capture")
        # A held proc directory continues to refer to this process, including
        # after exit. Relative opens cannot move to a reused numeric PID.
        process = os.open(f"/proc/{child.pid}", os.O_RDONLY | os.O_DIRECTORY)
        try:
            with os.fdopen(os.open("exe", os.O_RDONLY, dir_fd=process), "rb") as image:
                original = identity(os.fstat(image.fileno()))
                if original != identity(os.stat(executable, follow_symlinks=False)):
                    raise ValueError("owned child is not executing its staged binary")
                selected = mappings(process)
                if original not in selected:
                    raise ValueError("owned child's executable image is absent from its maps")
                binary, size = self._retain(image, original, CAPTURE_BYTES)
            loaded = {}
            files = [self._mapped_file(original, selected[original], binary)]
            remaining = CAPTURE_BYTES - size
            root = os.open("root", os.O_RDONLY | os.O_DIRECTORY, dir_fd=process)
            try:
                for key, path in selected.items():
                    if key == original:
                        continue
                    with open_mapped(root, path, key) as image:
                        reference, size = self._retain(image, key, remaining)
                    loaded[reference["path"]] = reference["sha256"]
                    files.append(self._mapped_file(key, path, reference))
                    remaining -= size
            finally:
                os.close(root)
            if (mappings(process) != selected
                    or identity(os.stat("exe", dir_fd=process)) != original
                    or child.poll() is not None):
                raise ValueError("owned child's executable mappings changed during image capture")
            return {"binary": binary, "loaded_files": loaded, "mapped_files": files}
        finally:
            os.close(process)

    @staticmethod
    def _mapped_file(key, path, reference):
        return {"device": list(key[:2]), "inode": key[2], "mapped_path": os.fsdecode(path),
                "artifact": reference}
