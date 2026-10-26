"""The one place in the product that opens a local file or directory.

A path check followed by a separate open by name is not safe: an ancestor that
becomes a junction between the check and the open is followed by the open
before there is a handle, and a check on the handle afterwards cannot undo an
open that already landed outside the approved directory or on a share. So
this module opens EVERY component itself, relative to a handle it holds, and
never follows a link through an open:

1. spelling, without opening anything (`check_spelling` plus the strict form:
   absolute `X:\\...` or `\\\\?\\Volume{GUID}\\...`, no empty component, no
   `.` or `..`, no `/`, no colon in a component);
2. volume, without opening the path or the volume: `GetDriveTypeW` must say
   `DRIVE_FIXED` and `QueryDosDeviceW` must give exactly one
   `\\Device\\HarddiskVolumeN` target;
3. the volume root, opened on that device target (the drive letter is not
   resolved again), checked to be a local disk device;
4. every next component opened with `NtCreateFile` relative to the held parent
   handle, the name being exactly that one component, with
   `FILE_OPEN_REPARSE_POINT` and no type flag; directories are held without
   `FILE_SHARE_DELETE` until the operation is done, so a held directory cannot
   be renamed, deleted or replaced;
5. after every open the reparse tag is read FIRST and the type only after it
   (NTFS checks a type flag before the caller sees the tag, which turned a
   junction in the place of a file into "not a file" instead of "a link").
   Inside the root - the root itself included - every reparse point is
   refused. Above the root only a symbolic link or a mount point is followed:
   its data is read from the link itself (its target is never opened), the
   target text goes through steps 1 and 2 before anything of it is opened,
   and the walk starts again at step 3;
6. the leaf is read with `ReadFile` on the handle; no second open by name;
7. containment is structural: the root is walked on its own text (the path
   must begin with that text exactly, ordinal, or it is `buiten_wortel`), and
   everything under it is opened relative to the held root handle. There is
   no case-folding comparison and no second, separately resolved root path.

`_native` is the seam for every native call: tests count the calls, record
every open with its parent handle, replace a single call, and run a callback
between two components to swap a directory for a junction mid-walk.

The status of a native call goes to the server log only (stderr, with
`NSMCP_DEBUG`), as a hex value; the path likewise. A `PathRefused` carries a
fixed Dutch sentence per kind (`REASONS`) without the path.

Off Windows (testability only; the product is Windows-only) the read walk runs
with `os.open(component, O_NOFOLLOW, dir_fd=parent)`; the write routes refuse
there (`NotImplementedError`). Those logic runs prove nothing about the race
freedom on Windows; the Windows proofs are separate.
"""

from __future__ import annotations

import contextlib
import errno
import os
import re
import secrets
import struct
import sys
from collections import Counter
from collections.abc import Callable, Iterator
from pathlib import Path
from typing import NamedTuple

LINK_LIMIT = 32

SOORTEN = (
    "netwerkpad",
    "apparaatpad",
    "stroom",
    "netwerkstation",
    "koppeling",
    "herparseerpunt",
    "buiten_wortel",
    "geen_gewoon_bestand",
    "te_veel_koppelingen",
    "onleesbaar",
)

# One fixed sentence per kind, never a path, never a status, never a line break.
REASONS: dict[str, str] = {
    "netwerkpad": "het pad leidt naar een netwerkpad; dit product leest en schrijft alleen op een lokale schijf",
    "apparaatpad": (
        "het pad leidt naar een apparaat of naar een station dat geen vaste lokale schijf is; dit product leest en"
        " schrijft alleen op een lokale schijf"
    ),
    "stroom": (
        "het pad noemt een alternatieve gegevensstroom (een dubbele punt in een padonderdeel); dit product leest"
        " alleen de gewone inhoud van een bestand"
    ),
    "netwerkstation": "het pad ligt op een netwerkstation; dit product leest en schrijft alleen op een lokale schijf",
    "koppeling": (
        "het bestand ligt niet als gewoon lokaal bestand op de goedgekeurde plek (er zit een koppeling in het pad);"
        " dit product volgt binnen een goedgekeurde map geen koppelingen"
    ),
    "herparseerpunt": (
        "het pad gaat door een herparseerpunt dat geen gewone map of gewoon bestand is (bijvoorbeeld een"
        " cloud-plaatshouder); dit product leest of schrijft op zo'n plek niet"
    ),
    "buiten_wortel": "het pad ligt buiten de goedgekeurde map",
    "geen_gewoon_bestand": "op deze plek staat geen gewoon bestand of geen gewone map van de verwachte soort",
    "te_veel_koppelingen": f"het pad loopt via meer dan {LINK_LIMIT} koppelingen; zo'n pad wordt niet gevolgd",
    "onleesbaar": "het pad kan niet als gewoon lokaal bestand of als gewone lokale map gelezen of vastgesteld worden",
}

# Which spelling rule refused (`PathRefused.detail`); internal codes, never a path.
SPELLING_NETWORK_OR_DEVICE = "spelling:netwerk-of-apparaat"
SPELLING_STREAM = "spelling:dubbele-punt"
SPELLING_DOT_OR_SPACE = "spelling:punt-of-spatie"
VOLUME_REMOTE = "volume:netwerkstation"


class PathRefused(OSError):
    """A local path this module will not open. `str()` is `REASONS[soort]`.

    `path` is the place the refusal was about (after following links above the
    root), for the server log and for openness `volledig` only. `followed` says
    whether that place was reached through a link. `status` is the NTSTATUS of
    the call that failed, for the server log only.

    An `OSError` on purpose: every reader already has a fail-closed route for
    a file it cannot open (`except OSError`), so a refusal can never escape as
    an unhandled exception or pass a reader that only knew the old failures.
    A reader that names the refusal catches `PathRefused` first and shows
    `reason`."""

    def __init__(
        self,
        soort: str,
        *,
        path: str | None = None,
        status: int | None = None,
        detail: str = "",
        followed: bool = False,
    ) -> None:
        if soort not in REASONS:  # fail closed: an unknown kind is unreadable
            detail = f"onbekende soort {soort!r}"
            soort = "onleesbaar"
        self.soort = soort
        self.path = path
        self.status = status
        self.detail = detail
        self.followed = followed
        super().__init__(REASONS[soort])

    @property
    def reason(self) -> str:
        """The fixed sentence of the kind: never a path, a status or a line break."""
        return REASONS[self.soort]


def describe(exc: BaseException) -> str:
    """What a message may say about a failed file operation: the fixed
    sentence of a refusal, else only the class name (an `OSError` text carries
    the absolute path)."""
    return exc.reason if isinstance(exc, PathRefused) else exc.__class__.__name__


# ---------------------------------------------------------------------------
# Server log
# ---------------------------------------------------------------------------

DEFECT_LINE = "[nsmcp-pad] DEFECT: een netwerkstatus in de lokale wandeling; deze route hoort onbereikbaar te zijn"


def _debug(line: str) -> None:
    if os.environ.get("NSMCP_DEBUG"):
        sys.stderr.write("[nsmcp-pad] " + line + "\n")


def log_kind(context: str, exc: PathRefused) -> None:
    """One server-log line (stderr) for a refusal a reader does not show in
    an answer: a fixed context and the kind, never a path. Best effort: a
    closed stderr changes nothing on disk."""
    try:
        sys.stderr.write(f"[nsmcp-pad] {context}: geweigerd (soort={exc.soort})\n")
    except (OSError, ValueError):
        pass


def _log_refusal(exc: PathRefused) -> None:
    status = f"0x{exc.status:08X}" if exc.status is not None else "-"
    _debug(f"geweigerd soort={exc.soort} status={status} detail={exc.detail!r} pad={exc.path!r}")


# ---------------------------------------------------------------------------
# Step 1: spelling
# ---------------------------------------------------------------------------

_LOCAL_DEVICE_DRIVE = re.compile(r"^\\\\[?.]\\[A-Za-z]:(\\|$)")
_LOCAL_VOLUME_GUID = re.compile(r"^\\\\\?\\Volume\{[0-9A-Fa-f-]{36}\}(\\|$)")
_UNC_PREFIX = re.compile(r"^\\\\(?:[?.]\\UNC(?:\\|$)|[^?.\\])", re.IGNORECASE)
_MAX_COMPONENT = 255


def check_spelling(text: str) -> None:
    """The spelling rules, on text only (nothing is opened): a UNC path or a
    `\\\\?\\UNC\\` path (`netwerkpad`), any other device path than a local drive
    or a volume GUID (`apparaatpad`), a colon after the drive letter
    (`stroom`), and a component that ends in a dot or a space (`onleesbaar`:
    Windows drops those, so the name read is not the name written). A
    relative path and `/` pass here; the strict form of `open_local` refuses
    them."""
    if not isinstance(text, str):
        raise PathRefused("onleesbaar", detail="geen tekst")
    spelled = text.replace("/", "\\")
    rest = spelled
    if spelled.startswith("\\\\"):
        drive = _LOCAL_DEVICE_DRIVE.match(spelled)
        guid = _LOCAL_VOLUME_GUID.match(spelled)
        if drive:
            rest = spelled[4:]
        elif guid:
            rest = spelled[guid.end() :]
        else:
            soort = "netwerkpad" if _UNC_PREFIX.match(spelled) else "apparaatpad"
            raise PathRefused(soort, path=text, detail=SPELLING_NETWORK_OR_DEVICE)
    if len(rest) >= 2 and rest[1] == ":" and rest[0].isascii() and rest[0].isalpha():
        rest = rest[2:]
    if ":" in rest:
        raise PathRefused("stroom", path=text, detail=SPELLING_STREAM)
    for part in rest.split("\\"):
        if part not in ("", ".", "..") and part[-1] in (".", " "):
            raise PathRefused("onleesbaar", path=text, detail=SPELLING_DOT_OR_SPACE)


def _split(text: str) -> tuple[str, list[str]]:
    """Step 1, strict: `(volume key, components)`. The key is `X:` or
    `Volume{GUID}`. Refuses everything that is not one absolute local
    spelling."""
    check_spelling(text)
    if "\0" in text:
        raise PathRefused("onleesbaar", path=text, detail="nul-teken")
    if "/" in text:
        raise PathRefused("onleesbaar", path=text, detail="schuine streep")
    if _LOCAL_DEVICE_DRIVE.match(text):
        text = text[4:]
    guid = _LOCAL_VOLUME_GUID.match(text)
    if guid:
        key = text[4 : guid.end()].rstrip("\\")
        tail = text[guid.end() :]
    elif len(text) >= 3 and text[0].isascii() and text[0].isalpha() and text[1] == ":" and text[2] == "\\":
        key = text[:2].upper()
        tail = text[3:]
    elif len(text) == 2 and text[0].isascii() and text[0].isalpha() and text[1] == ":":
        raise PathRefused("onleesbaar", path=text, detail="schijf zonder map")
    else:
        raise PathRefused("onleesbaar", path=text, detail="niet absoluut")
    return key, _components(tail, text)


def _components(tail: str, text: str) -> list[str]:
    if tail == "":
        return []
    parts = tail.split("\\")
    if parts[-1] == "":
        parts.pop()
    for part in parts:
        if part in ("", ".", ".."):
            raise PathRefused("onleesbaar", path=text, detail="leeg of punt-onderdeel")
        if ":" in part:
            raise PathRefused("stroom", path=text, detail=SPELLING_STREAM)
        if len(part) > _MAX_COMPONENT:
            raise PathRefused("onleesbaar", path=text, detail="onderdeel te lang")
    return parts


def _join(key: str, components: list[str]) -> str:
    base = key + "\\" if key.endswith(":") else "\\\\?\\" + key + "\\"
    return base + "\\".join(components)


def _within(key: str, components: list[str], root: str | None) -> list[str] | None:
    """The components to walk: the ROOT's own text components followed by the
    components of the path below it, or None without a root. A path whose text
    does not begin with the root text EXACTLY (ordinal, component by
    component; only the ASCII volume key ignores case) is `buiten_wortel`:
    no case folding, because Python folds differently from NTFS (a ligature,
    a sharp s or a long s would make a sibling of the root count as the root).
    What lies below the root is then opened relative to the held root handle
    (structural containment); nothing is compared after this split."""
    if root is None:
        return None
    root_key, root_components = _split(root)
    if root_key.upper() != key.upper() or components[: len(root_components)] != root_components:
        raise PathRefused("buiten_wortel", path=_join(key, components))
    return root_components + components[len(root_components) :]


# ---------------------------------------------------------------------------
# NTSTATUS
# ---------------------------------------------------------------------------

STATUS_SUCCESS = 0x00000000
STATUS_REPARSE = 0x00000104
STATUS_STOPPED_ON_SYMLINK = 0x8000002D
STATUS_ACCESS_DENIED = 0xC0000022
STATUS_OBJECT_NAME_INVALID = 0xC0000033
STATUS_OBJECT_NAME_NOT_FOUND = 0xC0000034
STATUS_OBJECT_NAME_COLLISION = 0xC0000035
STATUS_OBJECT_PATH_NOT_FOUND = 0xC000003A
STATUS_SHARING_VIOLATION = 0xC0000043
STATUS_DELETE_PENDING = 0xC0000056
STATUS_FILE_IS_A_DIRECTORY = 0xC00000BA
STATUS_NOT_A_DIRECTORY = 0xC0000103
STATUS_REPARSE_POINT_NOT_RESOLVED = 0xC0000280
STATUS_DIRECTORY_IS_A_REPARSE_POINT = 0xC0000281

_ABSENT = frozenset({STATUS_OBJECT_NAME_NOT_FOUND, STATUS_OBJECT_PATH_NOT_FOUND})
_NOT_REGULAR = frozenset({STATUS_NOT_A_DIRECTORY, STATUS_FILE_IS_A_DIRECTORY})
# STATUS_REPARSE and STATUS_STOPPED_ON_SYMLINK do not occur with
# FILE_OPEN_REPARSE_POINT; STATUS_REPARSE_POINT_NOT_RESOLVED was measured: a
# held directory emptied and given a mount point, then a relative open under it;
# STATUS_DIRECTORY_IS_A_REPARSE_POINT is its sibling for the directory itself.
_LINKISH = frozenset(
    {STATUS_REPARSE, STATUS_STOPPED_ON_SYMLINK, STATUS_REPARSE_POINT_NOT_RESOLVED, STATUS_DIRECTORY_IS_A_REPARSE_POINT}
)
_NETWORK = frozenset(
    {
        0xC00000BE,  # STATUS_BAD_NETWORK_PATH
        0xC00000BF,  # STATUS_NETWORK_BUSY
        0xC00000C4,  # STATUS_UNEXPECTED_NETWORK_ERROR
        0xC00000C9,  # STATUS_NETWORK_NAME_DELETED
        0xC00000CC,  # STATUS_BAD_NETWORK_NAME
        0xC000020C,  # STATUS_CONNECTION_DISCONNECTED
        0xC0000236,  # STATUS_CONNECTION_REFUSED
        0xC000023C,  # STATUS_NETWORK_UNREACHABLE
        0xC000023D,  # STATUS_HOST_UNREACHABLE
    }
)


class _Absent(Exception):
    """A component that is not there (only meaningful with `allow_missing`)."""


def _status_refusal(status: int, path: str, allow_missing: bool) -> Exception:
    """The kind for a failed open. Every status not named here is `onleesbaar`."""
    if status in _ABSENT:
        if allow_missing:
            return _Absent()
        return PathRefused("onleesbaar", path=path, status=status, detail="afwezig")
    if status in _NOT_REGULAR:
        return PathRefused("geen_gewoon_bestand", path=path, status=status)
    if status in _LINKISH:
        return PathRefused("koppeling", path=path, status=status)
    if status in _NETWORK:
        sys.stderr.write(DEFECT_LINE + "\n")
        return PathRefused("netwerkpad", path=path, status=status, detail="netwerkstatus")
    return PathRefused("onleesbaar", path=path, status=status)


# ---------------------------------------------------------------------------
# Native constants
# ---------------------------------------------------------------------------

FILE_READ_DATA = 0x0001
FILE_LIST_DIRECTORY = 0x0001
FILE_WRITE_DATA = 0x0002
FILE_APPEND_DATA = 0x0004
FILE_TRAVERSE = 0x0020
FILE_READ_ATTRIBUTES = 0x0080
DELETE = 0x00010000
SYNCHRONIZE = 0x00100000

FILE_SHARE_READ = 0x1
FILE_SHARE_WRITE = 0x2
FILE_SHARE_DELETE = 0x4

FILE_OPEN = 1
FILE_CREATE = 2
FILE_OPEN_IF = 3

FILE_DIRECTORY_FILE = 0x00000001
FILE_SEQUENTIAL_ONLY = 0x00000004
FILE_SYNCHRONOUS_IO_NONALERT = 0x00000020
FILE_NON_DIRECTORY_FILE = 0x00000040
FILE_OPEN_REPARSE_POINT = 0x00200000

OBJ_CASE_INSENSITIVE = 0x40

FILE_ATTRIBUTE_DIRECTORY = 0x10
FILE_ATTRIBUTE_REPARSE_POINT = 0x400
IO_REPARSE_TAG_MOUNT_POINT = 0xA0000003
IO_REPARSE_TAG_SYMLINK = 0xA000000C
SYMLINK_FLAG_RELATIVE = 0x1

DRIVE_FIXED = 3
DRIVE_REMOTE = 4
FILE_TYPE_DISK = 1
FILE_DEVICE_DISK = 7
FILE_REMOTE_DEVICE = 0x10
FSCTL_GET_REPARSE_POINT = 0x000900A8

FileStandardInformation = 5
FileRenameInformation = 10
FileDispositionInformation = 13
FileAttributeTagInformation = 35
FileFsDeviceInformation = 4

# A directory on the way is held with the traverse right only: a relative open
# needs no access on the parent handle, and a directory that may be traversed
# but not listed (a hardened D:\Apps) stays walkable, as it was in 1.0.3.
# Holding does not depend on the access mask but on the share mode below.
DIR_ACCESS = FILE_TRAVERSE | FILE_READ_ATTRIBUTES | SYNCHRONIZE
# A directory asked for itself (expect="dir", read) is opened for listing too:
# its caller works in it (lists it, or renames into it).
DIR_LIST_ACCESS = FILE_LIST_DIRECTORY | DIR_ACCESS
# Directories: other processes may read and write in a held directory (a
# collector writing beside the file, an append on the ledger), but nobody may
# rename, delete or replace it while it is held.
DIR_SHARE = FILE_SHARE_READ | FILE_SHARE_WRITE
_HARDDISK_VOLUME = re.compile(r"\\Device\\HarddiskVolume[0-9]+", re.IGNORECASE)


# ---------------------------------------------------------------------------
# The seam
# ---------------------------------------------------------------------------


class _Native:
    """Every native call of this module. `calls` counts per native function;
    with `record=True` every open and close is kept (`opens`, `closes`) with
    its parent handle. `between(index, component)` runs before component
    `index` is opened, when the parent is already held."""

    def __init__(self, *, record: bool = False) -> None:
        self.calls: Counter[str] = Counter()
        self.opens: list[dict] | None = [] if record else None
        self.closes: list[int] | None = [] if record else None
        # Opens and closes in the order they happened: ("open", index into opens) or ("close", handle).
        self.events: list[tuple[str, int]] | None = [] if record else None
        self.between: Callable[[int, str], None] | None = None
        self._bind()

    def _bind(self) -> None:
        if sys.platform != "win32":
            return
        import ctypes
        import ctypes.wintypes as wt

        self._ct = ctypes
        self._wt = wt

        class UNICODE_STRING(ctypes.Structure):
            _fields_ = [("Length", wt.USHORT), ("MaximumLength", wt.USHORT), ("Buffer", ctypes.c_void_p)]

        class OBJECT_ATTRIBUTES(ctypes.Structure):
            _fields_ = [
                ("Length", wt.ULONG),
                ("RootDirectory", wt.HANDLE),
                ("ObjectName", ctypes.POINTER(UNICODE_STRING)),
                ("Attributes", wt.ULONG),
                ("SecurityDescriptor", ctypes.c_void_p),
                ("SecurityQualityOfService", ctypes.c_void_p),
            ]

        class IO_STATUS_BLOCK(ctypes.Structure):
            _fields_ = [("Status", ctypes.c_void_p), ("Information", ctypes.c_size_t)]

        class FILE_ATTRIBUTE_TAG_INFORMATION(ctypes.Structure):
            _fields_ = [("FileAttributes", wt.ULONG), ("ReparseTag", wt.ULONG)]

        class FILE_STANDARD_INFORMATION(ctypes.Structure):
            _fields_ = [
                ("AllocationSize", ctypes.c_longlong),
                ("EndOfFile", ctypes.c_longlong),
                ("NumberOfLinks", wt.ULONG),
                ("DeletePending", ctypes.c_ubyte),
                ("Directory", ctypes.c_ubyte),
            ]

        class FILE_FS_DEVICE_INFORMATION(ctypes.Structure):
            _fields_ = [("DeviceType", wt.ULONG), ("Characteristics", wt.ULONG)]

        self._US = UNICODE_STRING
        self._OA = OBJECT_ATTRIBUTES
        self._IOSB = IO_STATUS_BLOCK
        self._TAG = FILE_ATTRIBUTE_TAG_INFORMATION
        self._STD = FILE_STANDARD_INFORMATION
        self._FSDEV = FILE_FS_DEVICE_INFORMATION

        ntdll = ctypes.WinDLL("ntdll")
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        ntstatus = ctypes.c_long
        ntdll.NtCreateFile.argtypes = [
            ctypes.POINTER(wt.HANDLE),
            wt.ULONG,
            ctypes.POINTER(OBJECT_ATTRIBUTES),
            ctypes.POINTER(IO_STATUS_BLOCK),
            ctypes.c_void_p,
            wt.ULONG,
            wt.ULONG,
            wt.ULONG,
            wt.ULONG,
            ctypes.c_void_p,
            wt.ULONG,
        ]
        ntdll.NtCreateFile.restype = ntstatus
        for name in ("NtQueryInformationFile", "NtQueryVolumeInformationFile", "NtSetInformationFile"):
            function = getattr(ntdll, name)
            function.argtypes = [wt.HANDLE, ctypes.POINTER(IO_STATUS_BLOCK), ctypes.c_void_p, wt.ULONG, ctypes.c_int]
            function.restype = ntstatus
        ntdll.NtClose.argtypes = [wt.HANDLE]
        ntdll.NtClose.restype = ntstatus
        kernel32.GetDriveTypeW.argtypes = [wt.LPCWSTR]
        kernel32.GetDriveTypeW.restype = wt.UINT
        kernel32.QueryDosDeviceW.argtypes = [wt.LPCWSTR, wt.LPWSTR, wt.DWORD]
        kernel32.QueryDosDeviceW.restype = wt.DWORD
        kernel32.GetFileType.argtypes = [wt.HANDLE]
        kernel32.GetFileType.restype = wt.DWORD
        kernel32.DeviceIoControl.argtypes = [
            wt.HANDLE,
            wt.DWORD,
            ctypes.c_void_p,
            wt.DWORD,
            ctypes.c_void_p,
            wt.DWORD,
            ctypes.POINTER(wt.DWORD),
            ctypes.c_void_p,
        ]
        kernel32.DeviceIoControl.restype = wt.BOOL
        kernel32.ReadFile.argtypes = [wt.HANDLE, ctypes.c_void_p, wt.DWORD, ctypes.POINTER(wt.DWORD), ctypes.c_void_p]
        kernel32.ReadFile.restype = wt.BOOL
        kernel32.WriteFile.argtypes = [wt.HANDLE, ctypes.c_void_p, wt.DWORD, ctypes.POINTER(wt.DWORD), ctypes.c_void_p]
        kernel32.WriteFile.restype = wt.BOOL
        kernel32.FlushFileBuffers.argtypes = [wt.HANDLE]
        kernel32.FlushFileBuffers.restype = wt.BOOL
        self._ntdll = ntdll
        self._kernel32 = kernel32

    # ---- ntdll

    def NtCreateFile(  # named after the native call
        self, parent: int | None, name: str, access: int, share: int, disposition: int, options: int
    ) -> tuple[int, int | None]:
        self.calls["NtCreateFile"] += 1
        ctypes, wt = self._ct, self._wt
        encoded = name.encode("utf-16-le")
        buffer = ctypes.create_string_buffer(encoded + b"\0\0")
        unicode = self._US(len(encoded), len(encoded) + 2, ctypes.cast(buffer, ctypes.c_void_p))
        attributes = self._OA(
            ctypes.sizeof(self._OA), parent or None, ctypes.pointer(unicode), OBJ_CASE_INSENSITIVE, None, None
        )
        iosb = self._IOSB()
        handle = wt.HANDLE()
        status = (
            self._ntdll.NtCreateFile(
                ctypes.byref(handle),
                access,
                ctypes.byref(attributes),
                ctypes.byref(iosb),
                None,
                0,
                share,
                disposition,
                options,
                None,
                0,
            )
            & 0xFFFFFFFF
        )
        result = handle.value if status == STATUS_SUCCESS else None
        if self.opens is not None:
            self.opens.append(
                {
                    "parent": parent,
                    "name": name,
                    "status": status,
                    "handle": result,
                    "access": access,
                    "share": share,
                    "disposition": disposition,
                    "options": options,
                }
            )
            if self.events is not None:
                self.events.append(("open", len(self.opens) - 1))
        return status, result

    def NtClose(self, handle: int) -> None:
        self.calls["NtClose"] += 1
        if self.closes is not None:
            self.closes.append(handle)
        if self.events is not None:
            self.events.append(("close", handle))
        self._ntdll.NtClose(handle)

    def query_attribute_tag(self, handle: int) -> tuple[int, int, int]:
        """`NtQueryInformationFile(FileAttributeTagInformation)`: (status, attributes, tag)."""
        self.calls["NtQueryInformationFile"] += 1
        info = self._TAG()
        iosb = self._IOSB()
        ctypes = self._ct
        status = (
            self._ntdll.NtQueryInformationFile(
                handle, ctypes.byref(iosb), ctypes.byref(info), ctypes.sizeof(info), FileAttributeTagInformation
            )
            & 0xFFFFFFFF
        )
        return status, info.FileAttributes, info.ReparseTag

    def query_standard(self, handle: int) -> tuple[int, int, bool]:
        """`NtQueryInformationFile(FileStandardInformation)`: (status, end of file, directory)."""
        self.calls["NtQueryInformationFile"] += 1
        info = self._STD()
        iosb = self._IOSB()
        ctypes = self._ct
        status = (
            self._ntdll.NtQueryInformationFile(
                handle, ctypes.byref(iosb), ctypes.byref(info), ctypes.sizeof(info), FileStandardInformation
            )
            & 0xFFFFFFFF
        )
        return status, info.EndOfFile, bool(info.Directory)

    def query_fs_device(self, handle: int) -> tuple[int, int, int]:
        """`NtQueryVolumeInformationFile(FileFsDeviceInformation)`: (status, device type, characteristics)."""
        self.calls["NtQueryVolumeInformationFile"] += 1
        info = self._FSDEV()
        iosb = self._IOSB()
        ctypes = self._ct
        status = (
            self._ntdll.NtQueryVolumeInformationFile(
                handle, ctypes.byref(iosb), ctypes.byref(info), ctypes.sizeof(info), FileFsDeviceInformation
            )
            & 0xFFFFFFFF
        )
        return status, info.DeviceType, info.Characteristics

    def set_rename(self, handle: int, parent: int, name: str, *, replace: bool = True) -> int:
        """`NtSetInformationFile(FileRenameInformation)`, the target named
        relative to the held `parent`; `ReplaceIfExists` only with `replace`."""
        self.calls["NtSetInformationFile"] += 1
        ctypes, wt = self._ct, self._wt
        encoded = name.encode("utf-16-le")

        class FILE_RENAME_INFORMATION(ctypes.Structure):
            _fields_ = [
                ("ReplaceIfExists", wt.ULONG),
                ("RootDirectory", wt.HANDLE),
                ("FileNameLength", wt.ULONG),
                ("FileName", ctypes.c_ubyte * (len(encoded) + 2)),
            ]

        info = FILE_RENAME_INFORMATION(1 if replace else 0, parent, len(encoded))
        # Byte copy: a char-array assignment stops at the first NUL of UTF-16.
        ctypes.memmove(ctypes.addressof(info) + FILE_RENAME_INFORMATION.FileName.offset, encoded, len(encoded))
        iosb = self._IOSB()
        return (
            self._ntdll.NtSetInformationFile(
                handle, ctypes.byref(iosb), ctypes.byref(info), ctypes.sizeof(info), FileRenameInformation
            )
            & 0xFFFFFFFF
        )

    def set_delete(self, handle: int) -> int:
        """`NtSetInformationFile(FileDispositionInformation)`: delete on close."""
        self.calls["NtSetInformationFile"] += 1
        ctypes = self._ct
        flag = ctypes.c_ubyte(1)
        iosb = self._IOSB()
        return (
            self._ntdll.NtSetInformationFile(
                handle, ctypes.byref(iosb), ctypes.byref(flag), 1, FileDispositionInformation
            )
            & 0xFFFFFFFF
        )

    # ---- kernel32

    def GetDriveTypeW(self, root: str) -> int:
        self.calls["GetDriveTypeW"] += 1
        return int(self._kernel32.GetDriveTypeW(root))

    def QueryDosDeviceW(self, name: str) -> list[str] | None:
        self.calls["QueryDosDeviceW"] += 1
        buffer = self._ct.create_unicode_buffer(4096)
        count = self._kernel32.QueryDosDeviceW(name, buffer, 4096)
        if not count:
            return None
        return [item for item in buffer[:count].split("\0") if item]

    def GetFileType(self, handle: int) -> int:
        self.calls["GetFileType"] += 1
        return int(self._kernel32.GetFileType(handle))

    def get_reparse_data(self, handle: int) -> bytes | None:
        """`DeviceIoControl(FSCTL_GET_REPARSE_POINT)` on the link itself: reads
        its data, never opens its target."""
        self.calls["DeviceIoControl"] += 1
        ctypes, wt = self._ct, self._wt
        out = ctypes.create_string_buffer(16 * 1024)
        returned = wt.DWORD(0)
        ok = self._kernel32.DeviceIoControl(
            handle, FSCTL_GET_REPARSE_POINT, None, 0, out, len(out), ctypes.byref(returned), None
        )
        if not ok:
            return None
        return out.raw[: returned.value]

    def ReadFile(self, handle: int, size: int) -> bytes | None:
        self.calls["ReadFile"] += 1
        ctypes, wt = self._ct, self._wt
        buffer = ctypes.create_string_buffer(size)
        got = wt.DWORD(0)
        if not self._kernel32.ReadFile(handle, buffer, size, ctypes.byref(got), None):
            return None
        return buffer.raw[: got.value]

    def WriteFile(self, handle: int, data: bytes) -> int | None:
        self.calls["WriteFile"] += 1
        ctypes, wt = self._ct, self._wt
        written = wt.DWORD(0)
        if not self._kernel32.WriteFile(handle, data, len(data), ctypes.byref(written), None):
            return None
        return written.value

    def FlushFileBuffers(self, handle: int) -> bool:
        self.calls["FlushFileBuffers"] += 1
        return bool(self._kernel32.FlushFileBuffers(handle))


class _PosixNative:
    """The same seam names off Windows, over file descriptors (read route only)."""

    def __init__(self, *, record: bool = False) -> None:
        self.calls: Counter[str] = Counter()
        self.opens: list[dict] | None = [] if record else None
        self.closes: list[int] | None = [] if record else None
        self.between: Callable[[int, str], None] | None = None

    def open_at(self, parent: int | None, name: str, flags: int) -> int:
        self.calls["open"] += 1
        try:
            fd = os.open(name, flags, 0o600, dir_fd=parent)
        except OSError:
            if self.opens is not None:
                self.opens.append({"parent": parent, "name": name, "handle": None})
            raise
        if self.opens is not None:
            self.opens.append({"parent": parent, "name": name, "handle": fd})
        return fd

    def NtClose(self, handle: int) -> None:  # the same seam name on every platform
        self.calls["close"] += 1
        if self.closes is not None:
            self.closes.append(handle)
        os.close(handle)

    def ReadFile(self, handle: int, size: int) -> bytes | None:
        self.calls["read"] += 1
        try:
            return os.read(handle, size)
        except OSError:
            return None


_native: _Native | _PosixNative = _Native() if sys.platform == "win32" else _PosixNative()


# ---------------------------------------------------------------------------
# The handle
# ---------------------------------------------------------------------------

_READ_CHUNK = 1024 * 1024


class LocalHandle:
    """A held chain: every directory handle from the volume root to the parent
    of the leaf, and the leaf. Closed exactly once, leaf first, then the chain
    in reverse order."""

    def __init__(self, native, chain: list[int], leaf: int | None, path: str, *, exists: bool, kind: str) -> None:
        self._native = native
        self._chain = chain
        self._leaf = leaf
        self.path = path
        self.exists = exists
        self.kind = kind
        self.closed = False

    @property
    def directory_handle(self) -> int | None:
        """The held handle of the directory (expect="dir"), or of the parent of the leaf."""
        if self.kind == "dir":
            return self._leaf
        return self._chain[-1] if self._chain else None

    def read(self, cap: int) -> bytes:
        """At most `cap + 1` bytes, read on the handle. More than `cap` bytes
        returned means the file is over the cap: the caller's existing cap
        route decides what that means."""
        if self.closed or self._leaf is None or self.kind != "file":
            raise PathRefused("onleesbaar", path=self.path, detail="geen leesbaar blad")
        native = self._native
        if isinstance(native, _Native):
            status, _size, directory = native.query_standard(self._leaf)
            if status != STATUS_SUCCESS:
                raise PathRefused("onleesbaar", path=self.path, status=status)
            if directory:
                raise PathRefused("geen_gewoon_bestand", path=self.path)
        parts: list[bytes] = []
        total = 0
        while total <= cap:
            chunk = native.ReadFile(self._leaf, min(_READ_CHUNK, cap + 1 - total))
            if chunk is None:
                raise PathRefused("onleesbaar", path=self.path, detail="lezen mislukt")
            if not chunk:
                break
            parts.append(chunk)
            total += len(chunk)
        return b"".join(parts)

    def size(self) -> int:
        """The size of the held leaf, read on its handle (no open by name)."""
        if self.closed or self._leaf is None or self.kind != "file":
            raise PathRefused("onleesbaar", path=self.path, detail="geen leesbaar blad")
        native = self._native
        if isinstance(native, _Native):
            status, size, directory = native.query_standard(self._leaf)
            if status != STATUS_SUCCESS:
                raise PathRefused("onleesbaar", path=self.path, status=status)
            if directory:
                raise PathRefused("geen_gewoon_bestand", path=self.path)
            return int(size)
        return os.fstat(self._leaf).st_size

    def flush_directory(self) -> bool:
        """Best effort: `FlushFileBuffers` on the HELD parent directory handle
        (the directory entry of a new file), never a second open by name.
        False where the platform or the handle's access does not allow it."""
        directory = self._chain[-1] if self._chain else None
        if self.closed or directory is None or not isinstance(self._native, _Native):
            return False
        return self._native.FlushFileBuffers(directory)

    def detach_leaf_fd(self) -> int:
        """Windows: hands the leaf handle over to a C runtime file descriptor
        (for a child process's standard output). The descriptor owns the
        handle from here: the caller closes it with `os.close`, and `close()`
        of this chain no longer closes the leaf."""
        if self.closed or self._leaf is None or self.kind != "file" or not isinstance(self._native, _Native):
            raise PathRefused("onleesbaar", path=self.path, detail="geen blad om over te dragen")
        import msvcrt

        fd = msvcrt.open_osfhandle(self._leaf, os.O_WRONLY | os.O_APPEND)
        self._leaf = None
        return fd

    def write(self, data: bytes) -> None:
        """Writes all of `data` on the handle, then flushes it to disk."""
        if self.closed or self._leaf is None or self.kind != "file":
            raise OSError(errno.EBADF, "geen schrijfbaar blad")
        view = memoryview(data)
        while view:
            written = self._native.WriteFile(self._leaf, bytes(view[: 1 << 20]))
            if not written:
                raise OSError(errno.EIO, "schrijven op de lokale handle mislukt")
            view = view[written:]
        if not self._native.FlushFileBuffers(self._leaf):
            raise OSError(errno.EIO, "wegschrijven naar de schijf mislukt")

    def close(self) -> None:
        if self.closed:
            return
        self.closed = True
        try:
            if self._leaf is not None:
                self._native.NtClose(self._leaf)
        finally:
            _close_all(self._native, self._chain)


def _close_all(native, handles: list[int]) -> None:
    """Closes `handles` in reverse order, each exactly once, even when one fails."""
    while handles:
        handle = handles.pop()
        with contextlib.suppress(OSError):
            native.NtClose(handle)


# ---------------------------------------------------------------------------
# Windows walk
# ---------------------------------------------------------------------------


class _Follow(Exception):
    def __init__(self, path: str) -> None:
        self.path = path


def _volume_target(native: _Native, key: str, path: str) -> str:
    """Step 2: the device target of the volume, without opening the path or the volume."""
    root = key + "\\" if key.endswith(":") else "\\\\?\\" + key + "\\"
    drive_type = native.GetDriveTypeW(root)
    if drive_type == DRIVE_REMOTE:
        raise PathRefused("netwerkstation", path=path, detail=VOLUME_REMOTE)
    if drive_type != DRIVE_FIXED:
        raise PathRefused("apparaatpad", path=path, detail=f"stationstype {drive_type}")
    targets = native.QueryDosDeviceW(key)
    if not targets or len(targets) != 1:
        raise PathRefused("apparaatpad", path=path, detail="apparaatdoel niet eenduidig")
    target = targets[0]
    if _HARDDISK_VOLUME.fullmatch(target):
        return target
    lowered = target.lower()
    if lowered.startswith("\\device\\mup") or "redirector" in lowered or lowered.startswith("\\??\\unc\\"):
        raise PathRefused("netwerkstation", path=path, detail=VOLUME_REMOTE)
    raise PathRefused("apparaatpad", path=path, detail="apparaatdoel")


def _link_target(raw: bytes, key: str, parent: list[str], rest: list[str], path: str) -> str:
    """The new absolute path text a link above the root leads to. Text only;
    the caller sends it through steps 1 and 2 before anything of it is opened."""
    try:
        tag = struct.unpack_from("<I", raw, 0)[0]
        if tag == IO_REPARSE_TAG_SYMLINK:
            offset, length, _po, _pl, flags = struct.unpack_from("<HHHHI", raw, 8)
            base = 20
        elif tag == IO_REPARSE_TAG_MOUNT_POINT:
            offset, length, _po, _pl = struct.unpack_from("<HHHH", raw, 8)
            flags = 0
            base = 16
        else:
            raise PathRefused("herparseerpunt", path=path, detail=f"tag 0x{tag:08X}")
        if base + offset + length > len(raw) or length % 2:
            raise PathRefused("onleesbaar", path=path, detail="koppelingsgegevens")
        substitute = raw[base + offset : base + offset + length].decode("utf-16-le")
    except (struct.error, UnicodeDecodeError):
        raise PathRefused("onleesbaar", path=path, detail="koppelingsgegevens") from None
    tail = ("\\" + "\\".join(rest)) if rest else ""
    if flags & SYMLINK_FLAG_RELATIVE:
        if "/" in substitute or "\0" in substitute:
            raise PathRefused("onleesbaar", path=path, detail="relatief koppelingsdoel")
        components = [] if substitute.startswith("\\") else list(parent)
        for part in substitute.split("\\"):
            if part in ("", "."):
                continue
            if part == "..":
                if not components:
                    raise PathRefused("onleesbaar", path=path, detail="relatief koppelingsdoel boven de schijf")
                components.pop()
                continue
            components.append(part)
        return _join(key, components) + tail
    if substitute[:8].upper() == "\\??\\UNC\\":
        return "\\\\" + substitute[8:] + tail
    if substitute.startswith("\\??\\"):
        rest_of = substitute[4:].rstrip("\\")
        if len(rest_of) >= 2 and rest_of[1] == ":":
            text = rest_of + tail
            return text + "\\" if len(text) == 2 else text
        return "\\\\?\\" + rest_of + tail
    return "\\\\?\\GLOBALROOT" + substitute + tail


def _leaf_open(expect: str, mode: str, shared_writers: bool) -> tuple[int, int, int, int]:
    """(access, share, disposition, options) for the last component. No type
    flag: the tag is read first, the type checked after it."""
    if expect == "dir":
        access = DIR_LIST_ACCESS if mode == "read" else DIR_ACCESS
        return access, DIR_SHARE, FILE_OPEN, FILE_OPEN_REPARSE_POINT | FILE_SYNCHRONOUS_IO_NONALERT
    share = FILE_SHARE_READ | (FILE_SHARE_WRITE if shared_writers else 0)
    if mode == "read":
        return (
            FILE_READ_DATA | FILE_READ_ATTRIBUTES | SYNCHRONIZE,
            share,
            FILE_OPEN,
            FILE_OPEN_REPARSE_POINT | FILE_SEQUENTIAL_ONLY | FILE_SYNCHRONOUS_IO_NONALERT,
        )
    if mode == "append":
        return (
            FILE_APPEND_DATA | FILE_READ_ATTRIBUTES | SYNCHRONIZE,
            share,
            FILE_OPEN_IF,
            FILE_OPEN_REPARSE_POINT | FILE_SYNCHRONOUS_IO_NONALERT,
        )
    if mode == "create":
        return (
            FILE_WRITE_DATA | FILE_READ_ATTRIBUTES | DELETE | SYNCHRONIZE,
            share,
            FILE_CREATE,
            FILE_OPEN_REPARSE_POINT | FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT,
        )
    # "check": attributes only, nothing read or written
    return (
        FILE_READ_ATTRIBUTES | SYNCHRONIZE,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        FILE_OPEN,
        FILE_OPEN_REPARSE_POINT | FILE_SYNCHRONOUS_IO_NONALERT,
    )


def _existing_leaf(native: _Native, parent: int, name: str, path: str, status: int) -> Exception:
    """An exclusive create met a name that exists: the existing object is
    opened as itself (attributes only) and named. A reparse point is the
    refusal of its kind (NTFS answers a directory junction with "is a
    directory" before "exists", so that status comes here too); a directory
    is `geen_gewoon_bestand`; a file is `FileExistsError` - the caller's own
    "already there" route (a scan lock held by another scan)."""
    first = status
    status, handle = native.NtCreateFile(
        parent,
        name,
        FILE_READ_ATTRIBUTES | SYNCHRONIZE,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        FILE_OPEN,
        FILE_OPEN_REPARSE_POINT | FILE_SYNCHRONOUS_IO_NONALERT,
    )
    if status != STATUS_SUCCESS or handle is None:
        return (
            _status_refusal(first, path, allow_missing=False)
            if first in _NOT_REGULAR
            else FileExistsError(errno.EEXIST, "bestaat al")
        )
    try:
        tag_status, attributes, tag = native.query_attribute_tag(handle)
    finally:
        native.NtClose(handle)
    if tag_status != STATUS_SUCCESS:
        return PathRefused("onleesbaar", path=path, status=tag_status, detail="tag")
    if attributes & FILE_ATTRIBUTE_REPARSE_POINT:
        soort = "koppeling" if tag in (IO_REPARSE_TAG_SYMLINK, IO_REPARSE_TAG_MOUNT_POINT) else "herparseerpunt"
        return PathRefused(soort, path=path, detail=f"tag 0x{tag:08X} bestaand blad")
    if attributes & FILE_ATTRIBUTE_DIRECTORY or first in _NOT_REGULAR:
        return PathRefused("geen_gewoon_bestand", path=path, status=first)
    return FileExistsError(errno.EEXIST, "bestaat al")


def _walk_windows(
    native: _Native,
    path: str,
    key: str,
    components: list[str],
    root_count: int | None,
    expect: str,
    mode: str,
    allow_missing: bool,
    shared_writers: bool,
) -> LocalHandle:
    """Steps 3 to 6 for one path text. Raises `_Follow` for a link above the root."""
    held: list[int] = []
    handed_over = False
    try:
        device = _volume_target(native, key, path)
        status, handle = native.NtCreateFile(
            None, device + "\\", DIR_ACCESS, DIR_SHARE, FILE_OPEN, FILE_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT
        )
        if status != STATUS_SUCCESS or handle is None:
            raise _status_refusal(status, path, allow_missing=False)
        held.append(handle)
        if native.GetFileType(handle) != FILE_TYPE_DISK:
            raise PathRefused("netwerkpad", path=path, detail="geen schijfhandle")
        status, device_type, characteristics = native.query_fs_device(handle)
        if status != STATUS_SUCCESS or device_type != FILE_DEVICE_DISK or characteristics & FILE_REMOTE_DEVICE:
            raise PathRefused("netwerkpad", path=path, status=status or None, detail="geen lokaal schijfapparaat")
        if not components and expect == "file":
            raise PathRefused("geen_gewoon_bestand", path=path, detail="volumewortel")
        last = len(components) - 1
        leaf: int | None = None
        for index, component in enumerate(components):
            if native.between is not None:
                native.between(index, component)
            is_leaf = index == last
            if is_leaf:
                access, share, disposition, options = _leaf_open(expect, mode, shared_writers)
            else:
                access, share, disposition, options = (
                    DIR_ACCESS,
                    DIR_SHARE,
                    FILE_OPEN,
                    FILE_OPEN_REPARSE_POINT | FILE_SYNCHRONOUS_IO_NONALERT,
                )
            status, handle = native.NtCreateFile(held[-1], component, access, share, disposition, options)
            if status != STATUS_SUCCESS or handle is None:
                if is_leaf and mode == "create" and (status == STATUS_OBJECT_NAME_COLLISION or status in _NOT_REGULAR):
                    raise _existing_leaf(native, held[-1], component, path, status)
                refusal = _status_refusal(status, path, allow_missing and mode in ("read", "check"))
                if isinstance(refusal, _Absent):
                    result = LocalHandle(native, held, None, path, exists=False, kind=expect)
                    handed_over = True
                    return result
                raise refusal
            held.append(handle)
            status, attributes, tag = native.query_attribute_tag(handle)
            if status != STATUS_SUCCESS:
                raise PathRefused("onleesbaar", path=path, status=status, detail="tag")
            if attributes & FILE_ATTRIBUTE_REPARSE_POINT:
                inside = root_count is not None and index >= root_count - 1
                is_link = tag in (IO_REPARSE_TAG_SYMLINK, IO_REPARSE_TAG_MOUNT_POINT)
                if inside:
                    soort = "koppeling" if is_link else "herparseerpunt"
                    raise PathRefused(soort, path=path, detail=f"tag 0x{tag:08X} onderdeel {index}")
                if not is_link:
                    raise PathRefused("herparseerpunt", path=path, detail=f"tag 0x{tag:08X} onderdeel {index}")
                raw = native.get_reparse_data(handle)
                if raw is None:
                    raise PathRefused("onleesbaar", path=path, detail="koppelingsgegevens")
                raise _Follow(_link_target(raw, key, components[:index], components[index + 1 :], path))
            is_directory = bool(attributes & FILE_ATTRIBUTE_DIRECTORY)
            if not (is_leaf and expect == "any") and is_directory != (not is_leaf or expect == "dir"):
                raise PathRefused("geen_gewoon_bestand", path=path, detail=f"onderdeel {index}")
        # The last handle is the leaf: the file, the directory, or (no
        # components) the volume root itself.
        leaf = held.pop() if components or expect != "file" else None
        result = LocalHandle(native, held, leaf, path, exists=True, kind=expect)
        handed_over = True
        return result
    finally:
        if not handed_over:
            _close_all(native, held)


# ---------------------------------------------------------------------------
# POSIX walk (logic runs only)
# ---------------------------------------------------------------------------


def _split_posix(text: str) -> list[str]:
    if not isinstance(text, str) or not text.startswith("/") or "\0" in text:
        raise PathRefused("onleesbaar", path=str(text), detail="niet absoluut")
    parts = [part for part in text.split("/")[1:]]
    if parts and parts[-1] == "":
        parts.pop()
    for part in parts:
        if part in ("", ".", ".."):
            raise PathRefused("onleesbaar", path=text, detail="leeg of punt-onderdeel")
        if ":" in part:
            raise PathRefused("stroom", path=text, detail=SPELLING_STREAM)
    return parts


def _walk_posix(
    native: _PosixNative,
    path: str,
    components: list[str],
    root_count: int | None,
    expect: str,
    mode: str,
    allow_missing: bool,
) -> LocalHandle:
    import stat as stat_module

    held: list[int] = []
    handed_over = False
    directory_flags = os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_DIRECTORY", 0)
    try:
        held.append(native.open_at(None, "/", directory_flags))
        last = len(components) - 1
        leaf: int | None = None
        for index, component in enumerate(components):
            if native.between is not None:
                native.between(index, component)
            is_leaf = index == last
            try:
                info = os.stat(component, dir_fd=held[-1], follow_symlinks=False)
            except FileNotFoundError:
                if allow_missing and mode in ("read", "check"):
                    result = LocalHandle(native, held, None, path, exists=False, kind=expect)
                    handed_over = True
                    return result
                raise PathRefused("onleesbaar", path=path, detail="afwezig") from None
            except OSError:
                raise PathRefused("onleesbaar", path=path) from None
            if stat_module.S_ISLNK(info.st_mode):
                if root_count is not None and index >= root_count - 1:
                    raise PathRefused("koppeling", path=path, detail=f"onderdeel {index}")
                target = os.readlink(component, dir_fd=held[-1])
                base = [] if target.startswith("/") else list(components[:index])
                for part in target.split("/"):
                    if part in ("", "."):
                        continue
                    if part == "..":
                        if base:
                            base.pop()
                        continue
                    base.append(part)
                raise _Follow("/" + "/".join(base + components[index + 1 :]))
            want_directory = not is_leaf or expect == "dir"
            if expect == "any" and is_leaf:
                want_directory = stat_module.S_ISDIR(info.st_mode)
            if want_directory:
                flags = directory_flags
            else:
                flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK
            try:
                handle = native.open_at(held[-1], component, flags)
            except OSError as exc:
                if exc.errno == errno.ELOOP:
                    raise PathRefused("koppeling", path=path) from None
                if exc.errno in (errno.ENOTDIR, errno.EISDIR):
                    raise PathRefused("geen_gewoon_bestand", path=path) from None
                raise PathRefused("onleesbaar", path=path) from None
            held.append(handle)
            kind = os.fstat(handle).st_mode
            if want_directory != stat_module.S_ISDIR(kind) or not (
                stat_module.S_ISDIR(kind) or stat_module.S_ISREG(kind)
            ):
                raise PathRefused("geen_gewoon_bestand", path=path, detail=f"onderdeel {index}")
            if is_leaf and not want_directory:
                leaf = held.pop()
        if expect in ("dir", "any") and leaf is None:
            leaf = held.pop()
        result = LocalHandle(native, held, leaf, path, exists=True, kind="dir" if expect == "any" else expect)
        if expect == "any" and leaf is not None and not stat_module.S_ISDIR(os.fstat(leaf).st_mode):
            result.kind = "file"
        handed_over = True
        return result
    finally:
        if not handed_over:
            _close_all(native, held)


# ---------------------------------------------------------------------------
# Public interface
# ---------------------------------------------------------------------------

_EXPECT = ("file", "dir")
_MODES = ("read", "append", "create")


def _open(
    path,
    *,
    root,
    expect: str,
    mode: str,
    allow_missing: bool,
    shared_writers: bool,
) -> LocalHandle:
    native = _native
    current = os.fspath(path)
    root_text = os.fspath(root) if root is not None else None
    hops = 0
    root_count: int | None = None
    try:
        while True:
            if isinstance(native, _Native):
                key, components = _split(current)
                if hops == 0 and root_text is not None:
                    components = _within(key, components, root_text)
                    root_count = len(_split(root_text)[1])
            else:
                components = _split_posix(current)
                key = ""
                if hops == 0 and root_text is not None:
                    root_components = _split_posix(root_text)
                    if components[: len(root_components)] != root_components:
                        raise PathRefused("buiten_wortel", path=current)
                    root_count = len(root_components)
            try:
                if isinstance(native, _Native):
                    return _walk_windows(
                        native, current, key, components, root_count, expect, mode, allow_missing, shared_writers
                    )
                return _walk_posix(native, current, components, root_count, expect, mode, allow_missing)
            except _Follow as follow:
                hops += 1
                if hops > LINK_LIMIT:
                    raise PathRefused("te_veel_koppelingen", path=follow.path) from None
                before = len(components)
                current = follow.path
                new_components = _split(current)[1] if isinstance(native, _Native) else _split_posix(current)
                if root_count is not None:
                    # The components below the root stay below it; only the ones before them changed.
                    root_count = len(new_components) - (before - root_count)
    except PathRefused as exc:
        if exc.path is None:
            exc.path = current
        exc.followed = hops > 0
        _log_refusal(exc)
        raise


@contextlib.contextmanager
def open_local(
    path,
    *,
    root=None,
    expect: str = "file",
    mode: str = "read",
    allow_missing: bool = False,
    shared_writers: bool = False,
) -> Iterator[LocalHandle]:
    """Opens `path` component by component (see the module docstring) and
    yields the held chain. `root`: the approved directory; nothing in it, the
    root itself included, may be a reparse point. `shared_writers`: the leaf
    is opened with `FILE_SHARE_READ | FILE_SHARE_WRITE` instead of
    `FILE_SHARE_READ` only - for a file another process appends to while it is
    read (the ledger, the runner log); a file whose bytes must stay fixed
    while held (a bundle, a sidecar, a key, an export file) keeps the default.
    `allow_missing` (read only): a missing component yields a handle with
    `exists == False` instead of a refusal."""
    if expect not in _EXPECT:
        raise ValueError(f"expect moet een van {_EXPECT} zijn")
    if mode not in _MODES or (expect == "dir" and mode != "read"):
        raise ValueError(f"mode moet een van {_MODES} zijn (een map alleen read)")
    if mode != "read":
        _require_windows_for_writing()
    handle = _open(
        path, root=root, expect=expect, mode=mode, allow_missing=allow_missing, shared_writers=shared_writers
    )
    try:
        yield handle
    finally:
        handle.close()


def check_where_it_leads(path, *, root=None, expect: str, allow_missing: bool = False) -> Path:
    """The same walk, opening and closing the chain, for the configuration
    check at start and for messages. Returns where the path leads (after the
    links above the root). Gives no licence for a later open by name: every
    product read goes through `open_local` again. `expect="any"` checks the
    place without asserting file or directory (the caller asserts the type
    with its own message)."""
    if expect not in (*_EXPECT, "any"):
        raise ValueError("expect moet file, dir of any zijn")
    handle = _open(path, root=root, expect=expect, mode="check", allow_missing=allow_missing, shared_writers=True)
    try:
        return Path(handle.path)
    finally:
        handle.close()


def read_local_bytes(path, *, root=None, max_bytes: int, shared_writers: bool = False) -> bytes:
    """At most `max_bytes + 1` bytes of the file, read on the held handle;
    more than `max_bytes` means over the cap (the caller's cap route)."""
    with open_local(path, root=root, expect="file", mode="read", shared_writers=shared_writers) as handle:
        return handle.read(max_bytes)


class LocalRead(NamedTuple):
    """One read of a file: `exists` False only with `allow_missing`; `size`
    is the size on the held handle; `over_cap` means nothing was read past
    the cap and `data` is empty - the caller's own cap route decides."""

    exists: bool
    data: bytes
    size: int
    over_cap: bool


def read_local(
    path, *, root=None, max_bytes: int, allow_missing: bool = False, shared_writers: bool = False
) -> LocalRead:
    """`open_local(..., mode="read")`, the size checked on the handle BEFORE a
    byte is read, then at most `max_bytes + 1` bytes read on the handle."""
    with open_local(
        path, root=root, expect="file", mode="read", allow_missing=allow_missing, shared_writers=shared_writers
    ) as handle:
        if not handle.exists:
            return LocalRead(False, b"", 0, False)
        size = handle.size()
        if size > max_bytes:
            return LocalRead(True, b"", size, True)
        data = handle.read(max_bytes)
        if len(data) > max_bytes:
            return LocalRead(True, b"", len(data), True)
        return LocalRead(True, data, len(data), False)


def read_configured(path, *, max_bytes: int, allow_missing: bool = False) -> LocalRead:
    """A file named by the configuration or on a command line, which has no
    approved directory around it (the configuration file, the targets file,
    the knowledge package, a regression matrix): `read_local` without a
    root on the absolute text of `path`. A link on the way is followed only
    after its target text passed the spelling and volume steps; the leaf
    itself is read on its held handle."""
    return read_local(absolute_text(path), root=None, max_bytes=max_bytes, allow_missing=allow_missing)


def as_text(data: bytes, encoding: str = "utf-8") -> str:
    """Bytes read on a handle as the text `Path.read_text` gave a reader
    before 1.1: decoded, and every `\\r\\n` and lone `\\r` turned into `\\n`
    (universal newlines), so a parse error names the same position as before."""
    return data.decode(encoding).replace("\r\n", "\n").replace("\r", "\n")


def create_local(path, data: bytes, *, root) -> None:
    """Creates the file exclusively (`FILE_CREATE`) relative to the held
    parent and writes `data` on its handle. An existing name raises
    `FileExistsError`, or the refusal of its kind when it is a reparse point
    (opened as itself, never followed)."""
    with open_local(path, root=root, expect="file", mode="create") as handle:
        handle.write(data)


_STRICT_ABSOLUTE = re.compile(r"^(?:[A-Za-z]:\\|\\\\[?.]\\)")


def absolute_text(path) -> str:
    """The text a walk is given for a configured path: the spelling rules
    first (on the text as written, before anything could drop a trailing dot
    or space), then - only for a path that is not already absolute - the
    absolute form against the working directory. An absolute text is
    returned as it is, so a root and a path below it built from the SAME
    text keep the same prefix (the walk compares it ordinally)."""
    text = os.fspath(path)
    check_spelling(text)
    if sys.platform != "win32":
        return text if text.startswith("/") else os.path.abspath(text)
    if not text.startswith("\\\\"):
        text = text.replace("/", "\\")
    if _STRICT_ABSOLUTE.match(text):
        return text
    return os.path.abspath(text)


def under(root_text: str, *parts: str) -> str:
    """`parts` below `root_text`, joined as text with the separator of the
    platform. Nothing is normalized: an empty, `.` or `..` part reaches the
    walk as it is and is refused there."""
    separator = "\\" if sys.platform == "win32" else "/"
    pieces = []
    for part in parts:
        pieces.extend(re.split(r"[\\/]", part))
    return separator.join([root_text.rstrip(separator), *pieces])


def parent_text(path_text: str) -> str:
    """The directory part of a path text (`C:\\a\\b.txt` -> `C:\\a`, `C:\\b`
    -> `C:\\`), by text: a root for a file whose own directory is the
    approved place (the ledger, the action register, the code file)."""
    separator = "\\" if sys.platform == "win32" else "/"
    head, _, _ = path_text.rstrip(separator).rpartition(separator)
    if head.endswith(":") or head == "" or head.endswith("\\\\?") or head.endswith("\\\\."):
        head += separator
    return head


def rename_local(path, new_name: str, *, root) -> None:
    """Renames the file or directory at `path` to `new_name` in the same,
    held parent, by the handle of what is renamed; never replaces an existing
    name (`FileExistsError`). What is renamed is opened as itself and refused
    when it is a reparse point."""
    _require_windows_for_writing()
    text = os.fspath(path)
    parent, _, name = text.rstrip("\\").rpartition("\\")
    if not name or not parent:
        raise PathRefused("onleesbaar", path=text, detail="geen naam")
    _split(text)
    if _components(new_name, new_name) != [new_name]:
        raise PathRefused("onleesbaar", path=text, detail="nieuwe naam is geen onderdeel")
    if parent.endswith(":"):
        parent += "\\"
    native = _native
    with open_local(parent, root=root, expect="dir") as held:
        directory = held.directory_handle
        status, handle = native.NtCreateFile(
            directory,
            name,
            DELETE | FILE_READ_ATTRIBUTES | SYNCHRONIZE,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            FILE_OPEN,
            FILE_OPEN_REPARSE_POINT | FILE_SYNCHRONOUS_IO_NONALERT,
        )
        if status != STATUS_SUCCESS or handle is None:
            refusal = _status_refusal(status, text, allow_missing=False)
            _log_refusal(refusal)
            raise refusal
        try:
            tag_status, attributes, tag = native.query_attribute_tag(handle)
            if tag_status != STATUS_SUCCESS:
                raise PathRefused("onleesbaar", path=text, status=tag_status, detail="tag")
            if attributes & FILE_ATTRIBUTE_REPARSE_POINT:
                soort = "koppeling" if tag in (IO_REPARSE_TAG_SYMLINK, IO_REPARSE_TAG_MOUNT_POINT) else "herparseerpunt"
                raise PathRefused(soort, path=text, detail=f"tag 0x{tag:08X} te hernoemen")
            status = native.set_rename(handle, directory, new_name, replace=False)
            if status == STATUS_OBJECT_NAME_COLLISION:
                raise FileExistsError(errno.EEXIST, "de nieuwe naam bestaat al")
            if status != STATUS_SUCCESS:
                raise _status_refusal(status, text, allow_missing=False)
        except PathRefused as exc:
            _log_refusal(exc)
            raise
        finally:
            native.NtClose(handle)


@contextlib.contextmanager
def open_local_for_append(path, *, root, shared_writers: bool = False) -> Iterator[LocalHandle]:
    """The chain to the parent held, the leaf opened for append (created when
    missing). An existing leaf that is a reparse point is opened as itself and
    refused before a byte is written. Write with `LocalHandle.write`, which
    flushes."""
    with open_local(path, root=root, expect="file", mode="append", shared_writers=shared_writers) as handle:
        yield handle


def replace_local(path, data: bytes, *, root) -> None:
    """Replaces the file at `path` with `data`: a temporary file with a random
    name created exclusively relative to the held parent, written and flushed;
    an existing target opened as itself and refused when it is a reparse point
    or a directory (nothing destructive happens before every check is done);
    then a rename of the temporary file by its handle onto the target name,
    relative to the held parent. On a failure only the own temporary file is
    removed, through its handle."""
    _require_windows_for_writing()
    text = os.fspath(path)
    parent_text, _, name = text.rstrip("\\").rpartition("\\")
    if not name or not parent_text:
        raise PathRefused("onleesbaar", path=text, detail="geen bestandsnaam")
    _split(text)  # the whole spelling, the name included, before anything opens
    if parent_text.endswith(":"):
        parent_text += "\\"
    with open_local(parent_text, root=root, expect="dir") as parent:
        _replace_windows(_native, parent, name, data, text)


def _require_windows_for_writing() -> None:
    """Off Windows nothing is written through this module: the product is
    Windows-only, the POSIX walk exists for the logic runs of the read route,
    and a write route that no run of this repository executes is not offered."""
    if not isinstance(_native, _Native):
        raise NotImplementedError("schrijven via nsmcp.localpath bestaat alleen op Windows")


def _replace_windows(native: _Native, parent: LocalHandle, name: str, data: bytes, path: str) -> None:
    directory = parent.directory_handle
    if directory is None:
        raise PathRefused("onleesbaar", path=path, detail="geen ouder")
    status, existing = native.NtCreateFile(
        directory,
        name,
        FILE_READ_ATTRIBUTES | SYNCHRONIZE,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        FILE_OPEN,
        FILE_OPEN_REPARSE_POINT | FILE_SYNCHRONOUS_IO_NONALERT,
    )
    if status == STATUS_SUCCESS and existing is not None:
        try:
            tag_status, attributes, tag = native.query_attribute_tag(existing)
        finally:
            native.NtClose(existing)
        if tag_status != STATUS_SUCCESS:
            raise PathRefused("onleesbaar", path=path, status=tag_status, detail="tag")
        if attributes & FILE_ATTRIBUTE_REPARSE_POINT:
            soort = "koppeling" if tag in (IO_REPARSE_TAG_SYMLINK, IO_REPARSE_TAG_MOUNT_POINT) else "herparseerpunt"
            raise PathRefused(soort, path=path, detail=f"tag 0x{tag:08X} doel")
        if attributes & FILE_ATTRIBUTE_DIRECTORY:
            raise PathRefused("geen_gewoon_bestand", path=path, detail="doel is een map")
    elif status not in _ABSENT:
        raise _status_refusal(status, path, allow_missing=False)
    temporary = f".{secrets.token_hex(8)}.nsmcp-tmp"
    status, handle = native.NtCreateFile(
        directory,
        temporary,
        FILE_WRITE_DATA | FILE_READ_ATTRIBUTES | DELETE | SYNCHRONIZE,
        0,
        FILE_CREATE,
        FILE_NON_DIRECTORY_FILE | FILE_OPEN_REPARSE_POINT | FILE_SYNCHRONOUS_IO_NONALERT,
    )
    if status != STATUS_SUCCESS or handle is None:
        raise _status_refusal(status, path, allow_missing=False)
    renamed = False
    try:
        own = LocalHandle(native, [], handle, path, exists=True, kind="file")
        own.write(data)
        status = native.set_rename(handle, directory, name)
        if status != STATUS_SUCCESS:
            raise _status_refusal(status, path, allow_missing=False)
        renamed = True
    finally:
        if not renamed:
            native.set_delete(handle)
        native.NtClose(handle)


def drive_is_remote(drive: str) -> bool:
    """Whether `drive` (`Z:`) is a network drive, by `GetDriveTypeW` on the
    seam: it reads the local drive mapping and opens nothing on the share."""
    if not isinstance(_native, _Native) or len(drive) != 2 or drive[1] != ":":
        return False
    return _native.GetDriveTypeW(drive + "\\") == DRIVE_REMOTE
