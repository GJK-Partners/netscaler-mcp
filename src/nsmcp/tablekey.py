"""Integrity of the pseudonym table (1.1 C, SR-7): the table slot, the anchor
record, the protected key, the row HMAC chain and the commit protocol.

Why this module exists: the table maps every pseudonym back to a real name,
and at `openheid: beperkt` the writing path resolves a pseudonym the human
confirmed into the real object a script acts on. A table whose rows were
swapped is still a well-formed table. So every row carries an HMAC over its
content and the MAC of the row before it (a hash chain), under a key that is
protected with Windows DPAPI, and the last committed state of the table lives
OUTSIDE the file, in an anchor record in HKCU that a party that can only write
files cannot write.

The four facts, each with one owner here:

1. The SLOT is the identity of the PLACE of the table: the serial number of
   its volume and the normalized name of its directory, both read on the
   handles the `localpath` walk of the CONFIGURED path holds (never read from
   the offered file). A table at another place has another slot and therefore
   no anchor.
2. The ANCHOR (`HKCU\\Software\\GJK\\netscaler-mcp\\vertaaltabel\\anker-<slot>`,
   value `record`) holds the active table id, the generation, the count and
   the chain in ONE record, written with ONE `RegSetValueExW` and validated in
   full before any field is used. Only the explicit creation, migration,
   restore and reset routes change it, and every write re-reads the record
   under the same lock first: a delayed writer can never move it back.
3. The KEY (32 random bytes) lies next to the table, protected with DPAPI in
   the user context with the slot, the table id and the generation as extra
   entropy: the key of another generation or another place does not open.
4. The CHAIN: `mac_i` covers slot, id, generation, row number, pseudonym, real
   name and `mac_{i-1}`; the head covers the count and the last MAC. Every
   comparison is `hmac.compare_digest`.

A deviation is a `Fault` with a kind (`soort`) and at most a row position;
`disclosure.py` owns the sentences. Nothing here ever repairs, overwrites or
chooses an identity out of the offered file. Every commit point of every
route is a `_step(label)` call below (a1-a4, t1-t2, m2-m6, h2-h3, r1-r5), so
a test can crash right there.

Every read and write of a file goes through `localpath`, relative to the table
directory the caller's lock holds; `directory_names()` lists NAMES (never
contents) on the held directory handle, not on a path text.
"""

from __future__ import annotations

import ctypes
import datetime
import hashlib
import hmac
import json
import os
import re
import secrets
import sys
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path

from nsmcp import localpath

TABLE_FORMAT = "nsmcp-vertaaltabel/2"
ANCHOR_FORMAT = "nsmcp-vt-anker/1"
# A module constant on purpose: no environment variable and no configuration
# field may point the anchor somewhere else (a file-writing party could then
# choose the anchor too). Tests replace `_registry`, the seam, not this text.
REGISTRY_BASE = "Software\\GJK\\netscaler-mcp\\vertaaltabel"
ANCHOR_VALUE = "record"
ZERO_CHAIN = "0" * 64
MAX_DISCARDED = 32
KEY_MAGIC = b"NSMCPVK1"
KEY_BYTES = 32
KEY_FILE_CAP = 4096

STATES = ("vastgelegd", "aanmaak", "migratie", "reset")
SOORTEN = (
    "mac",
    "keten",
    "kop",
    "teruggedraaid",
    "anker_ontbreekt",
    "anker_onleesbaar",
    "bestand_ontbreekt",
    "sleutel_ontbreekt",
    "sleutel_onleesbaar",
    "tabelid",
    "afgedankt",
    "slot",
    "aanmaak_onderbroken",
    "migratie_onderbroken",
    "reset_onderbroken",
    "formaat",
)

_HEX64 = re.compile(r"[0-9a-f]{64}")
_HEX32 = re.compile(r"[0-9a-f]{32}")


# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------


class Fault(Exception):
    """An integrity deviation. `soort` is one of `SOORTEN`; `positie` is a
    1-based row position or None; `vorm` distinguishes the three `formaat`
    cases (`"1"`: the 1.0.x form without an anchor, `"1-naast-anker"`: the
    1.0.x form at a place that has an anchor, `"2"`: a broken form 2). Never
    carries table content, an id or a pseudonym."""

    def __init__(self, soort: str, positie: int | None = None, *, vorm: str = "") -> None:
        if soort not in SOORTEN:
            raise ValueError(soort)
        super().__init__(soort)
        self.soort = soort
        self.positie = positie
        self.vorm = vorm


class PlaceRefused(Exception):
    """A file of the table family does not lie as a plain local file in the
    table's directory (`localpath.PathRefused`); `what` names which file."""

    def __init__(self, what: str, exc: localpath.PathRefused) -> None:
        super().__init__(what)
        self.what = what
        self.exc = exc


class FileFailed(Exception):
    """A file of the table family could not be read or written for another
    reason (access, a full disk). `what` names the file; `exc` the cause."""

    def __init__(self, what: str, exc: BaseException) -> None:
        super().__init__(what)
        self.what = what
        self.exc = exc


class Stop(Exception):
    """A CLI route stops with a human sentence; nothing after the last commit
    point was written."""


class AnchorStoreError(Exception):
    """The anchor store itself failed (not: the record is absent)."""


class KeyUnprotectError(Exception):
    """DPAPI refused to open a key blob (another account, another machine,
    other entropy, a damaged blob)."""


# ---------------------------------------------------------------------------
# Seams: the registry, DPAPI and the crash points
# ---------------------------------------------------------------------------


class _WinRegistry:
    """The anchor store in HKCU. One `RegQueryValueExW` to read, one
    `RegSetValueExW` to write the whole record."""

    def __init__(self, base: str) -> None:
        self.base = base

    def _key(self, slot: str) -> str:
        return f"{self.base}\\anker-{slot}"

    def read(self, slot: str) -> str | None:
        import winreg

        try:
            key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, self._key(slot), 0, winreg.KEY_QUERY_VALUE)
        except FileNotFoundError:
            return None
        except OSError as exc:
            raise AnchorStoreError("openen") from exc
        with key:
            try:
                value, kind = winreg.QueryValueEx(key, ANCHOR_VALUE)
            except FileNotFoundError:
                return None
            except OSError as exc:
                raise AnchorStoreError("lezen") from exc
        if kind != winreg.REG_SZ or not isinstance(value, str):
            raise AnchorStoreError("type")
        return value

    def write(self, slot: str, text: str) -> None:
        import winreg

        with winreg.CreateKeyEx(winreg.HKEY_CURRENT_USER, self._key(slot), 0, winreg.KEY_SET_VALUE) as key:
            winreg.SetValueEx(key, ANCHOR_VALUE, 0, winreg.REG_SZ, text)


class MemoryRegistry:
    """The anchor store for tests: a dict, with the same read/write contract.
    A value that is not a `str` reads as a store error (a wrong value type)."""

    def __init__(self) -> None:
        self.values: dict[str, object] = {}
        self.writes: list[tuple[str, str]] = []

    def read(self, slot: str) -> str | None:
        if slot not in self.values:
            return None
        value = self.values[slot]
        if not isinstance(value, str):
            raise AnchorStoreError("type")
        return value

    def write(self, slot: str, text: str) -> None:
        self.values[slot] = text
        self.writes.append((slot, text))


class _DataBlob(ctypes.Structure):
    _fields_ = [("cbData", ctypes.c_ulong), ("pbData", ctypes.POINTER(ctypes.c_char))]


CRYPTPROTECT_UI_FORBIDDEN = 0x1


class _Dpapi:
    """`CryptProtectData` / `CryptUnprotectData` in the user context. Not the
    Credential Manager: nothing is stored by Windows, the blob is ours."""

    @staticmethod
    def _blob(data: bytes) -> tuple[_DataBlob, object]:
        buffer = ctypes.create_string_buffer(data, len(data))
        return _DataBlob(len(data), ctypes.cast(buffer, ctypes.POINTER(ctypes.c_char))), buffer

    def _call(self, name: str, data: bytes, entropy: bytes) -> bytes | None:
        if sys.platform != "win32":
            raise KeyUnprotectError("geen Windows")
        crypt32 = ctypes.WinDLL("crypt32")
        kernel32 = ctypes.WinDLL("kernel32")
        function = getattr(crypt32, name)
        function.restype = ctypes.c_int
        source, keep_source = self._blob(data)
        extra, keep_extra = self._blob(entropy)
        out = _DataBlob()
        ok = function(
            ctypes.byref(source),
            None,
            ctypes.byref(extra),
            None,
            None,
            CRYPTPROTECT_UI_FORBIDDEN,
            ctypes.byref(out),
        )
        del keep_source, keep_extra
        if not ok:
            return None
        try:
            return ctypes.string_at(out.pbData, out.cbData)
        finally:
            kernel32.LocalFree(out.pbData)

    def protect(self, data: bytes, entropy: bytes) -> bytes:
        blob = self._call("CryptProtectData", data, entropy)
        if blob is None:
            raise OSError("CryptProtectData mislukte")
        return blob

    def unprotect(self, blob: bytes, entropy: bytes) -> bytes:
        data = self._call("CryptUnprotectData", blob, entropy)
        if data is None:
            raise KeyUnprotectError("CryptUnprotectData weigerde")
        return data


_registry: _WinRegistry | MemoryRegistry = _WinRegistry(REGISTRY_BASE)
_dpapi = _Dpapi()


def _no_crash(label: str) -> None:
    return None


# Called after every commit point with its label (a1..a4, t1, t2, m2..m6, h2,
# h3, r1..r5); a test replaces it to crash exactly there.
_after_step: Callable[[str], None] = _no_crash


def _step(label: str) -> None:
    _after_step(label)


# ---------------------------------------------------------------------------
# The slot and the place
# ---------------------------------------------------------------------------


def compute_slot(volume_serial: int, directory: str, table_name: str) -> str:
    """SHA-256 over the volume serial, the components of the normalized
    directory name and the table name, all case-folded to upper, separated by
    NUL. Inputs come from held handles only (`place_of`)."""
    parts = [part.upper() for part in directory.split("\\") if part]
    text = "\0".join(["nsmcp-vt-slot/1", f"{volume_serial:08x}", *parts, table_name.upper()])
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def key_path(table: Path) -> Path:
    """The key file beside the table: the table's stem with `.sleutel`."""
    return table.with_suffix(".sleutel")


@dataclass(frozen=True)
class Place:
    table: Path
    root: str
    slot: str
    # The chain the caller's lock holds; the directory listing is read on it.
    held: localpath.LocalHandle | None = field(default=None, compare=False, repr=False)

    @property
    def table_name(self) -> str:
        return self.table.name

    @property
    def key_name(self) -> str:
        return key_path(self.table).name


def place_of(table: Path, root: str, held: localpath.LocalHandle) -> Place:
    """The place of the table, from the chain the caller's lock holds (every
    directory from the volume root to the table's directory, held without
    delete sharing). A place that cannot be established is `slot`.

    The table's own name is its STORED name when the file exists
    (`localpath.leaf_name`, on the handle of a walk from the held directory),
    so an 8.3 spelling or another case of the file name gives the same slot;
    only when there is no file yet does the configured name stand in."""
    try:
        serial = held.volume_serial()
        directory = held.directory_name()
    except localpath.PathRefused:
        raise Fault("slot") from None
    try:
        stored = localpath.leaf_name(localpath.under(root, table.name), root=root)
    except localpath.PathRefused as exc:
        raise PlaceRefused("de vertaaltabel", exc) from exc
    except OSError as exc:
        raise FileFailed("de vertaaltabel", exc) from exc
    return Place(table, root, compute_slot(serial, directory, stored or table.name), held)


def directory_names(place: Place) -> list[str]:
    """The NAMES in the held table directory - never their contents (every
    content read afterwards goes through `localpath`). Read on the directory
    handle the caller's lock holds (`LocalHandle.directory_names`), never on
    a path text: a link above the root that the walk followed cannot be
    swapped between the walk and this listing."""
    if place.held is None:
        raise FileFailed("de map van de vertaaltabel", OSError("geen vastgehouden map"))
    try:
        return place.held.directory_names()
    except localpath.PathRefused as exc:
        raise PlaceRefused("de map van de vertaaltabel", exc) from exc


def _leftovers(place: Place) -> bool:
    prefixes = (f"{place.table_name}.afgedankt-", f"{place.table_name}.v1-", f"{place.key_name}.afgedankt-")
    return any(name.startswith(prefixes) for name in directory_names(place))


# ---------------------------------------------------------------------------
# Files, always through localpath
# ---------------------------------------------------------------------------


def _read(place: Place, name: str, what: str, cap: int) -> bytes | None:
    try:
        got = localpath.read_local(
            localpath.under(place.root, name), root=place.root, max_bytes=cap, allow_missing=True
        )
    except localpath.PathRefused as exc:
        raise PlaceRefused(what, exc) from exc
    except OSError as exc:
        raise FileFailed(what, exc) from exc
    if not got.exists:
        return None
    if got.over_cap:
        raise FileFailed(what, OSError("groter dan het plafond"))
    return got.data


def _replace(place: Place, name: str, data: bytes, what: str) -> None:
    try:
        localpath.replace_local(localpath.under(place.root, name), data, root=place.root)
    except localpath.PathRefused as exc:
        raise PlaceRefused(what, exc) from exc
    except OSError as exc:
        raise FileFailed(what, exc) from exc


def _create(place: Place, name: str, data: bytes, what: str) -> None:
    try:
        localpath.create_local(localpath.under(place.root, name), data, root=place.root)
    except localpath.PathRefused as exc:
        raise PlaceRefused(what, exc) from exc
    except FileExistsError:
        raise
    except OSError as exc:
        raise FileFailed(what, exc) from exc


def _rename(place: Place, name: str, new_name: str, what: str) -> str:
    """Renames in the held directory, never over an existing name: on a
    collision a random suffix is added. Nothing is ever deleted."""
    candidate = new_name
    for _attempt in range(8):
        try:
            localpath.rename_local(localpath.under(place.root, name), candidate, root=place.root)
            return candidate
        except FileExistsError:
            candidate = f"{new_name}-{secrets.token_hex(4)}"
        except localpath.PathRefused as exc:
            raise PlaceRefused(what, exc) from exc
        except OSError as exc:
            raise FileFailed(what, exc) from exc
    raise FileFailed(what, FileExistsError("geen vrije naam"))


# ---------------------------------------------------------------------------
# The anchor record
# ---------------------------------------------------------------------------


def _canonical(value: object) -> str:
    return json.dumps(value, sort_keys=True, ensure_ascii=True, separators=(",", ":"))


def _is_int(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


@dataclass(frozen=True)
class Anchor:
    slot: str
    tabel_id: str | None
    generatie: int
    aantal: int
    keten: str
    toestand: str
    nieuw: dict | None
    afgedankt: tuple[str, ...]

    def body(self) -> dict:
        body: dict = {
            "formaat": ANCHOR_FORMAT,
            "slot": self.slot,
            "tabelId": self.tabel_id,
            "generatie": self.generatie,
            "aantal": self.aantal,
            "keten": self.keten,
            "toestand": self.toestand,
            "afgedankt": list(self.afgedankt),
        }
        if self.nieuw is not None:
            body["nieuw"] = dict(self.nieuw)
        return body

    def text(self) -> str:
        body = self.body()
        body["controle"] = hashlib.sha256(_canonical(body).encode("ascii")).hexdigest()
        return _canonical(body)


def _anchor_shape_ok(record: dict, slot: str) -> bool:
    keys = {"formaat", "slot", "tabelId", "generatie", "aantal", "keten", "toestand", "afgedankt", "controle"}
    toestand = record.get("toestand")
    if toestand not in STATES:
        return False
    interrupted = toestand != "vastgelegd"
    if set(record) != (keys | {"nieuw"} if interrupted else keys):
        return False
    if record["formaat"] != ANCHOR_FORMAT or record["slot"] != slot:
        return False
    tabel_id, generatie, aantal, keten = record["tabelId"], record["generatie"], record["aantal"], record["keten"]
    if not (_is_int(generatie) and _is_int(aantal) and isinstance(keten, str) and _HEX64.fullmatch(keten)):
        return False
    afgedankt = record["afgedankt"]
    if not isinstance(afgedankt, list) or len(afgedankt) > MAX_DISCARDED:
        return False
    if not all(isinstance(item, str) and _HEX32.fullmatch(item) for item in afgedankt):
        return False
    if tabel_id is None:
        if toestand == "vastgelegd" or generatie != 0 or aantal != 0 or keten != ZERO_CHAIN:
            return False
    elif not (isinstance(tabel_id, str) and _HEX32.fullmatch(tabel_id) and generatie >= 1 and aantal >= 0):
        return False
    if tabel_id is not None and tabel_id in afgedankt:
        return False
    if toestand in ("aanmaak", "migratie") and tabel_id is not None:
        return False
    if interrupted:
        nieuw = record["nieuw"]
        wanted = {"tabelId", "generatie", "bron"} if toestand == "migratie" else {"tabelId", "generatie"}
        if not isinstance(nieuw, dict) or set(nieuw) != wanted:
            return False
        if not (isinstance(nieuw["tabelId"], str) and _HEX32.fullmatch(nieuw["tabelId"])):
            return False
        if not _is_int(nieuw["generatie"]) or nieuw["generatie"] <= generatie:
            return False
        if nieuw["tabelId"] == tabel_id or nieuw["tabelId"] in afgedankt:
            return False
        if toestand == "migratie" and not (isinstance(nieuw["bron"], str) and _HEX64.fullmatch(nieuw["bron"])):
            return False
    return True


def parse_anchor(text: str, slot: str) -> Anchor:
    """The record, validated in full; any deviation is `anker_onleesbaar`."""
    try:
        record = json.loads(text)
    except (ValueError, RecursionError):
        raise Fault("anker_onleesbaar") from None
    if not isinstance(record, dict) or not _anchor_shape_ok(record, slot):
        raise Fault("anker_onleesbaar")
    without = {key: value for key, value in record.items() if key != "controle"}
    expected = hashlib.sha256(_canonical(without).encode("ascii")).hexdigest()
    if not hmac.compare_digest(expected, record["controle"]) or _canonical(record) != text:
        raise Fault("anker_onleesbaar")
    return Anchor(
        slot=record["slot"],
        tabel_id=record["tabelId"],
        generatie=record["generatie"],
        aantal=record["aantal"],
        keten=record["keten"],
        toestand=record["toestand"],
        nieuw=record.get("nieuw"),
        afgedankt=tuple(record["afgedankt"]),
    )


def read_anchor_raw(slot: str) -> str | None:
    try:
        return _registry.read(slot)
    except AnchorStoreError:
        raise Fault("anker_onleesbaar") from None


def write_anchor(place: Place, expected_raw: str | None, new: Anchor, label: str) -> str:
    """Writes the whole record in one store write, after re-reading it under
    the same lock: the record must still be the one the caller read
    (`expected_raw`), and (generation, count) never goes down. Anything else
    writes nothing."""
    current = read_anchor_raw(place.slot)
    if current != expected_raw:
        raise Fault("anker_onleesbaar")
    if current is not None:
        try:
            old = parse_anchor(current, place.slot)
        except Fault:
            old = None
        if old is not None and (new.generatie, new.aantal) < (old.generatie, old.aantal):
            raise Fault("teruggedraaid")
    text = new.text()
    try:
        _registry.write(place.slot, text)
    except OSError as exc:
        raise FileFailed("het anker van de vertaaltabel", exc) from exc
    _step(label)
    return text


# ---------------------------------------------------------------------------
# The table document, the MACs and the key
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Row:
    nr: int
    pseudoniem: str
    naam: str
    mac: str


@dataclass(frozen=True)
class TableDoc:
    slot: str
    tabel_id: str
    generatie: int
    rows: tuple[Row, ...]
    aantal: int
    keten: str
    kop_mac: str


@dataclass(frozen=True)
class TableBinding:
    """What a write confirmation binds: the place, the table identity and the
    exact row a pseudonym resolved through."""

    slot: str
    tabel_id: str
    generatie: int
    nr: int
    mac: str

    def channel_line(self) -> str:
        """The operator's presentation: never a name, never a pseudonym."""
        return f"vertaaltabel: {self.tabel_id[:8]}, generatie {self.generatie}, rij {self.nr}"


def is_form_1(raw: object) -> bool:
    """The 1.0.x form: a flat JSON object pseudonym -> name, no `formaat`."""
    return isinstance(raw, dict) and "formaat" not in raw


def parse_doc(raw: object) -> TableDoc:
    """Form 2, exactly; anything else is `formaat` (form 2)."""

    def bad() -> Fault:
        return Fault("formaat", vorm="2")

    if not isinstance(raw, dict) or set(raw) != {"formaat", "slot", "tabelId", "generatie", "rijen", "kop"}:
        raise bad()
    if raw["formaat"] != TABLE_FORMAT:
        raise bad()
    slot, tabel_id, generatie = raw["slot"], raw["tabelId"], raw["generatie"]
    if not (isinstance(slot, str) and _HEX64.fullmatch(slot)):
        raise bad()
    if not (isinstance(tabel_id, str) and _HEX32.fullmatch(tabel_id)):
        raise bad()
    if not _is_int(generatie) or generatie < 1:
        raise bad()
    rows = raw["rijen"]
    kop = raw["kop"]
    if not isinstance(rows, list) or not isinstance(kop, dict) or set(kop) != {"aantal", "keten", "mac"}:
        raise bad()
    parsed: list[Row] = []
    for row in rows:
        if not isinstance(row, dict) or set(row) != {"nr", "pseudoniem", "naam", "mac"}:
            raise bad()
        nr, pseudoniem, naam, mac = row["nr"], row["pseudoniem"], row["naam"], row["mac"]
        if not _is_int(nr) or not isinstance(pseudoniem, str) or not isinstance(naam, str):
            raise bad()
        if "\0" in pseudoniem or "\0" in naam or not (isinstance(mac, str) and _HEX64.fullmatch(mac)):
            raise bad()
        parsed.append(Row(nr, pseudoniem, naam, mac))
    aantal, keten, kop_mac = kop["aantal"], kop["keten"], kop["mac"]
    if not _is_int(aantal) or not (isinstance(keten, str) and _HEX64.fullmatch(keten)):
        raise bad()
    if not (isinstance(kop_mac, str) and _HEX64.fullmatch(kop_mac)):
        raise bad()
    return TableDoc(slot, tabel_id, generatie, tuple(parsed), aantal, keten, kop_mac)


def doc_bytes(doc: TableDoc) -> bytes:
    body = {
        "formaat": TABLE_FORMAT,
        "slot": doc.slot,
        "tabelId": doc.tabel_id,
        "generatie": doc.generatie,
        "rijen": [{"nr": r.nr, "pseudoniem": r.pseudoniem, "naam": r.naam, "mac": r.mac} for r in doc.rows],
        "kop": {"aantal": doc.aantal, "keten": doc.keten, "mac": doc.kop_mac},
    }
    return json.dumps(body, indent=2, ensure_ascii=False).replace("\n", os.linesep).encode("utf-8")


def _join(*parts: object) -> bytes:
    return b"\0".join(str(part).encode("utf-8") for part in parts)


def row_mac(
    key: bytes, slot: str, tabel_id: str, generatie: int, nr: int, pseudoniem: str, naam: str, prev: str
) -> str:
    message = _join("nsmcp-vt/2", slot, tabel_id, generatie, nr, pseudoniem, naam, prev)
    return hmac.new(key, message, hashlib.sha256).hexdigest()


def head_mac(key: bytes, slot: str, tabel_id: str, generatie: int, aantal: int, keten: str) -> str:
    message = _join("nsmcp-vt/2-kop", slot, tabel_id, generatie, aantal, keten)
    return hmac.new(key, message, hashlib.sha256).hexdigest()


def build_doc(
    key: bytes, slot: str, tabel_id: str, generatie: int, pairs: list[tuple[str, str]], base: TableDoc | None = None
) -> TableDoc:
    """A signed document: `base`'s rows (unchanged) followed by `pairs`."""
    rows = list(base.rows) if base is not None else []
    prev = rows[-1].mac if rows else ZERO_CHAIN
    for pseudoniem, naam in pairs:
        nr = len(rows) + 1
        prev = row_mac(key, slot, tabel_id, generatie, nr, pseudoniem, naam, prev)
        rows.append(Row(nr, pseudoniem, naam, prev))
    keten = rows[-1].mac if rows else ZERO_CHAIN
    kop = head_mac(key, slot, tabel_id, generatie, len(rows), keten)
    return TableDoc(slot, tabel_id, generatie, tuple(rows), len(rows), keten, kop)


def verify_doc(doc: TableDoc, key: bytes) -> None:
    """Row MACs in order (`mac`), row numbers 1..n without a gap (`keten`),
    and the head (`kop`)."""
    prev = ZERO_CHAIN
    for position, row in enumerate(doc.rows, start=1):
        if row.nr != position:
            raise Fault("keten", position)
        expected = row_mac(key, doc.slot, doc.tabel_id, doc.generatie, row.nr, row.pseudoniem, row.naam, prev)
        if not hmac.compare_digest(expected, row.mac):
            raise Fault("mac", position)
        prev = row.mac
    if doc.aantal != len(doc.rows) or not hmac.compare_digest(doc.keten, prev):
        raise Fault("kop")
    expected_head = head_mac(key, doc.slot, doc.tabel_id, doc.generatie, doc.aantal, doc.keten)
    if not hmac.compare_digest(expected_head, doc.kop_mac):
        raise Fault("kop")


def watermark(doc: TableDoc, anchor: Anchor) -> bool:
    """Load rule 8 against the anchor. True when the table is AHEAD of the
    anchor (a crash after the table, before the anchor): the caller moves the
    anchor forward, which is only reached after `verify_doc` proved the whole
    chain with the valid key."""
    if doc.aantal < anchor.aantal:
        raise Fault("teruggedraaid")
    at = doc.rows[anchor.aantal - 1].mac if anchor.aantal else ZERO_CHAIN
    if not hmac.compare_digest(at, anchor.keten):
        raise Fault("keten", anchor.aantal or None)
    return doc.aantal > anchor.aantal


def entropy(slot: str, tabel_id: str, generatie: int) -> bytes:
    return _join("nsmcp-vertaaltabel/2", slot, tabel_id, generatie)


def wrap_key(key: bytes, slot: str, tabel_id: str, generatie: int) -> bytes:
    return KEY_MAGIC + _dpapi.protect(key, entropy(slot, tabel_id, generatie))


def unwrap_key(data: bytes, slot: str, tabel_id: str, generatie: int) -> bytes:
    if not data.startswith(KEY_MAGIC):
        raise Fault("sleutel_onleesbaar")
    try:
        key = _dpapi.unprotect(data[len(KEY_MAGIC) :], entropy(slot, tabel_id, generatie))
    except (KeyUnprotectError, OSError):
        raise Fault("sleutel_onleesbaar") from None
    if len(key) != KEY_BYTES:
        raise Fault("sleutel_onleesbaar")
    return key


def _active_id(anchor: Anchor) -> str:
    """The active id of a committed anchor (the shape check guarantees one)."""
    if anchor.tabel_id is None:
        raise Fault("anker_onleesbaar")
    return anchor.tabel_id


def _identity(doc: TableDoc, anchor: Anchor, slot: str) -> None:
    """Load rule 5: the file's copy of slot, id and generation against the
    COMPUTED slot and the ANCHOR. Never a choice, only a comparison."""
    if doc.slot != slot:
        raise Fault("slot")
    if doc.tabel_id in anchor.afgedankt:
        raise Fault("afgedankt")
    if doc.tabel_id != anchor.tabel_id or doc.generatie != anchor.generatie:
        raise Fault("tabelid")


# ---------------------------------------------------------------------------
# Loading (rules 1-8) and appending
# ---------------------------------------------------------------------------


@dataclass
class Verified:
    """A table that passed rules 1-8 under the caller's lock."""

    place: Place
    anchor_raw: str
    anchor: Anchor
    doc: TableDoc
    key: bytes

    def mapping(self) -> dict[str, str]:
        return {row.pseudoniem: row.naam for row in self.doc.rows}

    def binding(self, pseudoniem: str) -> TableBinding | None:
        for row in self.doc.rows:
            if row.pseudoniem == pseudoniem:
                return TableBinding(self.doc.slot, self.doc.tabel_id, self.doc.generatie, row.nr, row.mac)
        return None


Parse = Callable[[bytes, Path], object]


def _empty_table(place: Place, key: bytes, tabel_id: str, generatie: int) -> TableDoc:
    doc = build_doc(key, place.slot, tabel_id, generatie, [])
    _replace(place, place.table_name, doc_bytes(doc), "de vertaaltabel")
    return doc


def _first_start(place: Place) -> Verified:
    """Creation, a1-a4."""
    tabel_id = secrets.token_hex(16)
    pending = Anchor(place.slot, None, 0, 0, ZERO_CHAIN, "aanmaak", {"tabelId": tabel_id, "generatie": 1}, ())
    raw = write_anchor(place, None, pending, "a1")
    return _finish_creation(place, raw, pending, None, None)


def _finish_creation(
    place: Place, raw: str, pending: Anchor, table: bytes | None, key_data: bytes | None, parse: Parse | None = None
) -> Verified:
    """a2-a4, also the resumption of an interrupted creation: only on the id
    in `nieuw`; a file with another identity is `aanmaak_onderbroken`."""
    assert pending.nieuw is not None
    tabel_id, generatie = pending.nieuw["tabelId"], pending.nieuw["generatie"]
    if key_data is None:
        if table is not None:
            raise Fault("aanmaak_onderbroken")
        key = secrets.token_bytes(KEY_BYTES)
        _create(place, place.key_name, wrap_key(key, place.slot, tabel_id, generatie), "het sleutelbestand")
        _step("a2")
    else:
        try:
            key = unwrap_key(key_data, place.slot, tabel_id, generatie)
        except Fault:
            raise Fault("aanmaak_onderbroken") from None
    if table is None:
        doc = _empty_table(place, key, tabel_id, generatie)
        _step("a3")
    else:
        assert parse is not None
        try:
            doc = parse_doc(parse(table, place.table))
            if (doc.slot, doc.tabel_id, doc.generatie) != (place.slot, tabel_id, generatie):
                raise Fault("aanmaak_onderbroken")
            verify_doc(doc, key)
        except Fault:
            raise Fault("aanmaak_onderbroken") from None
    done = Anchor(place.slot, tabel_id, generatie, doc.aantal, doc.keten, "vastgelegd", None, ())
    text = write_anchor(place, raw, done, "a4")
    return Verified(place, text, done, doc, key)


def load(place: Place, parse: Parse, *, table_cap: int) -> Verified:
    """Rules 2-8 (rule 1, the slot, is `place_of`). Creates the table only on
    a first start: no anchor AND no table, key or discarded/backup file."""
    raw = read_anchor_raw(place.slot)
    table = _read(place, place.table_name, "de vertaaltabel", table_cap)
    key_data = _read(place, place.key_name, "het sleutelbestand van de vertaaltabel", KEY_FILE_CAP)
    if raw is None:
        if table is None and key_data is None and not _leftovers(place):
            return _first_start(place)
        if table is not None:
            content = parse(table, place.table)
            if is_form_1(content):
                raise Fault("formaat", vorm="1")
            if parse_doc(content).slot != place.slot:
                raise Fault("slot")
        raise Fault("anker_ontbreekt")
    anchor = parse_anchor(raw, place.slot)
    if anchor.toestand == "aanmaak":
        return _finish_creation(place, raw, anchor, table, key_data, parse)
    if anchor.toestand != "vastgelegd":
        raise Fault(f"{anchor.toestand}_onderbroken")
    if table is None:
        raise Fault("bestand_ontbreekt")
    if key_data is None:
        raise Fault("sleutel_ontbreekt")
    content = parse(table, place.table)
    if is_form_1(content):
        raise Fault("formaat", vorm="1-naast-anker")
    doc = parse_doc(content)
    _identity(doc, anchor, place.slot)
    key = unwrap_key(key_data, place.slot, _active_id(anchor), anchor.generatie)
    verify_doc(doc, key)
    if watermark(doc, anchor):
        forward = Anchor(
            place.slot, anchor.tabel_id, anchor.generatie, doc.aantal, doc.keten, "vastgelegd", None, anchor.afgedankt
        )
        raw = write_anchor(place, raw, forward, "vooruit")
        anchor = forward
    return Verified(place, raw, anchor, doc, key)


def append(verified: Verified, pairs: list[tuple[str, str]]) -> Verified:
    """t1 (the table) then t2 (the anchor forward). A crash between the two
    is load rule 8 on the next start."""
    if not pairs:
        return verified
    place, anchor = verified.place, verified.anchor
    assert anchor.tabel_id is not None
    doc = build_doc(verified.key, place.slot, anchor.tabel_id, anchor.generatie, pairs, verified.doc)
    _replace(place, place.table_name, doc_bytes(doc), "de vertaaltabel")
    _step("t1")
    forward = Anchor(
        place.slot, anchor.tabel_id, anchor.generatie, doc.aantal, doc.keten, "vastgelegd", None, anchor.afgedankt
    )
    raw = write_anchor(place, verified.anchor_raw, forward, "t2")
    return Verified(place, raw, forward, doc, verified.key)


# ---------------------------------------------------------------------------
# The CLI routes: migration, restore, reset
# ---------------------------------------------------------------------------

ALREADY_SIGNED = "de vertaaltabel is al ondertekend; er is niets gewijzigd en er is geen nieuwe sleutel gemaakt"
NEEDS_CONFIRMATION = (
    "er is niets gewijzigd: deze stap vraagt --gecontroleerd, uw verklaring dat u de tabel zelf gecontroleerd heeft"
)
MIGRATED = "de vertaaltabel is ondertekend; de exacte oude bytes staan in de backup ernaast"
RESTORED = "de kopie is teruggezet; zij hoort bij de actieve generatie en is volledig geverifieerd"
RESET_WARNING = (
    "LET OP: een reset dankt de huidige generatie van de vertaaltabel af. Oude pseudoniemen worden ongeldig en kunnen"
    " na de reset naar een ander object wijzen; stel na de reset eerst een nieuwe vraag voordat u iets laat schrijven."
    " De oude tabel en sleutel worden hernoemd, niet verwijderd."
)
RESET_DONE = "de vertaaltabel is gereset: een nieuwe, lege generatie met een nieuwe sleutel"


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _backup(place: Place, data: bytes, bron: str, table_cap: int) -> str:
    """m2: a backup of the EXACT bytes, created exclusively, read back and
    compared before anything else is written; a backup with the same SHA-256
    from an earlier run is reused."""
    prefix, suffix = f"{place.table_name}.v1-", f"-{bron[:8]}"
    for name in sorted(directory_names(place)):
        if name.startswith(prefix) and name.endswith(suffix):
            existing = _read(place, name, "de backup van de vertaaltabel", table_cap)
            if existing is not None and hmac.compare_digest(_sha(existing), bron):
                _step("m2")
                return name
    name = f"{prefix}{datetime.date.today():%Y%m%d}{suffix}"
    try:
        _create(place, name, data, "de backup van de vertaaltabel")
    except FileExistsError:
        raise Stop(
            "er staat al een backup met deze naam en een andere inhoud naast de vertaaltabel; er is niets gewijzigd"
        ) from None
    back = _read(place, name, "de backup van de vertaaltabel", table_cap)
    if back is None or not hmac.compare_digest(_sha(back), bron):
        raise Stop("de backup kon niet byte-gelijk teruggelezen worden; de oude tabel is niet vervangen")
    _step("m2")
    return name


def _backup_present(place: Place, bron: str, table_cap: int) -> bool:
    prefix, suffix = f"{place.table_name}.v1-", f"-{bron[:8]}"
    for name in directory_names(place):
        if name.startswith(prefix) and name.endswith(suffix):
            existing = _read(place, name, "de backup van de vertaaltabel", table_cap)
            if existing is not None and hmac.compare_digest(_sha(existing), bron):
                return True
    return False


def migrate(
    place: Place,
    parse: Parse,
    validate_form_1: Callable[[object], list[tuple[str, str]]],
    *,
    confirmed: bool,
    say: Callable[[str], None],
    table_cap: int,
) -> int:
    """The migration row of the commit table (m0-m6), and its resumption."""
    raw = read_anchor_raw(place.slot)
    if raw is not None:
        anchor = parse_anchor(raw, place.slot)
        if anchor.toestand == "vastgelegd":
            load(place, parse, table_cap=table_cap)
            say(ALREADY_SIGNED)
            return 0
        if anchor.toestand != "migratie":
            raise Fault(f"{anchor.toestand}_onderbroken")
        return _resume_migration(place, raw, anchor, parse, validate_form_1, confirmed, say, table_cap)
    data = _read(place, place.table_name, "de vertaaltabel", table_cap)
    if data is None:
        raise Stop("er staat op deze plek geen vertaaltabel om te ondertekenen; er is niets gewijzigd")
    content = parse(data, place.table)
    if not is_form_1(content):
        if parse_doc(content).slot != place.slot:
            raise Fault("slot")
        raise Fault("anker_ontbreekt")
    pairs = validate_form_1(content)
    say(f"de vertaaltabel in de vorm van 1.0.x telt {len(pairs)} rijen")
    if not confirmed:
        say(NEEDS_CONFIRMATION)
        return 2
    bron = _sha(data)
    _backup(place, data, bron, table_cap)
    tabel_id = secrets.token_hex(16)
    pending = Anchor(
        place.slot, None, 0, 0, ZERO_CHAIN, "migratie", {"tabelId": tabel_id, "generatie": 1, "bron": bron}, ()
    )
    raw = write_anchor(place, None, pending, "m3")
    key = secrets.token_bytes(KEY_BYTES)
    _create(place, place.key_name, wrap_key(key, place.slot, tabel_id, 1), "het sleutelbestand")
    _step("m4")
    return _finish_migration(place, raw, pending, key, pairs, say)


def _finish_migration(
    place: Place, raw: str, pending: Anchor, key: bytes, pairs: list[tuple[str, str]], say: Callable[[str], None]
) -> int:
    assert pending.nieuw is not None
    tabel_id, generatie = pending.nieuw["tabelId"], pending.nieuw["generatie"]
    doc = build_doc(key, place.slot, tabel_id, generatie, pairs)
    _replace(place, place.table_name, doc_bytes(doc), "de vertaaltabel")
    _step("m5")
    done = Anchor(place.slot, tabel_id, generatie, doc.aantal, doc.keten, "vastgelegd", None, ())
    write_anchor(place, raw, done, "m6")
    say(MIGRATED)
    return 0


def _resume_migration(
    place: Place,
    raw: str,
    anchor: Anchor,
    parse: Parse,
    validate_form_1: Callable[[object], list[tuple[str, str]]],
    confirmed: bool,
    say: Callable[[str], None],
    table_cap: int,
) -> int:
    """Only on the identity in `nieuw` and on the recorded source SHA-256."""
    assert anchor.nieuw is not None
    tabel_id, generatie, bron = anchor.nieuw["tabelId"], anchor.nieuw["generatie"], anchor.nieuw["bron"]
    if not _backup_present(place, bron, table_cap):
        raise Stop("de backup van de onderbroken migratie ontbreekt of wijkt af; er is niets gewijzigd")
    data = _read(place, place.table_name, "de vertaaltabel", table_cap)
    if data is None:
        raise Stop("de vertaaltabel ontbreekt sinds de onderbroken migratie; zet de backup terug en draai opnieuw")
    key_data = _read(place, place.key_name, "het sleutelbestand van de vertaaltabel", KEY_FILE_CAP)
    if hmac.compare_digest(_sha(data), bron):
        pairs = validate_form_1(parse(data, place.table))
        say(f"de onderbroken ondertekening hervat op dezelfde bron ({len(pairs)} rijen)")
        if not confirmed:
            say(NEEDS_CONFIRMATION)
            return 2
        if key_data is None:
            key = secrets.token_bytes(KEY_BYTES)
            _create(place, place.key_name, wrap_key(key, place.slot, tabel_id, generatie), "het sleutelbestand")
            _step("m4")
        else:
            try:
                key = unwrap_key(key_data, place.slot, tabel_id, generatie)
            except Fault:
                raise Fault("migratie_onderbroken") from None
        return _finish_migration(place, raw, anchor, key, pairs, say)
    content = parse(data, place.table)
    if is_form_1(content) or key_data is None:
        raise Fault("migratie_onderbroken")
    doc = parse_doc(content)
    if (doc.slot, doc.tabel_id, doc.generatie) != (place.slot, tabel_id, generatie):
        raise Fault("migratie_onderbroken")
    try:
        key = unwrap_key(key_data, place.slot, tabel_id, generatie)
        verify_doc(doc, key)
    except Fault:
        raise Fault("migratie_onderbroken") from None
    if not confirmed:
        say(NEEDS_CONFIRMATION)
        return 2
    done = Anchor(place.slot, tabel_id, generatie, doc.aantal, doc.keten, "vastgelegd", None, ())
    write_anchor(place, raw, done, "m6")
    say(MIGRATED)
    return 0


def restore(
    place: Place, copy: Path, parse: Parse, *, confirmed: bool, say: Callable[[str], None], table_cap: int
) -> int:
    """h1-h3: a known good copy of the ACTIVE generation goes back; another
    generation, another place or fewer rows than committed is refused."""
    raw = read_anchor_raw(place.slot)
    if raw is None:
        raise Fault("anker_ontbreekt")
    anchor = parse_anchor(raw, place.slot)
    if anchor.toestand != "vastgelegd":
        raise Fault(f"{anchor.toestand}_onderbroken")
    try:
        got = localpath.read_configured(copy, max_bytes=table_cap)
    except localpath.PathRefused as exc:
        raise PlaceRefused("de herstelkopie", exc) from exc
    except OSError as exc:
        raise FileFailed("de herstelkopie", exc) from exc
    if got.over_cap:
        raise FileFailed("de herstelkopie", OSError("groter dan het plafond"))
    content = parse(got.data, copy)
    if is_form_1(content):
        raise Fault("formaat", vorm="1-naast-anker")
    doc = parse_doc(content)
    _identity(doc, anchor, place.slot)
    key_data = _read(place, place.key_name, "het sleutelbestand van de vertaaltabel", KEY_FILE_CAP)
    if key_data is None:
        raise Fault("sleutel_ontbreekt")
    key = unwrap_key(key_data, place.slot, _active_id(anchor), anchor.generatie)
    verify_doc(doc, key)
    forward = watermark(doc, anchor)
    if not confirmed:
        say(NEEDS_CONFIRMATION)
        return 2
    _replace(place, place.table_name, got.data, "de vertaaltabel")
    _step("h2")
    if forward:
        ahead = Anchor(
            place.slot, anchor.tabel_id, anchor.generatie, doc.aantal, doc.keten, "vastgelegd", None, anchor.afgedankt
        )
        write_anchor(place, raw, ahead, "h3")
    say(RESTORED)
    return 0


def _doc_or_none(data: bytes | None) -> TableDoc | None:
    if data is None:
        return None
    try:
        return parse_doc(json.loads(localpath.as_text(data)))
    except (ValueError, RecursionError, Fault):
        return None


def _discarded_generations(place: Place) -> list[int]:
    found = []
    for name in directory_names(place):
        for prefix in (f"{place.table_name}.afgedankt-", f"{place.key_name}.afgedankt-"):
            if name.startswith(prefix):
                head = name[len(prefix) :].split("-", 1)[0]
                if head.isdigit():
                    found.append(int(head))
    return found


def reset(place: Place, *, confirmed: bool, say: Callable[[str], None], table_cap: int) -> int:
    """r1-r5. Also without a readable anchor (R4): then the old active id is
    unknown and the new generation is one above every generation known here.
    Never the server's route; never a deletion."""
    say(RESET_WARNING)
    if not confirmed:
        say(NEEDS_CONFIRMATION)
        return 2
    raw = read_anchor_raw(place.slot)
    anchor: Anchor | None = None
    if raw is not None:
        try:
            anchor = parse_anchor(raw, place.slot)
        except Fault:
            anchor = None
    if anchor is not None and anchor.toestand == "reset":
        return _finish_reset(place, raw, anchor, say, table_cap)
    table = _read(place, place.table_name, "de vertaaltabel", table_cap)
    current = _doc_or_none(table)
    known = [0, *_discarded_generations(place)]
    afgedankt: list[str] = list(anchor.afgedankt) if anchor is not None else []
    if anchor is not None:
        known.append(anchor.generatie)
        if anchor.nieuw is not None:
            known.append(anchor.nieuw["generatie"])
            afgedankt.append(anchor.nieuw["tabelId"])
        if anchor.tabel_id is not None:
            afgedankt.append(anchor.tabel_id)
    if current is not None:
        known.append(current.generatie)
        afgedankt.append(current.tabel_id)
    afgedankt = list(dict.fromkeys(afgedankt))[-MAX_DISCARDED:]
    tabel_id = secrets.token_hex(16)
    nieuw = {"tabelId": tabel_id, "generatie": max(known) + 1}
    if anchor is not None and anchor.tabel_id is not None:
        # The record keeps the active identity until r5; it is not yet discarded.
        active = anchor.tabel_id
        rest = tuple(item for item in afgedankt if item != active)[-MAX_DISCARDED:]
        pending = Anchor(place.slot, active, anchor.generatie, anchor.aantal, anchor.keten, "reset", nieuw, rest)
    else:
        pending = Anchor(place.slot, None, 0, 0, ZERO_CHAIN, "reset", nieuw, tuple(afgedankt))
    written = write_anchor(place, raw, pending, "r1")
    return _finish_reset(place, written, pending, say, table_cap)


def _finish_reset(place: Place, raw: str | None, pending: Anchor, say: Callable[[str], None], table_cap: int) -> int:
    """r2-r5, also the resumption: only the identity in `nieuw` stays; every
    other table or key file is renamed to `.afgedankt-<generation>` (the
    anchor's generation, else the one in the old table's own head, else
    `onbekend` - never a made-up number). A table of the `nieuw` identity
    that no longer verifies, or has no usable key, is set aside as
    `.afgedankt-<new generation>-onvoltooid` and the route finishes with a
    fresh key and an empty table on that same identity: a repeated reset
    always ends, never in the same stop again."""
    assert pending.nieuw is not None
    tabel_id, generatie = pending.nieuw["tabelId"], pending.nieuw["generatie"]
    table = _read(place, place.table_name, "de vertaaltabel", table_cap)
    doc = _doc_or_none(table)
    if pending.tabel_id is not None:
        label = str(pending.generatie)
    elif doc is not None and (doc.tabel_id, doc.generatie) != (tabel_id, generatie):
        label = str(doc.generatie)
    else:
        label = "onbekend"
    if table is not None and not (doc is not None and (doc.tabel_id, doc.generatie) == (tabel_id, generatie)):
        _rename(place, place.table_name, f"{place.table_name}.afgedankt-{label}", "de vertaaltabel")
        table, doc = None, None
    key_data = _read(place, place.key_name, "het sleutelbestand van de vertaaltabel", KEY_FILE_CAP)
    key: bytes | None = None
    if key_data is not None:
        try:
            key = unwrap_key(key_data, place.slot, tabel_id, generatie)
        except Fault:
            _rename(place, place.key_name, f"{place.key_name}.afgedankt-{label}", "het sleutelbestand")
            key = None
    if doc is not None:
        usable = False
        if key is not None:
            try:
                verify_doc(doc, key)
                usable = True
            except Fault:
                usable = False
        if not usable:
            _rename(place, place.table_name, f"{place.table_name}.afgedankt-{generatie}-onvoltooid", "de vertaaltabel")
            doc = None
    _step("r2")
    if key is None:
        key = secrets.token_bytes(KEY_BYTES)
        _create(place, place.key_name, wrap_key(key, place.slot, tabel_id, generatie), "het sleutelbestand")
    _step("r3")
    if doc is None:
        doc = _empty_table(place, key, tabel_id, generatie)
    _step("r4")
    discarded = pending.afgedankt + ((pending.tabel_id,) if pending.tabel_id is not None else ())
    done = Anchor(
        place.slot, tabel_id, generatie, doc.aantal, doc.keten, "vastgelegd", None, discarded[-MAX_DISCARDED:]
    )
    write_anchor(place, raw, done, "r5")
    say(RESET_DONE)
    return 0
