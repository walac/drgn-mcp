"""Characterize sysfs listing and lookup tools."""

from collections.abc import Callable
from types import SimpleNamespace

import pytest

from drgn_mcp.tools import sysfs
from tests.conftest import mark_loaded


class _SysfsObject:
    """Pointer-like stand-in: type name, value_(), and optional falsiness."""

    def __init__(self, type_name: str, address: int, *, present: bool = True) -> None:
        self.type_ = SimpleNamespace(type_name=lambda: type_name)
        self._address = address
        self._present = present

    def __bool__(self) -> bool:
        return self._present

    def value_(self) -> int:
        return self._address


# --- list_sysfs --------------------------------------------------------------


def test_list_sysfs_defaults_to_sys_root(monkeypatch: pytest.MonkeyPatch) -> None:
    seen: list[str] = []

    def listdir(prog: object, path: str) -> list[bytes]:
        seen.append(path)
        return [b"block"]

    monkeypatch.setattr(sysfs, "sysfs_listdir", listdir)
    mark_loaded()

    assert sysfs.list_sysfs() == "block"
    assert seen == ["/sys"]


def test_list_sysfs_formats_unicode_replacement_and_next_page(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        sysfs,
        "sysfs_listdir",
        lambda prog, path: [b"block", b"dev\xffclass", b"kernel"],
    )
    mark_loaded()

    assert sysfs.list_sysfs("/sys", limit=1, offset=1) == "\n".join(
        [
            "dev\ufffdclass",
            "... (limited to 1 entries, use offset=2 for next page)",
        ]
    )


def test_list_sysfs_reports_empty_collection(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(sysfs, "sysfs_listdir", lambda prog, path: [])
    mark_loaded()

    assert sysfs.list_sysfs("/sys/empty") == "No sysfs entries"


def test_list_sysfs_reports_missing_node(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    mark_loaded()
    monkeypatch.setattr(sysfs, "sysfs_lookup_node", lambda prog, path: None, raising=False)
    monkeypatch.setattr(
        sysfs,
        "sysfs_listdir",
        lambda prog, path: (_ for _ in ()).throw(ValueError("upstream wording changed")),
    )
    assert sysfs.list_sysfs("/sys/missing") == "No sysfs entry at path '/sys/missing'"


def test_list_sysfs_reports_non_directory_without_matching_error_text(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    mark_loaded()
    monkeypatch.setattr(sysfs, "sysfs_lookup_node", lambda prog, path: object(), raising=False)
    monkeypatch.setattr(
        sysfs,
        "sysfs_listdir",
        lambda prog, path: (_ for _ in ()).throw(ValueError("upstream wording changed")),
    )
    assert sysfs.list_sysfs("/sys/kernel/vmcoreinfo") == (
        "'/sys/kernel/vmcoreinfo' is not a sysfs directory"
    )


def test_list_sysfs_reports_lookup_fault(
    monkeypatch: pytest.MonkeyPatch,
    drgn_error: Callable[..., BaseException],
) -> None:
    fault = drgn_error("fault", "sysfs root gone", address=0x40)
    monkeypatch.setattr(
        sysfs,
        "sysfs_listdir",
        lambda prog, path: (_ for _ in ()).throw(fault),
    )
    mark_loaded()

    assert sysfs.list_sysfs("/sys") == f"Memory fault listing sysfs '/sys': {fault}"


# --- lookup_sysfs ------------------------------------------------------------


def test_lookup_sysfs_formats_type_address_and_canonical_path(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    device = _SysfsObject("struct device *", 0xFFFF8F554E85EB10)
    kobj = object()
    monkeypatch.setattr(sysfs, "sysfs_lookup", lambda prog, path: device)
    monkeypatch.setattr(sysfs, "sysfs_lookup_kobject", lambda prog, path: kobj)
    monkeypatch.setattr(
        sysfs,
        "kobject_path",
        lambda obj: b"/sys/devices/pci0000:00/nvme/nvme0n1",
    )
    mark_loaded()

    assert sysfs.lookup_sysfs("/sys/block/nvme0n1") == "\n".join(
        [
            "Type: struct device *",
            "Address: 0xffff8f554e85eb10",
            "Sysfs path: /sys/devices/pci0000:00/nvme/nvme0n1",
        ]
    )


def test_lookup_sysfs_replaces_invalid_bytes_in_canonical_path(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    kobj = _SysfsObject("struct kobject *", 0x1000)
    monkeypatch.setattr(sysfs, "sysfs_lookup", lambda prog, path: kobj)
    monkeypatch.setattr(sysfs, "sysfs_lookup_kobject", lambda prog, path: kobj)
    monkeypatch.setattr(sysfs, "kobject_path", lambda obj: b"/sys/kernel/\xff")
    mark_loaded()

    assert sysfs.lookup_sysfs("kernel") == "\n".join(
        [
            "Type: struct kobject *",
            "Address: 0x1000",
            "Sysfs path: /sys/kernel/\ufffd",
        ]
    )


def test_lookup_sysfs_reports_missing_entry(monkeypatch: pytest.MonkeyPatch) -> None:
    missing = _SysfsObject("struct kobject *", 0, present=False)
    monkeypatch.setattr(sysfs, "sysfs_lookup_node", lambda prog, path: None, raising=False)
    monkeypatch.setattr(sysfs, "sysfs_lookup", lambda prog, path: missing)
    mark_loaded()

    assert sysfs.lookup_sysfs("/sys/nope") == "No sysfs entry at path '/sys/nope'"


def test_lookup_sysfs_reports_existing_node_without_associated_object(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    missing_object = _SysfsObject("struct kobject *", 0, present=False)
    monkeypatch.setattr(sysfs, "sysfs_lookup_node", lambda prog, path: object(), raising=False)
    monkeypatch.setattr(sysfs, "sysfs_lookup", lambda prog, path: missing_object)
    mark_loaded()

    assert (
        sysfs.lookup_sysfs("/sys") == "Sysfs entry at path '/sys' has no associated kernel object"
    )


def test_lookup_sysfs_omits_canonical_path_when_kobject_is_absent(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    obj = _SysfsObject("struct kobject *", 0x2000)
    monkeypatch.setattr(sysfs, "sysfs_lookup", lambda prog, path: obj)
    monkeypatch.setattr(sysfs, "sysfs_lookup_kobject", lambda prog, path: None)
    mark_loaded()

    assert sysfs.lookup_sysfs("/sys/kernel") == "Type: struct kobject *\nAddress: 0x2000"


def test_lookup_sysfs_reports_lookup_and_path_faults(
    monkeypatch: pytest.MonkeyPatch,
    drgn_error: Callable[..., BaseException],
) -> None:
    mark_loaded()
    lookup_fault = drgn_error("fault", "kernfs walk", address=0x41)
    monkeypatch.setattr(
        sysfs,
        "sysfs_lookup",
        lambda prog, path: (_ for _ in ()).throw(lookup_fault),
    )
    assert sysfs.lookup_sysfs("/sys/block") == (
        f"Memory fault looking up sysfs '/sys/block': {lookup_fault}"
    )

    obj = _SysfsObject("struct device *", 0x3000)
    path_fault = drgn_error("fault", "sd unreadable", address=0x42)
    monkeypatch.setattr(sysfs, "sysfs_lookup", lambda prog, path: obj)
    monkeypatch.setattr(sysfs, "sysfs_lookup_kobject", lambda prog, path: object())
    monkeypatch.setattr(sysfs, "kobject_path", lambda kobj: (_ for _ in ()).throw(path_fault))
    assert sysfs.lookup_sysfs("/sys/block/sda") == "\n".join(
        [
            "Type: struct device *",
            "Address: 0x3000",
            f"Sysfs path: <fault: {path_fault}>",
        ]
    )


def test_lookup_sysfs_reports_value_fault(
    monkeypatch: pytest.MonkeyPatch,
    drgn_error: Callable[..., BaseException],
) -> None:
    fault = drgn_error("fault", "pointer unreadable", address=0x43)
    obj = SimpleNamespace(
        type_=SimpleNamespace(type_name=lambda: "struct device *"),
        value_=lambda: (_ for _ in ()).throw(fault),
    )
    monkeypatch.setattr(sysfs, "sysfs_lookup", lambda prog, path: obj)
    mark_loaded()

    assert sysfs.lookup_sysfs("/sys/block/sda") == (
        f"Memory fault looking up sysfs '/sys/block/sda': {fault}"
    )
