"""Characterize filesystem, network-device, and cgroup tools."""

from collections.abc import Callable, Iterator
from ipaddress import IPv4Address, IPv6Address
from types import SimpleNamespace

import pytest

from drgn_mcp.tools import cgroup, fs, net
from tests.conftest import mark_loaded


class _Cgroup:
    """Minimal cgroup stand-in exposing its embedded css address."""

    def __init__(self, css_address: object = "css-address") -> None:
        self.self = SimpleNamespace(address_of_=lambda: css_address)


# --- filesystem --------------------------------------------------------------


def test_list_mounts_formats_unicode_replacement_and_next_page(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    mounts = [object(), object(), object()]
    values = {
        mounts[0]: (b"rootfs", b"/", b"ext4"),
        mounts[1]: (b"server:/share", b"/mnt/\xff", b"nfs"),
        mounts[2]: (b"tmpfs", b"/run", b"tmpfs"),
    }
    monkeypatch.setattr(fs, "for_each_mount", lambda prog, namespace: mounts)
    monkeypatch.setattr(fs, "mount_src", lambda mount: values[mount][0])
    monkeypatch.setattr(fs, "mount_dst", lambda mount: values[mount][1])
    monkeypatch.setattr(fs, "mount_fstype", lambda mount: values[mount][2])
    mark_loaded()

    assert fs.list_mounts(limit=1, offset=1) == "\n".join(
        [
            "server:/share on /mnt/\ufffd type nfs",
            "... (limited to 1 mounts, use offset=2 for next page)",
        ]
    )


def test_list_mounts_reports_empty_collection(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(fs, "for_each_mount", lambda prog, namespace: [])
    mark_loaded()

    assert fs.list_mounts() == "No mounts found"


def test_list_mounts_reports_item_and_iteration_faults(
    monkeypatch: pytest.MonkeyPatch,
    drgn_error: Callable[..., BaseException],
) -> None:
    item_fault = drgn_error("fault", "bad mount", address=0x10)
    good_mount = object()
    bad_mount = object()
    monkeypatch.setattr(fs, "for_each_mount", lambda prog, namespace: [bad_mount, good_mount])
    monkeypatch.setattr(
        fs,
        "mount_src",
        lambda mount: (_ for _ in ()).throw(item_fault) if mount is bad_mount else b"tmpfs",
    )
    monkeypatch.setattr(fs, "mount_dst", lambda mount: b"/run")
    monkeypatch.setattr(fs, "mount_fstype", lambda mount: b"tmpfs")
    mark_loaded()

    assert fs.list_mounts() == f"<fault: {item_fault}>\ntmpfs on /run type tmpfs"

    walk_fault = drgn_error("fault", "mount walk", address=0x11)

    def mounts() -> Iterator[object]:
        yield good_mount
        raise walk_fault

    monkeypatch.setattr(fs, "for_each_mount", lambda prog, namespace: mounts())
    assert fs.list_mounts() == (
        f"tmpfs on /run type tmpfs\n... Traversal aborted due to memory fault: {walk_fault}"
    )


def test_list_files_formats_paths_and_replaces_path_fault(
    monkeypatch: pytest.MonkeyPatch,
    drgn_error: Callable[..., BaseException],
) -> None:
    task = object()
    readable = object()
    unreadable = object()
    fault = drgn_error("fault", "dentry gone", address=0x12)
    monkeypatch.setattr(fs, "_find_task", lambda prog, pid: task if pid == 5 else None)
    monkeypatch.setattr(fs, "for_each_file", lambda found_task: [(3, readable), (4, unreadable)])
    monkeypatch.setattr(
        fs,
        "d_path",
        lambda file: b"/tmp/\xff" if file is readable else (_ for _ in ()).throw(fault),
    )
    mark_loaded()

    assert fs.list_files(5) == "fd=3 /tmp/\ufffd\nfd=4 <fault>"
    assert fs.list_files(99) == "No task found with PID 99"


def test_list_files_paginates_from_requested_offset(monkeypatch: pytest.MonkeyPatch) -> None:
    task = object()
    files = [(3, object()), (4, object()), (5, object())]
    paths = {files[0][1]: b"/first", files[1][1]: b"/second", files[2][1]: b"/third"}
    monkeypatch.setattr(fs, "_find_task", lambda prog, pid: task if pid == 5 else None)
    monkeypatch.setattr(fs, "for_each_file", lambda found_task: files)
    monkeypatch.setattr(fs, "d_path", lambda file: paths[file])
    mark_loaded()

    assert fs.list_files(5, limit=1, offset=1) == "\n".join(
        [
            "fd=4 /second",
            "... (limited to 1 files, use offset=2 for next page)",
        ]
    )


def test_list_files_reports_empty_and_iteration_faults(
    monkeypatch: pytest.MonkeyPatch,
    drgn_error: Callable[..., BaseException],
) -> None:
    task = object()
    monkeypatch.setattr(fs, "_find_task", lambda prog, pid: task)
    monkeypatch.setattr(fs, "for_each_file", lambda found_task: [])
    mark_loaded()
    assert fs.list_files(1) == "No open files"

    fault = drgn_error("fault", "fd table gone", address=0x13)
    file = object()

    def files() -> Iterator[tuple[int, object]]:
        yield 3, file
        raise fault

    monkeypatch.setattr(fs, "for_each_file", lambda found_task: files())
    monkeypatch.setattr(fs, "d_path", lambda open_file: b"/ok")
    assert fs.list_files(1) == f"fd=3 /ok\n... Traversal aborted due to memory fault: {fault}"


# --- network -----------------------------------------------------------------


def test_list_netdevs_formats_addresses_and_paginates(monkeypatch: pytest.MonkeyPatch) -> None:
    devices = [object(), object(), object()]
    names = {devices[0]: b"lo", devices[1]: b"eth\xff", devices[2]: b"vlan0"}
    monkeypatch.setattr(net, "for_each_netdev", lambda prog, namespace: devices)
    monkeypatch.setattr(net, "netdev_name", lambda dev: names[dev])
    monkeypatch.setattr(
        net,
        "netdev_ipv4_addrs",
        lambda dev: [IPv4Address("192.0.2.1")] if dev is devices[1] else [],
    )
    monkeypatch.setattr(
        net,
        "netdev_ipv6_addrs",
        lambda dev: [IPv6Address("2001:db8::1")] if dev is devices[1] else [],
    )
    mark_loaded()

    assert net.list_netdevs(limit=1, offset=1) == "\n".join(
        [
            "eth\ufffd: 192.0.2.1, 2001:db8::1",
            "... (limited to 1 devices, use offset=2 for next page)",
        ]
    )


def test_list_netdevs_reports_empty_and_addressless_devices(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    device = object()
    monkeypatch.setattr(net, "for_each_netdev", lambda prog, namespace: [device])
    monkeypatch.setattr(net, "netdev_name", lambda dev: b"lo")
    monkeypatch.setattr(net, "netdev_ipv4_addrs", lambda dev: [])
    monkeypatch.setattr(net, "netdev_ipv6_addrs", lambda dev: [])
    mark_loaded()
    assert net.list_netdevs() == "lo: no addresses"

    monkeypatch.setattr(net, "for_each_netdev", lambda prog, namespace: [])
    assert net.list_netdevs() == "No network devices found"


def test_list_netdevs_reports_item_and_iteration_faults(
    monkeypatch: pytest.MonkeyPatch,
    drgn_error: Callable[..., BaseException],
) -> None:
    bad_device = object()
    good_device = object()
    item_fault = drgn_error("fault", "bad device", address=0x20)
    monkeypatch.setattr(net, "for_each_netdev", lambda prog, namespace: [bad_device, good_device])
    monkeypatch.setattr(
        net,
        "netdev_name",
        lambda dev: (_ for _ in ()).throw(item_fault) if dev is bad_device else b"eth0",
    )
    monkeypatch.setattr(net, "netdev_ipv4_addrs", lambda dev: [])
    monkeypatch.setattr(net, "netdev_ipv6_addrs", lambda dev: [])
    mark_loaded()
    assert net.list_netdevs() == f"<fault: {item_fault}>\neth0: no addresses"

    walk_fault = drgn_error("fault", "device walk", address=0x21)

    def devices() -> Iterator[object]:
        yield good_device
        raise walk_fault

    monkeypatch.setattr(net, "for_each_netdev", lambda prog, namespace: devices())
    assert net.list_netdevs() == (
        f"eth0: no addresses\n... Traversal aborted due to memory fault: {walk_fault}"
    )


# --- cgroups -----------------------------------------------------------------


def test_get_cgroup_formats_paths_and_replaces_invalid_bytes(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    child = _Cgroup()
    parent = _Cgroup()
    monkeypatch.setattr(cgroup, "cgroup_get_from_path", lambda prog, path: child)
    monkeypatch.setattr(cgroup, "cgroup_name", lambda cgrp: b"user\xffslice")
    monkeypatch.setattr(
        cgroup, "cgroup_path", lambda cgrp: b"/user.slice" if cgrp is child else b"/"
    )
    monkeypatch.setattr(cgroup, "cgroup_parent", lambda cgrp: parent)
    mark_loaded()

    assert cgroup.get_cgroup("/user.slice") == "Name: user\ufffdslice\nPath: /user.slice\nParent: /"


def test_get_cgroup_reports_missing_and_lookup_errors(
    monkeypatch: pytest.MonkeyPatch,
    drgn_error: Callable[..., BaseException],
) -> None:
    mark_loaded()
    monkeypatch.setattr(cgroup, "cgroup_get_from_path", lambda prog, path: None)
    assert cgroup.get_cgroup("/missing") == "No cgroup found at path '/missing'"

    fault = drgn_error("fault", "cgroup root gone", address=0x30)
    monkeypatch.setattr(
        cgroup, "cgroup_get_from_path", lambda prog, path: (_ for _ in ()).throw(fault)
    )
    assert cgroup.get_cgroup("/") == f"Error looking up cgroup '/': {fault}"

    monkeypatch.setattr(
        cgroup,
        "cgroup_get_from_path",
        lambda prog, path: (_ for _ in ()).throw(LookupError("not indexed")),
    )
    assert cgroup.get_cgroup("/gone") == "Error looking up cgroup '/gone': not indexed"


def test_list_cgroups_paginates_and_replaces_invalid_bytes(monkeypatch: pytest.MonkeyPatch) -> None:
    root = _Cgroup("root-css")
    css = [object(), object(), object()]
    children = {css[0]: _Cgroup(), css[1]: _Cgroup(), css[2]: _Cgroup()}
    paths = {
        children[css[0]]: b"/",
        children[css[1]]: b"/user\xffslice",
        children[css[2]]: b"/system",
    }
    monkeypatch.setattr(cgroup, "cgroup_get_from_path", lambda prog, path: root)
    monkeypatch.setattr(cgroup, "css_for_each_descendant_pre", lambda address: css)
    monkeypatch.setattr(cgroup, "container_of", lambda item, type_name, member: children[item])
    monkeypatch.setattr(cgroup, "cgroup_path", lambda child: paths[child])
    mark_loaded()

    assert cgroup.list_cgroups(limit=1, offset=1) == "\n".join(
        ["/user\ufffdslice", "... (limited to 1 cgroups, use offset=2 for next page)"]
    )


def test_list_cgroups_reports_missing_lookup_and_traversal_faults(
    monkeypatch: pytest.MonkeyPatch,
    drgn_error: Callable[..., BaseException],
) -> None:
    mark_loaded()
    monkeypatch.setattr(cgroup, "cgroup_get_from_path", lambda prog, path: None)
    assert cgroup.list_cgroups("/missing") == "No cgroup found at path '/missing'"

    lookup_fault = drgn_error("fault", "cgroup root gone", address=0x31)
    monkeypatch.setattr(
        cgroup,
        "cgroup_get_from_path",
        lambda prog, path: (_ for _ in ()).throw(lookup_fault),
    )
    assert cgroup.list_cgroups("/") == f"Error looking up cgroup '/': {lookup_fault}"

    root = _Cgroup()
    walk_fault = drgn_error("fault", "css walk", address=0x32)
    monkeypatch.setattr(cgroup, "cgroup_get_from_path", lambda prog, path: root)

    def descendants(address: object) -> Iterator[object]:
        yield object()
        raise walk_fault

    child = _Cgroup()
    monkeypatch.setattr(cgroup, "css_for_each_descendant_pre", descendants)
    monkeypatch.setattr(cgroup, "container_of", lambda css, type_name, member: child)
    monkeypatch.setattr(cgroup, "cgroup_path", lambda cgrp: b"/ok")
    assert cgroup.list_cgroups() == (
        f"/ok\n... Traversal aborted due to memory fault: {walk_fault}"
    )


def test_list_cgroups_reports_empty_and_path_read_fault(
    monkeypatch: pytest.MonkeyPatch,
    drgn_error: Callable[..., BaseException],
) -> None:
    root = _Cgroup()
    monkeypatch.setattr(cgroup, "cgroup_get_from_path", lambda prog, path: root)
    monkeypatch.setattr(cgroup, "css_for_each_descendant_pre", lambda address: [])
    mark_loaded()
    assert cgroup.list_cgroups() == "No cgroups found"

    fault = drgn_error("fault", "path unreadable", address=0x33)
    monkeypatch.setattr(cgroup, "css_for_each_descendant_pre", lambda address: [object()])
    monkeypatch.setattr(cgroup, "container_of", lambda css, type_name, member: _Cgroup())
    monkeypatch.setattr(cgroup, "cgroup_path", lambda child: (_ for _ in ()).throw(fault))
    assert cgroup.list_cgroups() == f"... Traversal aborted due to memory fault: {fault}"
