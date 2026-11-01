"""Release checks: everything OTA installs is complete, and compiles as MicroPython.

OTA installs exactly the files listed in package.json, so a module that exists
in src/ but isn't listed there never reaches the device, and the first import
of it there kills boot.py or main.py.
"""

import ast
import json
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
SRC = ROOT / "src"
URL_PREFIX = "github:snacker-tracker/pico-scanner/src/"

# help('modules') on the RPI_PICO_W v1.28.0 firmware the devices run.
FIRMWARE_MODULES = {
    "aioble", "array", "_asyncio", "asyncio", "binascii", "bluetooth", "_boot",
    "_boot_fat", "builtins", "cmath", "collections", "cryptolib", "deflate", "dht",
    "ds18x20", "errno", "framebuf", "gc", "hashlib", "heapq", "io", "json", "lwip",
    "machine", "__main__", "math", "micropython", "mip", "neopixel", "network",
    "ntptime", "_onewire", "onewire", "os", "platform", "random", "re", "requests",
    "_rp2", "rp2", "select", "socket", "ssl", "struct", "sys", "_thread", "time",
    "tls", "uasyncio", "uctypes", "urequests", "vfs", "_webrepl", "webrepl",
    "webrepl_setup", "websocket",
}  # fmt: skip

SOURCES = sorted(SRC.glob("*.py"))


def _package_urls():
    return json.loads((ROOT / "package.json").read_text())["urls"]


def _installed_modules():
    return {Path(dest).stem for dest, _ in _package_urls()}


def _firmware_has(name):
    # MicroPython resolves `import ujson` to the built-in json, and so on.
    return name in FIRMWARE_MODULES or (
        name.startswith("u") and name[1:] in FIRMWARE_MODULES
    )


def _imports(path):
    """Top-level module names imported anywhere in `path`, except inside a
    try block, where a failed import is presumably handled."""
    tree = ast.parse(path.read_text())
    guarded = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Try):
            for stmt in node.body:
                guarded.update(id(n) for n in ast.walk(stmt))
    names = set()
    for node in ast.walk(tree):
        if id(node) in guarded:
            continue
        if isinstance(node, ast.Import):
            names.update(alias.name.split(".")[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            names.add(node.module.split(".")[0])
    return names


def test_every_source_file_is_installed_by_ota():
    listed = {dest for dest, _ in _package_urls()}
    on_disk = {p.name for p in SOURCES}
    assert on_disk - listed == set(), "add these to package.json"
    assert listed - on_disk == set(), "package.json lists files that don't exist"


@pytest.mark.parametrize("dest,url", _package_urls(), ids=lambda v: str(v))
def test_package_entry_points_at_its_source(dest, url):
    assert url == URL_PREFIX + dest
    assert (SRC / dest).is_file()


def test_package_has_no_duplicates():
    dests = [dest for dest, _ in _package_urls()]
    assert len(dests) == len(set(dests))


@pytest.mark.parametrize("path", SOURCES, ids=lambda p: p.name)
def test_imports_resolve_on_device(path):
    installed = _installed_modules()
    missing = {
        name
        for name in _imports(path)
        if name not in installed and not _firmware_has(name)
    }
    assert missing == set(), "not in package.json or the firmware"


@pytest.mark.parametrize("path", SOURCES, ids=lambda p: p.name)
def test_compiles_with_micropython(path, tmp_path):
    result = subprocess.run(
        ["mpy-cross", "-o", str(tmp_path / "out.mpy"), str(path)],
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stderr
