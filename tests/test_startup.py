import importlib
import time

import pytest


def _load_startup(monkeypatch, ticks):
    # CPython's time has no ticks_ms; supply the value boot.py would see.
    monkeypatch.setattr(time, "ticks_ms", lambda: ticks, raising=False)
    import startup

    return importlib.reload(startup)


@pytest.mark.parametrize("ticks", [0, 350, 5000])
def test_fresh_tick_counter_is_a_hardware_reset(monkeypatch, ticks):
    assert not _load_startup(monkeypatch, ticks).was_soft_reboot()


@pytest.mark.parametrize("ticks", [5001, 862163])
def test_running_tick_counter_is_a_soft_reboot(monkeypatch, ticks):
    assert _load_startup(monkeypatch, ticks).was_soft_reboot()
