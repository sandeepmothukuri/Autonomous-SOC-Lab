"""Tool allowlist tests."""
import pytest

from soc.soar.tools import ToolRegistry, default_tool_registry


def test_default_registry_denies_unregistered_tools():
    reg = default_tool_registry()
    with pytest.raises(PermissionError):
        reg.invoke("run_arbitrary_shell", mode="simulate")
    with pytest.raises(PermissionError):
        reg.invoke("execute_shell", mode="simulate")
    with pytest.raises(PermissionError):
        reg.invoke("wipe_host", mode="real")


def test_default_registry_has_no_real_handlers_in_research_build():
    reg = default_tool_registry()
    # No tool ships with a `real` implementation in this research build
    # (prevents accidentally acting on live systems).
    for name in reg.names():
        tool = reg.get(name)
        assert tool is not None
        assert tool.real is None, f"{name} unexpectedly has a real handler"


def test_dry_run_does_not_invoke_simulate():
    reg = default_tool_registry()
    out = reg.invoke("fw_block_ip", mode="dry_run", ip="10.0.0.1")
    assert out["mode"] == "dry_run"
    assert out["would_execute"] is True


def test_simulate_returns_simulated_output():
    reg = default_tool_registry()
    out = reg.invoke("edr_isolate_host", mode="simulate", host="wkstn-1")
    assert out["applied"] == "simulate"
    assert out["host"] == "wkstn-1"


def test_real_mode_without_real_handler_raises():
    reg = default_tool_registry()
    with pytest.raises(NotImplementedError):
        reg.invoke("fw_block_ip", mode="real", ip="10.0.0.1")


def test_registry_rejects_duplicates():
    reg = ToolRegistry()
    from soc.soar.tools import Tool
    reg.register(Tool("t", "d", False, simulate=lambda **kw: {"ok": True}))
    with pytest.raises(ValueError):
        reg.register(Tool("t", "d", False, simulate=lambda **kw: {"ok": True}))
