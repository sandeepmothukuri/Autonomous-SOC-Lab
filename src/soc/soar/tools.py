"""Tool registry — explicit allowlist of tools available to SOAR actions.

This implements the "tool allowlists" requirement: even if an action
handler wanted to call out to an arbitrary API or shell command, the
only way to do so is through a registered Tool. Unregistered tools
cannot be invoked.

AI never sees this registry. Tools are only invoked by the
deterministic action handlers.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable, Dict, List, Optional


@dataclass
class Tool:
    name: str
    description: str
    reversible: bool
    # Simulated impl. Real impls are wired in by deployment code; research
    # build uses the simulated versions everywhere.
    simulate: Callable[..., dict]
    real: Optional[Callable[..., dict]] = None
    rollback: Optional[Callable[..., dict]] = None


class ToolRegistry:
    def __init__(self):
        self._tools: Dict[str, Tool] = {}

    def register(self, tool: Tool) -> None:
        if tool.name in self._tools:
            raise ValueError(f"Tool already registered: {tool.name}")
        self._tools[tool.name] = tool

    def get(self, name: str) -> Optional[Tool]:
        return self._tools.get(name)

    def names(self) -> List[str]:
        return sorted(self._tools.keys())

    def invoke(self, name: str, *, mode: str, **kwargs) -> dict:
        """Invoke a tool by name, respecting global mode.

        mode: "dry_run" | "simulate" | "real"
        In dry_run, returns a description of what WOULD happen.
        In simulate, calls tool.simulate.
        In real, calls tool.real if registered, else raises.
        """
        tool = self.get(name)
        if tool is None:
            raise PermissionError(f"Tool not registered (denied by tool allowlist): {name}")
        if mode == "dry_run":
            return {"tool": name, "mode": "dry_run", "would_execute": True, "args": kwargs}
        if mode == "simulate":
            return tool.simulate(**kwargs)
        if mode == "real":
            if tool.real is None:
                raise NotImplementedError(f"Real handler not wired for tool: {name}")
            return tool.real(**kwargs)
        raise ValueError(f"Unknown mode: {mode}")


def default_tool_registry() -> ToolRegistry:
    reg = ToolRegistry()
    reg.register(Tool(
        name="fw_block_ip",
        description="Add an IP to the firewall block list.",
        reversible=True,
        simulate=lambda ip, **kw: {"tool": "fw_block_ip", "ip": ip, "applied": "simulate"},
        rollback=lambda ip, **kw: {"tool": "fw_unblock_ip", "ip": ip},
    ))
    reg.register(Tool(
        name="edr_isolate_host",
        description="Network-isolate a host via EDR.",
        reversible=True,
        simulate=lambda host, **kw: {"tool": "edr_isolate_host", "host": host, "applied": "simulate"},
        rollback=lambda host, **kw: {"tool": "edr_unisolate_host", "host": host},
    ))
    reg.register(Tool(
        name="idp_disable_user",
        description="Disable a user account in the IdP.",
        reversible=True,
        simulate=lambda user, **kw: {"tool": "idp_disable_user", "user": user, "applied": "simulate"},
        rollback=lambda user, **kw: {"tool": "idp_enable_user", "user": user},
    ))
    reg.register(Tool(
        name="edr_quarantine_file",
        description="Quarantine a file via EDR.",
        reversible=True,
        simulate=lambda file, **kw: {"tool": "edr_quarantine_file", "file": file, "applied": "simulate"},
        rollback=lambda file, **kw: {"tool": "edr_restore_file", "file": file},
    ))
    reg.register(Tool(
        name="ti_add_watch",
        description="Add an IOC to the threat-intel watch list.",
        reversible=False,
        simulate=lambda ioc, **kw: {"tool": "ti_add_watch", "ioc": ioc, "applied": "simulate"},
    ))
    reg.register(Tool(
        name="soc_notify",
        description="Send a notification to the SOC analyst queue.",
        reversible=False,
        simulate=lambda target, **kw: {"tool": "soc_notify", "target": target, "applied": "simulate"},
    ))
    return reg
