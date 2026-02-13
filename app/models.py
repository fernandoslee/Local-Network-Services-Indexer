"""Data models for the Service Lens dashboard."""

import re
from dataclasses import dataclass, field
from urllib.parse import urlparse

_STATE_SORT_ORDER = {
    "RUNNING": 0,
    "RESTARTING": 1,
    "PAUSED": 2,
    "EXITED": 3,
    "SHUTOFF": 3,
    "UNKNOWN": 4,
}


@dataclass
class ContainerInfo:
    """Resolved container data for display."""

    id: str
    name: str
    state: str
    image: str
    status: str
    auto_start: bool
    web_ui_url: str | None
    icon_url: str | None
    network_mode: str
    ports: list[dict]

    @property
    def is_running(self) -> bool:
        return self.state == "RUNNING"

    @property
    def is_restarting(self) -> bool:
        return self.state == "RESTARTING"

    @property
    def exit_code(self) -> int | None:
        """Extract exit code from status string like 'Exited (143) 3 months ago'."""
        m = re.search(r"Exited\s*\((\d+)\)", self.status, re.IGNORECASE)
        return int(m.group(1)) if m else None

    @property
    def exited_cleanly(self) -> bool:
        """True if container exited normally (code 0, 137/SIGKILL, 143/SIGTERM) or was never started."""
        code = self.exit_code
        if code is None:
            return True  # no exit code means never ran or status not available
        return code in (0, 137, 143)

    @property
    def state_lower(self) -> str:
        """State for CSS class. Differentiates clean exit vs crash."""
        s = self.state.lower()
        if s == "exited" and self.exited_cleanly:
            return "stopped"
        return s

    @property
    def display_status(self) -> str:
        """Clean up Docker status string for display."""
        s = self.status
        s = re.sub(r"\s*\(healthy\)", "", s, flags=re.IGNORECASE)
        s = re.sub(r"\s*\(unhealthy\)", "", s, flags=re.IGNORECASE)
        s = re.sub(r"Exited\s*\(\d+\)\s*", "Exited ", s, flags=re.IGNORECASE)
        return s.strip()

    @property
    def display_state(self) -> str:
        """Human-friendly state label."""
        if self.state == "EXITED":
            return "STOPPED" if self.exited_cleanly else "FAILED"
        return self.state

    @property
    def sort_key(self) -> tuple:
        return (_STATE_SORT_ORDER.get(self.state, 9), self.name.lower())

    @property
    def address(self) -> str | None:
        """Extract host:port from web_ui_url or port mappings."""
        if self.web_ui_url:
            try:
                parsed = urlparse(self.web_ui_url)
                if parsed.hostname:
                    port = parsed.port or (443 if parsed.scheme == "https" else 80)
                    return f"{parsed.hostname}:{port}"
            except Exception:
                pass
        # Fallback: first public port mapping
        for p in self.ports:
            if p.get("publicPort") and p.get("ip"):
                return f"{p['ip']}:{p['publicPort']}"
        return None

    @property
    def port_list(self) -> str:
        """Show the service port (from web UI URL) or fall back to all mappings."""
        if self.web_ui_url:
            try:
                parsed = urlparse(self.web_ui_url)
                port = parsed.port or (443 if parsed.scheme == "https" else 80)
                return str(port)
            except Exception:
                pass
        # No web UI — show public port mappings
        parts = []
        for p in self.ports:
            pub = p.get("publicPort")
            if pub:
                parts.append(str(pub))
        return ", ".join(parts[:3]) + ("..." if len(parts) > 3 else "") if parts else ""


@dataclass
class VmInfo:
    """VM data for display."""

    id: str
    name: str
    state: str

    @property
    def state_lower(self) -> str:
        return self.state.lower()

    @property
    def is_running(self) -> bool:
        return self.state == "RUNNING"

    @property
    def sort_key(self) -> tuple:
        return (_STATE_SORT_ORDER.get(self.state, 9), self.name.lower())


@dataclass
class PluginInfo:
    """Plugin data for display."""

    name: str
    version: str
    display_name: str


@dataclass
class SystemInfo:
    """System info for display."""

    hostname: str | None = None
    distro: str | None = None
    release: str | None = None
    kernel: str | None = None
    cpu_brand: str | None = None
    cpu_cores: int | None = None
    cpu_threads: int | None = None
    lan_ip: str | None = None
    sw_version: str | None = None


@dataclass
class SystemMetrics:
    """System metrics for display."""

    cpu_percent: float | None = None
    cpu_temperature: float | None = None
    memory_percent: float | None = None
    memory_total: int | None = None
    memory_used: int | None = None
    uptime: object = None  # datetime


@dataclass
class CachedData:
    containers: list[ContainerInfo] = field(default_factory=list)
    vms: list[VmInfo] = field(default_factory=list)
    plugins: list[PluginInfo] = field(default_factory=list)
    system_info: SystemInfo | None = None
    system_metrics: SystemMetrics | None = None
    last_fetched: float = 0.0
    error: str | None = None
    can_control_containers: bool = True
