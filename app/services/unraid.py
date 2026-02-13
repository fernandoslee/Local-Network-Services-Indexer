import logging
import re
import time

from unraid_api import UnraidClient
from unraid_api.exceptions import UnraidAPIError, UnraidAuthenticationError

from app.models import (
    CachedData,
    ContainerInfo,
    SystemInfo,
    SystemMetrics,
    VmInfo,
)

logger = logging.getLogger(__name__)

CONTAINER_QUERY = """
query {
    docker {
        containers {
            id
            names
            image
            state
            status
            autoStart
            ports { ip privatePort publicPort type }
            labels
            hostConfig { networkMode }
            networkSettings
        }
    }
}
"""

VM_QUERY = """
query {
    vms {
        domains {
            id
            name
            state
        }
    }
}
"""

def _resolve_webui_url(
    webui_template: str,
    server_ip: str,
    container_ip: str | None,
    ports: list[dict],
    network_mode: str,
) -> str | None:
    """Resolve a net.unraid.docker.webui template to an actual URL."""
    if not webui_template:
        return None

    url = webui_template

    # macvlan (br0/br1/etc.) containers have their own LAN IP
    # bridge and container-mode use the server IP
    # Note: "bridge" also starts with "br" so we must exclude it explicitly
    is_macvlan = network_mode.startswith("br") and network_mode != "bridge"
    if is_macvlan and container_ip:
        ip = container_ip
    else:
        ip = server_ip

    url = url.replace("[IP]", ip)

    def replace_port(match: re.Match) -> str:
        private_port = int(match.group(1))
        for p in ports:
            if p.get("privatePort") == private_port and p.get("publicPort"):
                return str(p["publicPort"])
        return str(private_port)

    url = re.sub(r"\[PORT:(\d+)\]", replace_port, url)

    # Validate URL scheme to prevent javascript: or data: URIs
    if not url.lower().startswith(("http://", "https://")):
        return None

    # Strip API-only paths that aren't the actual web UI
    # (e.g., Sonarr/Radarr templates end with /system/status which is an API endpoint)
    url = re.sub(r"/system/status/?$", "/", url)

    return url


class UnraidService:
    def __init__(self, client: UnraidClient, cache_ttl: int = 10, server_host: str = ""):
        self.client = client
        self.cache_ttl = cache_ttl
        self._cache = CachedData()
        self._server_host = server_host  # configured hostname (e.g., "tower.lan")
        self._server_ip: str | None = None
        self._can_control_containers: bool | None = None

    @property
    def can_control_containers(self) -> bool:
        """Whether the API key has DOCKER:UPDATE_ANY permission.

        Returns True (optimistic) until the first probe completes.
        """
        if self._can_control_containers is None:
            return True
        return self._can_control_containers

    async def _probe_container_control(self) -> None:
        """Probe whether the API key can control containers.

        Tries to start a non-existent container ID. A permission error means
        the key lacks DOCKER:UPDATE_ANY. Any other error (e.g., not found)
        means the key has the permission but the container ID was invalid.
        """
        try:
            await self.client.start_container("__probe__")
            # Unlikely: succeeded somehow — has permission
            self._can_control_containers = True
        except UnraidAuthenticationError:
            self._can_control_containers = False
        except UnraidAPIError as e:
            msg = str(e).lower()
            if "forbidden" in msg or "unauthorized" in msg or "permission" in msg:
                self._can_control_containers = False
            else:
                # Generic error (e.g., "not found") — has permission
                self._can_control_containers = True
        except Exception:
            # Network or unexpected errors — assume has permission
            self._can_control_containers = True

    def _cache_valid(self) -> bool:
        return (time.monotonic() - self._cache.last_fetched) < self.cache_ttl

    async def _get_server_ip(self) -> str:
        """Get the server address for URL resolution.

        Uses the configured hostname (e.g., tower.lan) when available,
        falling back to the LAN IP from the API. Using the hostname avoids
        Chrome's HTTPS-First mode blocking bare IP HTTP links.
        """
        if self._server_ip is None:
            # Prefer configured hostname over API-returned IP
            if self._server_host:
                self._server_ip = self._server_host
            else:
                try:
                    info = await self.client.get_server_info()
                    self._server_ip = info.lan_ip or "localhost"
                except Exception:
                    self._server_ip = "localhost"
        return self._server_ip

    async def get_all_data(self) -> CachedData:
        if self._cache_valid():
            return self._cache

        # Probe container control permission once
        if self._can_control_containers is None:
            await self._probe_container_control()

        errors: list[str] = []
        server_ip = await self._get_server_ip()

        # --- Containers ---
        containers: list[ContainerInfo] = []
        try:
            raw = await self.client.query(CONTAINER_QUERY)
            raw_containers = raw.get("docker", {}).get("containers", []) or []

            # Build lookup for container-mode networking (VPN parent ports)
            id_to_raw: dict[str, dict] = {}
            for c in raw_containers:
                cid = c.get("id", "")
                if ":" in cid:
                    docker_id = cid.split(":", 1)[1]
                    id_to_raw[docker_id] = c

            for c in raw_containers:
                labels = c.get("labels") or {}
                ports = c.get("ports") or []
                network_mode = (c.get("hostConfig") or {}).get("networkMode", "bridge")

                # For container-mode networking, get ports from parent
                effective_ports = ports
                if network_mode.startswith("container:"):
                    parent_id = network_mode.split(":", 1)[1]
                    parent = id_to_raw.get(parent_id)
                    if parent:
                        effective_ports = parent.get("ports") or []

                # Get container's own IP for macvlan
                container_ip = None
                ns = c.get("networkSettings")
                if ns and isinstance(ns, dict):
                    for net_info in (ns.get("Networks") or {}).values():
                        if isinstance(net_info, dict) and net_info.get("IPAddress"):
                            container_ip = net_info["IPAddress"]
                            break

                webui_template = labels.get("net.unraid.docker.webui", "")
                icon_url = labels.get("net.unraid.docker.icon") or None

                web_ui_url = _resolve_webui_url(
                    webui_template, server_ip, container_ip,
                    effective_ports, network_mode,
                )

                names = c.get("names") or ["unknown"]
                name = names[0].lstrip("/")

                containers.append(ContainerInfo(
                    id=c.get("id", ""),
                    name=name,
                    state=c.get("state", "UNKNOWN"),
                    image=c.get("image", ""),
                    status=c.get("status", ""),
                    auto_start=c.get("autoStart", False),
                    web_ui_url=web_ui_url,
                    icon_url=icon_url,
                    network_mode=network_mode,
                    ports=effective_ports,
                ))
        except UnraidAPIError as e:
            logger.error("Failed to fetch containers: %s", e)
            errors.append(f"Containers: {e}")
            containers = self._cache.containers

        # --- VMs ---
        vms: list[VmInfo] = []
        try:
            raw = await self.client.query(VM_QUERY)
            raw_vms = raw.get("vms", {}).get("domains", []) or []
            for v in raw_vms:
                vms.append(VmInfo(
                    id=v.get("id", ""),
                    name=v.get("name", "Unknown"),
                    state=v.get("state", "UNKNOWN"),
                ))
        except UnraidAPIError as e:
            logger.error("Failed to fetch VMs: %s", e)
            errors.append(f"VMs: {e}")
            vms = self._cache.vms

        # --- System info ---
        system_info: SystemInfo | None = None
        try:
            info = await self.client.get_server_info()
            system_info = SystemInfo(
                hostname=info.hostname,
                distro=info.os_distro,
                release=info.os_release,
                kernel=info.hw_version,
                cpu_brand=info.cpu_brand,
                cpu_cores=info.cpu_cores,
                cpu_threads=info.cpu_threads,
                lan_ip=info.lan_ip,
                sw_version=info.sw_version,
            )
        except UnraidAPIError as e:
            logger.error("Failed to fetch system info: %s", e)
            errors.append(f"System info: {e}")
            system_info = self._cache.system_info

        # --- System metrics ---
        system_metrics: SystemMetrics | None = None
        try:
            metrics = await self.client.get_system_metrics()
            system_metrics = SystemMetrics(
                cpu_percent=metrics.cpu_percent,
                cpu_temperature=metrics.cpu_temperature,
                memory_percent=metrics.memory_percent,
                memory_total=metrics.memory_total,
                memory_used=metrics.memory_used,
                uptime=metrics.uptime,
            )
        except UnraidAPIError as e:
            logger.error("Failed to fetch system metrics: %s", e)
            errors.append(f"Metrics: {e}")
            system_metrics = self._cache.system_metrics

        # Sort: running first, then alphabetical
        containers.sort(key=lambda c: c.sort_key)
        vms.sort(key=lambda v: v.sort_key)

        self._cache = CachedData(
            containers=containers,
            vms=vms,
            plugins=[],
            system_info=system_info,
            system_metrics=system_metrics,
            last_fetched=time.monotonic(),
            error="; ".join(errors) if errors else None,
            can_control_containers=self.can_control_containers,
        )
        return self._cache

    def invalidate_cache(self) -> None:
        self._cache.last_fetched = 0.0

    async def start_container(self, container_id: str) -> dict:
        result = await self.client.start_container(container_id)
        self.invalidate_cache()
        return result

    async def stop_container(self, container_id: str) -> dict:
        result = await self.client.stop_container(container_id)
        self.invalidate_cache()
        return result

    async def restart_container(self, container_id: str) -> dict:
        result = await self.client.restart_container(container_id)
        self.invalidate_cache()
        return result

    async def test_connection(self) -> bool:
        """Test connection using a query compatible with minimal permissions.

        The library's client.test_connection() queries ``{ online }`` which
        requires broad permissions.  We query docker containers instead,
        which only needs DOCKER:READ_ANY.
        """
        result = await self.client.query("query { docker { containers { id } } }")
        return "docker" in result
