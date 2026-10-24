import logging
import os
import ipaddress
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any

import requests

logger = logging.getLogger(__name__)

TERMINAL_STATUSES = {"completed", "failed", "cancelled"}
AGENT_PORT = 9000
AGENT_HEALTH_PATH = "/healthz"
MAX_AGENT_DISCOVERY_HOSTS = 256
AGENT_DISCOVERY_WORKERS = 64
AGENT_DISCOVERY_CONNECT_TIMEOUT = 0.4
AGENT_DISCOVERY_HTTP_TIMEOUT = (1, 2)


class NmapAgentError(RuntimeError):
    """Base error for communication with the Nmap agent."""


class NmapAgentConnectionError(NmapAgentError):
    """The backend could not connect to the Nmap agent."""


class NmapAgentResponseError(NmapAgentError):
    """The agent returned an unexpected or unsuccessful response."""


class NmapAgentClient:
    def __init__(
        self,
        base_url: str | None = None,
        token: str | None = None,
        # Full-subnet Nmap discovery can take longer than 30 seconds on some
        # LANs. The Pi agent itself allows Nmap up to 180 seconds, so allow a
        # little extra time for the HTTP response to return.
        request_timeout: tuple[float, float] = (15, 210),
        poll_interval: float = 2,
    ) -> None:
        self.base_url = (
            base_url or os.getenv("NMAP_AGENT_URL", "")
        ).rstrip("/")
        self.token = token or os.getenv("NMAP_AGENT_TOKEN", "")
        self.request_timeout = request_timeout
        self.poll_interval = poll_interval

        # The agent is a private-LAN service. Do not let desktop/system proxy
        # settings route requests for it away from the local network.
        self.session = requests.Session()
        self.session.trust_env = False
        self._agent_discovery_attempted_for: set[str] = set()
        self._agent_discovery_lock = threading.Lock()

        if not self.token:
            raise ValueError("NMAP_AGENT_TOKEN is not configured")

        self.headers = {
            "Authorization": f"Bearer {self.token}",
            "Accept": "application/json",
        }

    def _request(self, method: str, path: str, **kwargs: Any) -> dict[str, Any]:
        url = f"{self.base_url}{path}"

        try:
            response = self.session.request(
                method,
                url,
                headers=self.headers,
                timeout=self.request_timeout,
                **kwargs,
            )
        except requests.RequestException as exc:
            # Do not log the token or authorization headers.
            logger.exception("Could not connect to Nmap agent: %s %s", method, path)
            raise NmapAgentConnectionError(
                f"Could not connect to Nmap agent at {self.base_url}: {exc}"
            ) from exc

        if not response.ok:
            logger.error(
                "Nmap agent returned HTTP %s for %s %s",
                response.status_code,
                method,
                path,
            )
            raise NmapAgentResponseError(
                f"Nmap agent returned HTTP {response.status_code}"
            )

        try:
            payload = response.json()
        except ValueError as exc:
            raise NmapAgentResponseError(
                "Nmap agent returned invalid JSON"
            ) from exc

        if not isinstance(payload, dict):
            raise NmapAgentResponseError(
                "Nmap agent response must be a JSON object"
            )

        return payload

    def submit_subnet_job(self, network: str) -> str:
        payload = self._request(
            "POST",
            "/v1/jobs",
            json={"target": network},
        )

        job_id = payload.get("job_id")
        if not isinstance(job_id, str) or not job_id:
            raise NmapAgentResponseError(
                "Nmap agent response did not contain a valid job_id"
            )

        return job_id

    def scan_host(self, target: str) -> dict[str, Any]:
        """Perform a direct service and port scan on a single target host via the Pi agent."""
        payload = self._request(
            "POST",
            "/v1/scan",
            json={"target": target},
        )
        if not isinstance(payload, dict):
            raise NmapAgentResponseError("Nmap agent scan response must be a JSON object")
        return payload

    def discover_hosts(self, network: str) -> list[dict[str, Any]]:
        """Return live hosts from the agent's dedicated L2/L3 discovery endpoint."""
        if not self.base_url:
            self.base_url = self._find_agent_url(network)
        try:
            payload = self._request(
                "POST",
                "/v1/discover",
                json={"network": network},
            )
        except NmapAgentConnectionError as exc:
            # A read timeout means the agent may still be running the scan;
            # do not start a second discovery. For connect/DNS failures, find
            # its current DHCP address on the scan's private LAN and retry.
            if isinstance(exc.__cause__, requests.ReadTimeout):
                raise
            self.base_url = self._find_agent_url(network)
            payload = self._request(
                "POST",
                "/v1/discover",
                json={"network": network},
            )
        hosts = payload.get("hosts")
        if not isinstance(hosts, list):
            raise NmapAgentResponseError(
                "Nmap agent discovery response did not contain a hosts list"
            )

        normalized = []
        for host in hosts:
            if not isinstance(host, dict):
                continue
            ip_address = host.get("ip_address") or host.get("ip")
            if not isinstance(ip_address, str) or not ip_address:
                logger.warning("Skipping discovered agent host without an IP: %r", host)
                continue
            hostnames = host.get("hostnames") or []
            normalized.append({
                **host,
                "ip_address": ip_address,
                "hostname": host.get("hostname") or (hostnames[0] if hostnames else None),
                "mac_address": host.get("mac_address") or host.get("mac"),
            })
        return normalized

    def _find_agent_url(self, network: str) -> str:
        """Find the Pi agent by its health endpoint inside the requested LAN."""
        try:
            lan = ipaddress.ip_network(network, strict=False)
        except ValueError as exc:
            raise NmapAgentConnectionError(
                f"Cannot search for the Pi agent: invalid LAN CIDR {network!r}"
            ) from exc

        private_ranges = (
            ipaddress.ip_network("10.0.0.0/8"),
            ipaddress.ip_network("172.16.0.0/12"),
            ipaddress.ip_network("192.168.0.0/16"),
        )
        if (
            not isinstance(lan, ipaddress.IPv4Network)
            or not any(lan.subnet_of(private_range) for private_range in private_ranges)
            or lan.prefixlen < 24
            or lan.num_addresses > MAX_AGENT_DISCOVERY_HOSTS
        ):
            raise NmapAgentConnectionError(
                f"Automatic Pi-agent discovery only searches private IPv4 networks up to /24; got {network}"
            )

        with self._agent_discovery_lock:
            if str(lan) in self._agent_discovery_attempted_for:
                raise NmapAgentConnectionError(
                    f"Could not locate the Pi agent on {lan}; confirm it is online on this LAN and TCP port {AGENT_PORT} is reachable"
                )
            self._agent_discovery_attempted_for.add(str(lan))

        candidates = list(lan.hosts())

        def probe(address: ipaddress.IPv4Address) -> str | None:
            try:
                with requests.Session() as session:
                    session.trust_env = False
                    response = session.get(
                        f"http://{address}:{AGENT_PORT}{AGENT_HEALTH_PATH}",
                        timeout=AGENT_DISCOVERY_HTTP_TIMEOUT,
                    )
                    if not response.ok:
                        return None
                    health = response.json()
                    if (
                        isinstance(health, dict)
                        and health.get("service") == "AI-GRC Nmap Agent"
                        and health.get("status") == "ok"
                        and health.get("nmap_available") is True
                    ):
                        return f"http://{address}:{AGENT_PORT}"
            except (requests.RequestException, ValueError):
                return None
            return None

        with ThreadPoolExecutor(max_workers=AGENT_DISCOVERY_WORKERS) as pool:
            futures = {
                pool.submit(probe, address): address
                for address in candidates
            }
            for future in as_completed(futures):
                discovered_url = future.result()
                if discovered_url:
                    for pending in futures:
                        pending.cancel()
                    logger.info("Automatically discovered Pi Nmap agent at %s", discovered_url)
                    return discovered_url

        raise NmapAgentConnectionError(
            f"Could not locate the Pi agent on {lan}; confirm it is online on this LAN and TCP port {AGENT_PORT} is reachable"
        )

    def get_job(self, job_id: str) -> dict[str, Any]:
        return self._request("GET", f"/v1/jobs/{job_id}")

    def cancel_job(self, job_id: str) -> dict[str, Any]:
        return self._request("POST", f"/v1/jobs/{job_id}/cancel")

    def wait_for_job(
        self,
        job_id: str,
        max_wait_seconds: float | None = None,
    ) -> Any:
        deadline = (
            time.monotonic() + max_wait_seconds
            if max_wait_seconds is not None
            else None
        )

        while True:
            job = self.get_job(job_id)
            status = job.get("status")

            if status == "completed":
                if "results" not in job:
                    raise NmapAgentResponseError(
                        "Completed Nmap job response did not contain results"
                    )
                return job["results"]

            if status == "failed":
                detail = job.get("error") or job.get("detail") or "Unknown agent error"
                raise NmapAgentError(f"Nmap job failed: {detail}")

            if status == "cancelled":
                raise NmapAgentError(f"Nmap job {job_id} was cancelled")

            if status not in {"queued", "running", "cancelling"}:
                raise NmapAgentResponseError(
                    f"Nmap agent returned unknown job status: {status!r}"
                )

            if deadline is not None and time.monotonic() >= deadline:
                raise TimeoutError(f"Timed out waiting for Nmap job {job_id}")

            time.sleep(self.poll_interval)

    def scan_subnet(
        self,
        network: str,
        max_wait_seconds: float | None = None,
    ) -> tuple[str, Any]:
        """Submit a subnet job and return (job_id, results) when it completes."""
        job_id = self.submit_subnet_job(network)
        results = self.wait_for_job(job_id, max_wait_seconds=max_wait_seconds)
        return job_id, results
