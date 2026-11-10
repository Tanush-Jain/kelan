
from __future__ import annotations

from urllib.parse import urlparse

import structlog

from kelan.core.finding import Confidence, Finding, Severity
from kelan.core.plugin import PluginResult, ScanContext, ScanPlugin, ScopeKind
from kelan.recon.ports import DEFAULT_PORTS, scan_host

log = structlog.get_logger()


class PortsPlugin(ScanPlugin):
    name = "recon_ports"
    version = "0.1"
    description = "Asynchronous TCP port discovery and banner grabbing"
    applies_to = {ScopeKind.HOST, ScopeKind.URL}

    async def run(self, ctx: ScanContext) -> PluginResult:
        target_value = ctx.target.value
        

        if ctx.target.kind == ScopeKind.URL:
            u = urlparse(target_value)
            host = u.hostname or u.path
        else:
            host = target_value

        if not host:
            return PluginResult(self.name, errors=["Empty target host resolved"])

        cfg = ctx.config.section("recon_ports")
        ports = cfg.get("ports") or DEFAULT_PORTS
        timeout = cfg.get("timeout", 0.5)
        concurrency = cfg.get("concurrency", 50)
        scan_mode = cfg.get("mode", "tcp_connect")

        pr = PluginResult(plugin=self.name)

        # Check for optional recon extra (scapy, netifaces)
        has_recon_extra = True
        try:
            import netifaces  # noqa: F401
            import scapy  # noqa: F401
        except ImportError:
            has_recon_extra = False

        if scan_mode in ("syn", "raw") and not has_recon_extra:
            err_msg = (
                "Raw packet recon requires the [recon] extra (scapy, netifaces). "
                "Install with: pip install kelan[recon]. On Windows, Npcap is also required."
            )
            pr.errors.append(err_msg)
            pr.meta["recon_degraded"] = True
            pr.meta["recon_notice"] = (
                "Advanced raw packet scanning unavailable without kelan[recon]. "
                "Degrading to standard TCP connect socket scan."
            )
            log.warning("recon_ports_degraded", reason=err_msg)
        elif not has_recon_extra:
            pr.meta["recon_notice"] = (
                "Optional [recon] extra (scapy, netifaces) not installed. "
                "Running in standard TCP connect mode. Install with: pip install kelan[recon] (Npcap required on Windows)."
            )

        log.info("ports_scan_start", host=host, port_count=len(ports), mode=scan_mode)
        findings = []
        open_http_urls = []

        async for res in scan_host(host, ports, timeout=timeout, concurrency=concurrency):
            if res["status"] == "OPEN":
                port = res["port"]
                banner = res["banner"]
                

                f = Finding(
                    plugin=self.name,
                    category="port",
                    title=f"Open TCP Port: {port}",
                    severity=Severity.INFO if port not in (80, 443, 8080, 22) else Severity.LOW,
                    confidence=Confidence.STRONG,
                    cwe="CWE-200",
                    remediation=f"Ensure port {port} is intentionally exposed and properly ACLed.",
                    location=f"{host}:{port}",
                    target=host,
                )
                
                detail = f"TCP port {port} is open."
                if banner:
                    detail += f" Grabbed banner: {banner}"
                f.add_evidence(
                    kind="port_open",
                    detail=detail,
                    ref=f"{host}:{port}",
                    snippet=banner,
                )
                findings.append(f)


                if port in (80, 8080, 8000):
                    open_http_urls.append(f"http://{host}:{port}")
                elif port in (443, 8443):
                    open_http_urls.append(f"https://{host}:{port}")

        pr.findings = findings
        pr.meta.update({
            "open_ports": [f.location for f in findings],
            "open_http_urls": open_http_urls,
        })
        

        if open_http_urls:
            ctx.publish("open_http", open_http_urls)
            log.info("ports_published_http", urls=open_http_urls)

        return pr
