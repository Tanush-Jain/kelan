
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

        log.info("ports_scan_start", host=host, port_count=len(ports))
        findings = []
        open_http_urls = []

        pr = PluginResult(plugin=self.name)

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
        pr.meta = {
            "open_ports": [f.location for f in findings],
            "open_http_urls": open_http_urls,
        }
        

        if open_http_urls:
            ctx.publish("open_http", open_http_urls)
            log.info("ports_published_http", urls=open_http_urls)

        return pr
