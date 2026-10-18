import json
import tempfile
from pathlib import Path
from unittest import mock

import pytest

from kelan.core.finding import Confidence, Finding, FindingSet, Severity
from kelan.core.plugin import (
    PluginRegistry,
    PluginResult,
    ScanConfig,
    ScanContext,
    ScanPlugin,
    ScanTarget,
    Scheduler,
    ScopeKind,
    _topo_order,
)
from kelan.plugins.ports import PortsPlugin
from kelan.plugins.sca import ScaPlugin


def test_topo_order():
    class P1(ScanPlugin):
        name = "p1"
        applies_to = {ScopeKind.URL}

    class P2(ScanPlugin):
        name = "p2"
        applies_to = {ScopeKind.URL}
        requires = ("p1",)

    class P3(ScanPlugin):
        name = "p3"
        applies_to = {ScopeKind.URL}
        requires = ("p2", "p1")

    ordered = _topo_order([P3(), P2(), P1()], {"p1", "p2", "p3"})
    names = [p.name for p in ordered]
    assert names == ["p1", "p2", "p3"]


def test_finding_set_deduplication():
    fs = FindingSet()
    
    f1 = Finding(plugin="t1", category="cat1", title="title1", location="loc1")
    f1.add_evidence("kind1", "detail1")
    
    f2 = Finding(plugin="t1", category="cat1", title="title1", location="loc1")
    f2.add_evidence("kind1", "detail1")
    
    f3 = Finding(plugin="t1", category="cat1", title="title2", location="loc2")
    f3.add_evidence("kind1", "detail2")
    
    assert fs.add(f1) is True
    assert fs.add(f2) is False
    assert fs.add(f3) is True
    assert len(fs) == 2


def test_finding_set_sarif():
    fs = FindingSet()
    f = Finding(
        plugin="test", category="vuln", title="High Vuln",
        severity=Severity.HIGH, confidence=Confidence.STRONG,
        location="src/lib.py:42"
    )
    f.add_evidence("kind", "detail")
    fs.add(f)
    
    sarif = fs.to_sarif()
    assert sarif["version"] == "2.1.0"
    assert len(sarif["runs"]) == 1
    run = sarif["runs"][0]
    assert run["tool"]["driver"]["name"] == "kelan"
    assert len(run["results"]) == 1
    res = run["results"][0]
    assert res["ruleId"] == "kelan/test/vuln"
    assert res["level"] == "error"
    assert res["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] == "src/lib.py"
    assert res["locations"][0]["physicalLocation"]["region"]["startLine"] == 42


@pytest.mark.asyncio
async def test_sca_manifest_parsing():
    with tempfile.TemporaryDirectory() as tmp_dir:
        tmp_path = Path(tmp_dir)
        

        req_file = tmp_path / "requirements.txt"
        req_file.write_text("requests==2.31.0\npytest===8.1.0\n# comment\ninvalid_line")
        

        pkg_file = tmp_path / "package.json"
        pkg_file.write_text(json.dumps({
            "dependencies": {
                "express": "^4.18.2"
            }
        }))
        
        sca = ScaPlugin()
        specs = await sca._collect_manifests(tmp_path)
        
        assert len(specs) == 3

        reqs = [s for s in specs if s["eco"] == "PyPI"]
        assert len(reqs) == 2
        assert any(r["name"] == "requests" and r["version"] == "2.31.0" for r in reqs)
        assert any(r["name"] == "pytest" and r["version"] == "8.1.0" for r in reqs)
        

        npms = [s for s in specs if s["eco"] == "npm"]
        assert len(npms) == 1
        assert npms[0]["name"] == "express"
        assert npms[0]["version"] == "4.18.2"


@pytest.mark.asyncio
@mock.patch("kelan.plugins.ports.scan_host")
async def test_ports_plugin_scanning(mock_scan):

    async def mock_generator(*args, **kwargs):
        yield {"port": 80, "status": "OPEN", "banner": "nginx/1.18.0"}
        yield {"port": 22, "status": "CLOSED", "banner": ""}
        
    mock_scan.side_effect = mock_generator
    
    target = ScanTarget(ScopeKind.URL, "http://localhost:8080")
    ctx = ScanContext(target, ScanConfig(), Path("/tmp"))
    
    ports_plugin = PortsPlugin()
    res = await ports_plugin.run(ctx)
    
    assert len(res.findings) == 1
    f = res.findings[0]
    assert f.title == "Open TCP Port: 80"
    assert f.severity == Severity.LOW
    assert len(f.evidence) == 1
    assert f.evidence[0].kind == "port_open"
    assert "nginx/1.18.0" in f.evidence[0].detail
    

    assert ctx.consume("open_http") == ["http://localhost:80"]


@pytest.mark.asyncio
async def test_scheduler_lifecycle():
    class DummyPlugin(ScanPlugin):
        name = "dummy"
        applies_to = {ScopeKind.URL}
        
        async def run(self, ctx: ScanContext) -> PluginResult:
            f = Finding(plugin=self.name, category="test", title="Dummy")
            f.add_evidence("advisory", "test dummy evidence")
            return PluginResult(self.name, findings=[f])

    registry = PluginRegistry()
    registry.register(DummyPlugin())
    
    target = ScanTarget(ScopeKind.URL, "http://example.com")
    scheduler = Scheduler(registry)
    
    findings, results = await scheduler.run(target)
    scheduler.cleanup()
    
    assert len(findings) == 1
    assert findings.items[0].plugin == "dummy"
    assert "dummy" in results
    assert results["dummy"].skipped is False
