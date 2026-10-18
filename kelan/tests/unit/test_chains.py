import pytest
from kelan.core.finding import Finding, Severity, Confidence
from kelan.chains.correlation import correlate

def test_chains_correlate_debug_port():
    findings = [
        Finding(
            plugin="recon_ports",
            category="port",
            title="Open TCP Port: 8080",
            severity=Severity.LOW,
            confidence=Confidence.STRONG,
            cwe="CWE-200"
        ),
        Finding(
            plugin="dast",
            category="misconfig",
            title="Exposed Spring Boot actuator/env configuration",
            severity=Severity.MEDIUM,
            confidence=Confidence.STRONG,
            cwe="CWE-200"
        )
    ]
    
    correlated = correlate(findings)
    assert len(correlated) == 1
    assert correlated[0].title == "Open debug port exposes configuration endpoints"
    assert correlated[0].severity == Severity.CRITICAL

def test_chains_correlate_static_to_live():
    findings = [
        Finding(
            plugin="sast",
            category="injection",
            title="SQL Injection sink detected",
            severity=Severity.HIGH,
            confidence=Confidence.MEDIUM,
            cwe="CWE-89"
        ),
        Finding(
            plugin="dast",
            category="injection",
            title="SQL Error message echo detected",
            severity=Severity.HIGH,
            confidence=Confidence.STRONG,
            cwe="CWE-89"
        )
    ]
    
    correlated = correlate(findings)
    assert len(correlated) == 1
    assert correlated[0].title == "Confirmed exploitable injection (static sink + live evidence)"
    assert correlated[0].severity == Severity.CRITICAL
