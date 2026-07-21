"""Tests for Sentinel anomaly detection."""
from kelan.sentinel.detector import SentinelDetector


class TestSentinel:

    def setup_method(self):
        self.s = SentinelDetector()

    def test_clean_session_no_anomalies(self):
        a = self.s.analyze("legit-entity", "INIT_ENROL")
        assert a == {}

    def test_sybil_detected_after_burst(self):
        a = {}
        for i in range(15):
            a = self.s.analyze(f"sybil-{i}", "INIT_ENROL", source_ip="10.0.0.10")
        assert "rapid_enrollment_burst" in a
        assert a["enrollment_count_from_ip"] >= 10
        assert a["pattern"] == "sybil_attack"

    def test_flood_detected_high_rate(self):
        # Simulate 60 connections in < 1 second
        a = {}
        for _ in range(60):
            a = self.s.analyze("flooder", "NETWORK_PACKET", source_ip="10.0.0.99")
        assert "syn_rate_per_second" in a
        assert a["syn_rate_per_second"] > 50

    def test_port_scan_threshold_100(self):
        for p in range(101):
            self.s.record_port_probe("10.0.0.5", p)
        events = self.s.recent(10)
        kinds = [e["kind"] for e in events]
        assert "port_scan" in kinds

    def test_recent_returns_list(self):
        assert isinstance(self.s.recent(), list)

    def test_brute_force_detected(self):
        a = {}
        for _ in range(25):
            a = self.s.analyze("bruteforce", "AUTH_ATTEMPT", source_ip="1.2.3.4")
        assert "failed_auth_attempts" in a
        assert a["pattern"] == "brute_force"

    def test_file_access_restricted_path_detected(self):
        res = self.s.record_file_access("agent-1", "/etc/ssh/sshd_config")
        assert res.get("out_of_scope_file_access") is True
        events = self.s.recent(1)
        assert events[0]["kind"] == "out_of_scope_file_access"

    def test_file_access_outside_declared_scope_detected(self):
        res = self.s.record_file_access("agent-1", "/var/data/secret.json", declared_scope=["/app/data/"])
        assert res.get("out_of_scope_file_access") is True

    def test_network_connect_outside_scope_detected(self):
        res = self.s.record_network_connect("agent-1", "untrusted-site.com", 443, declared_scope=["api.internal.org"])
        assert res.get("out_of_scope_network_connect") is True

    def test_process_spawn_outside_scope_detected(self):
        res = self.s.record_process_exec("agent-1", "/bin/nc", ["-e", "/bin/sh"], declared_scope=["/usr/bin/python3"])
        assert res.get("out_of_scope_process_spawn") is True
