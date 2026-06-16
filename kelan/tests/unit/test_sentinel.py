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
