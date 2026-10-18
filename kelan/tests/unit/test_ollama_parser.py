"""Tests for Ollama response parser — no Ollama needed."""
from kelan.ai.ollama_client import _parse, Verdict


class TestParser:

    def test_clean_json_deny(self):
        raw = '{"verdict":"DENY","confidence":0.95,"reason":"syn flood"}'
        v = _parse(raw)
        assert v.verdict    == Verdict.DENY
        assert v.confidence == 0.95
        assert "syn" in v.reason

    def test_clean_json_allow(self):
        raw = '{"verdict":"ALLOW","confidence":0.88,"reason":"clean session"}'
        v = _parse(raw)
        assert v.verdict == Verdict.ALLOW

    def test_clean_json_monitor(self):
        raw = '{"verdict":"MONITOR","confidence":0.60,"reason":"suspicious"}'
        v = _parse(raw)
        assert v.verdict == Verdict.MONITOR

    def test_low_confidence_forces_monitor(self):
        raw = '{"verdict":"DENY","confidence":0.3,"reason":"uncertain"}'
        v = _parse(raw)
        assert v.verdict == Verdict.MONITOR   # low conf → MONITOR

    def test_json_embedded_in_prose(self):
        raw = 'I analyzed the session and found: {"verdict":"DENY","confidence":0.91,"reason":"port scan"} based on the anomalies.'
        v = _parse(raw)
        assert v.verdict == Verdict.DENY

    def test_keyword_fallback_deny(self):
        v = _parse("The session should be DENY due to flood patterns")
        assert v.verdict == Verdict.DENY

    def test_keyword_fallback_allow(self):
        v = _parse("This session looks ALLOW - clean traffic")
        assert v.verdict == Verdict.ALLOW

    def test_completely_unparseable(self):
        v = _parse("I cannot determine the verdict from this data.")
        assert v.verdict    == Verdict.MONITOR
        assert v.confidence == 0.50

    def test_empty_string(self):
        v = _parse("")
        assert v.verdict == Verdict.MONITOR

    def test_markdown_json_block(self):
        raw = '```json\n{"verdict":"DENY","confidence":0.92,"reason":"attack"}\n```'
        v = _parse(raw)
        assert v.verdict == Verdict.DENY

    def test_reason_truncated(self):
        long_reason = "A" * 300
        raw = f'{{"verdict":"ALLOW","confidence":0.8,"reason":"{long_reason}"}}'
        v = _parse(raw)
        assert len(v.reason) <= 120
