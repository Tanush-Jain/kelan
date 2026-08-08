import tempfile
from pathlib import Path
from unittest.mock import AsyncMock, patch

import pytest

from kelan.cloud.audit import audit_creds, check_s3_bucket


def test_audit_creds_finding():
    code = f"""
aws_key = "{"AKIA"}{"1234567890ABCDEF"}"
stripe_key = "{"sk_live_"}{"123456789012345678901234"}"
metadata_ip = "169.254.169.254"
"""
    with tempfile.TemporaryDirectory() as tmpdir:
        p = Path(tmpdir) / "secrets.py"
        p.write_text(code)
        
        findings = audit_creds(Path(tmpdir))
        
        titles = [f.title for f in findings]
        assert "AWS Access Key ID leaked (aws)" in titles
        assert "Stripe Live Secret Key leaked (stripe)" in titles
        assert "Instance metadata endpoint (169.254.169.254) accessed" in titles

@pytest.mark.asyncio
async def test_check_s3_bucket_public():
    mock_response = AsyncMock()
    mock_response.status_code = 200
    mock_response.text = "<ListBucketResult xmlns='...'>...</ListBucketResult>"
    
    with patch("httpx.AsyncClient.get", return_value=mock_response):
        finding = await check_s3_bucket("my-public-bucket")
        assert finding is not None
        assert "allows public listing" in finding.title

@pytest.mark.asyncio
async def test_check_s3_bucket_private():
    mock_response = AsyncMock()
    mock_response.status_code = 403
    mock_response.text = "Access Denied"
    
    with patch("httpx.AsyncClient.get", return_value=mock_response):
        finding = await check_s3_bucket("my-private-bucket")
        assert finding is None
