import sys
import pytest
from unittest.mock import AsyncMock, patch, MagicMock
from kelan.doctor import doctor, _check


def test_check_helper(capsys):
    assert _check("Test Passed", True) is True
    out = capsys.readouterr().out
    assert "✔ Test Passed" in out

    assert _check("Test Failed Required", False, "some detail", required=True) is False
    out = capsys.readouterr().out
    assert "✘ Test Failed Required  (some detail)" in out

    assert _check("Test Failed Optional", False, "optional detail", required=False) is False
    out = capsys.readouterr().out
    assert "▲ Test Failed Optional  (optional detail)" in out


@pytest.mark.asyncio
async def test_doctor_failure_when_ollama_unreachable():
    with patch("httpx.AsyncClient.get", side_effect=Exception("Connection refused")):
        code = await doctor()
        assert code == 1


@pytest.mark.asyncio
async def test_doctor_failure_when_no_models_pulled():
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.content = b'{"models": []}'
    mock_resp.json.return_value = {"models": []}

    with patch("httpx.AsyncClient.get", new_callable=AsyncMock, return_value=mock_resp), \
         patch("importlib.util.find_spec", return_value=MagicMock()):
        code = await doctor()
        assert code == 1


@pytest.mark.asyncio
async def test_doctor_failure_when_python_too_old():
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.content = b'{"models": [{"name": "qwen2.5-coder:latest"}]}'
    mock_resp.json.return_value = {"models": [{"name": "qwen2.5-coder:latest"}]}

    with patch.object(sys, "version_info", (3, 9, 5)), \
         patch("httpx.AsyncClient.get", new_callable=AsyncMock, return_value=mock_resp), \
         patch("importlib.util.find_spec", return_value=MagicMock()):
        code = await doctor()
        assert code == 1


@pytest.mark.asyncio
async def test_doctor_failure_when_tree_sitter_grammars_missing():
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.content = b'{"models": [{"name": "qwen2.5-coder:latest"}]}'
    mock_resp.json.return_value = {"models": [{"name": "qwen2.5-coder:latest"}]}

    def mock_find_spec(mod):
        if mod == "tree_sitter_python":
            return None
        return MagicMock()

    with patch("httpx.AsyncClient.get", new_callable=AsyncMock, return_value=mock_resp), \
         patch("importlib.util.find_spec", side_effect=mock_find_spec):
        code = await doctor()
        assert code == 1


@pytest.mark.asyncio
async def test_doctor_success_mocked():
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.content = b'{"models": [{"name": "qwen2.5-coder:latest"}]}'
    mock_resp.json.return_value = {"models": [{"name": "qwen2.5-coder:latest"}]}

    with patch("httpx.AsyncClient.get", new_callable=AsyncMock, return_value=mock_resp), \
         patch("importlib.util.find_spec", return_value=MagicMock()):
        code = await doctor()
        assert code == 0
