import base64
import json

import pytest
import requests

from vt_agent.agent import check_indicator, identify_indicator, root_agent


def test_litellm_model_config_is_json_serializable_for_adk_web():
    model_config = root_agent.model.model_dump()
    assert model_config["model"] == "openai/gemini-3.8-flash-subscription"
    assert "llm_client" not in model_config
    json.dumps(model_config)


def test_identifies_url_domain_ipv4_and_ipv6():
    assert identify_indicator("https://example.com/a") == ("url", "https://example.com/a")
    assert identify_indicator("example.com") == ("domain", "example.com")
    assert identify_indicator("8.8.8.8") == ("ip", "8.8.8.8")
    assert identify_indicator("2001:4860:4860::8888") == ("ip", "2001:4860:4860::8888")


def test_rejects_ambiguous_or_unsupported_indicator():
    with pytest.raises(ValueError, match="Enter a URL, IP address, or domain"):
        identify_indicator("not an indicator")


def test_url_uses_url_safe_base64_without_padding(monkeypatch):
    monkeypatch.setenv("VT_API_KEY", "demo-key")
    captured = {}

    class Response:
        def raise_for_status(self):
            pass

        def json(self):
            return {"data": {"attributes": {"last_analysis_stats": {"malicious": 2, "suspicious": 1, "harmless": 4}}}}

    def fake_get(url, **kwargs):
        captured["url"] = url
        captured.update(kwargs)
        return Response()

    monkeypatch.setattr("vt_agent.agent.requests.get", fake_get)
    result = check_indicator("https://example.com/a?b=1")

    expected_id = base64.urlsafe_b64encode(b"https://example.com/a?b=1").decode().rstrip("=")
    assert captured["url"] == f"https://www.virustotal.com/api/v3/urls/{expected_id}"
    assert captured["headers"]["x-apikey"] == "demo-key"
    assert captured["timeout"] == 15
    assert result["indicator_type"] == "url"
    assert result["detections"] == {
        "malicious": 2,
        "suspicious": 1,
        "harmless": 4,
        "undetected": 0,
        "timeout": 0,
    }


def test_domain_and_ip_use_their_v3_report_endpoints(monkeypatch):
    monkeypatch.setenv("VT_API_KEY", "demo-key")
    requested = []

    class Response:
        def raise_for_status(self):
            pass

        def json(self):
            return {"data": {"attributes": {"last_analysis_stats": {"malicious": 0}}}}

    def fake_get(url, **kwargs):
        requested.append(url)
        return Response()

    monkeypatch.setattr("vt_agent.agent.requests.get", fake_get)
    check_indicator("example.com")
    check_indicator("8.8.8.8")

    assert requested == [
        "https://www.virustotal.com/api/v3/domains/example.com",
        "https://www.virustotal.com/api/v3/ip_addresses/8.8.8.8",
    ]


def test_missing_api_key_returns_setup_guidance(monkeypatch, tmp_path):
    monkeypatch.delenv("VT_API_KEY", raising=False)
    monkeypatch.setenv("VT_API_KEY_FILE", str(tmp_path / "missing-key"))
    result = check_indicator("example.com")
    assert result["error"] == "VirusTotal API key unavailable; check VT_API_KEY or VT_API_KEY_FILE"


def test_reads_virustotal_key_from_configured_secret_file(monkeypatch, tmp_path):
    key_file = tmp_path / "virustotal-api-key"
    key_file.write_text("file-secret\n")
    monkeypatch.delenv("VT_API_KEY", raising=False)
    monkeypatch.setenv("VT_API_KEY_FILE", str(key_file))
    captured = {}

    class Response:
        def raise_for_status(self):
            pass

        def json(self):
            return {"data": {"attributes": {}}}

    def fake_get(url, **kwargs):
        captured.update(kwargs)
        return Response()

    monkeypatch.setattr("vt_agent.agent.requests.get", fake_get)
    result = check_indicator("example.com")

    assert result["indicator_type"] == "domain"
    assert captured["headers"]["x-apikey"] == "file-secret"


def test_api_error_returns_safe_tool_error(monkeypatch):
    monkeypatch.setenv("VT_API_KEY", "demo-key")

    class Response:
        def raise_for_status(self):
            raise requests.HTTPError("private response detail")

    monkeypatch.setattr("vt_agent.agent.requests.get", lambda *args, **kwargs: Response())
    result = check_indicator("example.com")
    assert result["error"] == "VirusTotal lookup failed. Check the indicator, API quota, and connectivity."
    assert "private response detail" not in json.dumps(result)
