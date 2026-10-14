"""A small Google ADK agent that retrieves existing VirusTotal reports."""

import base64
import ipaddress
import os
import re
from pathlib import Path
from urllib.parse import urlsplit

import requests
from google.adk.agents import Agent
from google.adk.models.lite_llm import LiteLlm

VT_API_BASE = "https://www.virustotal.com/api/v3"
VT_API_KEY_FILE = "/home/cptcoggsworth/.local/state/cti-hermes/secrets/virustotal-api-key"
LITELLM_API_BASE = os.getenv("LITELLM_API_BASE", "http://127.0.0.1:4000/v1")
LITELLM_MODEL = os.getenv("LITELLM_MODEL", "gemini-3.8-flash-subscription")
REQUEST_TIMEOUT_SECONDS = 15


class WebSafeLiteLlm(LiteLlm):
    """Keep LiteLLM's runtime client out of ADK Web's JSON graph response."""

    def model_dump(self, *args, **kwargs):
        exclude = kwargs.get("exclude")
        if exclude is None:
            kwargs["exclude"] = {"llm_client"}
        elif isinstance(exclude, dict):
            kwargs["exclude"] = {**exclude, "llm_client": True}
        else:
            kwargs["exclude"] = set(exclude) | {"llm_client"}
        return super().model_dump(*args, **kwargs)


def identify_indicator(indicator: str) -> tuple[str, str]:
    """Return (kind, normalized value) for an HTTP(S) URL, IP, or domain."""
    value = indicator.strip()
    if not value:
        raise ValueError("Enter a URL, IP address, or domain.")

    if value.lower().startswith(("http://", "https://")):
        parsed = urlsplit(value)
        if not parsed.hostname or parsed.username or parsed.password:
            raise ValueError("Enter a valid HTTP(S) URL without embedded credentials.")
        try:
            ipaddress.ip_address(parsed.hostname)
        except ValueError:
            _normalize_domain(parsed.hostname)
        return "url", value

    try:
        return "ip", str(ipaddress.ip_address(value))
    except ValueError:
        return "domain", _normalize_domain(value)


def _normalize_domain(value: str) -> str:
    domain = value.rstrip(".").lower()
    try:
        ascii_domain = domain.encode("idna").decode("ascii")
    except UnicodeError as exc:
        raise ValueError("Enter a valid URL, IP address, or domain.") from exc
    if len(ascii_domain) > 253 or "." not in ascii_domain:
        raise ValueError("Enter a URL, IP address, or domain.")
    labels = ascii_domain.split(".")
    if any(
        not label
        or len(label) > 63
        or not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]*[a-z0-9])?", label)
        for label in labels
    ):
        raise ValueError("Enter a valid URL, IP address, or domain.")
    return ascii_domain


def _read_virustotal_api_key() -> str | None:
    """Read a key from env first, then the configured local secret file."""
    key = os.getenv("VT_API_KEY", "").strip()
    if key:
        return key
    key_path = Path(os.getenv("VT_API_KEY_FILE", VT_API_KEY_FILE))
    try:
        return key_path.read_text(encoding="utf-8").strip() or None
    except OSError:
        return None


def check_indicator(indicator: str) -> dict:
    """Look up an existing VirusTotal report; this does not submit or scan it."""
    try:
        kind, value = identify_indicator(indicator)
    except (AttributeError, ValueError) as exc:
        return {"error": str(exc)}

    api_key = _read_virustotal_api_key()
    if not api_key:
        return {
            "error": "VirusTotal API key unavailable; check VT_API_KEY or VT_API_KEY_FILE"
        }

    if kind == "url":
        report_id = base64.urlsafe_b64encode(value.encode("utf-8")).decode("ascii").rstrip("=")
        endpoint = f"{VT_API_BASE}/urls/{report_id}"
    elif kind == "ip":
        endpoint = f"{VT_API_BASE}/ip_addresses/{value}"
    else:
        endpoint = f"{VT_API_BASE}/domains/{value}"

    try:
        response = requests.get(
            endpoint,
            headers={"x-apikey": api_key},
            timeout=REQUEST_TIMEOUT_SECONDS,
        )
        response.raise_for_status()
        attributes = response.json()["data"]["attributes"]
    except (requests.RequestException, ValueError, KeyError, TypeError):
        return {
            "error": "VirusTotal lookup failed. Check the indicator, API quota, and connectivity."
        }

    stats = attributes.get("last_analysis_stats") or {}
    return {
        "indicator": value,
        "indicator_type": kind,
        "detections": {
            name: int(stats.get(name, 0))
            for name in ("malicious", "suspicious", "harmless", "undetected", "timeout")
        },
        "reputation": attributes.get("reputation"),
        "last_analysis_date": attributes.get("last_analysis_date"),
        "source": "VirusTotal existing report (read-only lookup)",
    }


root_agent = Agent(
    name="virustotal_lookup_agent",
    model=WebSafeLiteLlm(
        model=f"openai/{LITELLM_MODEL}",
        api_base=LITELLM_API_BASE,
        api_key=os.getenv("LITELLM_API_KEY"),
    ),
    description="Looks up existing VirusTotal reports for URLs, IP addresses, and domains.",
    instruction=(
        "You are a concise security-intelligence lookup assistant. Use check_indicator "
        "for a user's URL, IP address, or domain. Report the exact indicator type and "
        "the returned detection counts. Explain that this is an existing VirusTotal "
        "report, not a fresh scan. If input is invalid, ask for a supported indicator. "
        "Never claim an indicator is safe merely because there are no detections; "
        "describe the data as the current report and note that absence of detections "
        "is not proof of safety. Do not invent findings."
    ),
    tools=[check_indicator],
)
