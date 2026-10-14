# Google ADK + VirusTotal demo

A deliberately small Python agent for looking up existing VirusTotal reports for URLs, IP addresses, and domains. The agent uses Google ADK with Gemini 3.8 Flash routed through the existing LiteLLM OpenAI-compatible proxy. The model chooses when to call one narrow Python function; that function validates the input and makes a read-only VirusTotal API request.

## Run it

```bash
python -m venv .venv
source .venv/bin/activate  # Windows: .venv\\Scripts\\activate
python -m pip install -r requirements.txt
python -m pip install pytest
cp vt_agent/.env.example vt_agent/.env
# Set LITELLM_API_KEY to a LiteLLM key allowed to use gemini-3.8-flash-subscription.
# VirusTotal key is read from the specified local secret file by default.
adk web --port 8010
```

Run `adk web` from this project's root (the parent directory of `vt_agent/`). The defaults are `http://127.0.0.1:4000/v1` and the `gemini-3.8-flash-subscription` LiteLLM route; override with `LITELLM_API_BASE` or `LITELLM_MODEL` if needed. Open `http://localhost:8010`, select `vt_agent`, and try `Check 8.8.8.8 in VirusTotal.` The ADK Web per-turn event/trace view shows the model and function-tool interaction. This web UI is intended for local development/testing, not production.

The VirusTotal API key defaults to `/home/cptcoggsworth/.local/state/cti-hermes/secrets/virustotal-api-key`; set `VT_API_KEY_FILE` to change the path, or provide `VT_API_KEY` in the environment. No Google API key is needed directly because model requests use LiteLLM.

The current local setup has been validated end to end: the `gemini-3.8-flash-subscription` LiteLLM route returned structured tool calls, the ADK runner executed the VirusTotal lookup, and Gemini produced the final response. The adapter changes are available in the separate [google-sub-adapter repository](https://github.com/mrcoggsworth/google-sub-adapter). For another installation, make sure its adapter deployment includes function-call support before relying on this workflow.

Run tests: `python -m pytest -q`.

## Safety and scope

- Only performs GET lookups of existing VirusTotal reports; it does not submit URLs or upload files for scanning.
- The indicator is sent to LiteLLM/Gemini and VirusTotal. Use public demo indicators; consider privacy/terms and API quotas.
- The provided VirusTotal key is read from a local secret file and is not printed or committed.
- API results can be stale, incomplete, or false-positive/negative. No detections is not proof of safety.
- `.env` is ignored by Git. Never commit secrets.

See [`docs/20-minute-demo.md`](docs/20-minute-demo.md) for the timed walkthrough, speaker notes, code tour, live UI steps, and troubleshooting.
