# VirusTotal Lookup Agent — 20-minute demo

## Demo goal

Show that an AI agent can be a small, inspectable Python program: a model interprets a request, chooses one explicitly provided tool, and the tool calls a real service. This is not an autonomous SOC system and it does not replace analyst judgment.

**Audience:** SOC analysts and beginners who can read Python.
**Duration:** 20 minutes.
**Demo outcome:** Ask the agent to look up a domain, IP address, and URL in Google ADK's built-in web/debug interface, then inspect the tool call and result.

## Before the session (5–10 minutes)

1. Use Python 3.10+ in a virtual environment.
2. From the project root, install dependencies:
   ```bash
   python -m venv .venv
   source .venv/bin/activate        # Windows: .venv\\Scripts\\activate
   python -m pip install -r requirements.txt
   python -m pip install pytest
   ```
3. Copy `vt_agent/.env.example` to `vt_agent/.env`. Set `LITELLM_API_KEY` to an authorized key for the local LiteLLM proxy; the API base and model alias are prefilled for this environment. The agent uses the local VirusTotal secret file at `/home/cptcoggsworth/.local/state/cti-hermes/secrets/virustotal-api-key` by default. If you run this project elsewhere, set `VT_API_KEY_FILE` to your key file, or supply `VT_API_KEY` through the environment.

   Do not commit `.env` or paste any API keys into the demo transcript. The file is ignored by Git. No direct Google API key is needed: Gemini requests go through LiteLLM.
4. Run tests: `python -m pytest -q`.
5. Confirm CLI is installed with `adk --help`. For the ADK Web UI, run from the directory **containing** `vt_agent/`:
   ```bash
   adk web --port 8010
   ```
   Keep it bound to localhost for this demo. Open `http://localhost:8010` and select `vt_agent` in the agent selector. Port 8000 is already occupied in the current environment, so this walkthrough uses 8010.
6. **Preflight the live tool path:** confirm the selected LiteLLM route returns an OpenAI `tool_calls` response for the function schema. The current `gemini-3.8-flash-subscription` route was validated after deploying the updated adapter: streaming and non-streaming requests returned a structured `check_indicator` call, and the ADK runner completed the VirusTotal lookup. If you are using a different adapter deployment, run the preflight before presenting; the adapter implementation is in <https://github.com/mrcoggsworth/google-sub-adapter>.
7. Select ordinary public test indicators safe to query. Avoid customer/internal indicators: the request is sent to VirusTotal and the model provider. Suitable demo examples include `8.8.8.8` and `example.com`. Results can be missing, stale, or quota-limited.


## Minute-by-minute run of show

### 0:00–2:00 — Set the frame

**Say:** “We’re going to step beyond a chat-only interface without building a sprawling platform. The demo is one Python agent, one purpose-built tool, and one existing threat-intelligence API. The model handles language; deterministic Python validates the indicator and does the lookup.”

**Show:** Project tree and the requirements. Point out this is intentionally a demo, not a production deployment.

### 2:00–4:00 — Explain what makes it an agent

**Say:** “A chat model can produce text. An agent can also decide when to call a capability. Here the capability is visible, named, and narrowly scoped: `check_indicator`. The model itself is routed through our existing LiteLLM OpenAI-compatible proxy; it can only request this defined function, not run arbitrary shell commands or browse the network.”

**Show:** `root_agent` in `vt_agent/agent.py`: its name, `WebSafeLiteLlm(...)` configuration, model alias `gemini-3.8-flash-subscription`, instructions, and `tools=[check_indicator]`. The `openai/` prefix selects LiteLLM's OpenAI-compatible proxy interface, not a different model provider. `WebSafeLiteLlm.model_dump()` omits only LiteLLM's runtime client object so ADK Web can serialize the graph; it does not change inference.

### 4:00–7:00 — Walk through validation and routing

**Show:** `identify_indicator()`.

**Say:** “Before any external request, we classify the value as an HTTP(S) URL, IP address, or domain. IP parsing uses Python’s standard `ipaddress`; URL parsing uses `urllib.parse`; domains receive basic IDNA/label validation. Invalid inputs are rejected early.”

**Point out:** The supported interface is deliberately narrow. It does not accept bare URL paths, arbitrary schemes, or credentials embedded in a URL.

### 7:00–10:00 — Walk through the VirusTotal call

**Show:** `check_indicator()` endpoint selection and request.

**Say:** “This performs a read-only GET of the existing v3 report. For URLs, VirusTotal accepts a URL-safe Base64 identifier without padding. IPs and domains go to their own report endpoints. The VirusTotal key is read from the provided local secret file at call time (or an environment override), never printed. The request has a timeout, and failures return a safe error without exposing response details.”

**Important caveat:** “This does not submit a URL for scanning or upload content. It only asks VirusTotal for what it already knows. A report is not a verdict; zero detections do not prove safety, and data can be stale or incomplete.”

### 10:00–12:00 — Tests and code quality

**Show:** `tests/test_agent.py`, then run `python -m pytest -q` if not already running.

**Say:** “Tests verify classification, URL identifier construction, correct API endpoints, missing-key behavior, and safe handling of API errors. Tests mock the outbound HTTP response so the suite is fast, repeatable, and does not consume API quota. The live UI demo complements these deterministic tests; it doesn’t replace them.”

### 12:00–17:00 — Live product demo in ADK Web

At `http://localhost:8010`, select `vt_agent`.

1. Enter: `Check 8.8.8.8 in VirusTotal.`
2. Show the response and the **Events/trace/debug panel** for the turn. Expand the agent and tool events to point out:
   - the user message;
   - the model's `check_indicator` tool call and its argument;
   - the tool result (indicator type and detection counts);
   - the model's final explanation.
3. Enter: `Look up the domain example.com.` Show the tool invocation again and compare endpoint/routed type.
4. Enter: `Check https://example.com/path`. Point out the tool accepts the URL as one string and the Python code encodes it for the URL-report endpoint.
5. Optionally ask: `Is it definitely safe if there are no detections?` The expected behavior is a cautious explanation, not a definitive clean verdict.

**Say:** “The debugger/trace view is the most useful learning moment: it makes the agent’s decision, tool handoff, and tool output inspectable. The model is the coordinator; the reliable service boundary is ordinary code.”

**UI note:** ADK Web's exact labels can vary by ADK version. Use the per-turn event/trace view and expand the function/tool call and response. The interface is a development/testing UI, not a production console.

### 17:00–19:00 — Boundaries and next steps

**Say:** “This is intentionally small. It has no database, memory, scheduler, autonomous response, or multi-agent orchestration. Sensible next steps would be structured logging with indicator redaction, stronger schema validation, caching under a clear freshness policy, unit/integration test split, and human-approved response actions. We would add each only for a requirement.”

**Discuss:** VirusTotal terms, API quotas, privacy and data handling, false positives/negatives, model/API costs, and who is authorized to submit or query indicators.

### 19:00–20:00 — Close

**Say:** “The takeaway is not ‘AI writes everything.’ It is: start with a narrow capability, use the model where language understanding helps, keep the action deterministic and testable, expose the boundary, and inspect what happened.”

Invite audience questions about converting a repetitive analyst workflow into a small, constrained tool.

## Troubleshooting during the demo

| Symptom | Likely cause / response |
|---|---|
| Agent does not appear | Start `adk web` from the project root (parent of `vt_agent/`); check that `vt_agent/__init__.py` and `vt_agent/agent.py` exist. |
| LiteLLM authentication/model error | Check `LITELLM_API_BASE`, the `gemini-3.8-flash-subscription` route, and `LITELLM_API_KEY` in `vt_agent/.env`; confirm the proxy is reachable and the key can use the route. |
| VirusTotal key unavailable | Confirm the requested file exists and is readable, or set `VT_API_KEY_FILE`/`VT_API_KEY`. |
| VirusTotal lookup failed | Check network access, API quota/permissions, and whether the indicator has a report. The demo intentionally does not expose raw service errors. |
| No tool call appears | Ask directly to “check” or “look up” a supported indicator; inspect the model and tool events. |
| Agent says data is clean | Correct it: the report's counters are point-in-time observations, not proof of safety. Review the instruction and tool result. |

## Architecture at a glance

```text
Analyst
  │ natural-language request
  ▼
ADK web UI ──► Gemini 3.8 Flash (via LiteLLM proxy)
                     │ chooses check_indicator(indicator)
                     ▼
              Python validation + routing
                     │ HTTPS GET + x-apikey
                     ▼
              VirusTotal v3 report API
                     │ concise structured result
                     ▼
              ADK event/trace + final explanation
```

**Trust boundary:** the indicator leaves the local demo machine and is sent to Google (prompt/model) and VirusTotal (report lookup). Use public demo indicators only unless the organization has approved the data handling.

## References

- Google ADK Python quickstart: <https://google.github.io/adk-docs/get-started/python/>
- ADK Web interface (development UI): <https://google.github.io/adk-docs/runtime/web-interface/>
- Google ADK with LiteLLM: <https://docs.litellm.ai/docs/tutorials/google_adk>
- VirusTotal URL report endpoint: <https://docs.virustotal.com/reference/url-info>
- VirusTotal URL identifiers: <https://docs.virustotal.com/reference/url>
- VirusTotal domain report endpoint: <https://docs.virustotal.com/reference/domain-info>
- VirusTotal IP address report endpoint: <https://docs.virustotal.com/reference/ip-info>
