# Cybot — Cybersecurity Threat Analysis & Response Agent

Cybot ingests security alerts from heterogeneous tools over REST, normalizes them into one
schema, correlates them by shared indicators, enriches indicators with threat intelligence, and
runs an **agentic RAG workflow** (LangGraph + a local LLM via Ollama) that produces a risk
assessment and response recommendations grounded in incident-response playbooks, MITRE ATT&CK
notes and organization context. It then carries out **response actions** under an approval
policy: low-impact actions run automatically, and the rest pause for an analyst's decision.

**Stack:** Python 3.12 · FastAPI · LangGraph · Ollama · ChromaDB · ONNX MiniLM embeddings · SQLAlchemy/SQLite

## Architecture

```
 Suricata · Wazuh · CrowdStrike · Splunk · generic
                 │  POST /api/v1/ingest/{source}
                 ▼
 normalizers ─► NormalizedAlert ─► SQLite (alerts, indicators, analyses, intel cache)
 (IOC extraction, severity/category mapping, dedupe)
                 │
                 ▼  LangGraph workflow
 ┌──────────────────────────────────────────────────────────────────────────────┐
 │ correlate            related alerts sharing indicators (SQL join, ± window)  │
 │   ▼                                                                          │
 │ select_indicators    intel lookup budget; LLM picks when over budget         │
 │   ▼                                                                          │
 │ enrich_indicators    local IOCs, AbuseIPDB, VirusTotal, GreyNoise, URLhaus   │
 │   ▼                                                                          │
 │ plan_queries (LLM) ─► retrieve (Chroma + RRF) ─► grade_documents (LLM)       │
 │                          ▲                          │ too little context     │
 │                          └── rewrite_queries (LLM) ◄┘ (bounded retries)      │
 │   ▼ enough context                                                           │
 │ assess_risk (LLM) ─► recommend_actions (LLM + containment guardrail)         │
 │   ▼                                                                          │
 │ plan_response (LLM → validated actions → approval policy)                    │
 │   ▼                                                                          │
 │ execute_actions (auto-approved) ──► await_approval (interrupt, checkpointed) │
 │        ▲                                   │ analyst decisions via API/CLI   │
 │        └───────────────────────────────────┘                                 │
 └──────────────────────────────────────────────────────────────────────────────┘
```

1. **Ingestion & normalization** — vendor-native payloads (single object or batch) are mapped to
   a common `NormalizedAlert` (severity, category, network 5-tuple, host/user, MITRE techniques,
   indicators). IOCs (IPs, domains, URLs, emails, hashes) are also extracted from free text.
   Webhook retries are de-duplicated on `(source, source_alert_id)`.
2. **Correlation** — alerts sharing any indicator (IP, host, user, hash, domain…) within a time
   window are pulled in, so the agent can see multi-stage attack chains.
3. **Threat-intel enrichment** — indicators from the alert and its correlated alerts are checked
   against a local IOC list and, when API keys are configured, AbuseIPDB, VirusTotal, GreyNoise
   and URLhaus. When there are more candidates than the lookup budget, the LLM decides which
   are worth checking. Results are cached in SQLite.
4. **Agentic RAG** — the LLM plans knowledge-base queries, results are fused with reciprocal rank
   fusion, the LLM grades relevance and **rewrites queries and retries** when context is
   insufficient (bounded by `max_retrieval_attempts`).
5. **Risk assessment** — 0-100 score mapped to the org's score bands, rationale with citations,
   MITRE techniques, confidence and false-positive likelihood. A deterministic heuristic score
   (severity, correlation, intel verdicts) is supplied as an anchor.
6. **Recommendations** — prioritized actions per IR phase (investigation, containment,
   eradication, recovery, prevention) that name the specific hosts, accounts and IOCs.
7. **Response actions** — the recommendations become executable actions (block, isolate, reset,
   ticket), checked against an approval policy. Auto-approved actions run at once; the run then
   pauses with a LangGraph `interrupt()` until an analyst approves or rejects the rest. Every
   step is recorded in an audit log.

Every LLM step has a deterministic fallback (heuristic scoring, similarity-based grading,
playbook default actions), so analyses still complete when the model is down or returns
invalid output; the returned `trace` shows which path each step took.

## Quick start

### Local (uv)

```bash
# 1. Install dependencies (installs Python 3.12 if needed)
uv sync

# 2. Start Ollama and pull a model (https://ollama.com)
ollama serve &
ollama pull llama3.1:8b

# 3. Run the API (knowledge base is indexed automatically on first start)
uv run cybot serve            # http://127.0.0.1:8000/docs

# Or try the end-to-end demo from the CLI
uv run cybot demo --top 2
```

### Docker Compose (API + Ollama)

```bash
docker compose up --build     # pulls the model on first run
```

## API

All `/api/v1` routes require `X-API-Key` when `CYBOT_API_KEY` is set. Interactive docs: `/docs`.

| Method | Path | Description |
|---|---|---|
| GET | `/health` | Liveness |
| GET | `/api/v1/sources` | Supported alert sources |
| POST | `/api/v1/ingest/{source}?analyze=false` | Ingest one alert or an array (native vendor format); optionally analyze in background |
| GET | `/api/v1/alerts` | List alerts (`source`, `min_severity`, `category`, `limit`, `offset`) |
| GET | `/api/v1/alerts/{id}` | Full normalized alert including raw payload |
| GET | `/api/v1/alerts/{id}/related` | Correlated alerts sharing indicators |
| POST | `/api/v1/alerts/{id}/analyze` | Run the agent; returns analysis + workflow trace |
| GET | `/api/v1/alerts/{id}/analyses` | Analysis history |
| POST | `/api/v1/analyze/{source}` | Ingest + analyze a single alert in one call |
| GET | `/api/v1/analyses?min_score=60` | Triage queue of high-risk analyses |
| GET | `/api/v1/intel/providers` | Configured threat-intel providers |
| POST | `/api/v1/intel/lookup` | Reputation of one indicator `{"value": "...", "type": null}` (type auto-detected) |
| POST | `/api/v1/alerts/{id}/enrich?limit=` | Threat intel for a stored alert's indicators |
| GET | `/api/v1/actions?status=pending_approval` | Approval queue; without a filter, the full action audit log (`alert_id`, `analysis_id` filters) |
| GET | `/api/v1/actions/{id}` | One action with its audit trail |
| GET | `/api/v1/alerts/{id}/actions` | Actions taken or proposed for an alert |
| POST | `/api/v1/analyses/{id}/decisions` | Approve/reject pending actions and resume the paused run |
| GET | `/api/v1/knowledge/stats` | Vector index stats |
| POST | `/api/v1/knowledge/search` | Semantic search `{"query": "...", "k": 4}` |
| POST | `/api/v1/knowledge/reindex` | Rebuild the index from `knowledge/` |

Example:

```bash
curl -s -X POST localhost:8000/api/v1/ingest/wazuh \
     -H 'content-type: application/json' --data @samples/wazuh.json

curl -s -X POST localhost:8000/api/v1/analyze/crowdstrike \
     -H 'content-type: application/json' \
     --data "$(jq '.[0]' samples/crowdstrike.json)" | jq '.analysis.assessment, .analysis.recommendations'
```

### Supported sources

| Source | Format |
|---|---|
| `suricata` | EVE JSON `event_type: alert` (severity 1-4) |
| `wazuh` | Wazuh alerts (`rule.level` 0-15, `rule.mitre`) |
| `crowdstrike` | Falcon `DetectionSummaryEvent` (Severity 1-5, hashes, command line) |
| `splunk` | Saved-search / ES webhook (`{"search_name", "result": {...}}`) |
| `generic` | Any JSON with common field names (`title`, `severity`, `src_ip`, `hostname`, `indicators`…) |

Add a source by subclassing `Normalizer` in `src/cybot/ingestion/normalizers/` and registering
it in `NORMALIZERS`.

## Configuration

Environment variables (or `.env`, see `.env.example`), all prefixed with `CYBOT_`:

| Variable | Default | Purpose |
|---|---|---|
| `API_KEY` | – | Require `X-API-Key` on `/api/v1` |
| `DATABASE_URL` | `sqlite:///data/cybot.db` | SQLAlchemy URL |
| `OLLAMA_BASE_URL` | `http://localhost:11434` | Ollama server |
| `OLLAMA_MODEL` | `llama3.1:8b` | Chat model (any model with JSON-schema output) |
| `OLLAMA_NUM_CTX` | `8192` | Context window (Ollama's 2048 default truncates RAG prompts) |
| `LLM_TIMEOUT_SECONDS` | `120` | Per-call timeout |
| `EMBEDDING_BACKEND` | `default` | `default` (ONNX all-MiniLM-L6-v2), `sentence-transformers`, `ollama`, `hashing` |
| `EMBEDDING_MODEL` | `all-MiniLM-L6-v2` | Model for `sentence-transformers` / `ollama` backends |
| `CHROMA_PATH` | `data/chroma` | Persistent vector store |
| `KNOWLEDGE_DIR` | `knowledge/` | Markdown knowledge base |
| `RETRIEVAL_K` | `4` | Hits per query |
| `MAX_RETRIEVAL_ATTEMPTS` | `2` | Retrieve → grade → rewrite loop budget |
| `CORRELATION_WINDOW_HOURS` | `24` | ± window for indicator correlation |
| `INTEL_ENABLED` | `true` | Turn threat-intel enrichment on/off |
| `ABUSEIPDB_API_KEY` / `VIRUSTOTAL_API_KEY` / `GREYNOISE_API_KEY` / `URLHAUS_API_KEY` | – | Enable remote intel providers |
| `INTEL_LOCAL_PATH` | `intel/local_iocs.csv` | Local IOC list |
| `INTEL_MAX_LOOKUPS` | `8` | Indicators enriched per analysis |
| `INTEL_CACHE_TTL_HOURS` | `24` | Cache lifetime for remote results |
| `INTEL_TIMEOUT_SECONDS` | `10` | Per-request timeout |
| `RESPONSE_ENABLED` | `true` | Plan and execute response actions |
| `RESPONSE_MODE` | `dry_run` | `dry_run` simulates every action; `live` sends approved actions to the webhook |
| `RESPONSE_WEBHOOK_URL` | – | SOAR/automation endpoint for `live` mode (required in `live`) |
| `RESPONSE_WEBHOOK_SECRET` | – | HMAC key for `X-Cybot-Signature` |
| `RESPONSE_POLICY_PATH` | `policy/response_policy.toml` | Approval policy |
| `CHECKPOINT_PATH` | `data/checkpoints.db` | LangGraph checkpoints (paused runs survive restarts) |

The `sentence-transformers` backend needs the extra: `uv sync --extra sentence-transformers`.
If you change the embedding backend, rebuild the index (`cybot index`).

## Threat intelligence

| Provider | Indicator types | Enabled when |
|---|---|---|
| `local` | IP (incl. CIDR), domain (incl. subdomains), URL, email, hashes | `intel/local_iocs.csv` exists |
| `abuseipdb` | IP | `CYBOT_ABUSEIPDB_API_KEY` set |
| `virustotal` | IP, domain, URL, MD5/SHA1/SHA256 | `CYBOT_VIRUSTOTAL_API_KEY` set |
| `greynoise` | IP (Community API) | `CYBOT_GREYNOISE_API_KEY` set |
| `urlhaus` | URL, host (domain/IP), MD5/SHA256 | `CYBOT_URLHAUS_API_KEY` set |

- Each provider's response is normalized to a verdict (`malicious`, `suspicious`, `harmless`,
  `unknown`) and a 0-100 score. Per indicator, any malicious verdict wins.
- Remote providers skip private and reserved IPs. Errors and rate limits (HTTP 429) are reported
  in the result and never fail an analysis.
- Successful remote results are cached for `CYBOT_INTEL_CACHE_TTL_HOURS`.
- `intel/local_iocs.csv` holds internal blocklists and IOCs from past incidents. The shipped
  entries are fictional (RFC 5737 IP ranges) and match the sample alerts.

```bash
uv run cybot intel update-cdn-sync.net
curl -s -X POST localhost:8000/api/v1/intel/lookup -H 'content-type: application/json' \
     -d '{"value": "8.8.8.8"}'
```

Free API tiers are rate-limited (e.g. VirusTotal: 4 requests/minute), so keep
`CYBOT_INTEL_MAX_LOOKUPS` small; the cache absorbs repeat lookups.

## Automated response

### Actions and approval

| Action | Target | Default policy |
|---|---|---|
| `block_ip`, `block_domain`, `block_url`, `block_hash` | indicator | auto (internal ranges and own domains are **denied**) |
| `isolate_host` | host | auto; **approval** for protected hosts (`web-srv-01`, `vpn-gw-01`, `dc-01/02`) |
| `disable_account`, `reset_credentials` | user | **approval** |
| `open_ticket` | the alert | auto |

How actions are produced and approved:

- **Planning:** the LLM converts its recommendations into actions. Every target must be an
  entity seen in the alert, its correlated alerts or the intel results, so invented hosts or IPs
  are dropped.
- **Guardrails:** intel-confirmed malicious indicators are always blocked, and medium-risk or
  higher incidents always get a ticket. Without the LLM, a rule-based plan is used.
- **Policy:** `policy/response_policy.toml` mirrors the escalation policy. Below
  `min_auto_risk_score` (60), every disruptive action needs approval. Edit the file to match
  your environment.
- **Pausing:** a run waiting for approval is checkpointed in SQLite under its analysis id, so it
  survives restarts. Decisions can be partial; the run pauses again until nothing is pending.

```bash
uv run cybot actions list                                   # approval queue
uv run cybot actions approve <action-id> --analyst alice --note "confirmed"
uv run cybot actions reject  <action-id> --analyst alice

curl -s -X POST localhost:8000/api/v1/analyses/<analysis-id>/decisions \
     -H 'content-type: application/json' \
     -d '{"analyst": "alice", "decisions": [{"action_id": "<id>", "approve": true}]}'
```

Each action keeps an audit trail of `(time, status, actor, note)` entries. The actor is `policy`,
the analyst's name, or `connector:<name>`.

### Execution (dry-run vs. live)

By default (`CYBOT_RESPONSE_MODE=dry_run`) nothing is changed: actions are marked `simulated`.
In `live` mode, approved actions are POSTed to `CYBOT_RESPONSE_WEBHOOK_URL`, typically a SOAR
or automation workflow (Tines, n8n, Shuffle, XSOAR) that calls the firewall, EDR or IdP. The
POST body has this shape:

```json
{"event": "cybot.response_action",
 "action": {"id": "...", "type": "isolate_host", "target": "WS-FIN-07", "reason": "...",
            "priority": "immediate", "alert_id": "...", "analysis_id": "...", "...": "..."}}
```

Headers:

- `X-Cybot-Delivery`: the action id, usable as an idempotency key.
- `X-Cybot-Timestamp`: a Unix timestamp.
- `X-Cybot-Signature`: `sha256=` followed by the HMAC-SHA256 of `"{timestamp}.{body}"` with
  `CYBOT_RESPONSE_WEBHOOK_SECRET`. Receivers can verify it with
  `cybot.response.verify_signature`, which also rejects stale timestamps.

A 2xx response marks the action `executed`; anything else marks it `failed`, with the response
recorded.

## Knowledge base

`knowledge/` holds markdown documents with front matter (`title`, `type`, `tags`, `mitre`),
chunked by `##` section:

- `playbooks/` — IR playbooks (brute force, credential dumping, phishing, C2, exfiltration, …)
- `mitre/` — ATT&CK technique notes (detection & mitigation)
- `organization/` — asset inventory, risk-scoring guide, escalation policy

The organization documents are fictional examples. Replace them with your environment's
assets and policies, since the agent uses them to judge asset criticality and approval rules.

## Development

```bash
uv run pytest -q              # tests use a scripted fake LLM and hashing embedder — no Ollama needed
uv run ruff check . && uv run ruff format --check .
```

```
src/cybot/
  api/          FastAPI routers, schemas, dependencies (auth)
  ingestion/    normalizers per source, IOC extraction, ingestion service
  models/       NormalizedAlert, RiskAssessment, Recommendation, AnalysisResult
  storage/      SQLAlchemy models + repository (alerts, indicators, analyses)
  intel/        threat-intel providers (local, AbuseIPDB, VirusTotal, GreyNoise, URLhaus) + cached service
  response/     action planner, approval policy, connectors (simulated, signed webhook)
  rag/          markdown chunking, embedders, Chroma knowledge base
  agent/        LangGraph workflow, checkpointing, prompts, Ollama client, heuristic fallbacks
  cli.py        cybot serve | index | ingest | analyze | intel | actions | demo
knowledge/      RAG source documents
intel/          local IOC list
policy/         response approval policy
samples/        example vendor payloads forming one attack story
```
