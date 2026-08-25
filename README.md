# TOTP + OAuth Automation

Automated Google Authenticator (TOTP) two-step verification setup and OAuth
account connection, built for high-concurrency batch processing.

## Overview

Each account is processed in an isolated browser session through a two-phase flow:

1. **Login + TOTP / 2FA** — signs in, then either sets up the Authenticator app
   (first-time accounts) or answers the 2-step verification code from a stored
   secret (already-enrolled accounts).
2. **OAuth authorization** — in the same session, opens the provider's OAuth URL,
   selects the account, and completes consent (Continue → Allow).

Per-account results stream back live; an optional datastore records outcomes.

## Components

| File | Role |
|------|------|
| `reverse_merged.py` | Automation engine — the flow plus concurrency/orchestration. |
| `reverse_server.py` | HTTP endpoint that runs the engine and streams results over SSE. |

## Requirements

- Python 3.10+
- Google Chrome
- `libzbar0` (QR decoding)
- `pip install -r requirements.txt`

## Configuration

Copy `.env.example` to `.env` and fill in the values. **All credentials and
service endpoints are read from environment variables — nothing is hardcoded.**

## Usage

### CLI (batch)

```bash
# CSV of email,password
MAX_PARALLEL=40 python3 reverse_merged.py accounts.csv

# JSON payload
ACCOUNTS_JSON='{"accounts":[{"Email":"..","Password":".."}]}' python3 reverse_merged.py

# Single account
python3 reverse_merged.py user@example.com password
```

### HTTP endpoint

```bash
python3 reverse_server.py
```

```bash
curl -N -X POST http://<host>:5000/api/trigger \
  -H "x-api-key: $API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"accounts":[{"Email":"..","Password":".."}],"max_parallel_tabs":40}'
```

Health check: `GET /health` → `{"status":"ok"}`

### Response (Server-Sent Events)

```
data: {"status":"started","details":"processing N account(s)","max_parallel":N}
data: {"email":"..","status":"success|partial|error","details":".."}
data: {"status":"done","total":N,"success":x,"partial":y,"error":z}
```

## Runtime options

| Variable | Default | Purpose |
|----------|---------|---------|
| `MAX_PARALLEL` | 100 | Maximum concurrent accounts |
| `MAX_CONCURRENT_LAUNCHES` | 6 | Browsers allowed to start at once (ramp control) |
| `MIN_FREE_MB` | 1500 | Hold a launch when free RAM drops below this |
| `MAX_RETRIES` | 10 | Fresh-browser retries per account before giving up |
| `HEADLESS` | false | Run browsers headless |
| `PAGELOAD_TIMEOUT` | 90 | Page-load timeout (seconds) |

## Notes

- Each retry launches a brand-new browser session (fresh profile) so transient
  failures recover cleanly.
- Concurrency is bounded by a launch semaphore and a memory guard to keep the
  host stable under load.
