#!/usr/bin/env python3
"""
Endpoint for the reverse-merge flow, matching the Instantly Trigger structure:

  POST /api/trigger   (header x-api-key)   -> SSE stream of per-account status events
  GET  /health                             -> {"status":"ok"}

Body:
  { "accounts": [ {"Email":..,"Password":..}, ... ], "max_parallel_tabs": N }

SSE events (text/event-stream, `data: {json}\n\n`):
  {"status":"started", "details":..., "max_parallel":N}          (once at the start)
  {"email":.., "status":"success|partial|error", "details":..}   (one per account, as it finishes)
  {"status":"done", "total":N, "success":.., "partial":.., "error":..}   (once at the end)

Reuses the hardened engine in reverse_merged.py (launch throttle, memory guard,
challenge handling, 2FA mark, Supabase logging).
"""
import os
import json
from concurrent.futures import ThreadPoolExecutor, as_completed

import reverse_merged as rm
from flask import Flask, request, Response, jsonify

# Auth + concurrency (matches the Trigger server's env style)
API_KEY = os.getenv("API_KEY", "")
DEFAULT_MAX_PARALLEL = int(os.getenv("MAX_PARALLEL", "100"))
MAX_PARALLEL_CAP = int(os.getenv("MAX_PARALLEL_CAP", "100"))
PORT = int(os.getenv("PORT", "5000"))
HOST = os.getenv("HOST", "0.0.0.0")

app = Flask(__name__)


def _sse(payload):
    return f"data: {json.dumps(payload)}\n\n"


@app.get("/health")
def health():
    return jsonify({"status": "ok"}), 200


@app.post("/api/trigger")
def trigger():
    # Auth
    if request.headers.get("x-api-key", "") != API_KEY:
        return jsonify({"status": "error", "message": "Invalid API key"}), 403

    body = request.get_json(force=True, silent=True) or {}
    raw = body.get("accounts")
    if not raw:
        return jsonify({"status": "error", "message": "Missing accounts payload"}), 400

    accounts = [a for a in (rm._norm_account(x) for x in raw) if a["email"] and a["password"]]
    if not accounts:
        return jsonify({"status": "error", "message": "no valid accounts (need Email + Password)"}), 400

    mp = int(body.get("max_parallel_tabs") or body.get("max_parallel") or DEFAULT_MAX_PARALLEL)
    mp = max(1, min(mp, len(accounts), MAX_PARALLEL_CAP))
    retries = int(body.get("max_retries", 10))

    def stream():
        rm.log_event("TRIGGERED", "-", f"accounts={len(accounts)} | max_parallel={mp}")
        yield _sse({"status": "started", "details": f"processing {len(accounts)} account(s)", "max_parallel": mp})

        rm._raise_fd_limit()
        rm.ensure_chromedriver()  # one-time driver download before workers spin up

        counts = {"success": 0, "partial": 0, "error": 0}
        with ThreadPoolExecutor(max_workers=mp, thread_name_prefix="acct") as pool:
            # Launch throttle inside run_one caps concurrent browser starts; safe to submit all.
            futures = {pool.submit(rm.run_one, a["email"], a["password"], retries): a["email"]
                       for a in accounts}
            for fut in as_completed(futures):
                email = futures[fut]
                try:
                    res = fut.result()
                except Exception as e:
                    res = {"email": email, "status": "error", "error": str(e)}
                status = res.get("status", "error")
                counts[status] = counts.get(status, 0) + 1
                details = "" if status == "success" else res.get("error", "")
                yield _sse({"email": email, "status": status, "details": details})

        yield _sse({"status": "done", "total": len(accounts),
                    "success": counts["success"], "partial": counts["partial"], "error": counts["error"]})

    return Response(
        stream(),
        mimetype="text/event-stream",
        headers={"Cache-Control": "no-cache", "Connection": "keep-alive", "X-Accel-Buffering": "no"},
    )




if __name__ == "__main__":
    try:
        rm._raise_fd_limit()
    except Exception:
        pass
    print(f"[Server] reverse endpoint on {HOST}:{PORT} | POST /api/trigger (SSE) | GET /health")
    app.run(host=HOST, port=PORT, threaded=True)
