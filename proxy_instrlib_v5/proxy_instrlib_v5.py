"""
proxy_instrlib_v5.py — Anthropic Messages API enforcement proxy

A transparent proxy that sits between the Claude Agent SDK and the
real Anthropic API. The SDK sends requests to this proxy (via
ANTHROPIC_BASE_URL), the proxy forwards them to the real API,
inspects the response for tool_use blocks, applies MFOTL enforcement,
and returns the (possibly modified) response.

Usage:

    # Start the proxy
    cd proxy_instrlib_v5/
    ANTHROPIC_API_KEY=sk-ant-... uvicorn proxy_instrlib_v5:app --port 8005

    # Point NanoClaw's SDK at the proxy
    ANTHROPIC_BASE_URL=http://localhost:8005/v1 <start nanoclaw>

Non streaming mode

This version handles non-streaming requests. The Claude Agent SDK's
query() function can work in both modes. For demonstration,
non-streaming is simpler and shows the enforcement clearly.
A streaming extension is discussed as future work.
"""

import os
import json
import logging
import threading
from pathlib import Path
from typing import Any, Dict, List, Optional

import httpx
from fastapi import FastAPI, Request, Response
from fastapi.responses import JSONResponse

from instrlib.pdp import EnfGuardPDP
from instrlib.event import Event
from mappings import map_api_response
from tool_classifier import classify_tool_use, BASH_TOOLS, FILE_WRITE_TOOLS, WEB_TOOLS
from handlers import cause_block_action, cause_warn_action

# config

REAL_API_BASE = os.environ.get("REAL_ANTHROPIC_BASE_URL", "https://api.anthropic.com")
API_KEY = os.environ.get("ANTHROPIC_API_KEY", "")
ENFGUARD_BINARY = os.environ.get(
    "ENFGUARD_BINARY",
    "/Users/jonathanhofer/enfguard/bin/enfguard.exe",
)
DYLD_PATH = os.environ.get(
    "DYLD_LIBRARY_PATH",
    "/opt/anaconda3/envs/x86_python/lib",
)

SIG_FILE = str(Path(__file__).parent / "proxy_instrlib_v5.sig")
FORMULA_FILE = str(Path(__file__).parent / "proxy_instrlib_v5.mfotl")

# Logging

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)
log = logging.getLogger("v5-proxy")

# spp

app = FastAPI(title="proxy_instrlib_v5 Agent Enforcement Proxy")

# PDP (EnfGuard)

pdp = EnfGuardPDP(
    binary=ENFGUARD_BINARY,
    sig=SIG_FILE,
    formula=FORMULA_FILE,
    env={"DYLD_LIBRARY_PATH": DYLD_PATH},
)

# state

_timestep_lock = threading.Lock()
_timestep = 0


def _next_timestep() -> int:
    global _timestep
    with _timestep_lock:
        _timestep += 1
        return _timestep


# HTTP client for forwarding
_client = httpx.Client(timeout=120.0)


# Main proxy endpoint

@app.post("/v1/messages")
async def proxy_messages(request: Request):
    """
    Proxy endpoint for POST /v1/messages (Anthropic Messages API).

    1. Forward the request to the real Anthropic API
    2. Parse the response for tool_use blocks
    3. Map tool_use blocks to MFOTL events
    4. Run EnfGuard enforcement
    5. Apply enforcement actions (block/warn) to response
    6. Return modified response
    """
    # Read incoming request
    body = await request.body()
    request_json = json.loads(body)

    # Log what the Agent SDK is sending to Claude
    messages = request_json.get("messages", [])
    last_msg = messages[-1] if messages else {}
    role = last_msg.get("role", "?")
    content = last_msg.get("content", "")
    if isinstance(content, list):
        for block in content:
            if block.get("type") == "tool_result":
                result_text = block.get("content", "")
                if isinstance(result_text, list):
                    result_text = " ".join(b.get("text", "") for b in result_text)
                log.info(f"SDK→Claude [tool_result] {str(result_text)[:200]}")
    elif isinstance(content, str) and content:
        log.info(f"SDK→Claude [{role}] {content[:200]}")

    # Check if streaming is requested — for now, reject and fall back
    if request_json.get("stream", False):
        # For streaming, we'd need SSE interception. For now, disable
        # streaming and let the SDK handle the non-streamed response.
        request_json["stream"] = False
        body = json.dumps(request_json).encode()
        log.info("Streaming disabled for enforcement — using non-streaming mode")

    # Forward headers
    forward_headers = {
        "content-type": "application/json",
        "anthropic-version": request.headers.get("anthropic-version", "2023-06-01"),
    }
    # Use API key from header (SDK sends it) or from env
    auth_key = request.headers.get("x-api-key", API_KEY)
    if auth_key:
        forward_headers["x-api-key"] = auth_key

    # Also forward anthropic-beta if present
    beta = request.headers.get("anthropic-beta")
    if beta:
        forward_headers["anthropic-beta"] = beta

    # Forward to real API 
    try:
        api_response = _client.post(
            f"{REAL_API_BASE}/v1/messages",
            content=body,
            headers=forward_headers,
        )
    except Exception as e:
        log.error(f"Failed to reach Anthropic API: {e}")
        return JSONResponse(
            status_code=502,
            content={"error": {"type": "proxy_error", "message": str(e)}},
        )

    # Parse API response
    if api_response.status_code != 200:
        # Pass through errors unmodified
        return Response(
            content=api_response.content,
            status_code=api_response.status_code,
            headers={"content-type": "application/json"},
        )

    response_body = api_response.json()
    content_blocks = response_body.get("content", [])

    # Extract tool_use blocks 
    tool_use_blocks = [b for b in content_blocks if b.get("type") == "tool_use"]

    if not tool_use_blocks:
        # Text-only response — no enforcement needed
        log.info("Text-only response — passing through")
        return JSONResponse(content=response_body)

    # Log raw tool calls from LLM
    for block in tool_use_blocks:
        tool_name = block.get("name", "?")
        tool_input = block.get("input", {})
        log.info(f"LLM proposed → {tool_name}({tool_input})")

    # Map to MFOTL events (η_i) 
    timestep = _next_timestep()
    events = map_api_response(timestep, content_blocks)

    log.info(f"@{timestep} Events: {[str(e) for e in events]}")

    # Run EnfGuard (PDP)
    verdict = pdp.process_events(events, timestep)

    caused = verdict.get("caused", [])
    log.info(f"@{timestep} Verdict: caused={[c['name'] for c in caused]}")

    # Apply enforcement actions (η_e)
    has_block = any(c["name"] == "BlockAction" for c in caused)
    has_warn = any(c["name"] == "WarnAction" for c in caused)

    if has_block:
        # Determine which tools to block
        blocked_tool_names = _get_dangerous_tool_names(tool_use_blocks)
        log.info(f"@{timestep} BLOCKING tools: {blocked_tool_names}")
        response_body = cause_block_action(timestep, response_body, blocked_tool_names)

    elif has_warn:
        warned_tool_names = [b.get("name", "") for b in tool_use_blocks]
        log.info(f"@{timestep} WARNING tools: {warned_tool_names}")
        response_body = cause_warn_action(timestep, response_body, warned_tool_names)

    else:
        log.info(f"@{timestep} ALLOWED — no enforcement")

    # Log what we're returning to NanoClaw 
    log.info(f"@{timestep} Response to NanoClaw → stop_reason={response_body.get('stop_reason')}")
    for block in response_body.get("content", []):
        if block.get("type") == "text":
            log.info(f"  [text] {block['text'][:120]}")
        elif block.get("type") == "tool_use":
            log.info(f"  [tool_use] {block.get('name')}({block.get('input', {})})")

    return JSONResponse(content=response_body)


# Catch-all for other API endpoints 

@app.api_route("/v1/{path:path}", methods=["GET", "POST", "PUT", "DELETE", "PATCH"])
async def proxy_other(path: str, request: Request):
    """Forward all other /v1/* requests to the real API without modification."""
    body = await request.body()

    forward_headers = dict(request.headers)
    # Remove host header (httpx sets its own)
    forward_headers.pop("host", None)

    auth_key = request.headers.get("x-api-key", API_KEY)
    if auth_key:
        forward_headers["x-api-key"] = auth_key

    try:
        api_response = _client.request(
            method=request.method,
            url=f"{REAL_API_BASE}/v1/{path}",
            content=body,
            headers=forward_headers,
        )
    except Exception as e:
        return JSONResponse(
            status_code=502,
            content={"error": {"type": "proxy_error", "message": str(e)}},
        )

    return Response(
        content=api_response.content,
        status_code=api_response.status_code,
        headers={"content-type": api_response.headers.get("content-type", "application/json")},
    )


# Health check

@app.get("/health")
def health():
    return {
        "status": "ok",
        "proxy": "proxy_instrlib_v5",
        "timestep": _timestep,
        "enfguard_binary": ENFGUARD_BINARY,
        "sig": SIG_FILE,
        "formula": FORMULA_FILE,
    }


# Helpers

def _get_dangerous_tool_names(tool_use_blocks: List[Dict]) -> List[str]:
    """
    From a list of tool_use blocks, return the names of tools
    that classify as dangerous.
    """
    dangerous = []
    for block in tool_use_blocks:
        tool_name = block.get("name", "")
        tool_input = block.get("input", {})
        event_names = classify_tool_use(tool_name, tool_input)
        if "DangerousCommand" in event_names:
            dangerous.append(tool_name)
    # If nothing specifically dangerous, block all tool_use blocks
    # (e.g., rate-limit policy fires on file writes)
    if not dangerous:
        dangerous = [b.get("name", "") for b in tool_use_blocks]
    return dangerous
