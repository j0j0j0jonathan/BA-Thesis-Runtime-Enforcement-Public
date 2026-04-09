"""
proxy_instrlib_v4.py LLM Enforcement Proxy (Tool Call Extension)
The FOURTH VERSION of the enforcement proxy.

Builds directly on v2's @Instrument architecture with one conceptual
extension: the enforcer now reasons about Proposed actions (tool calls),
not just text content.


    proxy_instrlib_v2                  proxy_instrlib_v4 (this)
        
    Policies: 1a, 1b, 2               Policies: 1a, 1b, 2, 3, 4
    Events: 5                          Events: 10 (5 new for tool calls)
    Classifiers: safety.py             Classifiers: safety.py + tool_parser.py
    Handlers: 2 (Block, Disclaimer)    Handlers: 4 (+BlockToolCall, +WarnToolCall)
    Port: 8002                         Port: 8003

Everything else (@Instrument, Logger, PDP, Schema, PEP, batch subprocess,
accumulated trace) is the same

1. Block        
2. BlockToolCall  
3. WarnToolCall    
4. Disclaimer      

how to run:

    export OPENAI_API_KEY="sk-..."
    cd code/proxy_instrlib_v4/
    uvicorn proxy_instrlib_v4:app --reload --port 8003
"""

import os
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Optional

import openai
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from instrlib import Event, Schema, PEP, EnfGuardPDP, Instrument, Logger
from handlers import (
    cause_block, cause_disclaimer,
    cause_block_tool_call, cause_warn_tool_call,
)
from mappings import ask_mapping
from safety import classify
from tool_parser import extract_tool_call, classify_tool_call

# paths

BASE_DIR     = Path(__file__).parent
ENFGUARD_BIN = Path("/Users/jonathanhofer/enfguard/bin/enfguard.exe")
SIG_FILE     = BASE_DIR / "proxy_instrlib_v4.sig"
FORMULA_FILE = BASE_DIR / "proxy_instrlib_v4.mfotl"

# PEP
# Registration order = handler priority when multiple policies fire at once.

pep = PEP(
    mapping={
        ("LLMProxy", "chat"): ask_mapping,
    },
    causation_handlers={
        "Block":          cause_block,            # Policy 1b/2: content block
        "BlockToolCall":  cause_block_tool_call,  # Policy 3:    dangerous tool call
        "WarnToolCall":   cause_warn_tool_call,   # Policy 4:    tool call escalation
        "Disclaimer":     cause_disclaimer,       # Policy 1a:   content disclaimer
    },
)

# schema

schema = Schema({
    "Ask":               [int],
    "SafeResponse":      [int],
    "UnsafeResponse":    [int],
    "ToolCallProposed":  [int],
    "SafeToolCall":      [int],
    "DangerousToolCall": [int],
    "Disclaimer":        [int],
    "Block":             [int],
    "BlockToolCall":     [int],
    "WarnToolCall":      [int],
})

# PDP

_env = os.environ.copy()
_env["DYLD_LIBRARY_PATH"] = (
    "/opt/anaconda3/envs/x86_python/lib"
    + ":" + _env.get("DYLD_LIBRARY_PATH", "")
)

pdp = EnfGuardPDP(
    binary  = str(ENFGUARD_BIN),
    sig     = str(SIG_FILE),
    formula = str(FORMULA_FILE),
    env     = _env,
)

logger = Logger(pep=pep, schema=schema, pdp=pdp)

# @Instrument 

@Instrument(logger)
class LLMProxy:
    """
    System under Enforcement (SuE). Zero enforcement code.

    What @Instrument injects at decoration time (for LLMProxy.chat):
        1.  ask_mapping(event_id, llm_response)
                → [Ask(n), Safe/UnsafeResponse(n)]
                  + [ToolCallProposed(n), Safe/DangerousToolCall(n)]  if detected
        2.  logger.log(events) → runs EnfGuard on accumulated trace
        3.  original chat(self, n, llm_response) → llm_response
        4.  route to: cause_block / cause_block_tool_call /
                      cause_warn_tool_call / cause_disclaimer / pass-through
    """

    def chat(self, event_id: int, llm_response: str) -> str:
        return llm_response


# state

_n: int = 0

# lifespan

@asynccontextmanager
async def lifespan(app: FastAPI):
    global _n
    _n = 0
    logger.reset()
    print("InstrLib v4 (tool call enforcement) proxy started.")
    print(f"Policy:\n{FORMULA_FILE.read_text().strip()}")
    yield
    pdp.stop()

# app

app = FastAPI(
    title="LLM Enforcement Proxy v4 — Tool Call Extension",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# models

class ChatRequest(BaseModel):
    message: str

class ChatResponse(BaseModel):
    response:           str
    event_id:           int
    enforcement_action: str            # "allowed" | "disclaimer" | "blocked" | "tool_blocked" | "tool_warned"
    reason:             str            # human-readable explanation
    detected_command:   Optional[str]  # the extracted shell command, if any


# llm helper

def call_llm(message: str) -> str:
    client = openai.OpenAI()
    completion = client.chat.completions.create(
        model="gpt-4o-mini",
        messages=[{"role": "user", "content": message}],
    )
    return completion.choices[0].message.content

# endpoint

@app.post("/chat", response_model=ChatResponse)
def chat(req: ChatRequest):
    """
    Enforcement endpoint: content safety + tool call policies.

    The endpoint's own logic (everything below proxy.chat()) exists only
    to interpret the enforced result and build a rich response. The
    enforcement itself is entirely inside @Instrument.
    """
    global _n
    _n += 1
    n = _n

    print(f"\n[{n}] User: {req.message}")
    llm_response = call_llm(req.message)
    print(f"[{n}] LLM:  {llm_response[:120]}...")

    # Classify for reason reporting (before enforcement)
    is_safe_content  = classify(llm_response)
    detected_command = extract_tool_call(llm_response)
    is_safe_command  = classify_tool_call(detected_command) if detected_command else None

    if detected_command:
        safe_label = "safe" if is_safe_command else "DANGEROUS"
        print(f"[{n}] Tool call detected ({safe_label}): {detected_command[:80]}")

    # The only enforcement call 
    proxy = LLMProxy()
    final_response = proxy.chat(n, llm_response)

    # interpret result

    # None = blocked (either content block or tool call block)
    if final_response is None:
        # Determine which policy caused the block for the reason field.
        # Both content and tool policies return None — distinguish by context.
        if detected_command and not is_safe_command:
            action = "tool_blocked"
            reason = (
                f"Dangerous tool call blocked (Policy 3). "
                f"Detected command: `{detected_command}`. "
                f"This command matched one or more danger patterns and was "
                f"suppressed before reaching the user."
            )
        else:
            action = "blocked"
            reason = (
                "Unsafe content blocked (Policy 1b or 2): repeated unsafe "
                "responses detected within recent history or rate limit exceeded."
            )
        print(f"[{n}] {action.upper()}.")
        return ChatResponse(
            response="This response has been blocked by the enforcement layer.",
            event_id=n,
            enforcement_action=action,
            reason=reason,
            detected_command=detected_command,
        )

    # Warning prefix from WarnToolCall
    if final_response.startswith("⚠️ Tool call warning"):
        reason = (
            "Safe tool call proposed, but a dangerous command was detected "
            "recently (Policy 4: ONCE[1,3] escalation window). "
            f"Detected command: `{detected_command}`."
        )
        print(f"[{n}] TOOL_WARNED.")
        return ChatResponse(
            response=final_response,
            event_id=n,
            enforcement_action="tool_warned",
            reason=reason,
            detected_command=detected_command,
        )

    # Disclaimer prefix from content policy
    if final_response.startswith("⚠️ Policy notice"):
        reason = (
            "Unsafe content detected (Policy 1a): first unsafe response, "
            "no recent violation history. Disclaimer prepended."
        )
        print(f"[{n}] DISCLAIMER.")
        return ChatResponse(
            response=final_response,
            event_id=n,
            enforcement_action="disclaimer",
            reason=reason,
            detected_command=detected_command,
        )

    # Pass-through
    reason = "Response passed all enforcement checks."
    if detected_command and is_safe_command:
        reason += f" Safe tool call detected: `{detected_command}`."
    print(f"[{n}] ALLOWED.")
    return ChatResponse(
        response=final_response,
        event_id=n,
        enforcement_action="allowed",
        reason=reason,
        detected_command=detected_command,
    )
