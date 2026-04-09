#!/bin/bash
# ============================================================================
# tests/test_formula.sh — EnfGuard formula tests for proxy_instrlib_v4
# ============================================================================
#
# Run from proxy_instrlib_v4/:
#     chmod +x tests/test_formula.sh && ./tests/test_formula.sh
#
# Tests all 4 policies and their interactions.
# Each test prints PASS or FAIL with the reason.
# ============================================================================

ENFGUARD="/Users/jonathanhofer/enfguard/bin/enfguard.exe"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
SIG="$SCRIPT_DIR/../proxy_instrlib_v4.sig"
FORMULA="$SCRIPT_DIR/../proxy_instrlib_v4.mfotl"
export DYLD_LIBRARY_PATH="/opt/anaconda3/envs/x86_python/lib:$DYLD_LIBRARY_PATH"

TMPDIR_BASE=$(mktemp -d)
trap "rm -rf $TMPDIR_BASE" EXIT

PASS=0
FAIL=0

# ── Test runner ───────────────────────────────────────────────────────────────
# run_test NAME TRACE EXPECTED_PATTERN [UNEXPECTED_PATTERN]
#   EXPECTED_PATTERN : grep regex that must appear in EnfGuard output
#   UNEXPECTED_PATTERN: grep regex that must NOT appear (optional)

run_test() {
    local name="$1"
    local trace="$2"
    local expected="$3"
    local unexpected="${4:-}"

    local logfile="$TMPDIR_BASE/${name}.log"
    echo "$trace" > "$logfile"

    local output
    output=$("$ENFGUARD" -sig "$SIG" -formula "$FORMULA" -log "$logfile" 2>&1)

    # Strip the formula preamble: everything before the first [Enforcer] line.
    # The preamble contains event names like Block/Disclaimer in the formula
    # text, which would cause false positives on absence checks.
    local enforcer_output
    enforcer_output=$(echo "$output" | sed -n '/^\[Enforcer\]/,$p')

    local ok=true

    # Check expected pattern is present in enforcer output
    if [ -n "$expected" ] && ! echo "$enforcer_output" | grep -qE "$expected"; then
        ok=false
    fi

    # Check unexpected pattern is absent from enforcer output
    if [ -n "$unexpected" ] && echo "$enforcer_output" | grep -qE "$unexpected"; then
        ok=false
    fi

    if $ok; then
        echo "  ✓ PASS  $name"
        ((PASS++))
    else
        echo "  ✗ FAIL  $name"
        echo "          Expected pattern : $expected"
        [ -n "$unexpected" ] && echo "          Unexpected pattern: $unexpected"
        echo "          EnfGuard output:"
        echo "$output" | sed 's/^/            /'
        ((FAIL++))
    fi
}

echo ""
echo "════════════════════════════════════════════════════════════"
echo "  proxy_instrlib_v4 — Formula Tests"
echo "════════════════════════════════════════════════════════════"

# ── Policy 1a: First unsafe content → Disclaimer ──────────────────────────────
echo ""
echo "Policy 1a — First unsafe content response → Disclaimer"

run_test "1a_single_unsafe_gets_disclaimer" \
"@1 Ask(1) UnsafeResponse(1)" \
"Disclaimer\(1\)"

run_test "1a_safe_response_no_enforcement" \
"@1 Ask(1) SafeResponse(1)" \
"@1 OK." \
"Disclaimer|Block"

run_test "1a_after_window_resets_to_disclaimer" \
"@1 Ask(1) UnsafeResponse(1)
@2 Ask(2) SafeResponse(2)
@3 Ask(3) SafeResponse(3)
@4 Ask(4) UnsafeResponse(4)" \
"Disclaimer\(4\)"

# ── Policy 1b: Repeated unsafe → Block ───────────────────────────────────────
echo ""
echo "Policy 1b — Repeated unsafe content response → Block"

run_test "1b_second_consecutive_unsafe_gets_block" \
"@1 Ask(1) UnsafeResponse(1)
@2 Ask(2) UnsafeResponse(2)" \
"Block\(2\)"

run_test "1b_third_consecutive_still_block" \
"@1 Ask(1) UnsafeResponse(1)
@2 Ask(2) UnsafeResponse(2)
@3 Ask(3) UnsafeResponse(3)" \
"Block\(3\)"

run_test "1b_unsafe_after_one_safe_resets_window" \
"@1 Ask(1) UnsafeResponse(1)
@2 Ask(2) SafeResponse(2)
@3 Ask(3) UnsafeResponse(3)" \
"Block\(3\)"   # t=3: ONCE[1,2] sees t=1 UnsafeResponse → still in window

run_test "1b_unsafe_after_two_safe_gives_disclaimer" \
"@1 Ask(1) UnsafeResponse(1)
@2 Ask(2) SafeResponse(2)
@3 Ask(3) SafeResponse(3)
@4 Ask(4) UnsafeResponse(4)" \
"Disclaimer\(4\)"  # t=4: ONCE[1,2] sees t=2,3 which are safe → window clear

# ── Policy 2: Rate limit — 3+ unsafe in last 5 → Block ───────────────────────
echo ""
echo "Policy 2 — Rate limit: 3+ unsafe in last 5 → Block"

run_test "2_rate_limit_with_gap_causes_block" \
"@1 Ask(1) UnsafeResponse(1)
@2 Ask(2) UnsafeResponse(2)
@3 Ask(3) UnsafeResponse(3)
@4 Ask(4) SafeResponse(4)
@5 Ask(5) SafeResponse(5)
@6 Ask(6) UnsafeResponse(6)" \
"Block\(6\)"   # rate limit: 3 unsafe in [1,5] → override disclaimer

run_test "2_only_two_unsafe_no_rate_limit" \
"@1 Ask(1) UnsafeResponse(1)
@2 Ask(2) UnsafeResponse(2)
@3 Ask(3) SafeResponse(3)
@4 Ask(4) SafeResponse(4)
@5 Ask(5) SafeResponse(5)
@6 Ask(6) SafeResponse(6)
@7 Ask(7) UnsafeResponse(7)" \
"Disclaimer\(7\)"   # only 1 unsafe in [2,6] → no rate limit, disclaimer only

run_test "2_rate_limit_fires_alongside_policy1b" \
"@1 Ask(1) UnsafeResponse(1)
@2 Ask(2) SafeResponse(2)
@3 Ask(3) UnsafeResponse(3)
@4 Ask(4) SafeResponse(4)
@5 Ask(5) UnsafeResponse(5)
@6 Ask(6) UnsafeResponse(6)" \
"Block\(6\)"   # both 1b and 2 fire simultaneously

# ── Policy 3: Dangerous tool call → BlockToolCall ─────────────────────────────
echo ""
echo "Policy 3 — Dangerous tool call → BlockToolCall"

run_test "3_dangerous_tool_call_blocked" \
"@1 Ask(1) SafeResponse(1) ToolCallProposed(1) DangerousToolCall(1)" \
"BlockToolCall\(1\)"

run_test "3_safe_content_dangerous_tool_still_blocked" \
"@1 Ask(1) SafeResponse(1) ToolCallProposed(1) DangerousToolCall(1)" \
"BlockToolCall\(1\)"

run_test "3_no_tool_call_no_block_tool" \
"@1 Ask(1) SafeResponse(1)" \
"" \
"BlockToolCall|WarnToolCall"

run_test "3_safe_tool_call_not_blocked" \
"@1 Ask(1) SafeResponse(1) ToolCallProposed(1) SafeToolCall(1)" \
"" \
"BlockToolCall"

run_test "3_dangerous_tool_multiple_timesteps" \
"@1 Ask(1) SafeResponse(1) ToolCallProposed(1) SafeToolCall(1)
@2 Ask(2) SafeResponse(2) ToolCallProposed(2) DangerousToolCall(2)
@3 Ask(3) SafeResponse(3) ToolCallProposed(3) SafeToolCall(3)" \
"BlockToolCall\(2\)"

# ── Policy 4: Safe tool call after recent dangerous → WarnToolCall ────────────
echo ""
echo "Policy 4 — Safe tool call after recent dangerous → WarnToolCall"

run_test "4_safe_tool_after_dangerous_warns" \
"@1 Ask(1) SafeResponse(1) ToolCallProposed(1) DangerousToolCall(1)
@2 Ask(2) SafeResponse(2) ToolCallProposed(2) SafeToolCall(2)" \
"WarnToolCall\(2\)"

run_test "4_safe_tool_within_window_still_warns" \
"@1 Ask(1) SafeResponse(1) ToolCallProposed(1) DangerousToolCall(1)
@2 Ask(2) SafeResponse(2)
@3 Ask(3) SafeResponse(3) ToolCallProposed(3) SafeToolCall(3)" \
"WarnToolCall\(3\)"

run_test "4_safe_tool_outside_window_no_warn" \
"@1 Ask(1) SafeResponse(1) ToolCallProposed(1) DangerousToolCall(1)
@2 Ask(2) SafeResponse(2)
@3 Ask(3) SafeResponse(3)
@4 Ask(4) SafeResponse(4)
@5 Ask(5) SafeResponse(5) ToolCallProposed(5) SafeToolCall(5)" \
"" \
"WarnToolCall\(5\)"  # ONCE[1,3] at t=5 looks at [2,4] — DangerousToolCall at t=1 is outside

run_test "4_dangerous_tool_after_dangerous_still_blocked_not_warned" \
"@1 Ask(1) SafeResponse(1) ToolCallProposed(1) DangerousToolCall(1)
@2 Ask(2) SafeResponse(2) ToolCallProposed(2) DangerousToolCall(2)" \
"BlockToolCall\(2\)"

# ── Policy interactions ────────────────────────────────────────────────────────
echo ""
echo "Policy interactions — multiple policies firing simultaneously"

run_test "interaction_unsafe_content_and_dangerous_tool" \
"@1 Ask(1) UnsafeResponse(1) ToolCallProposed(1) DangerousToolCall(1)" \
"Disclaimer\(1\).*BlockToolCall\(1\)|BlockToolCall\(1\).*Disclaimer\(1\)"

run_test "interaction_safe_content_dangerous_tool_only_block_tool" \
"@1 Ask(1) SafeResponse(1) ToolCallProposed(1) DangerousToolCall(1)" \
"BlockToolCall\(1\)" \
"Disclaimer\|Block\b"

# ── Summary ────────────────────────────────────────────────────────────────────
echo ""
echo "════════════════════════════════════════════════════════════"
total=$((PASS + FAIL))
echo "  Results: $PASS/$total passed"
if [ $FAIL -eq 0 ]; then
    echo "  All tests passed ✓"
else
    echo "  $FAIL test(s) failed ✗"
fi
echo "════════════════════════════════════════════════════════════"
echo ""

exit $FAIL
