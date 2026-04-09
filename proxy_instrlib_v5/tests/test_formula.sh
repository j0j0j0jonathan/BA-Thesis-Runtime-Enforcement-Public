#!/bin/bash
# ============================================================================
# tests/test_formula.sh — EnfGuard formula tests for proxy_instrlib_v5
# ============================================================================
#
# Run from proxy_instrlib_v5/:
#     chmod +x tests/test_formula.sh && ./tests/test_formula.sh
#
# Tests all 4 agent enforcement policies and their interactions.
# ============================================================================

ENFGUARD="/Users/jonathanhofer/enfguard/bin/enfguard.exe"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
SIG="$SCRIPT_DIR/../proxy_instrlib_v5.sig"
FORMULA="$SCRIPT_DIR/../proxy_instrlib_v5.mfotl"
export DYLD_LIBRARY_PATH="/opt/anaconda3/envs/x86_python/lib:$DYLD_LIBRARY_PATH"

TMPDIR_BASE=$(mktemp -d)
trap "rm -rf $TMPDIR_BASE" EXIT

PASS=0
FAIL=0

# ── Test runner ───────────────────────────────────────────────────────────────

run_test() {
    local name="$1"
    local trace="$2"
    local expected="$3"
    local unexpected="${4:-}"

    local logfile="$TMPDIR_BASE/${name}.log"
    echo "$trace" > "$logfile"

    local output
    output=$("$ENFGUARD" -sig "$SIG" -formula "$FORMULA" -log "$logfile" 2>&1)

    # Only check patterns against [Enforcer] lines and beyond
    local enforcer_output
    enforcer_output=$(echo "$output" | sed -n '/^\[Enforcer\]/,$p')

    local ok=true

    if [ -n "$expected" ] && ! echo "$enforcer_output" | grep -qE "$expected"; then
        ok=false
    fi

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
echo "  proxy_instrlib_v5 — Agent Enforcement Formula Tests"
echo "════════════════════════════════════════════════════════════"

# ── Policy 1: Block dangerous bash commands ──────────────────────────────────
echo ""
echo "Policy 1 — Dangerous bash → BlockAction"

run_test "1_dangerous_bash_blocked" \
"@1 AgentTurn(1) BashExec(1) DangerousCommand(1)" \
"BlockAction\(1\)"

run_test "1_safe_bash_allowed" \
"@1 AgentTurn(1) BashExec(1) SafeCommand(1)" \
"" \
"BlockAction"

run_test "1_text_only_no_block" \
"@1 AgentTurn(1) TextOnly(1)" \
"" \
"BlockAction"

run_test "1_dangerous_at_multiple_timesteps" \
"@1 AgentTurn(1) BashExec(1) SafeCommand(1)
@2 AgentTurn(2) BashExec(2) DangerousCommand(2)
@3 AgentTurn(3) BashExec(3) SafeCommand(3)" \
"BlockAction\(2\)"

# ── Policy 2: Warn on safe bash after recent dangerous ───────────────────────
echo ""
echo "Policy 2 — Safe bash after recent dangerous → WarnAction"

run_test "2_safe_after_dangerous_warns" \
"@1 AgentTurn(1) BashExec(1) DangerousCommand(1)
@2 AgentTurn(2) BashExec(2) SafeCommand(2)" \
"WarnAction\(2\)"

run_test "2_safe_within_window_still_warns" \
"@1 AgentTurn(1) BashExec(1) DangerousCommand(1)
@2 AgentTurn(2) TextOnly(2)
@3 AgentTurn(3) BashExec(3) SafeCommand(3)" \
"WarnAction\(3\)"

run_test "2_safe_outside_window_no_warn" \
"@1 AgentTurn(1) BashExec(1) DangerousCommand(1)
@2 AgentTurn(2) TextOnly(2)
@3 AgentTurn(3) TextOnly(3)
@4 AgentTurn(4) TextOnly(4)
@5 AgentTurn(5) BashExec(5) SafeCommand(5)" \
"" \
"WarnAction\(5\)"

run_test "2_no_prior_dangerous_no_warn" \
"@1 AgentTurn(1) BashExec(1) SafeCommand(1)
@2 AgentTurn(2) BashExec(2) SafeCommand(2)" \
"" \
"WarnAction"

# ── Policy 3: Rate-limit file writes ─────────────────────────────────────────
echo ""
echo "Policy 3 — 3+ distinct files written → BlockAction"
echo "         (ONCE[0,5]: includes current turn, so batching is not a bypass)"

# One distinct file — no block
run_test "3_single_write_allowed" \
"@1 AgentTurn(1) FileWrite(1001) SafeCommand(1)" \
"" \
"BlockAction"

# Two distinct files — no block (need 2 past + 1 current = 3 total)
run_test "3_two_writes_allowed" \
"@1 AgentTurn(1) FileWrite(1001) SafeCommand(1)
@2 AgentTurn(2) FileWrite(1002) SafeCommand(2)" \
"" \
"BlockAction"

# Three distinct files — blocks on the THIRD write (fid=1003, a=1001, b=1002)
run_test "3_third_distinct_write_blocked" \
"@1 AgentTurn(1) FileWrite(1001) SafeCommand(1)
@2 AgentTurn(2) FileWrite(1002) SafeCommand(2)
@3 AgentTurn(3) FileWrite(1003) SafeCommand(3)" \
"BlockAction\(3\)"

# Same file written 3 times — NOT blocked (a <> b fails: both are 1001)
run_test "3_same_file_repeated_no_block" \
"@1 AgentTurn(1) FileWrite(1001) SafeCommand(1)
@2 AgentTurn(2) FileWrite(1001) SafeCommand(2)
@3 AgentTurn(3) FileWrite(1001) SafeCommand(3)" \
"" \
"BlockAction"

# All 3 distinct files written in the SAME turn (batched) — still blocked
# This is the key regression test for ONCE[0,5]: with the old ONCE[1,5]
# formula this would have passed (bypassed), now it must be blocked.
run_test "3_batched_writes_blocked" \
"@1 AgentTurn(1) FileWrite(1001) FileWrite(1002) FileWrite(1003) SafeCommand(1)" \
"BlockAction\(1\)"

# 3 writes then gap of 5+ turns — window expired, new write allowed
run_test "3_writes_outside_window_no_block" \
"@1 AgentTurn(1) FileWrite(1001) SafeCommand(1)
@2 AgentTurn(2) FileWrite(1002) SafeCommand(2)
@3 AgentTurn(3) FileWrite(1003) SafeCommand(3)
@4 AgentTurn(4) TextOnly(4)
@5 AgentTurn(5) TextOnly(5)
@6 AgentTurn(6) TextOnly(6)
@7 AgentTurn(7) TextOnly(7)
@8 AgentTurn(8) FileWrite(1004) SafeCommand(8)" \
"" \
"BlockAction\(8\)"

# ── Policy 4: Block web access after recent dangerous ────────────────────────
echo ""
echo "Policy 4 — Web access after dangerous command → BlockAction"

run_test "4_web_after_dangerous_blocked" \
"@1 AgentTurn(1) BashExec(1) DangerousCommand(1)
@2 AgentTurn(2) WebAccess(2) SafeCommand(2)" \
"BlockAction\(2\)"

run_test "4_web_after_safe_allowed" \
"@1 AgentTurn(1) BashExec(1) SafeCommand(1)
@2 AgentTurn(2) WebAccess(2) SafeCommand(2)" \
"" \
"BlockAction\(2\)"

run_test "4_web_outside_window_allowed" \
"@1 AgentTurn(1) BashExec(1) DangerousCommand(1)
@2 AgentTurn(2) TextOnly(2)
@3 AgentTurn(3) TextOnly(3)
@4 AgentTurn(4) TextOnly(4)
@5 AgentTurn(5) WebAccess(5) SafeCommand(5)" \
"" \
"BlockAction\(5\)"

# ── Policy interactions ───────────────────────────────────────────────────────
echo ""
echo "Policy interactions"

run_test "interaction_dangerous_bash_and_web_warn" \
"@1 AgentTurn(1) BashExec(1) DangerousCommand(1)
@2 AgentTurn(2) BashExec(2) SafeCommand(2) WebAccess(2)" \
"BlockAction\(2\)"

run_test "interaction_file_write_burst_then_dangerous_bash" \
"@1 AgentTurn(1) FileWrite(1) SafeCommand(1)
@2 AgentTurn(2) FileWrite(2) SafeCommand(2)
@3 AgentTurn(3) FileWrite(3) SafeCommand(3)
@4 AgentTurn(4) BashExec(4) DangerousCommand(4)" \
"BlockAction\(4\)"

# ── Summary ───────────────────────────────────────────────────────────────────
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
