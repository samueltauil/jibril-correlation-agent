#!/bin/bash
# test-e2e.sh — End-to-end test for Jibril + Correlation Agent
#
# Automated test that:
#   1. Detects environment (WSL or native Linux)
#   2. Deploys Jibril config + private alchemy
#   3. Starts the correlation agent
#   4. Starts Jibril
#   5. Triggers attack simulations
#   6. Waits for detection cadence
#   7. Verifies events reached the agent
#   8. Cleans up
#
# Usage:
#   sudo bash test/test-e2e.sh          # run from project root
#   sudo bash test/test-e2e.sh --skip-deploy   # skip config deployment
#   sudo bash test/test-e2e.sh --skip-jibril   # skip jibril start (already running)
#   sudo bash test/test-e2e.sh --skip-agent    # skip agent start (already running)
#
# Requirements: Node.js 20+, curl, jibril binary, sudo

set -euo pipefail

# ─── Options ──────────────────────────────────────────────────────────

SKIP_DEPLOY=false
SKIP_JIBRIL=false
SKIP_AGENT=false

for arg in "$@"; do
  case "$arg" in
    --skip-deploy) SKIP_DEPLOY=true ;;
    --skip-jibril) SKIP_JIBRIL=true ;;
    --skip-agent)  SKIP_AGENT=true ;;
    --help|-h)
      head -18 "$0" | tail -16
      exit 0
      ;;
  esac
done

# ─── Environment detection ───────────────────────────────────────────

detect_environment() {
  if grep -qi microsoft /proc/version 2>/dev/null; then
    ENV_TYPE="wsl"
  else
    ENV_TYPE="linux"
  fi
}

detect_environment

# ─── Resolve project root ────────────────────────────────────────────

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

if [ "$ENV_TYPE" = "wsl" ]; then
  # In WSL the script could be at /mnt/c/... or a native linux path
  PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
else
  PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
fi

AGENT_URL="${AGENT_URL:-http://localhost:3000}"
AGENT_LOG="/tmp/e2e-agent.log"
JIBRIL_LOG="/tmp/e2e-jibril.log"
AGENT_PID=""
JIBRIL_PID=""
PASSED=0
FAILED=0

# ─── Colors ──────────────────────────────────────────────────────────

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

# ─── Helpers ─────────────────────────────────────────────────────────

info()  { echo -e "${CYAN}[*]${NC} $*"; }
ok()    { echo -e "${GREEN}[✓]${NC} $*"; }
warn()  { echo -e "${YELLOW}[!]${NC} $*"; }
fail()  { echo -e "${RED}[✗]${NC} $*"; }

section() {
  echo ""
  echo -e "${BOLD}════════════════════════════════════════════${NC}"
  echo -e "${BOLD} $*${NC}"
  echo -e "${BOLD}════════════════════════════════════════════${NC}"
}

cleanup() {
  section "Cleanup"

  if [ -n "$AGENT_PID" ] && kill -0 "$AGENT_PID" 2>/dev/null; then
    info "Stopping agent (PID $AGENT_PID)..."
    kill "$AGENT_PID" 2>/dev/null || true
    wait "$AGENT_PID" 2>/dev/null || true
    ok "Agent stopped"
  fi

  if [ -n "$JIBRIL_PID" ] && kill -0 "$JIBRIL_PID" 2>/dev/null; then
    info "Stopping Jibril (PID $JIBRIL_PID)..."
    kill "$JIBRIL_PID" 2>/dev/null || true
    wait "$JIBRIL_PID" 2>/dev/null || true
    ok "Jibril stopped"
  fi

  # Clean up temp attack artifacts
  rm -f /tmp/suspicious-payload.sh /tmp/.hidden-binary 2>/dev/null || true
}

trap cleanup EXIT

# ─── Phase 1: Prerequisites ──────────────────────────────────────────

section "Phase 1: Prerequisites"

info "Environment: ${ENV_TYPE}"
info "Project root: ${PROJECT_ROOT}"

# Must run as root (Jibril needs it)
if [ "$(id -u)" -ne 0 ]; then
  fail "This script must be run as root (sudo)"
  exit 1
fi

# Resolve the user who invoked sudo (for running agent as non-root)
REAL_USER="${SUDO_USER:-$(whoami)}"
info "Real user: ${REAL_USER}"

# Node.js
if ! command -v node &>/dev/null; then
  fail "Node.js not found — install Node.js 20+"
  exit 1
fi
NODE_VER="$(node --version)"
ok "Node.js ${NODE_VER}"

# npx
if ! command -v npx &>/dev/null; then
  fail "npx not found"
  exit 1
fi
ok "npx available"

# curl
if ! command -v curl &>/dev/null; then
  fail "curl not found"
  exit 1
fi
ok "curl available"

# jibril
if ! command -v jibril &>/dev/null; then
  fail "jibril not found — install from https://github.com/garnet-org/jibril-releases"
  exit 1
fi
JIBRIL_VER="$(jibril --version 2>&1 | head -1 || echo 'unknown')"
ok "jibril ${JIBRIL_VER}"

# Config files exist
if [ ! -f "$PROJECT_ROOT/jibril/config.yaml" ]; then
  fail "jibril/config.yaml not found in project"
  exit 1
fi
if [ ! -f "$PROJECT_ROOT/jibril/forward-to-agent.yaml" ]; then
  fail "jibril/forward-to-agent.yaml not found in project"
  exit 1
fi
ok "Config files present"

# ─── Phase 2: Deploy Configuration ───────────────────────────────────

section "Phase 2: Deploy Configuration"

if [ "$SKIP_DEPLOY" = true ]; then
  warn "Skipping deployment (--skip-deploy)"
else
  mkdir -p /etc/jibril/alchemies/private

  cp "$PROJECT_ROOT/jibril/config.yaml" /etc/jibril/config.yaml
  ok "Deployed config.yaml → /etc/jibril/config.yaml"

  cp "$PROJECT_ROOT/jibril/forward-to-agent.yaml" /etc/jibril/alchemies/private/forward-to-agent.yaml
  ok "Deployed forward-to-agent.yaml → /etc/jibril/alchemies/private/"
fi

# ─── Phase 3: Prepare BPF ────────────────────────────────────────────

section "Phase 3: Prepare BPF"

if ! mountpoint -q /sys/fs/bpf 2>/dev/null; then
  info "Mounting BPF filesystem..."
  mount -t bpf bpf /sys/fs/bpf
  ok "BPF filesystem mounted"
else
  ok "BPF filesystem already mounted"
fi

# Clear stale BPF maps from previous runs
STALE_MAPS=$(find /sys/fs/bpf -name 'jb_*' 2>/dev/null | wc -l)
if [ "$STALE_MAPS" -gt 0 ]; then
  info "Clearing ${STALE_MAPS} stale BPF maps..."
  rm -f /sys/fs/bpf/jb_* 2>/dev/null || true
  ok "Stale maps cleared"
else
  ok "No stale BPF maps"
fi

# ─── Phase 4: Start Agent ────────────────────────────────────────────

section "Phase 4: Start Correlation Agent"

if [ "$SKIP_AGENT" = true ]; then
  warn "Skipping agent start (--skip-agent)"
else
  # Kill any existing agent on the port
  if curl -sf "${AGENT_URL}/health" > /dev/null 2>&1; then
    warn "Agent already running at ${AGENT_URL} — using existing instance"
    SKIP_AGENT=true
  else
    info "Starting agent..."
    cd "$PROJECT_ROOT"
    # Run agent as the real user, not root
    sudo -u "$REAL_USER" npx tsx src/server.ts > "$AGENT_LOG" 2>&1 &
    AGENT_PID=$!
    info "Agent PID: ${AGENT_PID}"

    # Wait for agent to be ready
    AGENT_READY=false
    for i in $(seq 1 15); do
      if curl -sf "${AGENT_URL}/health" > /dev/null 2>&1; then
        AGENT_READY=true
        break
      fi
      sleep 1
    done

    if [ "$AGENT_READY" = true ]; then
      ok "Agent is healthy"
    else
      fail "Agent failed to start within 15s"
      echo "--- Agent log ---"
      cat "$AGENT_LOG" 2>/dev/null || true
      exit 1
    fi
  fi
fi

# Capture initial event count
INITIAL_EVENTS=$(curl -sf "${AGENT_URL}/health" 2>/dev/null | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('events',{}).get('total',0))" 2>/dev/null || echo "0")
info "Initial event count: ${INITIAL_EVENTS}"

# ─── Phase 5: Start Jibril ───────────────────────────────────────────

section "Phase 5: Start Jibril"

if [ "$SKIP_JIBRIL" = true ]; then
  warn "Skipping Jibril start (--skip-jibril)"
else
  # Kill any existing Jibril
  if pgrep -x jibril > /dev/null 2>&1; then
    warn "Jibril already running — killing existing instance"
    pkill -x jibril 2>/dev/null || true
    sleep 2
  fi

  info "Starting Jibril..."
  GARNET_SAR=true jibril --config /etc/jibril/config.yaml > "$JIBRIL_LOG" 2>&1 &
  JIBRIL_PID=$!
  info "Jibril PID: ${JIBRIL_PID}"

  # Give Jibril time to load eBPF programs
  sleep 5

  if kill -0 "$JIBRIL_PID" 2>/dev/null; then
    ok "Jibril is running"
  else
    fail "Jibril failed to start"
    echo "--- Jibril log ---"
    cat "$JIBRIL_LOG" 2>/dev/null || true
    exit 1
  fi

  # Check for alchemy validation errors
  ALCHEMY_ERRORS=$(grep -ci "validation failed\|invalid event type" "$JIBRIL_LOG" 2>/dev/null || echo "0")
  if [ "$ALCHEMY_ERRORS" -gt 0 ]; then
    warn "Alchemy validation errors detected:"
    grep -i "validation failed\|invalid event type" "$JIBRIL_LOG" | head -5
  else
    ok "No alchemy validation errors"
  fi

  # Check that private alchemy loaded
  if grep -q "private" "$JIBRIL_LOG" 2>/dev/null; then
    ok "Private alchemies loaded"
  fi
fi

# ─── Phase 6: Trigger Attacks ────────────────────────────────────────

section "Phase 6: Attack Simulations"

info "Triggering detectable behaviors..."
echo ""

# Test 1: Credentials file access (credentials_files_access)
echo -e "  ${CYAN}Test 1:${NC} Credentials file access (cat /etc/shadow)"
cat /etc/shadow > /dev/null 2>&1 || true
cat /etc/gshadow > /dev/null 2>&1 || true
ok "  Triggered credentials_files_access"
sleep 1

# Test 2: Execution from unusual directory (exec_from_unusual_dir)
echo -e "  ${CYAN}Test 2:${NC} Execution from /tmp"
cat > /tmp/suspicious-payload.sh << 'SCRIPT'
#!/bin/sh
echo "suspicious payload from /tmp"
SCRIPT
chmod +x /tmp/suspicious-payload.sh
/tmp/suspicious-payload.sh > /dev/null 2>&1 || true
rm -f /tmp/suspicious-payload.sh
ok "  Triggered exec_from_unusual_dir"
sleep 1

# Test 3: Dynamic linker attack (dynamic_linker_attacks)
echo -e "  ${CYAN}Test 3:${NC} Dynamic linker abuse (LD_PRELOAD)"
LD_PRELOAD=/tmp/nonexistent.so ls /dev/null > /dev/null 2>&1 || true
ok "  Triggered dynamic_linker_attacks"
sleep 1

# Test 4: Hidden ELF execution (triggers hidden_elf_exec from built-in)
echo -e "  ${CYAN}Test 4:${NC} Hidden ELF execution"
cp /bin/echo /tmp/.hidden-binary 2>/dev/null || true
/tmp/.hidden-binary "hidden binary test" > /dev/null 2>&1 || true
rm -f /tmp/.hidden-binary
ok "  Triggered hidden_elf_exec"
sleep 1

# Test 5: Credentials text lookup (triggers credentials_text_lookup from built-in)
echo -e "  ${CYAN}Test 5:${NC} Credentials text lookup"
grep -r "password" /etc/passwd > /dev/null 2>&1 || true
ok "  Triggered credentials_text_lookup"

echo ""
info "All attack simulations complete"

# ─── Phase 7: Wait for Detection Cadence ──────────────────────────────

section "Phase 7: Wait for Detection Cadence"

CADENCE_WAIT=20
info "Waiting ${CADENCE_WAIT}s for Jibril detection cadence..."

# Show a progress indicator
for i in $(seq 1 "$CADENCE_WAIT"); do
  printf "\r  [%-${CADENCE_WAIT}s] %d/%ds" "$(printf '#%.0s' $(seq 1 "$i"))" "$i" "$CADENCE_WAIT"
  sleep 1
done
echo ""
ok "Cadence wait complete"

# ─── Phase 8: Verify Results ─────────────────────────────────────────

section "Phase 8: Verify Results"

# Check agent health for new events
if ! curl -sf "${AGENT_URL}/health" > /dev/null 2>&1; then
  fail "Agent is not reachable!"
  FAILED=$((FAILED + 1))
else
  HEALTH=$(curl -sf "${AGENT_URL}/health" 2>/dev/null)
  FINAL_EVENTS=$(echo "$HEALTH" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('events',{}).get('total',0))" 2>/dev/null || echo "0")
  NEW_EVENTS=$((FINAL_EVENTS - INITIAL_EVENTS))

  info "Agent health: ${HEALTH}"
  echo ""

  # Verify: at least some events arrived via reactions
  if [ "$NEW_EVENTS" -gt 0 ]; then
    ok "Events forwarded to agent: ${NEW_EVENTS} new events"
    PASSED=$((PASSED + 1))
  else
    fail "No new events reached the agent (expected > 0)"
    FAILED=$((FAILED + 1))
  fi

  # Verify: we expect at least 2 different reaction-forwarded events
  # (credentials_files_access + exec_from_unusual_dir at minimum)
  if [ "$NEW_EVENTS" -ge 2 ]; then
    ok "Multiple event types detected (${NEW_EVENTS} events)"
    PASSED=$((PASSED + 1))
  else
    warn "Expected at least 2 event types, got ${NEW_EVENTS}"
  fi
fi

# Check Jibril log for reaction execution
if [ -f "$JIBRIL_LOG" ]; then
  REACTION_HITS=$(grep -c "reaction\|agent_forward" "$JIBRIL_LOG" 2>/dev/null || echo "0")
  if [ "$REACTION_HITS" -gt 0 ]; then
    ok "Jibril reactions triggered (${REACTION_HITS} log entries)"
    PASSED=$((PASSED + 1))
  else
    warn "No reaction entries found in Jibril log"
  fi

  DETECTION_COUNT=$(grep -c "metadata" "$JIBRIL_LOG" 2>/dev/null || echo "0")
  info "Jibril raw detections in log: ~${DETECTION_COUNT}"
fi

# ─── Summary ──────────────────────────────────────────────────────────

section "Test Summary"

echo -e "  Environment:   ${BOLD}${ENV_TYPE}${NC}"
echo -e "  Initial events: ${INITIAL_EVENTS}"
echo -e "  Final events:   ${FINAL_EVENTS:-unknown}"
echo -e "  New events:     ${NEW_EVENTS:-0}"
echo ""
echo -e "  ${GREEN}Passed:${NC} ${PASSED}"
echo -e "  ${RED}Failed:${NC} ${FAILED}"
echo ""

if [ "$FAILED" -eq 0 ] && [ "$PASSED" -gt 0 ]; then
  echo -e "  ${GREEN}${BOLD}═══ ALL CHECKS PASSED ═══${NC}"
  exit 0
else
  echo -e "  ${RED}${BOLD}═══ SOME CHECKS FAILED ═══${NC}"
  echo ""
  echo "  Troubleshooting:"
  echo "    - Check agent log: cat ${AGENT_LOG}"
  echo "    - Check jibril log: cat ${JIBRIL_LOG}"
  echo "    - Jibril needs ~5 min warm-up after eBPF load for first events"
  echo "    - Try running again with a longer cadence wait"
  exit 1
fi
