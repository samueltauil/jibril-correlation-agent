#!/bin/bash
# send-events.sh — Send sample Jibril events to the correlation agent
#
# Usage:
#   ./test/send-events.sh                    # Send all sample events
#   ./test/send-events.sh crypto-miner       # Send only matching events
#   AGENT_URL=http://host:3000 ./test/send-events.sh

set -e

AGENT_URL="${AGENT_URL:-http://localhost:3000}"
EVENTS_DIR="$(dirname "$0")/sample-events"
FILTER="${1:-}"

echo "=== Jibril Correlation Agent — Sample Event Sender ==="
echo "Target: ${AGENT_URL}/events"
echo ""

# Check if agent is running
if ! curl -sf "${AGENT_URL}/health" > /dev/null 2>&1; then
  echo "ERROR: Agent is not reachable at ${AGENT_URL}/health"
  echo "Start the agent first:  npm run dev"
  exit 1
fi

echo "Agent is healthy."
echo ""

sent=0
for event_file in "${EVENTS_DIR}"/*.json; do
  filename=$(basename "$event_file")

  # Apply filter if provided
  if [ -n "$FILTER" ] && [[ "$filename" != *"$FILTER"* ]]; then
    continue
  fi

  echo "--- Sending: ${filename} ---"

  response=$(curl -sf -X POST \
    -H "Content-Type: application/json" \
    -d @"$event_file" \
    "${AGENT_URL}/events" 2>&1) || {
    echo "  FAILED to send ${filename}"
    continue
  }

  echo "  Response: ${response}"
  sent=$((sent + 1))
  echo ""
done

echo "=== Done: ${sent} event(s) sent ==="
echo ""
echo "Now check the agent:"
echo "  curl -s ${AGENT_URL}/health | jq ."
echo ""
echo "Or use @jibril in Copilot Chat:"
echo "  @jibril what happened?"
echo "  @jibril stats"
echo "  @jibril analyze <uuid>"
