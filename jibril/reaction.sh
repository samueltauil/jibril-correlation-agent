#!/bin/sh
# Jibril Shell Reaction — forwards detection events to the correlation agent
# Usage: configured as a shell reaction in Jibril alchemy YAML
#
# The REACTION_DATA environment variable contains the full event JSON
# set by Jibril when the reaction is triggered.

AGENT_URL="${AGENT_URL:-http://localhost:3000/events}"

if [ -z "$REACTION_DATA" ]; then
  echo "[jibril-reaction] ERROR: REACTION_DATA is empty" >&2
  exit 1
fi

curl -sf -X POST \
  -H "Content-Type: application/json" \
  -H "X-Webhook-Secret: ${WEBHOOK_SECRET:-}" \
  -d "$REACTION_DATA" \
  "$AGENT_URL" \
  >/dev/null 2>&1 || echo "[jibril-reaction] WARNING: Failed to send event to $AGENT_URL" >&2
