#!/bin/bash
# test-real-attacks.sh — Trigger real suspicious behaviors for Jibril to detect
#
# Run INSIDE WSL after Jibril and the agent are both running.
# These are HARMLESS test actions that trigger Jibril detections.
#
# Usage: sudo bash test/test-real-attacks.sh

set -e

AGENT_URL="${AGENT_URL:-http://localhost:3000}"

echo "============================================"
echo " Jibril Real Attack Simulation"
echo "============================================"
echo ""
echo "Agent URL: ${AGENT_URL}"
echo ""

# Check if agent is reachable
echo "[*] Checking if agent is running..."
if curl -sf "${AGENT_URL}/health" > /dev/null 2>&1; then
  echo "    Agent is healthy!"
  curl -s "${AGENT_URL}/health" | python3 -m json.tool 2>/dev/null || curl -s "${AGENT_URL}/health"
else
  echo "    WARNING: Agent not reachable at ${AGENT_URL}/health"
  echo "    Events will still be detected by Jibril but won't reach the agent."
fi
echo ""

echo "============================================"
echo " Test 1: Credentials File Access"
echo "   (cat /etc/shadow — triggers credentials_files_access)"
echo "============================================"
echo ""
cat /etc/shadow > /dev/null 2>&1 || true
echo "    Done — read /etc/shadow"
sleep 2

echo ""
echo "============================================"
echo " Test 2: Execution From Unusual Directory"
echo "   (write and run a script from /tmp)"
echo "============================================"
echo ""
cat > /tmp/suspicious-payload.sh << 'SCRIPT'
#!/bin/sh
echo "I am a suspicious payload running from /tmp"
whoami
hostname
SCRIPT
chmod +x /tmp/suspicious-payload.sh
/tmp/suspicious-payload.sh
rm -f /tmp/suspicious-payload.sh
echo "    Done — executed /tmp/suspicious-payload.sh"
sleep 2

echo ""
echo "============================================"
echo " Test 3: Credentials Text Lookup"
echo "   (grep for passwords in common locations)"
echo "============================================"
echo ""
grep -r "password" /etc/passwd 2>/dev/null || true
echo "    Done — searched for credentials patterns"
sleep 2

echo ""
echo "============================================"
echo " Test 4: Dynamic Linker Attack (LD_PRELOAD)"
echo "   (set LD_PRELOAD and run a command)"
echo "============================================"
echo ""
LD_PRELOAD=/tmp/nonexistent.so ls /dev/null 2>/dev/null || true
echo "    Done — ran command with LD_PRELOAD set"
sleep 2

echo ""
echo "============================================"
echo " Test 5: Shell Config Modification"
echo "   (append to .bashrc — will revert)"
echo "============================================"
echo ""
MARKER="# JIBRIL-TEST-MARKER-REMOVE-ME"
echo "$MARKER" >> ~/.bashrc
sed -i "/$MARKER/d" ~/.bashrc
echo "    Done — briefly modified .bashrc"
sleep 2

echo ""
echo "============================================"
echo " Test 6: Hidden ELF Execution"
echo "   (copy /bin/echo to a dotfile and execute)"
echo "============================================"
echo ""
cp /bin/echo /tmp/.hidden-binary 2>/dev/null || true
/tmp/.hidden-binary "I am a hidden binary" 2>/dev/null || true
rm -f /tmp/.hidden-binary
echo "    Done — executed hidden binary /tmp/.hidden-binary"
sleep 2

echo ""
echo "============================================"
echo " All tests complete!"
echo "============================================"
echo ""

# Check agent health again
if curl -sf "${AGENT_URL}/health" > /dev/null 2>&1; then
  echo "[*] Agent health after tests:"
  curl -s "${AGENT_URL}/health" | python3 -m json.tool 2>/dev/null || curl -s "${AGENT_URL}/health"
fi
echo ""
echo "If Jibril is running with the reaction alchemy, events should"
echo "have been forwarded to the agent. Check the agent logs and"
echo "Jibril stdout/varlog for detection output."
echo ""
echo "You can also check /var/log/jibril.out for raw detection JSON."
