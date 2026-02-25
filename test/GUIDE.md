# End-to-End Testing Guide

This guide walks you through testing the Jibril Correlation Agent from start to finish — from spinning it up locally, ingesting sample security events, querying via the API, and understanding how the Copilot Extension integration works.

No Jibril installation required. We'll simulate events using sample JSON files.

---

## Table of Contents

1. [What You'll Learn](#what-youll-learn)
2. [Prerequisites](#prerequisites)
3. [Part 1: Start the Agent](#part-1-start-the-agent)
4. [Part 2: Understand the Sample Events](#part-2-understand-the-sample-events)
5. [Part 3: Send Events to the Agent](#part-3-send-events-to-the-agent)
6. [Part 4: Query the Agent](#part-4-query-the-agent)
7. [Part 5: How It Works With Real Jibril](#part-5-how-it-works-with-real-jibril)
8. [Part 6: Setting Up the Copilot Extension](#part-6-setting-up-the-copilot-extension)
9. [Part 7: Docker Deployment](#part-7-docker-deployment)
9. [Part 8: Automated End-to-End Testing with Jibril](#part-8-automated-end-to-end-testing-with-jibril)
10. [Troubleshooting](#troubleshooting)

---

## What You'll Learn

- How runtime security events flow from Jibril to this agent
- The structure of Jibril events (metadata, severity scores, process ancestry)
- How the agent normalizes, stores, and classifies events
- How to query events via the health endpoint
- How the Copilot Extension turns events into actionable code insights
- How to deploy and connect everything in production

---

## Prerequisites

- **Node.js 20+** — check with `node --version`
- **curl** — for sending test requests
- **jq** (optional) — for pretty-printing JSON responses: `brew install jq`

---

## Part 1: Start the Agent

From the project root:

```bash
# Install dependencies (if you haven't already)
npm install

# Start in development mode (auto-restarts on changes)
npm run dev
```

You should see:

```
Jibril Correlation Agent listening on port 3000
  POST /events  — Jibril event ingestion
  POST /agent   — Copilot Extension endpoint
  GET  /health  — Health check
```

Verify it's running:

```bash
curl -s http://localhost:3000/health | jq .
```

### Expose the Agent Publicly

The Copilot Extension requires a public HTTPS URL. During development, use Cloudflare Tunnel:

```bash
# Install (if you haven't)
brew install cloudflared

# In a separate terminal
cloudflared tunnel --url http://localhost:3000
```

You'll see output like:

```
Your quick Tunnel has been created! Visit it at:
  https://random-words-here.trycloudflare.com
```

This URL is your agent's public address. Use it when configuring the GitHub App:
- Copilot Extension endpoint: `https://random-words-here.trycloudflare.com/agent`

> **Note**: Quick tunnel URLs change every time you restart `cloudflared`. For a stable URL, set up a named tunnel:
> ```bash
> cloudflared tunnel login
> cloudflared tunnel create jibril-agent
> cloudflared tunnel route dns jibril-agent jibril.yourdomain.com
> cloudflared tunnel run --url http://localhost:3000 jibril-agent
> ```

You can verify the tunnel works:

```bash
curl -s https://random-words-here.trycloudflare.com/health
```

Expected output:

```json
{
  "status": "ok",
  "events": {
    "total": 0,
    "bySeverity": {},
    "byType": {}
  }
}
```

The agent is up and has zero events. Let's fix that.

---

## Part 2: Understand the Sample Events

The `test/sample-events/` directory contains 5 realistic Jibril events, each representing a different type of security detection. Let's understand what Jibril would actually see at the kernel level.

### Event 1: Crypto Miner Execution (`crypto-miner-execution.json`)

**What happened**: The `xmrig` cryptocurrency miner was executed inside a container. Jibril's eBPF hooks captured the `execve` syscall.

```
Process chain: systemd → containerd-shim → node → xmrig
```

Key fields:
- **severity**: 95/100 (critical) — crypto miners are a clear indicator of compromise
- **confidence**: 0.92 — Jibril is very sure this is xmrig
- **MITRE ATT&CK**: T1059.004 (Command and Scripting Interpreter: Unix Shell)
- **exec.cmdline**: The full command with mining pool and wallet address

**Why this matters**: A node.js app spawning a crypto miner means either a supply chain attack (malicious dependency) or remote code execution. The agent would search GitHub for `child_process.spawn`, `exec()`, or recently added npm packages.

---

### Event 2: Threat Domain Access (`threat-domain-access.json`)

**What happened**: A process made an outbound HTTPS connection to `evil-analytics.darksite.io`, a domain flagged as malicious by Jibril's 2M+ domain reputation database.

Key fields:
- **severity**: 80/100 (high)
- **network.domain**: `evil-analytics.darksite.io`
- **network.destination_ip**: `185.199.42.13`

**Why this matters**: This looks like a malicious analytics SDK phoning home. The agent would search for `fetch()`, `axios`, `http.request`, or the domain string itself in the codebase.

---

### Event 3: Credentials File Access (`credentials-file-access.json`)

**What happened**: Inside a container, a `python3` process spawned `sh`, which ran `cat /etc/shadow`. This reads the system's password hash file.

```
Process chain: containerd-shim → python3 → sh → cat /etc/shadow
```

Key fields:
- **severity**: 85/100 (high)
- **file.file**: `/etc/shadow`
- **file.actions**: `["read"]`

**Why this matters**: No legitimate application reads `/etc/shadow`. This suggests credential harvesting — likely from a Python subprocess call. The agent would search for `subprocess.run`, `os.system`, `open('/etc/shadow')`.

---

### Event 4: Execution From Unusual Directory (`exec-from-unusual-dir.json`)

**What happened**: A binary at `/tmp/payload` was executed with exfiltration flags.

Key fields:
- **severity**: 60/100 (medium) — `/tmp` execution is suspicious but could be a build artifact
- **confidence**: 0.65 — lower confidence, might be a false positive
- **exec.cmdline**: `/tmp/payload --exfil --target s3://data-bucket`

**Why this matters**: Legitimate binaries don't live in `/tmp`. This looks like a dropped payload. The agent would search for code that downloads files to `/tmp` or calls `exec()` on temporary paths.

---

### Event 5: Dynamic Linker Attack (`dynamic-linker-attack.json`)

**What happened**: The `LD_PRELOAD` environment variable was set to `/tmp/libhook.so`, hijacking the dynamic linker to load a malicious shared library.

Key fields:
- **severity**: 88/100 (high)
- **confidence**: 0.90 — `LD_PRELOAD` abuse is a well-known technique
- **exec.env.LD_PRELOAD**: `/tmp/libhook.so`
- **MITRE ATT&CK**: T1574.006 (Hijack Execution Flow: Dynamic Linker Hijacking)

**Why this matters**: `LD_PRELOAD` injection lets attackers intercept any function call in any process. The agent would search for code that sets `LD_PRELOAD`, `LD_LIBRARY_PATH`, or calls `dlopen()`.

---

## Part 3: Send Events to the Agent

### Option A: Use the Script

```bash
chmod +x test/send-events.sh
./test/send-events.sh
```

Output:

```
=== Jibril Correlation Agent — Sample Event Sender ===
Target: http://localhost:3000/events

Agent is healthy.

--- Sending: credentials-file-access.json ---
  Response: {"id":"c3d4e5f6-a7b8-9012-cdef-123456789012","status":"ingested"}

--- Sending: crypto-miner-execution.json ---
  Response: {"id":"a1b2c3d4-e5f6-7890-abcd-ef1234567890","status":"ingested"}

...

=== Done: 5 event(s) sent ===
```

You can also send a single event:

```bash
./test/send-events.sh crypto-miner
```

### Option B: Send Manually with curl

```bash
curl -s -X POST \
  -H "Content-Type: application/json" \
  -d @test/sample-events/crypto-miner-execution.json \
  http://localhost:3000/events | jq .
```

Response:

```json
{
  "id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
  "status": "ingested"
}
```

### Deduplication

Try sending the same event twice — the agent deduplicates by UUID:

```bash
curl -s -X POST -H "Content-Type: application/json" \
  -d @test/sample-events/crypto-miner-execution.json \
  http://localhost:3000/events | jq .

# Same response, event not duplicated in store
```

---

## Part 4: Query the Agent

### Health Check (with stats)

After sending all 5 events:

```bash
curl -s http://localhost:3000/health | jq .
```

```json
{
  "status": "ok",
  "events": {
    "total": 5,
    "bySeverity": {
      "critical": 1,
      "high": 3,
      "medium": 1
    },
    "byType": {
      "execution": 2,
      "network_peers": 1,
      "file_access": 1,
      "env_vars": 1
    }
  }
}
```

This tells you:
- **5 events** ingested
- **1 critical** (the crypto miner), **3 high**, **1 medium**
- Events span **4 different detection types** — Jibril monitors all of these via eBPF

### Webhook Secret (Optional)

If you set `WEBHOOK_SECRET`, events must include the secret header:

```bash
# Start agent with secret
WEBHOOK_SECRET=my-secret npm run dev

# Send event with secret
curl -s -X POST \
  -H "Content-Type: application/json" \
  -H "X-Webhook-Secret: my-secret" \
  -d @test/sample-events/crypto-miner-execution.json \
  http://localhost:3000/events | jq .

# Without the secret → 401 Unauthorized
curl -s -X POST \
  -H "Content-Type: application/json" \
  -d @test/sample-events/crypto-miner-execution.json \
  http://localhost:3000/events
# {"error":"Invalid webhook secret"}
```

---

## Part 5: How It Works With Real Jibril

In production, Jibril replaces the manual curl commands with **shell reactions** — automated scripts triggered when a detection recipe matches.

### The Flow

```
1. Jibril eBPF hooks capture a syscall (execve, connect, open, etc.)
2. Jibril's detection engine matches it against alchemy recipes
3. If matched, the shell reaction fires
4. The reaction sends REACTION_DATA (event JSON) to your agent
5. The agent stores it and makes it available via @jibril in Copilot Chat
```

### Configuring the Reaction

In your Jibril config (e.g., `/etc/jibril/alchemies/private/correlation.yaml`):

```yaml
- kind: correlation_agent_forward
  name: forward_high_severity_events
  enabled: true
  version: 1.0
  description: "Forward events to the correlation agent"
  breed: execution
  mechanism: execution
  tactic: any
  technique: any
  severity_level: high
  severity: 75
  confidence: 0.8
  reactions:
    - format: shell
      code: |
        curl -sf -X POST \
          -H "Content-Type: application/json" \
          -d "$REACTION_DATA" \
          http://your-agent-host:3000/events
```

Key points:
- `$REACTION_DATA` is set by Jibril automatically — it contains the full event JSON
- You can create multiple alchemies for different severity levels or event types
- The `severity: 75` and `confidence: 0.8` thresholds prevent flooding the agent with noise

### Repo Mappings

To enable code correlation, the agent needs to know which GitHub repo corresponds to which container image:

```bash
REPO_MAPPINGS="myorg/api-server=myorg/api-server-repo,myorg/background-worker=myorg/worker-repo" npm run dev
```

Format: `container-image=github-owner/repo`, comma-separated.

When an event arrives with `container.image: "myorg/api-server"`, the agent maps it to the GitHub repo `myorg/api-server-repo` for code search.

---

## Part 6: Setting Up the Copilot Extension

This is where the magic happens — `@jibril` in Copilot Chat.

### Step 1: Create a GitHub App

1. Go to **https://github.com/settings/apps** → **New GitHub App**
2. Fill in:
   - **Name**: `Jibril Correlation Agent` (or your preferred name)
   - **Homepage URL**: your agent's URL
   - **Callback URL**: `https://your-agent-host.com/agent`
   - **Webhook**: disable (not needed — we use the `/events` endpoint directly)
3. **Permissions**:
   - Contents: **Read** (for searching code)
   - Issues: **Read & Write** (for creating issues)
   - Pull requests: **Read & Write** (for creating PRs)
   - Metadata: **Read**

### Step 2: Enable Copilot Extension

In the GitHub App settings:
1. Go to **Copilot** tab
2. Enable **Copilot Extension**
3. Set **Agent Type**: Agent
4. Set **URL**: `https://your-agent-host.com/agent` (must be HTTPS)

### Step 3: Install the App

Install the GitHub App on relevant repositories/organizations.

### Step 4: Use It

Open Copilot Chat (VS Code, github.com, JetBrains, or CLI) and type:

```
@jibril what happened?
```

The agent will:
1. Verify the request cryptographically (using GitHub's public keys)
2. Read the user token from the request headers
3. Query the event store
4. Use `prompt()` to call GitHub's LLM for analysis
5. Stream back a markdown-formatted response

### Available Commands

```
@jibril events                          # List recent events with LLM summary
@jibril stats                           # Event counts by severity and type
@jibril analyze a1b2c3d4                # Deep dive on a specific event
@jibril correlate a1b2c3d4              # Find related source code and commits
@jibril create issue for a1b2c3d4       # File a GitHub issue
@jibril why is my container connecting to unknown IPs?  # Natural language query
```

### How the Agent Responds

The Copilot Extension protocol uses **Server-Sent Events (SSE)**:

```
event: copilot_ack        ← "I'm working on it"
data: {}

event: copilot_text       ← Markdown analysis
data: {"body": "## Analysis\n\nA crypto miner (xmrig) was..."}

event: copilot_references ← Clickable links to code
data: {"references": [{"id": "code-0", "metadata": {"display_name": "src/worker.ts"}}]}

event: copilot_done       ← "I'm finished"
data: {}
```

---

## Part 7: Docker Deployment

### Build

```bash
docker build -t jibril-correlation-agent .
```

### Run

```bash
docker run -p 3000:3000 \
  -e REPO_MAPPINGS="myorg/api-server=myorg/api-server" \
  jibril-correlation-agent
```

### Test

```bash
# Health check
curl -s http://localhost:3000/health | jq .

# Send a sample event
curl -s -X POST \
  -H "Content-Type: application/json" \
  -d @test/sample-events/crypto-miner-execution.json \
  http://localhost:3000/events | jq .
```

### Production Hosting

The Copilot Extension requires a **publicly accessible HTTPS endpoint**. Options:

| Platform | Pros | How |
|----------|------|-----|
| **Local/Prototype** | cloudflared | `cloudflared tunnel --url http://localhost:3000` |
| **Railway** | Simple Docker deploy, auto-HTTPS | `railway up` |
| **Fly.io** | Global edge, auto-HTTPS | `fly deploy` |
| **Your K8s cluster** | Same network as Jibril, lowest latency | Deploy as a Deployment + Service + Ingress |

---

## Troubleshooting

### "Agent is not reachable"

```bash
# Check if port 3000 is in use
lsof -i :3000

# Start the agent
npm run dev
```

### Event rejected with 400

```bash
# Ensure the JSON has required fields
cat test/sample-events/crypto-miner-execution.json | jq '.uuid, .metadata'
```

Both `uuid` and `metadata` are required.

### Event rejected with 401

```bash
# You have WEBHOOK_SECRET set but didn't send it
# Either unset the env var or add the header:
curl -H "X-Webhook-Secret: your-secret" ...
```

### Copilot Extension returns 401

The Copilot Extension verifies requests using GitHub's public key signing. This only works with real requests from GitHub's Copilot infrastructure — not with plain curl. For local testing, use the `/events` endpoint directly and check results via `/health`.

### Events disappear after a while

Events expire after 24 hours (configurable in `src/events.ts` via `DEFAULT_TTL_MS`). Re-send sample events to repopulate.

---

## Part 8: Automated End-to-End Testing with Jibril

The `test/test-e2e.sh` script runs the full pipeline automatically — deploying configs, starting services, triggering attacks, and verifying events reach the agent. It works on both WSL and native Linux.

### Prerequisites

- **Linux** (native or WSL2 with kernel 5.8+)
- **Node.js 20+**, **curl**
- **Jibril binary** installed at `/usr/bin/jibril` ([releases](https://github.com/garnet-org/jibril-releases))
- **sudo** access (Jibril needs root for eBPF)

### Run It

```bash
# From the project root
sudo bash test/test-e2e.sh
```

### What It Does

1. **Detects environment** — WSL vs native Linux (via `/proc/version`)
2. **Checks prerequisites** — Node.js, curl, jibril binary, sudo
3. **Deploys config** — copies `jibril/config.yaml` and `jibril/forward-to-agent.yaml` to `/etc/jibril/`
4. **Prepares BPF** — mounts BPF filesystem, clears stale maps
5. **Starts agent** — runs the correlation agent on port 3000
6. **Starts Jibril** — with `GARNET_SAR=true` (no API token needed)
7. **Triggers attacks** — credential file access, /tmp execution, LD_PRELOAD abuse, hidden ELF, credential text lookup
8. **Waits for cadence** — 20s for Jibril's detection cycle
9. **Verifies results** — checks events arrived at the agent via `/health`
10. **Cleans up** — stops agent and Jibril

### Options

```bash
sudo bash test/test-e2e.sh --skip-deploy   # Don't redeploy configs
sudo bash test/test-e2e.sh --skip-jibril   # Jibril already running
sudo bash test/test-e2e.sh --skip-agent    # Agent already running
```

### Troubleshooting

- **"No new events"**: Jibril needs ~5 minutes warm-up after eBPF programs load on first run. Run the test again after Jibril has been up for a few minutes.
- **BPF mount fails**: On WSL, run `sudo mount -t bpf bpf /sys/fs/bpf` manually first.
- **Stale BPF maps**: If Jibril crashes, clear maps with `rm -f /sys/fs/bpf/jb_*` before restarting.

---

## What's Next?

After testing locally with sample events:

1. **Deploy** the agent to a public HTTPS host
2. **Create** a GitHub App with Copilot Extension enabled
3. **Configure** Jibril shell reactions to forward events to the agent
4. **Use** `@jibril` in Copilot Chat to investigate security events

The agent bridges the gap between *"something suspicious happened at runtime"* and *"here's the exact code and commit responsible, with a fix."*

---

## Part 9: Testing with Cosmos DB

The agent supports two storage modes. By default (no `COSMOS_ENDPOINT` set), it uses in-memory storage. When `COSMOS_ENDPOINT` is set, it persists events, chains, and correlation state to Azure Cosmos DB.

### In-Memory Mode (Default)

No additional setup needed — just run `npm run dev`. All state is lost when the agent restarts. This is ideal for local development and testing.

### Testing with Cosmos DB

To test persistence across restarts:

1. Set up a Cosmos DB account (serverless, free tier) or use the [Azure Cosmos DB Emulator](https://learn.microsoft.com/en-us/azure/cosmos-db/emulator)
2. Authenticate via `az login` (the agent uses `DefaultAzureCredential` — no keys needed)
3. Start the agent with Cosmos config:

```bash
export COSMOS_ENDPOINT="https://your-account.documents.azure.com:443/"
export COSMOS_DATABASE="jibril"
npm run dev
```

4. Send sample events, then restart the agent and verify state persists:

```bash
# Send events
bash test/send-events.sh

# Check events exist
curl -s http://localhost:3000/health | jq .

# Restart the agent (Ctrl+C, then npm run dev)
# Check events still exist
curl -s http://localhost:3000/health | jq .
```

The database and containers are created automatically on first startup.
