# Jibril Correlation Agent

A **GitHub Copilot Extension** that bridges runtime security and source code. When [Jibril](https://jibril.garnet.ai/) (an eBPF-based runtime security platform) detects anomalous behavior, this agent correlates the event with your codebase — identifying the responsible code, the commit that introduced it, and proposing a fix.

```
[Jibril eBPF] → runtime event → [This Agent] → code analysis → [GitHub Issue / PR]
```

## How It Works

1. **Jibril detects** a runtime security event (suspicious execution, file access, network connection, etc.)
2. **A shell reaction** forwards the event JSON to this agent's `/events` endpoint
3. **You ask `@jibril`** in Copilot Chat (VS Code, github.com, JetBrains, CLI):
   - *"What happened?"* — see recent security events
   - *"Analyze `<event-id>`"* — deep dive analysis of a specific event
   - *"Correlate `<event-id>`"* — find the source code responsible
   - *"Create issue for `<event-id>`"* — file a GitHub issue with full details
4. **The agent uses LLM reasoning** (via GitHub Copilot's API) to correlate runtime behavior with code patterns, recent commits, and dependencies

## Quick Start

### Prerequisites

- Node.js 20+
- A GitHub App configured as a Copilot Extension ([setup guide](https://docs.github.com/en/copilot/building-copilot-extensions))
- Jibril installed on your Linux host or Kubernetes cluster ([jibril.garnet.ai](https://jibril.garnet.ai/))

### Install & Run

```bash
git clone <this-repo>
cd jibril-correlation-agent
npm install
npm run dev
```

The agent starts on port 3000 (configurable via `PORT` env var).

### Environment Variables

| Variable | Required | Description |
|----------|----------|-------------|
| `PORT` | No | Server port (default: `3000`) |
| `WEBHOOK_SECRET` | No | Shared secret for authenticating Jibril event webhooks |
| `REPO_MAPPINGS` | No | Map container images to GitHub repos: `image1=owner/repo1,image2=owner/repo2` |

### Endpoints

| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/events` | Receives Jibril event JSON from shell reactions |
| `POST` | `/agent` | Copilot Extension endpoint (handles `@jibril` chat) |
| `GET` | `/health` | Health check with event statistics |

## Agent Commands

Once connected as a Copilot Extension, use `@jibril` in any Copilot Chat:

| Command | What it does |
|---------|-------------|
| `events` | List recent security events with LLM summary |
| `analyze <uuid>` | Deep dive analysis of a specific event |
| `correlate <uuid>` | Search source code and commits related to the event |
| `create issue for <uuid>` | File a GitHub issue with structured security finding |
| `stats` | Show event count by severity and type |

You can also ask natural language questions — the agent will analyze the latest high-severity event in context.

## Connecting Jibril

Add a shell reaction to your Jibril alchemy configuration to forward events to the agent:

```yaml
reactions:
  - format: shell
    code: |
      curl -sf -X POST \
        -H "Content-Type: application/json" \
        -d "$REACTION_DATA" \
        http://<agent-host>:3000/events
```

See [`jibril/forward-to-agent.yaml`](jibril/forward-to-agent.yaml) for the complete working alchemy, and the [`test/`](test/) directory for an end-to-end walkthrough with sample events.

## Project Structure

```
src/
  server.ts      — Express HTTP server, routes
  agent.ts       — Copilot Extension handler (intent routing, SSE responses)
  events.ts      — Event ingestion, normalization, in-memory store
  reasoning.ts   — LLM reasoning via prompt() (analysis, correlation, summaries)
  github.ts      — GitHub API (code search, commits, issue/PR creation)
  types.ts       — TypeScript interfaces for Jibril events
jibril/
  config.yaml           — Jibril configuration for testing
  forward-to-agent.yaml — Private alchemy with shell reactions
test/
  GUIDE.md              — End-to-end walkthrough
  test-e2e.sh           — Automated end-to-end test (WSL + native Linux)
  test-real-attacks.sh  — Attack simulation triggers
  sample-events/        — Sample Jibril event JSON files
  send-events.sh        — Script to send sample events to the agent
Dockerfile              — Production container image
```

## Deployment

### Pre-built Image (GitHub Container Registry)

```bash
docker pull ghcr.io/samueltauil/jibril-correlation-agent:latest

docker run -p 3000:3000 \
  -e REPO_MAPPINGS="myorg/api=myorg/api-server" \
  ghcr.io/samueltauil/jibril-correlation-agent:latest
```

Available tags:
- `latest` — latest build from main
- `0.1.0` — pinned version

### Build From Source

```bash
docker build -t jibril-correlation-agent .
docker run -p 3000:3000 \
  -e REPO_MAPPINGS="myorg/api=myorg/api-server" \
  jibril-correlation-agent
```

### Exposing the Agent

The Copilot Extension requires a public HTTPS endpoint. Options by stage:

| Stage | Tool | Command |
|-------|------|---------|
| **Local dev** | cloudflared | `cloudflared tunnel --url http://localhost:3000` |
| **Stable prototype** | cloudflared named tunnel | `cloudflared tunnel run jibril-agent` (one-time setup, permanent URL) |
| **Production** | Railway / Fly.io / K8s | Deploy container with Dockerfile |

## Setting Up the GitHub App

1. Go to **GitHub Settings → Developer Settings → GitHub Apps → New GitHub App**
2. Set the **Callback URL** to your agent's `/agent` endpoint (e.g., `https://your-domain.com/agent`)
3. Under **Permissions**, grant:
   - **Contents**: Read (for code search)
   - **Issues**: Read & Write (for issue creation)
   - **Pull Requests**: Read & Write (for PR creation)
   - **Metadata**: Read
4. Under **Copilot**, enable the extension and set the agent endpoint
5. Install the app on your target repositories

## License

MIT
