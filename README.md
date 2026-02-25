# Jibril Correlation Agent

A **GitHub Copilot Extension** that bridges runtime security and source code. When [Jibril](https://jibril.garnet.ai/) (an eBPF-based runtime security platform) detects anomalous behavior, this agent correlates events into **multi-step attack chains** using MITRE ATT&CK kill-chain ordering, then correlates with your codebase — identifying the responsible code, the commit that introduced it, and proposing a fix.

```
[Jibril eBPF] → runtime events → [This Agent] → attack chain correlation → [GitHub Issue / PR]
```

## Key Features

- **Attack Chain Detection**: Automatically correlates events from the same container/host into multi-step attack patterns (e.g., credential theft → privilege escalation → persistence)
- **MITRE ATT&CK Mapping**: Uses kill-chain ordering to detect sophisticated attacks that span multiple tactics
- **Auto-Alerts**: Creates GitHub issues when high-confidence attack chains are detected (via GitHub App installation tokens)
- **Code Correlation**: Searches your codebase for the source of each runtime behavior
- **Copilot Chat Integration**: Ask `@jibril` about events, chains, and code connections

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
| `ALERT_REPO` | No | Repository for auto-alert issues: `owner/repo` |
| `GITHUB_APP_ID` | No | GitHub App ID (required for auto-alerts) |
| `GITHUB_APP_PRIVATE_KEY` | No | GitHub App private key PEM (required for auto-alerts) |
| `COSMOS_ENDPOINT` | No | Azure Cosmos DB endpoint URL (enables persistent storage) |
| `COSMOS_DATABASE` | No | Cosmos DB database name (default: `jibril`) |

### Endpoints

| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/events` | Receives Jibril event JSON from shell reactions |
| `POST` | `/agent` | Copilot Extension endpoint (handles `@jibril` chat) |
| `GET` | `/health` | Health check with event and chain statistics |
| `GET` | `/chains` | List detected attack chains (supports ?confidence, ?pattern, ?scope filters) |

## Agent Commands

Once connected as a Copilot Extension, use `@jibril` in any Copilot Chat:

| Command | What it does |
|---------|--------------|
| `events` | List recent security events with LLM summary |
| `analyze <uuid>` | Deep dive analysis of a specific event |
| `correlate <uuid>` | Search source code and commits related to the event |
| `create issue for <uuid>` | File a GitHub issue with structured security finding |
| `chains` | List detected attack chains with kill-chain progression |
| `chain <id>` | Deep analysis of a specific attack chain |
| `stats` | Show event count by severity, type, and detected chains |

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

## Testing with the Demo Target App

The [**jibril-demo-target**](https://github.com/samueltauil/jibril-demo-target) repository provides a deliberately vulnerable application you can deploy alongside Jibril to generate real security events for this agent.

### Quick start

1. **Clone the demo target**:
   ```bash
   git clone https://github.com/samueltauil/jibril-demo-target.git
   cd jibril-demo-target
   ```
2. **Run it** (Docker or directly) — see its README for full instructions.
3. **Trigger attack scenarios** — the demo app exposes endpoints that simulate credential access, crypto miner execution, dynamic linker attacks, and more.
4. **Jibril detects** the runtime behavior and forwards events to the correlation agent via the shell reaction in [`jibril/forward-to-agent.yaml`](jibril/forward-to-agent.yaml).
5. **Ask `@jibril`** in Copilot Chat to analyze, correlate, and create issues for the detected events.

This is the recommended way to see the full end-to-end flow without manually crafting event payloads.

## Project Structure

```
src/
  server.ts      — Express HTTP server, routes, alert wiring
  agent.ts       — Copilot Extension handler (intent routing, SSE responses)
  store.ts       — Storage abstraction (IEventStore, CosmosEventStore, InMemoryEventStore)
  cosmos.ts      — Azure Cosmos DB client and CRUD helpers
  events.ts      — Backward-compat re-exports from store.ts
  correlation.ts — Attack chain correlation engine (pattern matching, grouping)
  reasoning.ts   — LLM reasoning via prompt() (analysis, correlation, chain analysis)
  alerts.ts      — Auto-alert issue creation via GitHub App
  github.ts      — GitHub API (code search, commits, issue/PR creation, App auth)
  codeql.ts      — CodeQL / code scanning alert integration
  types.ts       — TypeScript interfaces for Jibril events and attack chains
infra/
  main.bicep         — Azure resource definitions (Cosmos DB, Container Apps, RBAC)
  parameters.json    — Deployment parameters template
jibril/
  config.yaml           — Jibril configuration for testing
  forward-to-agent.yaml — Private alchemy with shell reactions
test/
  GUIDE.md              — End-to-end walkthrough
  test-e2e.sh           — Automated end-to-end test (WSL + native Linux)
  test-real-attacks.sh  — Attack simulation triggers
  sample-events/        — Sample Jibril event JSON files
  send-events.sh        — Script to send sample events to the agent
.github/workflows/
  deploy.yml            — CI/CD: build, push to GHCR, deploy to Azure
  release.yml           — Release: build & push versioned image on GitHub release
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
- `x.y.z` — pinned semver release (e.g., `0.1.0`)
- `x.y` — minor release track (e.g., `0.1`)
- `x` — major release track (e.g., `0`)

### Build From Source

```bash
docker build -t jibril-correlation-agent .
docker run -p 3000:3000 \
  -e REPO_MAPPINGS="myorg/api=myorg/api-server" \
  jibril-correlation-agent
```

### Azure Deployment

The agent can be deployed to Azure Container Apps with Cosmos DB for persistent storage (~$0–10/month).

**Prerequisites**: Azure CLI, a resource group, and a GitHub App configured for the Copilot Extension.

```bash
# Login and create resource group
az login
az group create --name jibril-rg --location eastus

# Deploy all resources (Cosmos DB + Container Apps + RBAC)
az deployment group create \
  --resource-group jibril-rg \
  --template-file infra/main.bicep \
  --parameters infra/parameters.json \
  --parameters \
    githubAppId="<your-app-id>" \
    githubAppPrivateKey="$(cat path/to/private-key.pem)" \
    webhookSecret="<your-secret>" \
    alertRepo="owner/repo" \
    repoMappings="image1=owner/repo1"
```

**What gets deployed**:
- **Cosmos DB** (NoSQL, serverless, free tier, local auth disabled)
- **Container Apps** (consumption plan, scale-to-zero, system-assigned managed identity)
- **RBAC role assignment** (Cosmos DB Data Contributor for Container App)

Authentication uses managed identity via `DefaultAzureCredential` — no Cosmos keys needed.

**CI/CD**: Two GitHub Actions workflows are included:
- **[`deploy.yml`](.github/workflows/deploy.yml)** — On every push to `main`: builds the image, pushes to GHCR, and deploys to Azure Container Apps.
- **[`release.yml`](.github/workflows/release.yml)** — On GitHub release publish: builds and pushes semver-tagged images (`x.y.z`, `x.y`, `x`, `latest`) to GHCR.

To create a release: go to **Releases → Draft a new release**, create a semver tag (e.g., `v0.2.0`), and publish. The release workflow will automatically build and push the versioned image.

Configure these repository secrets:
- `AZURE_CLIENT_ID`, `AZURE_TENANT_ID`, `AZURE_SUBSCRIPTION_ID` (federated identity, for deploy)
- `GITHUB_APP_ID`, `GITHUB_APP_PRIVATE_KEY`, `WEBHOOK_SECRET`

**Storage modes**:
- **Cosmos DB** (set `COSMOS_ENDPOINT`): Events, chains, and correlation state persist across restarts. TTL auto-expires old data.
- **In-memory** (no `COSMOS_ENDPOINT`): Everything lives in memory — perfect for local dev. No Azure account needed.

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
