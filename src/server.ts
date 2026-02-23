import express from "express";
import { EventStore } from "./events.js";
import { handleAgentRequest } from "./agent.js";
import type { JibrilEvent, AgentConfig, RepoMapping } from "./types.js";

const config: AgentConfig = {
  port: parseInt(process.env.PORT ?? "3000", 10),
  webhookSecret: process.env.WEBHOOK_SECRET,
  repoMappings: parseRepoMappings(process.env.REPO_MAPPINGS),
};

const eventStore = new EventStore();
const app = express();

// Health check
app.get("/health", (_req, res) => {
  const stats = eventStore.stats();
  res.json({ status: "ok", events: stats });
});

// Event ingestion from Jibril reactions
app.post("/events", express.json({ limit: "1mb" }), (req, res) => {
  // Optional: verify webhook secret
  if (config.webhookSecret) {
    const providedSecret = req.headers["x-webhook-secret"];
    if (providedSecret !== config.webhookSecret) {
      res.status(401).json({ error: "Invalid webhook secret" });
      return;
    }
  }

  const body = req.body as JibrilEvent;

  if (!body.uuid || !body.metadata) {
    res.status(400).json({ error: "Invalid event: missing uuid or metadata" });
    return;
  }

  const normalized = eventStore.ingest(body, "reaction", config.repoMappings);
  console.log(`[event] Ingested ${normalized.id} | ${normalized.event.metadata.name} | ${normalized.event.score.severity_level}`);

  res.status(201).json({ id: normalized.id, status: "ingested" });
});

// Copilot Extension agent endpoint
app.post("/agent", (req, res) => {
  handleAgentRequest(req, res, { eventStore, repoMappings: config.repoMappings });
});

// Start server
app.listen(config.port, () => {
  console.log(`Jibril Correlation Agent listening on port ${config.port}`);
  console.log(`  POST /events  — Jibril event ingestion`);
  console.log(`  POST /agent   — Copilot Extension endpoint`);
  console.log(`  GET  /health  — Health check`);
  if (config.repoMappings.length > 0) {
    console.log(`  Repo mappings: ${config.repoMappings.map(m => `${m.image} → ${m.repo}`).join(", ")}`);
  }
});

/** Parse REPO_MAPPINGS env var: "image1=owner/repo1,image2=owner/repo2" */
function parseRepoMappings(envValue?: string): RepoMapping[] {
  if (!envValue) return [];
  return envValue.split(",").map(pair => {
    const [image, repo] = pair.trim().split("=");
    return { image: image.trim(), repo: repo.trim() };
  }).filter(m => m.image && m.repo);
}

// Graceful shutdown
process.on("SIGTERM", () => {
  console.log("Shutting down...");
  eventStore.destroy();
  process.exit(0);
});
