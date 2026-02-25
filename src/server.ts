import express from "express";
import { createStore, type IEventStore } from "./store.js";
import { handleAgentRequest } from "./agent.js";
import { handleChainAlert } from "./alerts.js";
import type { JibrilEvent, AgentConfig, RepoMapping } from "./types.js";

interface ExtendedConfig extends AgentConfig {
  cosmosEndpoint?: string;
  cosmosDatabase?: string;
}

const config: ExtendedConfig = {
  port: parseInt(process.env.PORT ?? "3000", 10),
  webhookSecret: process.env.WEBHOOK_SECRET,
  repoMappings: parseRepoMappings(process.env.REPO_MAPPINGS),
  alertRepo: process.env.ALERT_REPO,
  githubAppId: process.env.GITHUB_APP_ID,
  githubAppPrivateKey: process.env.GITHUB_APP_PRIVATE_KEY,
  cosmosEndpoint: process.env.COSMOS_ENDPOINT,
  cosmosDatabase: process.env.COSMOS_DATABASE,
};

// Set up alert callback if configured
const alertEnabled = config.alertRepo && config.githubAppId && config.githubAppPrivateKey;
const alertCallback = alertEnabled
  ? (chain: import("./types.js").DetectedChain) => {
      handleChainAlert(chain, {
        alertRepo: config.alertRepo!,
        appId: config.githubAppId!,
        privateKey: config.githubAppPrivateKey!,
      });
    }
  : undefined;

async function main() {
  const eventStore = await createStore({
    cosmosEndpoint: config.cosmosEndpoint,
    cosmosDatabase: config.cosmosDatabase,
    alertCallback,
  });

  const app = express();

  // Health check
  app.get("/health", async (_req, res) => {
    try {
      const stats = await eventStore.stats();
      const chainStats = await eventStore.correlationStats();
      res.json({ status: "ok", events: stats, chains: chainStats });
    } catch (err) {
      console.error("[health] Error:", err);
      res.status(500).json({ error: "Internal server error" });
    }
  });

  // Event ingestion from Jibril reactions
  app.post("/events", express.json({ limit: "1mb" }), async (req, res) => {
    try {
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

      const normalized = await eventStore.ingest(body, "reaction", config.repoMappings);
      console.log(`[event] Ingested ${normalized.id} | ${normalized.event.metadata.name} | ${normalized.event.score.severity_level}`);

      res.status(201).json({ id: normalized.id, status: "ingested" });
    } catch (err) {
      console.error("[events] Error:", err);
      res.status(500).json({ error: "Internal server error" });
    }
  });

  // Copilot Extension agent endpoint
  app.post("/agent", (req, res) => {
    handleAgentRequest(req, res, { eventStore, repoMappings: config.repoMappings });
  });

  // Detected chains endpoint
  app.get("/chains", async (req, res) => {
    try {
      const minConfidence = req.query.confidence ? parseFloat(req.query.confidence as string) : undefined;
      const pattern = req.query.pattern as string | undefined;
      const scope = req.query.scope as string | undefined;
      const chains = await eventStore.getChains({ minConfidence, pattern, scope });
      res.json({ chains, total: chains.length });
    } catch (err) {
      console.error("[chains] Error:", err);
      res.status(500).json({ error: "Internal server error" });
    }
  });

  // Start server
  app.listen(config.port, () => {
    console.log(`Jibril Correlation Agent listening on port ${config.port}`);
    console.log(`  POST /events  \u2014 Jibril event ingestion`);
    console.log(`  POST /agent   \u2014 Copilot Extension endpoint`);
    console.log(`  GET  /health  \u2014 Health check`);
    console.log(`  GET  /chains  \u2014 Detected attack chains`);
    if (alertEnabled) {
      console.log(`  Auto-alerts:   Creating issues in ${config.alertRepo}`);
    }
    if (config.repoMappings.length > 0) {
      console.log(`  Repo mappings: ${config.repoMappings.map(m => `${m.image} \u2192 ${m.repo}`).join(", ")}`);
    }
    if (config.cosmosEndpoint) {
      console.log(`  Storage:       Cosmos DB (${config.cosmosDatabase ?? "jibril"})`);
    } else {
      console.log(`  Storage:       In-memory`);
    }
  });

  // Graceful shutdown
  process.on("SIGTERM", () => {
    console.log("Shutting down...");
    eventStore.destroy();
    process.exit(0);
  });
}

main().catch(err => {
  console.error("Failed to start agent:", err);
  process.exit(1);
});

/** Parse REPO_MAPPINGS env var: "image1=owner/repo1,image2=owner/repo2" */
function parseRepoMappings(envValue?: string): RepoMapping[] {
  if (!envValue) return [];
  return envValue.split(",").map(pair => {
    const [image, repo] = pair.trim().split("=");
    return { image: image.trim(), repo: repo.trim() };
  }).filter(m => m.image && m.repo);
}
