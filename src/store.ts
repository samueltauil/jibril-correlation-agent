import type { JibrilEvent, NormalizedEvent, EventType, RepoMapping, DetectedChain } from "./types.js";
import type { CosmosStore } from "./cosmos.js";
import { CorrelationEngine, type AlertCallback } from "./correlation.js";

/** Async storage interface for events and correlation state */
export interface IEventStore {
  ingest(raw: JibrilEvent, source: "reaction" | "varlog", repoMappings: RepoMapping[]): Promise<NormalizedEvent>;
  get(id: string): Promise<NormalizedEvent | undefined>;
  list(options?: { limit?: number; severity?: string; eventType?: EventType; repo?: string }): Promise<NormalizedEvent[]>;
  stats(): Promise<{ total: number; bySeverity: Record<string, number>; byType: Record<string, number> }>;
  getChains(options?: { minConfidence?: number; pattern?: string; scope?: string }): Promise<DetectedChain[]>;
  getChain(id: string): Promise<DetectedChain | undefined>;
  correlationStats(): Promise<{ totalChains: number; byPattern: Record<string, number>; activeGroups: number; lastDetection: number | null }>;
  destroy(): void;
}

// ---------------------------------------------------------------------------
// Cosmos-backed store
// ---------------------------------------------------------------------------

export class CosmosEventStore implements IEventStore {
  private correlationEngine: CorrelationEngine;

  constructor(
    private cosmos: CosmosStore,
    alertCallback?: AlertCallback,
  ) {
    this.correlationEngine = new CorrelationEngine({
      alertCallback,
      cosmos,
    });
  }

  async ingest(raw: JibrilEvent, source: "reaction" | "varlog", repoMappings: RepoMapping[]): Promise<NormalizedEvent> {
    // Deduplicate
    const existing = await this.cosmos.getEvent(raw.uuid);
    if (existing) return existing;

    const normalized: NormalizedEvent = {
      id: raw.uuid,
      receivedAt: Date.now(),
      source,
      event: raw,
      eventType: classifyEvent(raw),
      repo: resolveRepo(raw, repoMappings),
    };

    // Persist event
    await this.cosmos.upsertEvent(normalized);

    // Correlation (async)
    const newChains = await this.correlationEngine.onEvent(normalized);
    if (newChains.length > 0) {
      console.log(`[correlation] ${newChains.length} new chain(s) detected:`,
        newChains.map(c => `${c.pattern.name} (confidence: ${c.confidence.toFixed(2)})`).join(", "));
    }

    return normalized;
  }

  async get(id: string): Promise<NormalizedEvent | undefined> {
    return this.cosmos.getEvent(id);
  }

  async list(options?: { limit?: number; severity?: string; eventType?: EventType; repo?: string }): Promise<NormalizedEvent[]> {
    return this.cosmos.queryEvents(options);
  }

  async stats() {
    return this.cosmos.eventStats();
  }

  async getChains(options?: { minConfidence?: number; pattern?: string; scope?: string }) {
    return this.cosmos.queryChains(options);
  }

  async getChain(id: string) {
    return this.cosmos.getChain(id);
  }

  async correlationStats() {
    return this.cosmos.chainStats();
  }

  destroy(): void {
    this.correlationEngine.destroy();
  }
}

// ---------------------------------------------------------------------------
// In-memory store (backward compatible, no Azure needed)
// ---------------------------------------------------------------------------

const DEFAULT_TTL_MS = 24 * 60 * 60 * 1000;
const CLEANUP_INTERVAL_MS = 5 * 60 * 1000;

export class InMemoryEventStore implements IEventStore {
  private events = new Map<string, NormalizedEvent>();
  private cleanupTimer: ReturnType<typeof setInterval>;
  readonly correlationEngine: CorrelationEngine;

  constructor(private ttlMs: number = DEFAULT_TTL_MS, alertCallback?: AlertCallback) {
    this.correlationEngine = new CorrelationEngine({ alertCallback });
    this.cleanupTimer = setInterval(() => this.cleanup(), CLEANUP_INTERVAL_MS);
  }

  async ingest(raw: JibrilEvent, source: "reaction" | "varlog", repoMappings: RepoMapping[]): Promise<NormalizedEvent> {
    const existing = this.events.get(raw.uuid);
    if (existing) return existing;

    const normalized: NormalizedEvent = {
      id: raw.uuid,
      receivedAt: Date.now(),
      source,
      event: raw,
      eventType: classifyEvent(raw),
      repo: resolveRepo(raw, repoMappings),
    };

    this.events.set(normalized.id, normalized);

    const newChains = await this.correlationEngine.onEvent(normalized);
    if (newChains.length > 0) {
      console.log(`[correlation] ${newChains.length} new chain(s) detected:`,
        newChains.map(c => `${c.pattern.name} (confidence: ${c.confidence.toFixed(2)})`).join(", "));
    }

    return normalized;
  }

  async get(id: string): Promise<NormalizedEvent | undefined> {
    return this.events.get(id);
  }

  async list(options?: { limit?: number; severity?: string; eventType?: EventType; repo?: string }): Promise<NormalizedEvent[]> {
    let results = Array.from(this.events.values());

    if (options?.severity) {
      results = results.filter(e => e.event.score.severity_level === options.severity);
    }
    if (options?.eventType) {
      results = results.filter(e => e.eventType === options.eventType);
    }
    if (options?.repo) {
      results = results.filter(e => e.repo === options.repo);
    }

    results.sort((a, b) => b.receivedAt - a.receivedAt);
    const limit = options?.limit ?? 50;
    return results.slice(0, limit);
  }

  async stats() {
    const bySeverity: Record<string, number> = {};
    const byType: Record<string, number> = {};

    for (const event of this.events.values()) {
      const sev = event.event.score.severity_level;
      bySeverity[sev] = (bySeverity[sev] ?? 0) + 1;
      byType[event.eventType] = (byType[event.eventType] ?? 0) + 1;
    }

    return { total: this.events.size, bySeverity, byType };
  }

  async getChains(options?: { minConfidence?: number; pattern?: string; scope?: string }) {
    return this.correlationEngine.getChains(options);
  }

  async getChain(id: string) {
    return this.correlationEngine.getChain(id);
  }

  async correlationStats() {
    return this.correlationEngine.stats();
  }

  private cleanup(): void {
    const cutoff = Date.now() - this.ttlMs;
    for (const [id, event] of this.events) {
      if (event.receivedAt < cutoff) {
        this.events.delete(id);
      }
    }
  }

  destroy(): void {
    clearInterval(this.cleanupTimer);
    this.correlationEngine.destroy();
  }
}

// ---------------------------------------------------------------------------
// Factory
// ---------------------------------------------------------------------------

export async function createStore(options: {
  cosmosEndpoint?: string;
  cosmosDatabase?: string;
  alertCallback?: AlertCallback;
}): Promise<IEventStore> {
  if (options.cosmosEndpoint) {
    const { CosmosStore } = await import("./cosmos.js");
    const cosmos = await CosmosStore.create(
      options.cosmosEndpoint,
      options.cosmosDatabase ?? "jibril",
    );
    console.log("[store] Using Cosmos DB persistence");
    return new CosmosEventStore(cosmos, options.alertCallback);
  }

  console.log("[store] Using in-memory storage (no COSMOS_ENDPOINT set)");
  return new InMemoryEventStore(undefined, options.alertCallback);
}

// ---------------------------------------------------------------------------
// Shared helpers (moved from events.ts)
// ---------------------------------------------------------------------------

/** Classify event type from Jibril metadata */
export function classifyEvent(event: JibrilEvent): EventType {
  const format = event.metadata?.format?.toLowerCase() ?? "";
  const kind = event.metadata?.kind?.toLowerCase() ?? "";

  if (format.includes("file") || kind.includes("file")) return "file_access";
  if (format.includes("exec") || kind.includes("exec")) return "execution";
  if (format.includes("network") || format.includes("flow") || kind.includes("domain") || kind.includes("peer")) return "network_peers";
  if (format.includes("env") || kind.includes("env") || kind.includes("linker")) return "env_vars";

  if (event.file) return "file_access";
  if (event.exec) return "execution";
  if (event.network) return "network_peers";

  return "unknown";
}

/** Resolve GitHub repo from container image using configured mappings */
export function resolveRepo(event: JibrilEvent, mappings: RepoMapping[]): string | undefined {
  const image = event.container?.image;
  if (!image) return undefined;

  for (const mapping of mappings) {
    if (image.includes(mapping.image)) {
      return mapping.repo;
    }
  }

  return undefined;
}
