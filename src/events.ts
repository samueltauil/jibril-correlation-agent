import type { JibrilEvent, NormalizedEvent, EventType, RepoMapping, DetectedChain } from "./types.js";
import { CorrelationEngine, type AlertCallback } from "./correlation.js";

const DEFAULT_TTL_MS = 24 * 60 * 60 * 1000; // 24 hours
const CLEANUP_INTERVAL_MS = 5 * 60 * 1000;  // 5 minutes

export class EventStore {
  private events = new Map<string, NormalizedEvent>();
  private cleanupTimer: ReturnType<typeof setInterval>;
  readonly correlationEngine: CorrelationEngine;

  constructor(private ttlMs: number = DEFAULT_TTL_MS, alertCallback?: AlertCallback) {
    this.correlationEngine = new CorrelationEngine({ alertCallback });
    this.cleanupTimer = setInterval(() => this.cleanup(), CLEANUP_INTERVAL_MS);
  }

  /** Ingest a raw Jibril event, normalize it, and store */
  ingest(raw: JibrilEvent, source: "reaction" | "varlog", repoMappings: RepoMapping[]): NormalizedEvent {
    // Deduplicate by uuid
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

    // Feed into correlation engine for chain detection
    const newChains = this.correlationEngine.onEvent(normalized);
    if (newChains.length > 0) {
      console.log(`[correlation] ${newChains.length} new chain(s) detected:`,
        newChains.map(c => `${c.pattern.name} (confidence: ${c.confidence.toFixed(2)})`).join(", "));
    }

    return normalized;
  }

  /** Get a single event by ID */
  get(id: string): NormalizedEvent | undefined {
    return this.events.get(id);
  }

  /** List recent events, optionally filtered */
  list(options?: {
    limit?: number;
    severity?: string;
    eventType?: EventType;
    repo?: string;
  }): NormalizedEvent[] {
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

    // Most recent first
    results.sort((a, b) => b.receivedAt - a.receivedAt);

    const limit = options?.limit ?? 50;
    return results.slice(0, limit);
  }

  /** Get detected attack chains */
  getChains(options?: { minConfidence?: number; pattern?: string; scope?: string }): DetectedChain[] {
    return this.correlationEngine.getChains(options);
  }

  /** Get a specific chain by ID */
  getChain(id: string): DetectedChain | undefined {
    return this.correlationEngine.getChain(id);
  }

  /** Get correlation statistics */
  correlationStats() {
    return this.correlationEngine.stats();
  }

  /** Get summary stats */
  stats(): { total: number; bySeverity: Record<string, number>; byType: Record<string, number> } {
    const bySeverity: Record<string, number> = {};
    const byType: Record<string, number> = {};

    for (const event of this.events.values()) {
      const sev = event.event.score.severity_level;
      bySeverity[sev] = (bySeverity[sev] ?? 0) + 1;
      byType[event.eventType] = (byType[event.eventType] ?? 0) + 1;
    }

    return { total: this.events.size, bySeverity, byType };
  }

  /** Remove expired events */
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

/** Classify event type from Jibril metadata */
function classifyEvent(event: JibrilEvent): EventType {
  const format = event.metadata?.format?.toLowerCase() ?? "";
  const kind = event.metadata?.kind?.toLowerCase() ?? "";

  if (format.includes("file") || kind.includes("file")) return "file_access";
  if (format.includes("exec") || kind.includes("exec")) return "execution";
  if (format.includes("network") || format.includes("flow") || kind.includes("domain") || kind.includes("peer")) return "network_peers";
  if (format.includes("env") || kind.includes("env") || kind.includes("linker")) return "env_vars";

  // Fallback: check which data fields are present
  if (event.file) return "file_access";
  if (event.exec) return "execution";
  if (event.network) return "network_peers";

  return "unknown";
}

/** Resolve GitHub repo from container image using configured mappings */
function resolveRepo(event: JibrilEvent, mappings: RepoMapping[]): string | undefined {
  const image = event.container?.image;
  if (!image) return undefined;

  for (const mapping of mappings) {
    if (image.includes(mapping.image)) {
      return mapping.repo;
    }
  }

  return undefined;
}
