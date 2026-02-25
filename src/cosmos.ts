import { CosmosClient, type Container, type Database } from "@azure/cosmos";
import { DefaultAzureCredential } from "@azure/identity";
import type { NormalizedEvent, DetectedChain, CorrelationGroup } from "./types.js";

// Cosmos DB document types with discriminator
interface EventDocument {
  id: string;
  type: "event";
  eventType: string;
  receivedAt: number;
  source: "reaction" | "varlog";
  event: NormalizedEvent["event"];
  repo?: string;
  ttl: number;
}

interface GroupDocument {
  id: string;            // groupKey
  type: "group";
  key: string;
  eventIds: string[];
  lastUpdated: number;
  ttl: number;
}

interface AlertHistoryDocument {
  id: string;            // throttleKey
  type: "alert";
  key: string;
  lastAlerted: number;
  ttl: number;
}

interface ChainDocument {
  id: string;            // dedupeKey (patternId:scope)
  type: "chain";
  scope: string;
  chain: DetectedChain;
}

const EVENT_TTL = 86400;       // 24 hours
const GROUP_TTL = 3600;        // 1 hour
const ALERT_HISTORY_TTL = 7200; // 2 hours

export class CosmosStore {
  private db!: Database;
  private eventsContainer!: Container;
  private chainsContainer!: Container;
  private correlationContainer!: Container;

  private constructor() {}

  static async create(endpoint: string, databaseName: string): Promise<CosmosStore> {
    const store = new CosmosStore();
    const credential = new DefaultAzureCredential();
    const client = new CosmosClient({ endpoint, aadCredentials: credential });

    // Create database if not exists
    const { database } = await client.databases.createIfNotExists({ id: databaseName });
    store.db = database;

    // Create containers with partition keys and TTL
    const { container: events } = await database.containers.createIfNotExists({
      id: "events",
      partitionKey: { paths: ["/eventType"] },
      defaultTtl: EVENT_TTL,
    });
    store.eventsContainer = events;

    const { container: chains } = await database.containers.createIfNotExists({
      id: "chains",
      partitionKey: { paths: ["/scope"] },
      defaultTtl: -1, // no default TTL — chains persist
    });
    store.chainsContainer = chains;

    const { container: correlation } = await database.containers.createIfNotExists({
      id: "correlation",
      partitionKey: { paths: ["/key"] },
      defaultTtl: GROUP_TTL,
    });
    store.correlationContainer = correlation;

    console.log(`[cosmos] Connected to ${endpoint}, database: ${databaseName}`);
    return store;
  }

  // --- Events ---

  async upsertEvent(event: NormalizedEvent): Promise<void> {
    const doc: EventDocument = {
      id: event.id,
      type: "event",
      eventType: event.eventType,
      receivedAt: event.receivedAt,
      source: event.source,
      event: event.event,
      repo: event.repo,
      ttl: EVENT_TTL,
    };
    await this.eventsContainer.items.upsert(doc);
  }

  async getEvent(id: string): Promise<NormalizedEvent | undefined> {
    // Query across partitions since we don't know eventType
    const { resources } = await this.eventsContainer.items
      .query<EventDocument>({
        query: "SELECT * FROM c WHERE c.id = @id AND c.type = 'event'",
        parameters: [{ name: "@id", value: id }],
      })
      .fetchAll();

    if (resources.length === 0) return undefined;
    return this.docToEvent(resources[0]);
  }

  async queryEvents(options?: {
    limit?: number;
    severity?: string;
    eventType?: string;
    repo?: string;
  }): Promise<NormalizedEvent[]> {
    const conditions = ["c.type = 'event'"];
    const params: { name: string; value: string | number }[] = [];

    if (options?.severity) {
      conditions.push("c.event.score.severity_level = @severity");
      params.push({ name: "@severity", value: options.severity });
    }
    if (options?.eventType) {
      conditions.push("c.eventType = @eventType");
      params.push({ name: "@eventType", value: options.eventType });
    }
    if (options?.repo) {
      conditions.push("c.repo = @repo");
      params.push({ name: "@repo", value: options.repo });
    }

    const limit = options?.limit ?? 50;
    const query = `SELECT TOP ${limit} * FROM c WHERE ${conditions.join(" AND ")} ORDER BY c.receivedAt DESC`;

    const { resources } = await this.eventsContainer.items
      .query<EventDocument>({ query, parameters: params })
      .fetchAll();

    return resources.map(d => this.docToEvent(d));
  }

  async countEvents(): Promise<number> {
    const { resources } = await this.eventsContainer.items
      .query<number>({ query: "SELECT VALUE COUNT(1) FROM c WHERE c.type = 'event'" })
      .fetchAll();
    return resources[0] ?? 0;
  }

  async eventStats(): Promise<{
    total: number;
    bySeverity: Record<string, number>;
    byType: Record<string, number>;
  }> {
    // Get totals by severity
    const { resources: sevRows } = await this.eventsContainer.items
      .query<{ level: string; count: number }>({
        query: "SELECT c.event.score.severity_level AS level, COUNT(1) AS count FROM c WHERE c.type = 'event' GROUP BY c.event.score.severity_level",
      })
      .fetchAll();

    // Get totals by type
    const { resources: typeRows } = await this.eventsContainer.items
      .query<{ eventType: string; count: number }>({
        query: "SELECT c.eventType, COUNT(1) AS count FROM c WHERE c.type = 'event' GROUP BY c.eventType",
      })
      .fetchAll();

    const bySeverity: Record<string, number> = {};
    const byType: Record<string, number> = {};
    let total = 0;

    for (const row of sevRows) {
      bySeverity[row.level] = row.count;
      total += row.count;
    }
    for (const row of typeRows) {
      byType[row.eventType] = row.count;
    }

    return { total, bySeverity, byType };
  }

  // --- Correlation Groups ---

  async upsertGroup(group: CorrelationGroup): Promise<void> {
    const doc: GroupDocument = {
      id: group.key,
      type: "group",
      key: group.key,
      eventIds: group.events.map(e => e.id),
      lastUpdated: group.lastUpdated,
      ttl: GROUP_TTL,
    };
    await this.correlationContainer.items.upsert(doc);
  }

  async getGroup(key: string): Promise<{ eventIds: string[]; lastUpdated: number } | undefined> {
    try {
      const { resource } = await this.correlationContainer.item(key, key).read<GroupDocument>();
      if (!resource || resource.type !== "group") return undefined;
      return { eventIds: resource.eventIds, lastUpdated: resource.lastUpdated };
    } catch {
      return undefined;
    }
  }

  async getGroupCount(): Promise<number> {
    const { resources } = await this.eventsContainer.items
      .query<number>({ query: "SELECT VALUE COUNT(1) FROM c WHERE c.type = 'group'" })
      .fetchAll();
    return resources[0] ?? 0;
  }

  // --- Alert History ---

  async getAlertTimestamp(throttleKey: string): Promise<number | undefined> {
    try {
      const { resource } = await this.correlationContainer
        .item(throttleKey, "alert-history")
        .read<AlertHistoryDocument>();
      if (!resource || resource.type !== "alert") return undefined;
      return resource.lastAlerted;
    } catch {
      return undefined;
    }
  }

  async setAlertTimestamp(throttleKey: string, timestamp: number): Promise<void> {
    const doc: AlertHistoryDocument = {
      id: throttleKey,
      type: "alert",
      key: "alert-history",
      lastAlerted: timestamp,
      ttl: ALERT_HISTORY_TTL,
    };
    await this.correlationContainer.items.upsert(doc);
  }

  // --- Chains ---

  async upsertChain(dedupeKey: string, chain: DetectedChain): Promise<void> {
    const doc: ChainDocument = {
      id: dedupeKey,
      type: "chain",
      scope: chain.scope,
      chain,
    };
    await this.chainsContainer.items.upsert(doc);
  }

  async getChain(id: string): Promise<DetectedChain | undefined> {
    // Search by chain.id (the UUID), not the document id (dedupeKey)
    const { resources } = await this.chainsContainer.items
      .query<ChainDocument>({
        query: "SELECT * FROM c WHERE c.chain.id = @id AND c.type = 'chain'",
        parameters: [{ name: "@id", value: id }],
      })
      .fetchAll();

    return resources.length > 0 ? resources[0].chain : undefined;
  }

  async queryChains(options?: {
    minConfidence?: number;
    pattern?: string;
    scope?: string;
  }): Promise<DetectedChain[]> {
    const conditions = ["c.type = 'chain'"];
    const params: { name: string; value: string | number }[] = [];

    if (options?.minConfidence) {
      conditions.push("c.chain.confidence >= @minConfidence");
      params.push({ name: "@minConfidence", value: options.minConfidence });
    }
    if (options?.pattern) {
      conditions.push("c.chain.pattern.id = @pattern");
      params.push({ name: "@pattern", value: options.pattern });
    }
    if (options?.scope) {
      conditions.push("CONTAINS(c.scope, @scope)");
      params.push({ name: "@scope", value: options.scope });
    }

    const query = `SELECT * FROM c WHERE ${conditions.join(" AND ")} ORDER BY c.chain.confidence DESC`;

    const { resources } = await this.chainsContainer.items
      .query<ChainDocument>({ query, parameters: params })
      .fetchAll();

    return resources.map(d => d.chain);
  }

  async chainStats(): Promise<{
    totalChains: number;
    byPattern: Record<string, number>;
    activeGroups: number;
    lastDetection: number | null;
  }> {
    const chains = await this.queryChains();
    const activeGroups = await this.getGroupCount();

    const byPattern: Record<string, number> = {};
    let lastDetection: number | null = null;

    for (const chain of chains) {
      const name = chain.pattern.name;
      byPattern[name] = (byPattern[name] ?? 0) + 1;
      if (lastDetection === null || chain.lastSeen > lastDetection) {
        lastDetection = chain.lastSeen;
      }
    }

    return { totalChains: chains.length, byPattern, activeGroups, lastDetection };
  }

  // --- Helpers ---

  private docToEvent(doc: EventDocument): NormalizedEvent {
    return {
      id: doc.id,
      receivedAt: doc.receivedAt,
      source: doc.source,
      event: doc.event,
      eventType: doc.eventType as NormalizedEvent["eventType"],
      repo: doc.repo,
    };
  }
}
