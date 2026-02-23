import { randomUUID } from "node:crypto";
import type {
  NormalizedEvent,
  AttackChainPattern,
  ChainStep,
  DetectedChain,
  CorrelationGroup,
} from "./types.js";

const DEFAULT_WINDOW_MS = 60 * 60 * 1000; // 1 hour
const CLEANUP_INTERVAL_MS = 10 * 60 * 1000; // 10 minutes
const DEFAULT_THRESHOLD = 0.6;
const ALERT_COOLDOWN_MS = 60 * 60 * 1000; // 1 hour per pattern+scope

/** Built-in attack chain patterns */
export const ATTACK_CHAIN_PATTERNS: AttackChainPattern[] = [
  {
    id: "credential-theft-privesc-persistence",
    name: "Credential Theft \u2192 Privilege Escalation \u2192 Persistence",
    description:
      "Attacker steals credentials, escalates privileges, and establishes persistence (e.g., modifying sudoers or shell configs).",
    steps: [
      { tactic: "credential_access" },
      { tactic: "privilege_escalation" },
      { tactic: "persistence" },
    ],
  },
  {
    id: "execution-c2-exfiltration",
    name: "Execution \u2192 C2 \u2192 Exfiltration",
    description:
      "Malicious binary executes, contacts a command-and-control server, and exfiltrates data.",
    steps: [
      { tactic: "execution" },
      { tactic: "command_and_control" },
      { tactic: "exfiltration" },
    ],
  },
  {
    id: "container-breakout",
    name: "Container Breakout",
    description:
      "Execution from unusual directory followed by credential access and privilege escalation \u2014 classic container escape pattern.",
    steps: [
      { tactic: "defense_evasion", kind: "exec_from_unusual_dir" },
      { tactic: "credential_access" },
      { tactic: "privilege_escalation", kind: "sudoers_modification" },
    ],
  },
  {
    id: "cryptojacking",
    name: "Cryptojacking",
    description:
      "Crypto miner is executed, connects to a mining pool or threat domain, consuming resources.",
    steps: [
      { tactic: "impact", kind: "crypto_miner_execution" },
      { tactic: "command_and_control" },
    ],
  },
  {
    id: "supply-chain-lateral",
    name: "Supply Chain + Lateral Movement",
    description:
      "Malicious code executes, evades defenses, steals credentials, and moves laterally.",
    steps: [
      { tactic: "execution" },
      { tactic: "defense_evasion" },
      { tactic: "credential_access" },
    ],
  },
  {
    id: "linker-hijack-persistence",
    name: "Dynamic Linker Hijack + Persistence",
    description:
      "Attacker hijacks the dynamic linker for persistence, evades defenses, then executes malicious code.",
    steps: [
      { tactic: "persistence", kind: "dynamic_linker_attacks" },
      { tactic: "defense_evasion" },
      { tactic: "execution" },
    ],
  },
];

export type AlertCallback = (chain: DetectedChain) => void;

export class CorrelationEngine {
  private groups = new Map<string, CorrelationGroup>();
  private detectedChains = new Map<string, DetectedChain>();
  private alertHistory = new Map<string, number>(); // pattern+scope \u2192 last alert timestamp
  private cleanupTimer: ReturnType<typeof setInterval>;
  private alertCallback?: AlertCallback;
  private patterns: AttackChainPattern[];
  private windowMs: number;
  private threshold: number;

  constructor(options?: {
    patterns?: AttackChainPattern[];
    windowMs?: number;
    threshold?: number;
    alertCallback?: AlertCallback;
  }) {
    this.patterns = options?.patterns ?? ATTACK_CHAIN_PATTERNS;
    this.windowMs = options?.windowMs ?? DEFAULT_WINDOW_MS;
    this.threshold = options?.threshold ?? DEFAULT_THRESHOLD;
    this.alertCallback = options?.alertCallback;
    this.cleanupTimer = setInterval(() => this.cleanup(), CLEANUP_INTERVAL_MS);
  }

  /** Process a newly ingested event */
  onEvent(event: NormalizedEvent): DetectedChain[] {
    const keys = this.getScopeKeys(event);
    const newChains: DetectedChain[] = [];

    for (const key of keys) {
      const group = this.getOrCreateGroup(key);
      group.events.push(event);
      group.lastUpdated = event.receivedAt;

      // Re-evaluate all patterns for this group
      const chains = this.evaluateGroup(group);
      for (const chain of chains) {
        const dedupeKey = `${chain.pattern.id}:${chain.scope}`;
        if (!this.detectedChains.has(dedupeKey)) {
          this.detectedChains.set(dedupeKey, chain);
          newChains.push(chain);
          this.maybeAlert(chain);
        }
      }
    }

    return newChains;
  }

  /** Get all detected chains */
  getChains(options?: {
    minConfidence?: number;
    pattern?: string;
    scope?: string;
  }): DetectedChain[] {
    let chains = Array.from(this.detectedChains.values());

    if (options?.minConfidence) {
      chains = chains.filter(c => c.confidence >= options.minConfidence!);
    }
    if (options?.pattern) {
      chains = chains.filter(c => c.pattern.id === options.pattern);
    }
    if (options?.scope) {
      chains = chains.filter(c => c.scope.includes(options.scope!));
    }

    chains.sort((a, b) => b.confidence - a.confidence);
    return chains;
  }

  /** Get a specific chain by ID */
  getChain(id: string): DetectedChain | undefined {
    for (const chain of this.detectedChains.values()) {
      if (chain.id === id) return chain;
    }
    return undefined;
  }

  /** Get correlation statistics */
  stats(): {
    totalChains: number;
    byPattern: Record<string, number>;
    activeGroups: number;
    lastDetection: number | null;
  } {
    const byPattern: Record<string, number> = {};
    let lastDetection: number | null = null;

    for (const chain of this.detectedChains.values()) {
      const name = chain.pattern.name;
      byPattern[name] = (byPattern[name] ?? 0) + 1;
      if (lastDetection === null || chain.lastSeen > lastDetection) {
        lastDetection = chain.lastSeen;
      }
    }

    return {
      totalChains: this.detectedChains.size,
      byPattern,
      activeGroups: this.groups.size,
      lastDetection,
    };
  }

  /** Set or update the alert callback */
  setAlertCallback(cb: AlertCallback): void {
    this.alertCallback = cb;
  }

  /** Evaluate a group against all attack chain patterns */
  private evaluateGroup(group: CorrelationGroup): DetectedChain[] {
    const detected: DetectedChain[] = [];

    for (const pattern of this.patterns) {
      const result = this.matchPattern(pattern, group);
      if (result && result.confidence >= this.threshold) {
        detected.push(result);
      }
    }

    return detected;
  }

  /** Greedy pattern matching: find events matching the ordered tactic sequence */
  private matchPattern(
    pattern: AttackChainPattern,
    group: CorrelationGroup,
  ): DetectedChain | null {
    // Sort events by time
    const sorted = [...group.events].sort((a, b) => a.receivedAt - b.receivedAt);

    const matched: NormalizedEvent[] = [];
    let searchFrom = 0;

    for (const step of pattern.steps) {
      let found = false;
      for (let i = searchFrom; i < sorted.length; i++) {
        if (this.eventMatchesStep(sorted[i], step)) {
          matched.push(sorted[i]);
          searchFrom = i + 1;
          found = true;
          break;
        }
      }
      if (!found) {
        // Step not matched \u2014 still compute partial score
        break;
      }
    }

    if (matched.length === 0) return null;

    // Score = (steps matched / total steps) \u00d7 average confidence of matched events
    const stepRatio = matched.length / pattern.steps.length;
    const avgConfidence =
      matched.reduce((sum, e) => sum + e.event.score.confidence, 0) / matched.length;
    const confidence = stepRatio * avgConfidence;

    return {
      id: randomUUID(),
      pattern,
      matchedEvents: matched,
      confidence,
      firstSeen: matched[0].receivedAt,
      lastSeen: matched[matched.length - 1].receivedAt,
      scope: group.key,
      status: "open",
    };
  }

  /** Check if an event matches a chain step */
  private eventMatchesStep(event: NormalizedEvent, step: ChainStep): boolean {
    const tactic = event.event.metadata.tactic?.toLowerCase() ?? "";
    if (tactic !== step.tactic.toLowerCase()) return false;

    if (step.kind) {
      const kind = event.event.metadata.kind?.toLowerCase() ?? "";
      if (kind !== step.kind.toLowerCase()) return false;
    }

    if (step.technique) {
      const technique = event.event.metadata.technique?.toLowerCase() ?? "";
      if (technique !== step.technique.toLowerCase()) return false;
    }

    return true;
  }

  /** Get scope keys for grouping \u2014 container_id, container_name, or fallback */
  private getScopeKeys(event: NormalizedEvent): string[] {
    const keys: string[] = [];
    const container = event.event.container;

    if (container?.container_id) {
      keys.push(`container:${container.container_id}`);
    }
    if (container?.container_name) {
      keys.push(`container:${container.container_name}`);
    }

    // Fallback: use ancestry root PID or "host"
    if (keys.length === 0) {
      const ancestry = event.event.base?.background?.ancestry;
      if (ancestry?.length) {
        keys.push(`ancestry:${ancestry[ancestry.length - 1].pid}`);
      } else {
        keys.push("host:default");
      }
    }

    return keys;
  }

  /** Get or create a correlation group */
  private getOrCreateGroup(key: string): CorrelationGroup {
    let group = this.groups.get(key);
    if (!group) {
      group = { key, events: [], chains: [], lastUpdated: Date.now() };
      this.groups.set(key, group);
    }
    return group;
  }

  /** Maybe fire an alert for a detected chain */
  private maybeAlert(chain: DetectedChain): void {
    if (!this.alertCallback) return;

    // Only alert for high-confidence chains with at least one critical event
    const hasCritical = chain.matchedEvents.some(
      e => e.event.score.severity_level === "critical",
    );
    if (chain.confidence < 0.8 || !hasCritical) return;

    // Throttle: max 1 alert per pattern+scope per hour
    const throttleKey = `${chain.pattern.id}:${chain.scope}`;
    const lastAlert = this.alertHistory.get(throttleKey);
    if (lastAlert && Date.now() - lastAlert < ALERT_COOLDOWN_MS) return;

    this.alertHistory.set(throttleKey, Date.now());
    chain.status = "escalated";
    this.alertCallback(chain);
  }

  /** Clean up old groups outside the time window */
  private cleanup(): void {
    const cutoff = Date.now() - this.windowMs;
    for (const [key, group] of this.groups) {
      if (group.lastUpdated < cutoff) {
        this.groups.delete(key);
      }
    }
    // Clean old alert history
    for (const [key, ts] of this.alertHistory) {
      if (Date.now() - ts > ALERT_COOLDOWN_MS * 2) {
        this.alertHistory.delete(key);
      }
    }
  }

  destroy(): void {
    clearInterval(this.cleanupTimer);
  }
}
