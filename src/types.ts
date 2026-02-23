// Jibril eBPF event types based on Jibril v2.10.1 documentation

export interface JibrilEventMetadata {
  kind: string;
  name: string;
  format: string;
  version: string;
  description: string;
  tactic: string;
  technique: string;
  subtechnique?: string;
  importance: string;
}

export interface JibrilEventScore {
  source: string;
  severity: number;       // 0-100
  severity_level: string; // low | medium | high | critical
  confidence: number;     // 0.0-1.0
  risk_score: number;     // severity * confidence
}

export interface JibrilProcessInfo {
  pid: number;
  ppid?: number;
  uid?: number;
  gid?: number;
  cmd: string;
  cmdline?: string;
  comm?: string;
  cwd?: string;
}

export interface JibrilAncestry {
  pid: number;
  cmd: string;
  cmdline?: string;
}

export interface JibrilBase {
  background: {
    ancestry: JibrilAncestry[];
    flows: Record<string, unknown>;
  };
}

export interface JibrilFileData {
  file: string;
  actions: string[];
  basename: string;
}

export interface JibrilExecData {
  cmd: string;
  cmdline: string;
  args?: string[];
  env?: Record<string, string>;
}

export interface JibrilNetworkData {
  destination_ip?: string;
  destination_port?: number;
  source_ip?: string;
  source_port?: number;
  protocol?: string;
  domain?: string;
}

export interface JibrilContainerInfo {
  container_id?: string;
  container_name?: string;
  image?: string;
  image_tag?: string;
}

/** Raw event as received from Jibril via reaction or varlog */
export interface JibrilEvent {
  uuid: string;
  timestamp: string;
  metadata: JibrilEventMetadata;
  score: JibrilEventScore;
  base: JibrilBase;
  file?: JibrilFileData;
  exec?: JibrilExecData;
  network?: JibrilNetworkData;
  container?: JibrilContainerInfo;
  [key: string]: unknown;
}

/** Normalized internal event with added agent metadata */
export interface NormalizedEvent {
  id: string;              // uuid from Jibril
  receivedAt: number;      // timestamp when agent received it
  source: "reaction" | "varlog";
  event: JibrilEvent;
  // Agent-computed fields
  eventType: EventType;
  repo?: string;           // mapped GitHub repo (owner/name)
}

export type EventType = "file_access" | "execution" | "network_peers" | "env_vars" | "unknown";

/** Mapping from container image to GitHub repository */
export interface RepoMapping {
  image: string;           // container image pattern (e.g., "myorg/api-server")
  repo: string;            // GitHub repo (e.g., "myorg/api-server")
}

/** Agent configuration */
export interface AgentConfig {
  port: number;
  webhookSecret?: string;
  repoMappings: RepoMapping[];
}
