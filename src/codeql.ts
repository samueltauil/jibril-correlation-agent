import { Octokit } from "@octokit/rest";
import type { NormalizedEvent } from "./types.js";

export interface CodeQLAlert {
  number: number;
  state: string;
  rule: {
    id: string;
    severity: string;
    securitySeverityLevel?: string;
    description: string;
    name: string;
    tags: string[];
    help?: string;
  };
  tool: {
    name: string;
    version: string | null;
  };
  htmlUrl: string;
  createdAt: string;
  location: {
    path: string;
    startLine: number;
    endLine: number;
  } | null;
  message: string;
  cwes: string[];
}

export interface CodeQLCorrelation {
  alert: CodeQLAlert;
  matchReason: string;
}

/** Fetch open CodeQL / code scanning alerts for a repo */
export async function getCodeScanningAlerts(
  token: string,
  repo: string,
  options?: { severity?: string; state?: string; toolName?: string },
): Promise<CodeQLAlert[]> {
  const octokit = new Octokit({ auth: token });
  const [owner, repoName] = repo.split("/");

  const params: Record<string, unknown> = {
    owner,
    repo: repoName,
    per_page: 100,
    state: options?.state ?? "open",
  };
  if (options?.severity) params.severity = options.severity;
  if (options?.toolName) params.tool_name = options.toolName;

  try {
    const result = await octokit.request(
      "GET /repos/{owner}/{repo}/code-scanning/alerts",
      params as { owner: string; repo: string },
    );

    return (result.data as Array<Record<string, unknown>>).map(normalizeAlert);
  } catch (error: unknown) {
    // 403 = GHAS not enabled, 404 = no alerts or repo not found
    if (error instanceof Error && "status" in error) {
      const status = (error as { status: number }).status;
      if (status === 403 || status === 404) return [];
    }
    throw error;
  }
}

/** Get a single code scanning alert with full details */
export async function getCodeScanningAlert(
  token: string,
  repo: string,
  alertNumber: number,
): Promise<CodeQLAlert | null> {
  const octokit = new Octokit({ auth: token });
  const [owner, repoName] = repo.split("/");

  try {
    const result = await octokit.request(
      "GET /repos/{owner}/{repo}/code-scanning/alerts/{alert_number}",
      { owner, repo: repoName, alert_number: alertNumber },
    );
    return normalizeAlert(result.data as Record<string, unknown>);
  } catch {
    return null;
  }
}

/** Get alert instances (all locations where the alert appears) */
export async function getAlertInstances(
  token: string,
  repo: string,
  alertNumber: number,
): Promise<Array<{ path: string; startLine: number; endLine: number; message: string }>> {
  const octokit = new Octokit({ auth: token });
  const [owner, repoName] = repo.split("/");

  try {
    const result = await octokit.request(
      "GET /repos/{owner}/{repo}/code-scanning/alerts/{alert_number}/instances",
      { owner, repo: repoName, alert_number: alertNumber, per_page: 50 },
    );

    return (result.data as Array<Record<string, unknown>>).map((instance) => {
      const loc = instance.location as Record<string, unknown> | undefined;
      const msg = instance.message as Record<string, unknown> | undefined;
      return {
        path: (loc?.path as string) ?? "",
        startLine: (loc?.start_line as number) ?? 0,
        endLine: (loc?.end_line as number) ?? 0,
        message: (msg?.text as string) ?? "",
      };
    });
  } catch {
    return [];
  }
}

/**
 * Correlate a Jibril runtime event with CodeQL/code scanning alerts.
 * Matches based on:
 * 1. CWE tags from the event's MITRE technique → CodeQL rule CWE tags
 * 2. File paths from the event (exec, file access) → alert locations
 * 3. Event type → relevant CodeQL rule categories
 */
export function correlateAlerts(
  event: NormalizedEvent,
  alerts: CodeQLAlert[],
): CodeQLCorrelation[] {
  const correlations: CodeQLCorrelation[] = [];
  const e = event.event;

  // Build match criteria from the Jibril event
  const eventCWEs = extractCWEsFromEvent(event);
  const eventPaths = extractPathsFromEvent(event);
  const eventCategories = mapEventTypeToRuleCategories(event.eventType);

  for (const alert of alerts) {
    const reasons: string[] = [];

    // 1. CWE match — strongest signal
    const cweOverlap = alert.cwes.filter(cwe => eventCWEs.includes(cwe));
    if (cweOverlap.length > 0) {
      reasons.push(`CWE match: ${cweOverlap.join(", ")}`);
    }

    // 2. File path match
    if (alert.location?.path && eventPaths.length > 0) {
      const alertPath = alert.location.path.toLowerCase();
      for (const evPath of eventPaths) {
        if (alertPath.includes(evPath) || evPath.includes(alertPath)) {
          reasons.push(`File path match: ${alert.location.path}`);
          break;
        }
      }
    }

    // 3. Rule category match
    const ruleId = alert.rule.id.toLowerCase();
    const ruleName = alert.rule.name.toLowerCase();
    for (const category of eventCategories) {
      if (ruleId.includes(category) || ruleName.includes(category)) {
        reasons.push(`Rule category match: ${alert.rule.id}`);
        break;
      }
    }

    if (reasons.length > 0) {
      correlations.push({
        alert,
        matchReason: reasons.join("; "),
      });
    }
  }

  // Sort: more match reasons = stronger correlation
  correlations.sort((a, b) => {
    const aReasons = a.matchReason.split(";").length;
    const bReasons = b.matchReason.split(";").length;
    return bReasons - aReasons;
  });

  return correlations;
}

/** Format CodeQL alerts for LLM context */
export function formatAlertsForLLM(correlations: CodeQLCorrelation[]): string {
  if (correlations.length === 0) return "No matching CodeQL/code scanning alerts found.";

  const lines = correlations.map((c, i) => {
    const a = c.alert;
    const loc = a.location
      ? `${a.location.path}:${a.location.startLine}-${a.location.endLine}`
      : "unknown location";
    return [
      `### Alert ${i + 1}: ${a.rule.description}`,
      `- **Rule**: \`${a.rule.id}\` (${a.rule.severity})`,
      `- **Location**: ${loc}`,
      `- **Message**: ${a.message}`,
      `- **CWEs**: ${a.cwes.length > 0 ? a.cwes.join(", ") : "none"}`,
      `- **Correlation reason**: ${c.matchReason}`,
      `- **URL**: ${a.htmlUrl}`,
    ].join("\n");
  });

  return `## CodeQL / Code Scanning Alerts\n\n${lines.join("\n\n")}`;
}

/** Format alerts summary as a markdown table */
export function formatAlertTable(alerts: CodeQLAlert[]): string {
  const rows = alerts.slice(0, 15).map(a => {
    const loc = a.location ? `${a.location.path}:${a.location.startLine}` : "—";
    return `| ${a.number} | ${a.rule.securitySeverityLevel ?? a.rule.severity} | \`${a.rule.id}\` | ${a.rule.description} | ${loc} | ${a.state} |`;
  });

  return [
    "| # | Severity | Rule | Description | Location | State |",
    "|---|----------|------|-------------|----------|-------|",
    ...rows,
  ].join("\n");
}

// --- Internal helpers ---

function normalizeAlert(raw: Record<string, unknown>): CodeQLAlert {
  const rule = raw.rule as Record<string, unknown>;
  const tool = raw.tool as Record<string, unknown>;
  const instance = raw.most_recent_instance as Record<string, unknown> | undefined;
  const loc = instance?.location as Record<string, unknown> | undefined;
  const msg = instance?.message as Record<string, unknown> | undefined;
  const tags = (rule.tags as string[]) ?? [];

  return {
    number: raw.number as number,
    state: raw.state as string,
    rule: {
      id: (rule.id as string) ?? "",
      severity: (rule.severity as string) ?? "warning",
      securitySeverityLevel: rule.security_severity_level as string | undefined,
      description: (rule.description as string) ?? "",
      name: (rule.name as string) ?? "",
      tags,
      help: rule.help as string | undefined,
    },
    tool: {
      name: (tool.name as string) ?? "unknown",
      version: (tool.version as string) ?? null,
    },
    htmlUrl: (raw.html_url as string) ?? "",
    createdAt: (raw.created_at as string) ?? "",
    location: loc
      ? {
          path: (loc.path as string) ?? "",
          startLine: (loc.start_line as number) ?? 0,
          endLine: (loc.end_line as number) ?? 0,
        }
      : null,
    message: (msg?.text as string) ?? "",
    cwes: tags.filter(t => t.startsWith("external/cwe/")).map(t => t.replace("external/cwe/", "").toUpperCase()),
  };
}

/** Extract CWE identifiers from event MITRE ATT&CK mapping */
function extractCWEsFromEvent(event: NormalizedEvent): string[] {
  const cwes: string[] = [];
  const technique = event.event.metadata.technique?.toLowerCase() ?? "";
  const tactic = event.event.metadata.tactic?.toLowerCase() ?? "";

  // Map common MITRE techniques to CWEs
  const mitreToCWE: Record<string, string[]> = {
    "command and scripting interpreter": ["CWE-078", "CWE-077"], // command injection
    "exploitation for privilege escalation": ["CWE-269", "CWE-250"],
    "credentials from password stores": ["CWE-522", "CWE-256"],
    "unsecured credentials": ["CWE-522", "CWE-200", "CWE-312"],
    "server software component": ["CWE-094"],
    "hijack execution flow": ["CWE-427", "CWE-426"],
    "dynamic linker hijacking": ["CWE-427"],
    "ingress tool transfer": ["CWE-829"],
    "indicator removal": ["CWE-117"],
    "process injection": ["CWE-094"],
    "native api": ["CWE-078"],
    "application layer protocol": ["CWE-918", "CWE-319"], // SSRF, cleartext
    "exfiltration over web service": ["CWE-200"],
    "file and directory discovery": ["CWE-548"],
    "system information discovery": ["CWE-200"],
  };

  for (const [key, cweList] of Object.entries(mitreToCWE)) {
    if (technique.includes(key) || tactic.includes(key)) {
      cwes.push(...cweList);
    }
  }

  // Event-type based fallback CWE mapping
  switch (event.eventType) {
    case "execution":
      cwes.push("CWE-078", "CWE-077");
      break;
    case "file_access":
      cwes.push("CWE-022", "CWE-200", "CWE-732");
      break;
    case "network_peers":
      cwes.push("CWE-918", "CWE-319", "CWE-295");
      break;
    case "env_vars":
      cwes.push("CWE-427", "CWE-426");
      break;
  }

  // Deduplicate
  return [...new Set(cwes)];
}

/** Extract file paths from event details */
function extractPathsFromEvent(event: NormalizedEvent): string[] {
  const paths: string[] = [];
  const e = event.event;

  if (e.exec?.cmd) {
    // Extract just the binary name for matching
    const parts = e.exec.cmd.split("/");
    paths.push(parts[parts.length - 1].toLowerCase());
  }

  if (e.file?.file) {
    const parts = e.file.file.split("/");
    paths.push(parts[parts.length - 1].toLowerCase());
  }

  return paths;
}

/** Map Jibril event types to CodeQL rule category prefixes */
function mapEventTypeToRuleCategories(eventType: string): string[] {
  const mapping: Record<string, string[]> = {
    execution: ["command-injection", "exec", "code-injection", "unsafe-shell", "command-line"],
    file_access: ["path-traversal", "zipslip", "file-access", "path-injection", "insecure-file"],
    network_peers: ["ssrf", "request-forgery", "url-redirect", "insecure-url", "cleartext", "http"],
    env_vars: ["dll-hijack", "path-injection", "environment"],
    container_escape: ["privilege-escalation", "container"],
    kernel_module: ["code-injection", "unsafe-native"],
    process_injection: ["code-injection", "process"],
    privilege_escalation: ["privilege-escalation", "escalation"],
  };

  return mapping[eventType] ?? [];
}
