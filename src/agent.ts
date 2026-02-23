import {
  verifyAndParseRequest,
  getUserMessage,
  getUserConfirmation,
  createAckEvent,
  createTextEvent,
  createDoneEvent,
  createConfirmationEvent,
  createReferencesEvent,
  createErrorsEvent,
} from "@copilot-extensions/preview-sdk";
import type { IncomingMessage, ServerResponse } from "node:http";
import { EventStore } from "./events.js";
import { analyzeEvent, correlateWithCode, summarizeEvents } from "./reasoning.js";
import { searchCode, getRecentCommits, createIssue } from "./github.js";
import { getCodeScanningAlerts, correlateAlerts, formatAlertsForLLM, formatAlertTable } from "./codeql.js";
import type { NormalizedEvent, RepoMapping } from "./types.js";

export interface AgentDeps {
  eventStore: EventStore;
  repoMappings: RepoMapping[];
}

/** Main Copilot Extension agent handler */
export async function handleAgentRequest(
  req: IncomingMessage,
  res: ServerResponse,
  deps: AgentDeps,
): Promise<void> {
  // Read raw body
  const chunks: Buffer[] = [];
  for await (const chunk of req) {
    chunks.push(typeof chunk === "string" ? Buffer.from(chunk) : chunk);
  }
  const rawBody = Buffer.concat(chunks).toString("utf-8");

  // Extract headers for verification
  const signature = req.headers["github-public-key-signature"] as string;
  const keyId = req.headers["github-public-key-identifier"] as string;
  const token = (req.headers["x-github-token"] as string) ?? "";

  // Verify and parse
  const { isValidRequest, payload } = await verifyAndParseRequest(
    rawBody,
    signature,
    keyId,
    { token },
  );

  if (!isValidRequest) {
    res.writeHead(401, { "Content-Type": "text/plain" });
    res.end("Request verification failed");
    return;
  }

  // Set SSE headers
  res.writeHead(200, {
    "Content-Type": "text/event-stream",
    "Cache-Control": "no-cache",
    Connection: "keep-alive",
  });

  // Acknowledge
  res.write(createAckEvent());

  try {
    // Check for confirmation response first
    const confirmation = getUserConfirmation(payload);
    if (confirmation?.id) {
      await handleConfirmation(confirmation as { id: string;[key: string]: unknown }, token, res, deps);
      return;
    }

    // Get user message and route
    const message = getUserMessage(payload);
    if (!message) {
      res.write(createTextEvent("I didn't receive a message. Try asking me about recent security events."));
      res.write(createDoneEvent());
      return;
    }

    await routeMessage(message, token, res, deps);
  } catch (error) {
    const errMsg = error instanceof Error ? error.message : "An unexpected error occurred";
    res.write(createErrorsEvent([{ type: "agent", code: "AGENT_ERROR", message: errMsg, identifier: "jibril-agent" }]));
    res.write(createDoneEvent());
  }
}

/** Route user message to appropriate handler */
async function routeMessage(
  message: string,
  token: string,
  res: ServerResponse,
  deps: AgentDeps,
): Promise<void> {
  const lower = message.toLowerCase().trim();

  // "what happened" / "events" / "status" → list recent events
  if (matchesIntent(lower, ["what happened", "events", "status", "show events", "recent", "overview"])) {
    await handleListEvents(token, res, deps);
    return;
  }

  // "analyze <uuid>" → deep dive on specific event
  const uuidMatch = lower.match(/analyze\s+([a-f0-9-]{8,})/);
  if (uuidMatch) {
    await handleAnalyzeEvent(uuidMatch[1], token, res, deps);
    return;
  }

  // "correlate <uuid>" / "find the code for <uuid>" → code correlation
  const correlateMatch = lower.match(/(?:correlate|find.*code.*for|investigate)\s+([a-f0-9-]{8,})/);
  if (correlateMatch) {
    await handleCorrelateEvent(correlateMatch[1], token, res, deps);
    return;
  }

  // "create issue for <uuid>" → issue creation
  const issueMatch = lower.match(/(?:create|open|file)\s+(?:an?\s+)?issue\s+(?:for\s+)?([a-f0-9-]{8,})/);
  if (issueMatch) {
    await handleCreateIssueRequest(issueMatch[1], token, res, deps);
    return;
  }

  // "codeql <repo>" / "code scanning" → show CodeQL alerts
  const codeqlMatch = lower.match(/(?:codeql|code\s*scanning)(?:\s+(?:for\s+)?([\w.-]+\/[\w.-]+))?/);
  if (codeqlMatch) {
    const repo = codeqlMatch[1] ?? inferRepoFromEvents(deps);
    await handleCodeQLAlerts(repo, token, res, deps);
    return;
  }

  // "stats" → show statistics
  if (matchesIntent(lower, ["stats", "statistics", "summary", "dashboard"])) {
    await handleStats(token, res, deps);
    return;
  }

  // Default: treat as a general question about the latest high-severity event
  await handleGeneralQuery(message, token, res, deps);
}

/** List recent security events */
async function handleListEvents(token: string, res: ServerResponse, deps: AgentDeps): Promise<void> {
  const events = deps.eventStore.list({ limit: 20 });

  if (events.length === 0) {
    res.write(createTextEvent("No security events received yet. Jibril events will appear here once the shell reaction is configured and detections occur."));
    res.write(createDoneEvent());
    return;
  }

  // Summarize via LLM
  const summary = await summarizeEvents(events, token);
  res.write(createTextEvent(summary));

  // Add event table
  const table = formatEventTable(events.slice(0, 10));
  res.write(createTextEvent("\n\n" + table));
  res.write(createTextEvent("\n\nUse `analyze <event-uuid>` to deep dive into a specific event, or `correlate <event-uuid>` to find related code."));
  res.write(createDoneEvent());
}

/** Deep dive analysis of a specific event */
async function handleAnalyzeEvent(id: string, token: string, res: ServerResponse, deps: AgentDeps): Promise<void> {
  const event = deps.eventStore.get(id);
  if (!event) {
    res.write(createTextEvent(`Event \`${id}\` not found. Use \`events\` to see available events.`));
    res.write(createDoneEvent());
    return;
  }

  res.write(createTextEvent("Analyzing event...\n\n"));

  const result = await analyzeEvent(event, token);
  res.write(createTextEvent(result.analysis));

  if (result.suggestedSearchPatterns.length > 0) {
    res.write(createTextEvent(`\n\n**Suggested code search patterns**: ${result.suggestedSearchPatterns.map(p => `\`${p}\``).join(", ")}`));
    res.write(createTextEvent(`\n\nUse \`correlate ${id}\` to automatically search for related code.`));
  }

  res.write(createDoneEvent());
}

/** Correlate an event with source code */
async function handleCorrelateEvent(id: string, token: string, res: ServerResponse, deps: AgentDeps): Promise<void> {
  const event = deps.eventStore.get(id);
  if (!event) {
    res.write(createTextEvent(`Event \`${id}\` not found.`));
    res.write(createDoneEvent());
    return;
  }

  if (!event.repo) {
    res.write(createTextEvent("No GitHub repository mapped for this event's container. Configure repo mappings to enable code correlation."));
    res.write(createDoneEvent());
    return;
  }

  res.write(createTextEvent("Searching for related code, commits, and CodeQL alerts...\n\n"));

  // Get search patterns and search code
  const { suggestedSearchPatterns } = await analyzeEvent(event, token);
  const codeMatches = await searchCode(token, event.repo, suggestedSearchPatterns, { maxResults: 5 });

  // Get recent commits for matched files
  const commitPaths = codeMatches.map(m => m.path);
  const commits = [];
  for (const path of commitPaths.slice(0, 3)) {
    const pathCommits = await getRecentCommits(token, event.repo, { path, maxResults: 5 });
    commits.push(...pathCommits);
  }
  // Deduplicate commits
  const uniqueCommits = [...new Map(commits.map(c => [c.sha, c])).values()];

  // Fetch and correlate CodeQL alerts
  const codeqlAlerts = await getCodeScanningAlerts(token, event.repo);
  const codeqlCorrelations = correlateAlerts(event, codeqlAlerts);
  const codeqlContext = codeqlCorrelations.length > 0
    ? formatAlertsForLLM(codeqlCorrelations)
    : undefined;

  // LLM correlation (now with CodeQL context)
  const correlation = await correlateWithCode(event, codeMatches, uniqueCommits, token, codeqlContext);
  res.write(createTextEvent(correlation));

  // Add references for matched code
  if (codeMatches.length > 0) {
    const references = codeMatches.map((m, i) => ({
      id: `code-${i}`,
      type: "code" as const,
      data: { path: m.path, repo: m.repo },
      is_implicit: false,
      metadata: {
        display_name: m.path,
        display_url: m.htmlUrl,
      },
    }));
    res.write(createReferencesEvent(references));
  }

  res.write(createTextEvent(`\n\nUse \`create issue for ${id}\` to file an issue with these findings.`));
  res.write(createDoneEvent());
}

/** Ask user to confirm issue creation */
async function handleCreateIssueRequest(id: string, _token: string, res: ServerResponse, deps: AgentDeps): Promise<void> {
  const event = deps.eventStore.get(id);
  if (!event) {
    res.write(createTextEvent(`Event \`${id}\` not found.`));
    res.write(createDoneEvent());
    return;
  }

  if (!event.repo) {
    res.write(createTextEvent("No GitHub repository mapped for this event. Configure repo mappings first."));
    res.write(createDoneEvent());
    return;
  }

  const e = event.event;
  res.write(
    createConfirmationEvent({
      id: `create-issue-${id}`,
      title: "Create Security Issue",
      message: `Create an issue in **${event.repo}** for:\n\n**${e.metadata.name}** (${e.score.severity_level}) — ${e.metadata.description}`,
      metadata: { eventId: id, repo: event.repo },
    }),
  );
  res.write(createDoneEvent());
}

/** Handle user confirmation for issue creation */
async function handleConfirmation(
  confirmation: { id: string; [key: string]: unknown },
  token: string,
  res: ServerResponse,
  deps: AgentDeps,
): Promise<void> {
  const confirmId = confirmation.id;
  if (typeof confirmId !== "string" || !confirmId.startsWith("create-issue-")) {
    res.write(createTextEvent("Unknown confirmation received."));
    res.write(createDoneEvent());
    return;
  }

  const eventId = confirmId.replace("create-issue-", "");
  const event = deps.eventStore.get(eventId);
  if (!event || !event.repo) {
    res.write(createTextEvent("Event no longer available."));
    res.write(createDoneEvent());
    return;
  }

  const e = event.event;
  const title = `[Jibril] ${e.metadata.name} — ${e.score.severity_level} severity`;
  const body = buildIssueBody(event);

  const issue = await createIssue(token, event.repo, title, body);
  res.write(createTextEvent(`Issue [#${issue.number}](${issue.htmlUrl}) created in ${event.repo}.`));
  res.write(createDoneEvent());
}

/** Show event statistics */
async function handleStats(_token: string, res: ServerResponse, deps: AgentDeps): Promise<void> {
  const stats = deps.eventStore.stats();

  if (stats.total === 0) {
    res.write(createTextEvent("No events have been received yet."));
    res.write(createDoneEvent());
    return;
  }

  const lines = [
    `## Event Statistics`,
    `**Total events**: ${stats.total}`,
    "",
    "### By Severity",
    ...Object.entries(stats.bySeverity).map(([k, v]) => `- **${k}**: ${v}`),
    "",
    "### By Type",
    ...Object.entries(stats.byType).map(([k, v]) => `- **${k}**: ${v}`),
  ];

  res.write(createTextEvent(lines.join("\n")));
  res.write(createDoneEvent());
}

/** Handle general query — analyze the latest high-severity event */
async function handleGeneralQuery(message: string, token: string, res: ServerResponse, deps: AgentDeps): Promise<void> {
  const events = deps.eventStore.list({ limit: 5, severity: "critical" });
  const fallback = events.length > 0 ? events : deps.eventStore.list({ limit: 5 });

  if (fallback.length === 0) {
    res.write(createTextEvent(
      "No security events have been received yet.\n\n" +
      "**Available commands:**\n" +
      "- `events` — List recent security events\n" +
      "- `analyze <uuid>` — Deep dive into a specific event\n" +
      "- `correlate <uuid>` — Find related source code\n" +
      "- `create issue for <uuid>` — File a GitHub issue\n" +
      "- `stats` — Show event statistics",
    ));
    res.write(createDoneEvent());
    return;
  }

  // Analyze with user's question as context
  const latest = fallback[0];
  const result = await analyzeEvent(latest, token, `User question: ${message}`);
  res.write(createTextEvent(result.analysis));
  res.write(createDoneEvent());
}

/** Show CodeQL / code scanning alerts and correlate with runtime events */
async function handleCodeQLAlerts(
  repo: string | undefined,
  token: string,
  res: ServerResponse,
  deps: AgentDeps,
): Promise<void> {
  if (!repo) {
    res.write(createTextEvent("No repository specified and no events with mapped repos found.\n\nUsage: `codeql owner/repo`"));
    res.write(createDoneEvent());
    return;
  }

  res.write(createTextEvent(`Fetching code scanning alerts for **${repo}**...\n\n`));

  const alerts = await getCodeScanningAlerts(token, repo);

  if (alerts.length === 0) {
    res.write(createTextEvent(`No open code scanning alerts found for **${repo}**.\n\nThis could mean:\n- No CodeQL analysis has been configured\n- GitHub Advanced Security is not enabled (required for private repos)\n- All alerts have been resolved`));
    res.write(createDoneEvent());
    return;
  }

  // Show alert summary table
  res.write(createTextEvent(`Found **${alerts.length}** open alert(s):\n\n`));
  res.write(createTextEvent(formatAlertTable(alerts)));

  // Cross-reference with runtime events
  const events = deps.eventStore.list({ limit: 50 });
  const repoEvents = events.filter(e => e.repo === repo);

  if (repoEvents.length > 0) {
    res.write(createTextEvent("\n\n### Runtime ↔ Static Correlation\n\n"));

    let totalCorrelations = 0;
    for (const event of repoEvents.slice(0, 10)) {
      const correlations = correlateAlerts(event, alerts);
      if (correlations.length > 0) {
        totalCorrelations += correlations.length;
        const e = event.event;
        res.write(createTextEvent(
          `**${e.metadata.name}** (${e.score.severity_level}) ↔ ` +
          correlations.map(c => `\`${c.alert.rule.id}\` (${c.matchReason})`).join(", ") +
          "\n",
        ));
      }
    }

    if (totalCorrelations === 0) {
      res.write(createTextEvent("No direct correlations found between runtime events and CodeQL alerts for this repo.\n"));
    } else {
      res.write(createTextEvent(`\n**${totalCorrelations}** correlation(s) found — these CodeQL alerts may explain the runtime behavior.\n`));
    }
  }

  // Add references
  const references = alerts.slice(0, 5).map((a, i) => ({
    id: `codeql-${i}`,
    type: "code" as const,
    data: { alertNumber: a.number, rule: a.rule.id },
    is_implicit: false,
    metadata: {
      display_name: `${a.rule.id}: ${a.rule.description}`,
      display_url: a.htmlUrl,
    },
  }));
  res.write(createReferencesEvent(references));

  res.write(createTextEvent("\n\nUse `correlate <event-uuid>` to deep-dive a specific runtime event with CodeQL context."));
  res.write(createDoneEvent());
}

/** Infer a repo from existing events */
function inferRepoFromEvents(deps: AgentDeps): string | undefined {
  const events = deps.eventStore.list({ limit: 10 });
  return events.find(e => e.repo)?.repo;
}

/** Format events as a markdown table */
function formatEventTable(events: NormalizedEvent[]): string {
  const rows = events.map(e => {
    const ev = e.event;
    return `| \`${e.id.slice(0, 8)}\` | ${ev.score.severity_level} | ${ev.metadata.name} | ${e.eventType} | ${ev.timestamp} |`;
  });

  return [
    "| ID | Severity | Name | Type | Time |",
    "|-----|----------|------|------|------|",
    ...rows,
  ].join("\n");
}

/** Build a structured issue body */
function buildIssueBody(event: NormalizedEvent): string {
  const e = event.event;
  const sections = [
    `## Runtime Security Event`,
    ``,
    `| Field | Value |`,
    `|-------|-------|`,
    `| **Event** | ${e.metadata.name} (\`${e.metadata.kind}\`) |`,
    `| **Severity** | ${e.score.severity_level} (${e.score.severity}/100) |`,
    `| **Confidence** | ${e.score.confidence} |`,
    `| **Risk Score** | ${e.score.risk_score} |`,
    `| **MITRE ATT&CK** | ${e.metadata.tactic} / ${e.metadata.technique} |`,
    `| **Detected** | ${e.timestamp} |`,
    ``,
    `### Description`,
    e.metadata.description,
  ];

  if (e.exec) {
    sections.push("", "### Execution Details", `- **Command**: \`${e.exec.cmdline ?? e.exec.cmd}\``);
  }
  if (e.file) {
    sections.push("", "### File Access", `- **File**: \`${e.file.file}\``, `- **Actions**: ${e.file.actions.join(", ")}`);
  }
  if (e.network) {
    sections.push("", "### Network Activity", `- **Destination**: ${e.network.destination_ip}:${e.network.destination_port}`);
    if (e.network.domain) sections.push(`- **Domain**: ${e.network.domain}`);
  }
  if (e.base?.background?.ancestry?.length) {
    const chain = e.base.background.ancestry.map(a => `\`${a.cmd}\``).join(" → ");
    sections.push("", "### Process Ancestry", chain);
  }

  sections.push(
    "",
    "---",
    "*Reported by [Jibril Correlation Agent](https://github.com) — Runtime→Code security correlation powered by Jibril eBPF*",
  );

  return sections.join("\n");
}

function matchesIntent(input: string, patterns: string[]): boolean {
  return patterns.some(p => input.includes(p));
}
