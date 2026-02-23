import { prompt } from "@copilot-extensions/preview-sdk";
import type { NormalizedEvent, DetectedChain } from "./types.js";

const SYSTEM_PROMPT = `You are a security analyst specializing in runtime-to-code correlation. You work with Jibril, an eBPF-based runtime security platform that monitors Linux systems and Kubernetes clusters.

When given a runtime security event, you:
1. Explain what happened in clear terms
2. Assess the severity and whether it's likely a true positive or false positive
3. Identify which code patterns could have caused this behavior
4. Suggest specific files, functions, or dependencies to investigate
5. Recommend remediation steps

Always reference the specific event data (process, file, network info) in your analysis. Be actionable and specific.`;

export interface ReasoningResult {
  analysis: string;
  suggestedSearchPatterns: string[];
}

/** Analyze a single event using LLM reasoning */
export async function analyzeEvent(
  event: NormalizedEvent,
  token: string,
  additionalContext?: string,
): Promise<ReasoningResult> {
  const eventSummary = formatEventForLLM(event);
  const userPrompt = additionalContext
    ? `Analyze this runtime security event:\n\n${eventSummary}\n\nAdditional context:\n${additionalContext}`
    : `Analyze this runtime security event:\n\n${eventSummary}`;

  const result = await prompt(userPrompt, {
    model: "gpt-4o",
    token,
    messages: [{ role: "system", content: SYSTEM_PROMPT }],
  });

  const analysis = result.message.content ?? "";
  const suggestedSearchPatterns = extractSearchPatterns(event);

  return { analysis, suggestedSearchPatterns };
}

/** Correlate an event with code search results, commit history, and optional CodeQL alerts */
export async function correlateWithCode(
  event: NormalizedEvent,
  codeMatches: Array<{ path: string; repo: string; snippet: string }>,
  recentCommits: Array<{ sha: string; message: string; author: string; date: string; files: string[] }>,
  token: string,
  codeqlContext?: string,
): Promise<string> {
  const eventSummary = formatEventForLLM(event);
  const codeContext = codeMatches
    .map(m => `File: ${m.repo}/${m.path}\n\`\`\`\n${m.snippet}\n\`\`\``)
    .join("\n\n");
  const commitContext = recentCommits
    .map(c => `- ${c.sha.slice(0, 7)} by ${c.author} (${c.date}): ${c.message}\n  Files: ${c.files.join(", ")}`)
    .join("\n");

  const codeqlSection = codeqlContext
    ? `\n\n## CodeQL / Code Scanning Alerts\n${codeqlContext}`
    : "";

  const userPrompt = `Given this runtime security event and the matching code/commits, identify the root cause and suggest a fix.

## Runtime Event
${eventSummary}

## Matching Code
${codeContext || "No code matches found."}

## Recent Commits
${commitContext || "No recent commits found."}${codeqlSection}

Provide:
1. Which commit most likely introduced the behavior
2. The specific code responsible
3. A concrete fix (code change or dependency removal)
4. Risk assessment (expected / suspicious / malicious)${codeqlContext ? "\n5. Whether any CodeQL alerts confirm the runtime behavior and should be prioritized" : ""}`;

  const result = await prompt(userPrompt, {
    model: "gpt-4o",
    token,
    messages: [{ role: "system", content: SYSTEM_PROMPT }],
  });

  return result.message.content ?? "";
}

/** Generate a summary of multiple events, including detected attack chains */
export async function summarizeEvents(
  events: NormalizedEvent[],
  token: string,
  chains?: DetectedChain[],
): Promise<string> {
  const summaries = events.map(e => {
    const s = e.event.score;
    const m = e.event.metadata;
    const container = e.event.container;
    const containerInfo = container?.container_name ?? container?.container_id ?? "host";
    const ancestry = e.event.base?.background?.ancestry;
    const ancestryRoot = ancestry?.length ? ancestry[ancestry.length - 1].cmd : "unknown";
    return `- [${s.severity_level.toUpperCase()}] ${m.name} (${m.kind}) | tactic: ${m.tactic} | severity: ${s.severity}, confidence: ${s.confidence} | container: ${containerInfo} | ancestry root: ${ancestryRoot} | ${e.event.timestamp}`;
  }).join("\n");

  let chainSection = "";
  if (chains && chains.length > 0) {
    const chainSummaries = chains.map(c => {
      const steps = c.matchedEvents.map(e => e.event.metadata.tactic).join(" \u2192 ");
      return `- **${c.pattern.name}** (confidence: ${(c.confidence * 100).toFixed(0)}%) \u2014 ${steps} | scope: ${c.scope}`;
    }).join("\n");
    chainSection = `\n\n## Detected Attack Chains\n${chainSummaries}\n\nIncorporate the attack chain analysis in your response. Explain how the individual events connect to form a multi-step attack.`;
  }

  const result = await prompt(
    `Summarize these runtime security events. Group by severity, identify patterns, and highlight the most critical items that need immediate attention:\n\n${summaries}${chainSection}`,
    {
      model: "gpt-4o",
      token,
      messages: [{ role: "system", content: SYSTEM_PROMPT }],
    },
  );

  return result.message.content ?? "";
}

/** Analyze a detected attack chain using LLM reasoning */
export async function correlateChains(
  chain: DetectedChain,
  token: string,
): Promise<string> {
  const eventDetails = chain.matchedEvents.map((event, i) => {
    return `### Step ${i + 1}: ${event.event.metadata.tactic}\n${formatEventForLLM(event)}`;
  }).join("\n\n");

  const userPrompt = `Analyze this detected attack chain and provide a security assessment.

## Attack Chain: ${chain.pattern.name}
**Description**: ${chain.pattern.description}
**Confidence**: ${(chain.confidence * 100).toFixed(0)}%
**Scope**: ${chain.scope}
**Time span**: ${new Date(chain.firstSeen).toISOString()} \u2192 ${new Date(chain.lastSeen).toISOString()}
**Status**: ${chain.status}

## Events in Chain (ordered by time)

${eventDetails}

Provide:
1. **Attack narrative**: Explain how these events form a coherent multi-step attack
2. **True positive assessment**: Is this a real attack chain or coincidental events?
3. **Investigation order**: Which event should be investigated first and why?
4. **Containment actions**: Immediate steps to contain the threat
5. **MITRE ATT&CK mapping**: Map each step to the kill chain stage`;

  const result = await prompt(userPrompt, {
    model: "gpt-4o",
    token,
    messages: [{ role: "system", content: SYSTEM_PROMPT }],
  });

  return result.message.content ?? "";
}

/** Format event data for LLM consumption */
function formatEventForLLM(event: NormalizedEvent): string {
  const e = event.event;
  const parts: string[] = [
    `**Event**: ${e.metadata.name} (${e.metadata.kind})`,
    `**Type**: ${event.eventType}`,
    `**Severity**: ${e.score.severity_level} (${e.score.severity}/100, confidence: ${e.score.confidence})`,
    `**Risk Score**: ${e.score.risk_score}`,
    `**MITRE ATT&CK**: ${e.metadata.tactic} / ${e.metadata.technique}${e.metadata.subtechnique ? ` / ${e.metadata.subtechnique}` : ""}`,
    `**Timestamp**: ${e.timestamp}`,
    `**Description**: ${e.metadata.description}`,
  ];

  if (e.base?.background?.ancestry?.length) {
    const ancestry = e.base.background.ancestry
      .map(a => `${a.cmd} (PID ${a.pid})`)
      .join(" \u2192 ");
    parts.push(`**Process Ancestry**: ${ancestry}`);
  }

  if (e.exec) {
    parts.push(`**Executed**: ${e.exec.cmdline ?? e.exec.cmd}`);
    if (e.exec.args?.length) parts.push(`**Args**: ${e.exec.args.join(" ")}`);
  }

  if (e.file) {
    parts.push(`**File**: ${e.file.file} (${e.file.actions.join(", ")})`);
  }

  if (e.network) {
    const net = e.network;
    parts.push(`**Network**: ${net.source_ip ?? "?"}:${net.source_port ?? "?"} \u2192 ${net.destination_ip ?? "?"}:${net.destination_port ?? "?"} (${net.protocol ?? "?"})`);
    if (net.domain) parts.push(`**Domain**: ${net.domain}`);
  }

  if (e.container) {
    parts.push(`**Container**: ${e.container.container_name ?? e.container.container_id ?? "unknown"} (image: ${e.container.image ?? "unknown"}:${e.container.image_tag ?? "latest"})`);
  }

  return parts.join("\n");
}

/** Extract search patterns to look for in code based on event type */
function extractSearchPatterns(event: NormalizedEvent): string[] {
  const patterns: string[] = [];
  const e = event.event;

  switch (event.eventType) {
    case "network_peers":
      patterns.push("http.request", "https.request", "fetch(", "axios", "net.connect", "dns.resolve");
      if (e.network?.domain) patterns.push(e.network.domain);
      if (e.network?.destination_ip) patterns.push(e.network.destination_ip);
      if (e.network?.destination_port) patterns.push(`:${e.network.destination_port}`);
      break;

    case "execution":
      patterns.push("child_process", "spawn(", "exec(", "execFile(", "execSync(");
      patterns.push("subprocess", "os.system", "os.popen", "Popen");
      if (e.exec?.cmd) patterns.push(e.exec.cmd);
      break;

    case "file_access":
      if (e.file?.file) patterns.push(e.file.file);
      patterns.push("readFile", "writeFile", "open(", "fs.access");
      break;

    case "env_vars":
      patterns.push("LD_PRELOAD", "LD_LIBRARY_PATH", "process.env");
      break;
  }

  return patterns;
}
