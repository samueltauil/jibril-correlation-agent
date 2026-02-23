import { Octokit } from "@octokit/rest";
import { createAppAuth } from "@octokit/auth-app";

// Cache installation tokens (they expire in 1 hour)
const installationCache = new Map<string, { octokit: Octokit; expiresAt: number }>();

export interface CodeMatch {
  path: string;
  repo: string;
  snippet: string;
  htmlUrl: string;
}

export interface CommitInfo {
  sha: string;
  message: string;
  author: string;
  date: string;
  files: string[];
  htmlUrl: string;
}

/** Search for code patterns in a GitHub repo */
export async function searchCode(
  token: string,
  repo: string,
  patterns: string[],
  options?: { maxResults?: number },
): Promise<CodeMatch[]> {
  const octokit = new Octokit({ auth: token });
  const [owner, repoName] = repo.split("/");
  const maxResults = options?.maxResults ?? 10;
  const matches: CodeMatch[] = [];

  for (const pattern of patterns) {
    if (matches.length >= maxResults) break;

    try {
      const result = await octokit.search.code({
        q: `${pattern} repo:${owner}/${repoName}`,
        per_page: Math.min(5, maxResults - matches.length),
      });

      for (const item of result.data.items) {
        if (matches.length >= maxResults) break;
        if (matches.some(m => m.path === item.path)) continue; // dedupe

        // Fetch file content for snippet
        let snippet = "";
        try {
          const content = await octokit.repos.getContent({
            owner,
            repo: repoName,
            path: item.path,
          });
          if ("content" in content.data && content.data.content) {
            const decoded = Buffer.from(content.data.content, "base64").toString("utf-8");
            snippet = extractRelevantLines(decoded, pattern);
          }
        } catch {
          snippet = "(could not fetch file content)";
        }

        matches.push({
          path: item.path,
          repo,
          snippet,
          htmlUrl: item.html_url,
        });
      }
    } catch {
      // Search may fail for some patterns (too broad, rate limited), continue
      continue;
    }
  }

  return matches;
}

/** Get recent commits, optionally filtered by file path */
export async function getRecentCommits(
  token: string,
  repo: string,
  options?: { path?: string; since?: string; maxResults?: number },
): Promise<CommitInfo[]> {
  const octokit = new Octokit({ auth: token });
  const [owner, repoName] = repo.split("/");

  const params: Parameters<typeof octokit.repos.listCommits>[0] = {
    owner,
    repo: repoName,
    per_page: options?.maxResults ?? 20,
  };
  if (options?.path) params.path = options.path;
  if (options?.since) params.since = options.since;

  const result = await octokit.repos.listCommits(params);

  const commits: CommitInfo[] = [];
  for (const commit of result.data) {
    // Fetch full commit for file list
    let files: string[] = [];
    try {
      const full = await octokit.repos.getCommit({
        owner,
        repo: repoName,
        ref: commit.sha,
      });
      files = full.data.files?.map(f => f.filename) ?? [];
    } catch {
      // skip file details if rate-limited
    }

    commits.push({
      sha: commit.sha,
      message: commit.commit.message,
      author: commit.commit.author?.name ?? "unknown",
      date: commit.commit.author?.date ?? "",
      files,
      htmlUrl: commit.html_url,
    });
  }

  return commits;
}

/** Create a GitHub issue with security finding details */
export async function createIssue(
  token: string,
  repo: string,
  title: string,
  body: string,
  labels?: string[],
): Promise<{ number: number; htmlUrl: string }> {
  const octokit = new Octokit({ auth: token });
  const [owner, repoName] = repo.split("/");

  const result = await octokit.issues.create({
    owner,
    repo: repoName,
    title,
    body,
    labels: labels ?? ["security", "jibril"],
  });

  return { number: result.data.number, htmlUrl: result.data.html_url };
}

/** Create a PR with a fix */
export async function createPullRequest(
  token: string,
  repo: string,
  params: {
    title: string;
    body: string;
    baseBranch: string;
    headBranch: string;
    files: Array<{ path: string; content: string }>;
  },
): Promise<{ number: number; htmlUrl: string }> {
  const octokit = new Octokit({ auth: token });
  const [owner, repoName] = repo.split("/");

  // Get base branch SHA
  const baseRef = await octokit.git.getRef({
    owner,
    repo: repoName,
    ref: `heads/${params.baseBranch}`,
  });
  const baseSha = baseRef.data.object.sha;

  // Create new branch
  await octokit.git.createRef({
    owner,
    repo: repoName,
    ref: `refs/heads/${params.headBranch}`,
    sha: baseSha,
  });

  // Commit files
  for (const file of params.files) {
    await octokit.repos.createOrUpdateFileContents({
      owner,
      repo: repoName,
      path: file.path,
      message: `fix: ${params.title}`,
      content: Buffer.from(file.content).toString("base64"),
      branch: params.headBranch,
    });
  }

  // Create PR
  const pr = await octokit.pulls.create({
    owner,
    repo: repoName,
    title: params.title,
    body: params.body,
    head: params.headBranch,
    base: params.baseBranch,
  });

  return { number: pr.data.number, htmlUrl: pr.data.html_url };
}

/** Get an Octokit instance authenticated as a GitHub App installation */
export async function getInstallationOctokit(
  owner: string,
  repo: string,
  appId: string,
  privateKey: string,
): Promise<Octokit> {
  const cacheKey = `${owner}/${repo}`;
  const cached = installationCache.get(cacheKey);
  if (cached && cached.expiresAt > Date.now() + 5 * 60 * 1000) {
    return cached.octokit;
  }

  // Create app-authenticated Octokit to find installation ID
  const appOctokit = new Octokit({
    authStrategy: createAppAuth,
    auth: {
      appId,
      privateKey,
    },
  });

  // Get the installation for this repo
  const { data: installation } = await appOctokit.apps.getRepoInstallation({
    owner,
    repo,
  });

  // Create installation-authenticated Octokit
  const installationOctokit = new Octokit({
    authStrategy: createAppAuth,
    auth: {
      appId,
      privateKey,
      installationId: installation.id,
    },
  });

  // Cache for 50 minutes (tokens last 1 hour)
  installationCache.set(cacheKey, {
    octokit: installationOctokit,
    expiresAt: Date.now() + 50 * 60 * 1000,
  });

  return installationOctokit;
}

/** Extract relevant lines around a pattern match */
function extractRelevantLines(content: string, pattern: string, contextLines = 5): string {
  const lines = content.split("\n");
  const patternLower = pattern.toLowerCase();
  const matchIndex = lines.findIndex(l => l.toLowerCase().includes(patternLower));

  if (matchIndex === -1) {
    return lines.slice(0, contextLines * 2).join("\n");
  }

  const start = Math.max(0, matchIndex - contextLines);
  const end = Math.min(lines.length, matchIndex + contextLines + 1);
  return lines.slice(start, end).join("\n");
}
