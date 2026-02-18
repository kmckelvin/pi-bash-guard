import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { homedir } from "node:os";
import { dirname, join } from "node:path";
import type { ExtensionAPI } from "@mariozechner/pi-coding-agent";

interface PersistedGuardConfig {
  blockedPrefixes?: string[];
  permittedPrefixes?: string[];
}

interface PrefixRule {
  prefix: string;
  tokens: string[];
  tokenCount: number;
}

interface BlockedInvocation {
  invocation: string;
  matchedBlocks: string[];
}

type NotifyLevel = "info" | "warning" | "error";

const CONFIG_DIR = join(homedir(), ".pi", "agent", "extensions");
const CONFIG_PATH = join(CONFIG_DIR, "bash-guard.json");
const DEFAULT_BLOCKED_PREFIXES = ["gcloud", "kubectl"];
const SUDO_OPTIONS_WITH_VALUE = new Set([
  "-u",
  "--user",
  "-g",
  "--group",
  "-h",
  "--host",
  "-p",
  "--prompt",
  "-r",
  "--role",
  "-t",
  "--type",
  "-c",
  "--close-from",
]);

function splitShellSegments(command: string): string[] {
  const segments: string[] = [];
  let current = "";
  let quote: "'" | '"' | null = null;
  let escaped = false;

  for (let i = 0; i < command.length; i += 1) {
    const ch = command[i];

    if (escaped) {
      current += ch;
      escaped = false;
      continue;
    }

    if (ch === "\\") {
      current += ch;
      escaped = true;
      continue;
    }

    if (quote) {
      current += ch;
      if (ch === quote) quote = null;
      continue;
    }

    if (ch === '"' || ch === "'") {
      quote = ch;
      current += ch;
      continue;
    }

    if (ch === ";" || ch === "|" || ch === "&" || ch === "\n") {
      if (current.trim()) segments.push(current.trim());
      current = "";
      continue;
    }

    current += ch;
  }

  if (current.trim()) segments.push(current.trim());
  return segments;
}

function tokenizeShellWords(segment: string): string[] {
  const tokens: string[] = [];
  let current = "";
  let quote: "'" | '"' | null = null;
  let escaped = false;

  for (let i = 0; i < segment.length; i += 1) {
    const ch = segment[i];

    if (escaped) {
      current += ch;
      escaped = false;
      continue;
    }

    if (ch === "\\" && quote !== "'") {
      escaped = true;
      continue;
    }

    if (quote) {
      if (ch === quote) {
        quote = null;
      } else {
        current += ch;
      }
      continue;
    }

    if (ch === '"' || ch === "'") {
      quote = ch;
      continue;
    }

    if (/\s/.test(ch)) {
      if (current.length > 0) {
        tokens.push(current);
        current = "";
      }
      continue;
    }

    current += ch;
  }

  if (current.length > 0) tokens.push(current);
  return tokens;
}

function isEnvAssignment(token: string): boolean {
  return /^[A-Za-z_][A-Za-z0-9_]*=.*/.test(token);
}

function normalizeCommandName(raw: string): string {
  const trimmed = raw.trim().replace(/^['"]+|['"]+$/g, "");
  const noParens = trimmed.replace(/^[()]+/, "").replace(/[()]+$/, "");
  const base = noParens.split("/").filter(Boolean).pop() ?? noParens;
  return base.replace(/\.exe$/i, "").toLowerCase();
}

function normalizeInvocationTokens(tokens: string[]): string[] {
  let idx = 0;

  while (idx < tokens.length) {
    while (idx < tokens.length && isEnvAssignment(tokens[idx])) idx += 1;
    if (idx >= tokens.length) return [];

    const token = normalizeCommandName(tokens[idx] ?? "");

    if (token === "env") {
      idx += 1;
      while (idx < tokens.length) {
        const envToken = tokens[idx];

        if (isEnvAssignment(envToken)) {
          idx += 1;
          continue;
        }

        if (envToken.startsWith("-")) {
          idx += 1;
          if (
            (envToken === "-u" || envToken === "--unset") &&
            idx < tokens.length
          )
            idx += 1;
          continue;
        }

        break;
      }
      continue;
    }

    if (token === "sudo") {
      idx += 1;
      while (idx < tokens.length && tokens[idx].startsWith("-")) {
        const option = normalizeCommandName(tokens[idx]);
        idx += 1;
        if (SUDO_OPTIONS_WITH_VALUE.has(option) && idx < tokens.length)
          idx += 1;
      }
      continue;
    }

    if (token === "command" || token === "nohup" || token === "time") {
      idx += 1;
      while (idx < tokens.length && tokens[idx].startsWith("-")) idx += 1;
      continue;
    }

    const normalized = tokens.slice(idx);
    normalized[0] = token;
    return normalized;
  }

  return [];
}

function canonicalizePrefix(input: string): string | undefined {
  const tokens = tokenizeShellWords(input.trim());
  const normalized = normalizeInvocationTokens(tokens);
  if (normalized.length === 0) return undefined;
  return normalized.join(" ");
}

function buildRules(prefixes: Set<string>): PrefixRule[] {
  const rules: PrefixRule[] = [];

  for (const prefix of prefixes) {
    const canonical = canonicalizePrefix(prefix);
    if (!canonical) continue;

    const tokens = tokenizeShellWords(canonical);
    rules.push({
      prefix: canonical,
      tokens,
      tokenCount: tokens.length,
    });
  }

  return rules;
}

function isPrefixMatch(
  invocationTokens: string[],
  ruleTokens: string[],
): boolean {
  if (ruleTokens.length === 0 || ruleTokens.length > invocationTokens.length) {
    return false;
  }

  for (let i = 0; i < ruleTokens.length; i += 1) {
    if (invocationTokens[i] !== ruleTokens[i]) return false;
  }

  return true;
}

function matchingRules(
  invocationTokens: string[],
  rules: PrefixRule[],
): PrefixRule[] {
  return rules.filter((rule) => isPrefixMatch(invocationTokens, rule.tokens));
}

function maxTokenCount(rules: PrefixRule[]): number {
  if (rules.length === 0) return -1;
  return Math.max(...rules.map((rule) => rule.tokenCount));
}

function mostSpecificPrefixes(rules: PrefixRule[]): string[] {
  const longest = maxTokenCount(rules);
  if (longest < 0) return [];

  return rules
    .filter((rule) => rule.tokenCount === longest)
    .map((rule) => rule.prefix);
}

function decideLayer(
  permitMatches: PrefixRule[],
  blockMatches: PrefixRule[],
): { action: "permit" | "block" | "none"; matchedBlocks: string[] } {
  const permitLen = maxTokenCount(permitMatches);
  const blockLen = maxTokenCount(blockMatches);

  if (permitLen < 0 && blockLen < 0) {
    return { action: "none", matchedBlocks: [] };
  }

  // If equally specific, permit wins.
  if (permitLen >= blockLen) {
    return { action: "permit", matchedBlocks: [] };
  }

  return {
    action: "block",
    matchedBlocks: mostSpecificPrefixes(blockMatches),
  };
}

function isBlockedByPersistentRules(
  prefix: string,
  persistentBlockedPrefixes: Set<string>,
  persistentPermitPrefixes: Set<string>,
): boolean {
  const invocationTokens = tokenizeShellWords(prefix);
  const persistentDecision = decideLayer(
    matchingRules(invocationTokens, buildRules(persistentPermitPrefixes)),
    matchingRules(invocationTokens, buildRules(persistentBlockedPrefixes)),
  );

  return persistentDecision.action === "block";
}

function findBlockedInvocations(
  input: string,
  persistentBlockedPrefixes: Set<string>,
  persistentPermitPrefixes: Set<string>,
  sessionBlockedPrefixes: Set<string>,
  sessionPermitPrefixes: Set<string>,
): BlockedInvocation[] {
  const sessionBlockRules = buildRules(sessionBlockedPrefixes);
  const sessionPermitRules = buildRules(sessionPermitPrefixes);
  const persistentBlockRules = buildRules(persistentBlockedPrefixes);
  const persistentPermitRules = buildRules(persistentPermitPrefixes);

  const blocked: BlockedInvocation[] = [];

  for (const segment of splitShellSegments(input)) {
    const invocationTokens = normalizeInvocationTokens(
      tokenizeShellWords(segment),
    );
    if (invocationTokens.length === 0) continue;

    const invocation = invocationTokens.join(" ");

    const sessionDecision = decideLayer(
      matchingRules(invocationTokens, sessionPermitRules),
      matchingRules(invocationTokens, sessionBlockRules),
    );

    if (sessionDecision.action === "permit") {
      continue;
    }

    if (sessionDecision.action === "block") {
      blocked.push({
        invocation,
        matchedBlocks: sessionDecision.matchedBlocks,
      });
      continue;
    }

    const persistentDecision = decideLayer(
      matchingRules(invocationTokens, persistentPermitRules),
      matchingRules(invocationTokens, persistentBlockRules),
    );

    if (persistentDecision.action === "block") {
      blocked.push({
        invocation,
        matchedBlocks: persistentDecision.matchedBlocks,
      });
    }
  }

  return blocked;
}

function formatList(values: Iterable<string>): string {
  const items = Array.from(new Set(values)).sort();
  return items.length > 0 ? items.join(", ") : "(none)";
}

function formatBlockedInvocations(blocked: BlockedInvocation[]): string {
  return blocked
    .map(
      (entry) =>
        `${entry.invocation} (matched: ${entry.matchedBlocks.join(" | ")})`,
    )
    .join("; ");
}

function loadPersistedGuardConfig(): {
  blockedPrefixes: Set<string>;
  permittedPrefixes: Set<string>;
  existed: boolean;
  error?: string;
} {
  const defaultBlocked = new Set(
    DEFAULT_BLOCKED_PREFIXES.map((prefix) => canonicalizePrefix(prefix)).filter(
      (prefix): prefix is string => Boolean(prefix),
    ),
  );

  if (!existsSync(CONFIG_PATH)) {
    return {
      blockedPrefixes: defaultBlocked,
      permittedPrefixes: new Set(),
      existed: false,
    };
  }

  try {
    const raw = readFileSync(CONFIG_PATH, "utf-8");
    const parsed = JSON.parse(raw) as PersistedGuardConfig | null;

    const blockedSource = Array.isArray(parsed?.blockedPrefixes)
      ? parsed.blockedPrefixes
      : undefined;

    const permittedSource = Array.isArray(parsed?.permittedPrefixes)
      ? parsed.permittedPrefixes
      : undefined;

    const blockedPrefixes = new Set(
      (blockedSource ?? (permittedSource ? [] : DEFAULT_BLOCKED_PREFIXES))
        .map((prefix) => canonicalizePrefix(prefix))
        .filter((prefix): prefix is string => Boolean(prefix)),
    );

    const permittedPrefixes = new Set(
      (permittedSource ?? [])
        .map((prefix) => canonicalizePrefix(prefix))
        .filter((prefix): prefix is string => Boolean(prefix)),
    );

    return {
      blockedPrefixes,
      permittedPrefixes,
      existed: true,
    };
  } catch (error) {
    return {
      blockedPrefixes: defaultBlocked,
      permittedPrefixes: new Set(),
      existed: true,
      error: error instanceof Error ? error.message : String(error),
    };
  }
}

function savePersistedGuardConfig(
  blockedPrefixes: Set<string>,
  permittedPrefixes: Set<string>,
): void {
  const payload: PersistedGuardConfig = {
    blockedPrefixes: Array.from(blockedPrefixes).sort(),
    permittedPrefixes: Array.from(permittedPrefixes).sort(),
  };

  mkdirSync(dirname(CONFIG_PATH), { recursive: true });
  writeFileSync(CONFIG_PATH, `${JSON.stringify(payload, null, 2)}\n`, "utf-8");
}

export default function piBashGuardExtension(pi: ExtensionAPI) {
  let persistentBlockedPrefixes = new Set<string>();
  let persistentPermitPrefixes = new Set<string>();
  let sessionBlockedPrefixes = new Set<string>();
  let sessionPermitPrefixes = new Set<string>();

  function usage(ctx: {
    ui: { notify: (message: string, level: NotifyLevel) => void };
  }) {
    ctx.ui.notify(
      "Commands: /bash-guard-block <prefix>, /bash-guard-permit <prefix>, /bash-guard-block-persist <prefix>, /bash-guard-permit-persist <prefix>, /bash-guard-reset, /bash-guard-status",
      "info",
    );
  }

  pi.registerCommand("bash-guard-block-persist", {
    description: "Persistently block a bash command prefix",
    handler: async (args, ctx) => {
      const prefix = canonicalizePrefix(args ?? "");
      if (!prefix) {
        ctx.ui.notify("Usage: /bash-guard-block-persist <prefix>", "warning");
        usage(ctx);
        return;
      }

      const wasBlocked = persistentBlockedPrefixes.has(prefix);
      const removedPermit = persistentPermitPrefixes.delete(prefix);

      const coveredByExistingBlock =
        removedPermit &&
        !wasBlocked &&
        isBlockedByPersistentRules(
          prefix,
          persistentBlockedPrefixes,
          persistentPermitPrefixes,
        );

      const addedBlock = !wasBlocked && !coveredByExistingBlock;
      if (addedBlock) {
        persistentBlockedPrefixes.add(prefix);
      }

      try {
        savePersistedGuardConfig(
          persistentBlockedPrefixes,
          persistentPermitPrefixes,
        );
        if (wasBlocked && !removedPermit) {
          ctx.ui.notify(`Already persistently blocked: ${prefix}`, "info");
        } else if (removedPermit && coveredByExistingBlock) {
          ctx.ui.notify(
            `Removed persistent permit: ${prefix}. Existing persistent block prefixes already cover it, so no redundant block rule was added.`,
            "info",
          );
        } else if (removedPermit && wasBlocked) {
          ctx.ui.notify(
            `Persistently blocked: ${prefix} (removed persistent permit for same prefix).`,
            "info",
          );
        } else if (removedPermit) {
          ctx.ui.notify(
            `Persistently blocked: ${prefix} (removed persistent permit for same prefix).`,
            "info",
          );
        } else {
          ctx.ui.notify(`Persistently blocked: ${prefix}`, "info");
        }
      } catch (error) {
        if (addedBlock) persistentBlockedPrefixes.delete(prefix);
        if (removedPermit) persistentPermitPrefixes.add(prefix);
        const message = error instanceof Error ? error.message : String(error);
        ctx.ui.notify(`Failed to persist guard config: ${message}`, "error");
      }
    },
  });

  pi.registerCommand("bash-guard-permit-persist", {
    description: "Persistently permit a bash command prefix",
    handler: async (args, ctx) => {
      const prefix = canonicalizePrefix(args ?? "");
      if (!prefix) {
        ctx.ui.notify("Usage: /bash-guard-permit-persist <prefix>", "warning");
        usage(ctx);
        return;
      }

      const wasPermitted = persistentPermitPrefixes.has(prefix);
      const removedBlock = persistentBlockedPrefixes.delete(prefix);
      persistentPermitPrefixes.add(prefix);

      try {
        savePersistedGuardConfig(
          persistentBlockedPrefixes,
          persistentPermitPrefixes,
        );
        if (wasPermitted && !removedBlock) {
          ctx.ui.notify(`Already persistently permitted: ${prefix}`, "info");
        } else if (removedBlock) {
          ctx.ui.notify(
            `Persistently permitted: ${prefix} (removed persistent block for same prefix).`,
            "info",
          );
        } else {
          ctx.ui.notify(`Persistently permitted: ${prefix}`, "info");
        }
      } catch (error) {
        if (!wasPermitted) persistentPermitPrefixes.delete(prefix);
        if (removedBlock) persistentBlockedPrefixes.add(prefix);
        const message = error instanceof Error ? error.message : String(error);
        ctx.ui.notify(`Failed to persist guard config: ${message}`, "error");
      }
    },
  });

  pi.registerCommand("bash-guard-block", {
    description: "Block a bash command prefix for the current session",
    handler: async (args, ctx) => {
      const prefix = canonicalizePrefix(args ?? "");
      if (!prefix) {
        ctx.ui.notify("Usage: /bash-guard-block <prefix>", "warning");
        usage(ctx);
        return;
      }

      sessionPermitPrefixes.delete(prefix);
      sessionBlockedPrefixes.add(prefix);
      ctx.ui.notify(`Blocked for this session: ${prefix}`, "info");
    },
  });

  pi.registerCommand("bash-guard-permit", {
    description: "Permit a bash command prefix for the current session",
    handler: async (args, ctx) => {
      const prefix = canonicalizePrefix(args ?? "");
      if (!prefix) {
        ctx.ui.notify("Usage: /bash-guard-permit <prefix>", "warning");
        usage(ctx);
        return;
      }

      sessionBlockedPrefixes.delete(prefix);
      sessionPermitPrefixes.add(prefix);
      ctx.ui.notify(`Permitted for this session: ${prefix}`, "info");
    },
  });

  pi.registerCommand("bash-guard-reset", {
    description: "Clear all session-only guard overrides",
    handler: async (_args, ctx) => {
      const permits = sessionPermitPrefixes.size;
      const blocks = sessionBlockedPrefixes.size;
      sessionPermitPrefixes.clear();
      sessionBlockedPrefixes.clear();

      ctx.ui.notify(
        permits + blocks > 0
          ? `Reset session guard overrides (cleared ${permits} permit${
              permits === 1 ? "" : "s"
            }, ${blocks} block${blocks === 1 ? "" : "s"}).`
          : "No session guard overrides to reset.",
        "info",
      );
    },
  });

  pi.registerCommand("bash-guard-status", {
    description: "Show persistent and session guard prefixes",
    handler: async (_args, ctx) => {
      const lines = [
        `Persistent blocks: ${formatList(persistentBlockedPrefixes)}`,
        `Persistent permits: ${formatList(persistentPermitPrefixes)}`,
        `Session blocks: ${formatList(sessionBlockedPrefixes)}`,
        `Session permits: ${formatList(sessionPermitPrefixes)}`,
        "Resolution order: session rules first, then persistent rules; within each layer, more specific prefix wins, ties go to permit.",
      ];
      ctx.ui.notify(lines.join("\n"), "info");
    },
  });

  pi.on("session_start", async (_event, ctx) => {
    const loaded = loadPersistedGuardConfig();
    persistentBlockedPrefixes = loaded.blockedPrefixes;
    persistentPermitPrefixes = loaded.permittedPrefixes;
    sessionBlockedPrefixes = new Set();
    sessionPermitPrefixes = new Set();

    // Ensure no stale status text from previous versions.
    ctx.ui.setStatus("pi-bash-guard", undefined);

    if (!loaded.existed) {
      try {
        savePersistedGuardConfig(
          persistentBlockedPrefixes,
          persistentPermitPrefixes,
        );
      } catch (error) {
        const message = error instanceof Error ? error.message : String(error);
        ctx.ui.notify(`Failed to initialize guard config: ${message}`, "error");
      }
    }

    if (loaded.error) {
      ctx.ui.notify(
        `Failed reading ${CONFIG_PATH}, using defaults (blocks: ${formatList(
          persistentBlockedPrefixes,
        )}, permits: ${formatList(persistentPermitPrefixes)}): ${loaded.error}`,
        "warning",
      );
    }
  });

  pi.on("tool_call", async (event) => {
    if (event.toolName !== "bash") return undefined;

    const command =
      typeof event.input.command === "string" ? event.input.command : "";
    if (!command) return undefined;

    const blocked = findBlockedInvocations(
      command,
      persistentBlockedPrefixes,
      persistentPermitPrefixes,
      sessionBlockedPrefixes,
      sessionPermitPrefixes,
    );
    if (blocked.length === 0) return undefined;

    return {
      block: true,
      reason: `Blocked bash invocation(s): ${formatBlockedInvocations(
        blocked,
      )}. Use /bash-guard-permit <prefix> to allow in this session.`,
    };
  });

  pi.on("user_bash", (event, ctx) => {
    const blocked = findBlockedInvocations(
      event.command,
      persistentBlockedPrefixes,
      persistentPermitPrefixes,
      sessionBlockedPrefixes,
      sessionPermitPrefixes,
    );
    if (blocked.length === 0) return undefined;

    const message = `Blocked bash invocation(s): ${formatBlockedInvocations(
      blocked,
    )}. Use /bash-guard-permit <prefix> to allow in this session.`;
    ctx.ui.notify(message, "warning");

    return {
      result: {
        output: message,
        exitCode: 1,
        cancelled: false,
        truncated: false,
      },
    };
  });
}
