import { createHash } from "node:crypto";
import * as fs from "node:fs";
import * as path from "node:path";
import type { TDaemonIntegrationKind } from "@openllmsh/protocol";
import {
  SHA256_RE,
  validateRegistryRawUrl,
} from "@openllmsh/protocol/registry-pointer";
import { daemonEnv } from "./env";
import { logDebug, logError, logInfo } from "./logger";
import { DEFAULT_BIN_DIRS } from "./path-utils";
import { daemonTempDir } from "./sandbox/working-set";

export type TIntegrationKind = TDaemonIntegrationKind;
export type TIntegrationMode = "install" | "uninstall" | "state";

/** Wire kinds map onto the ONE registry area: an `extension` is a setup entry
 *  whose frontmatter declares `extensions:` — same delivery contract. */
const AREA: Record<TIntegrationKind, "setup"> = {
  extension: "setup",
  setup: "setup",
};

export type TIntegrationResult = {
  readonly ok: boolean;
  readonly code: number;
  readonly output: string;
  readonly scriptSha256?: string;
};

const FETCH_TIMEOUT_MS = 15_000;
const SCRIPT_TIMEOUT_MS = 120_000;

const sha256Hex = (bytes: Uint8Array): string =>
  createHash("sha256").update(bytes).digest("hex");

const fail = (output: string): TIntegrationResult => {
  logError("integrations", output);
  return { ok: false, code: 1, output };
};

const fetchPointer = async (
  cloudOrigin: string,
  area: "setup",
  slug: string,
): Promise<{
  readonly scriptUrl: string;
  readonly scriptSha256: string;
} | null> => {
  try {
    const response = await fetch(
      `${cloudOrigin}/api/${area}/${encodeURIComponent(slug)}/pointer`,
      {
        redirect: "manual",
        signal: AbortSignal.timeout(FETCH_TIMEOUT_MS),
      },
    );
    if (!response.ok || response.status >= 300) return null;
    const body = (await response.json()) as {
      script_url?: unknown;
      script_sha256?: unknown;
    };
    if (
      typeof body.script_url !== "string" ||
      typeof body.script_sha256 !== "string" ||
      !SHA256_RE.test(body.script_sha256)
    ) {
      return null;
    }
    validateRegistryRawUrl(body.script_url, {
      area,
      slug,
      filename: "install.sh",
    });
    return {
      scriptUrl: body.script_url,
      scriptSha256: body.script_sha256,
    };
  } catch {
    return null;
  }
};

export const runIntegration = async (
  kind: TIntegrationKind,
  mode: TIntegrationMode,
  slug: string,
  target = "claude-code",
): Promise<TIntegrationResult> => {
  const { cloudOrigin, apiKey } = daemonEnv();
  const area = AREA[kind];
  const pointer = await fetchPointer(cloudOrigin, area, slug);
  if (pointer === null) {
    return fail(
      `integrity: no validated pointer for ${area}/${slug} — refusing to run`,
    );
  }

  let response: Response;
  try {
    response = await fetch(pointer.scriptUrl, {
      redirect: "manual",
      signal: AbortSignal.timeout(FETCH_TIMEOUT_MS),
    });
  } catch (error) {
    return fail(
      `fetch ${pointer.scriptUrl} failed: ${error instanceof Error ? error.message : String(error)}`,
    );
  }
  if (!response.ok || response.status >= 300) {
    return fail(`fetch ${pointer.scriptUrl} → ${response.status}`);
  }
  const bytes = new Uint8Array(await response.arrayBuffer());
  const actual = sha256Hex(bytes);
  if (actual !== pointer.scriptSha256) {
    return fail(
      `integrity mismatch for ${area}/${slug}: expected ${pointer.scriptSha256} got ${actual} — refusing to run`,
    );
  }

  const scriptPath = path.join(
    daemonTempDir(),
    `registry-${area}-${slug}-${process.pid}-${Date.now()}.sh`,
  );
  fs.writeFileSync(scriptPath, bytes, { mode: 0o600, flag: "wx" });
  try {
    const { OPENLLM_API_KEY: _omit, ...baseEnv } = process.env;
    const pathValue = [...DEFAULT_BIN_DIRS, baseEnv.PATH ?? ""]
      .filter((entry) => entry.length > 0)
      .join(":");
    const shared = {
      ...baseEnv,
      OPENLLM_SKIP_CLI_INSTALL: "1",
      OPENLLM_CLOUD_ORIGIN: cloudOrigin,
      PATH: pathValue,
    };
    const env =
      mode === "install"
        ? { ...shared, OPENLLM_API_KEY: apiKey ?? "" }
        : shared;
    const modeArgs =
      mode === "uninstall" ? ["-u"] : mode === "state" ? ["-s"] : [];
    const proc = Bun.spawn(
      ["bash", scriptPath, ...modeArgs, "--target", target],
      {
        env,
        cwd: daemonTempDir(),
        stdout: "pipe",
        stderr: "pipe",
        timeout: SCRIPT_TIMEOUT_MS,
      },
    );
    const [stdout, stderr, code] = await Promise.all([
      new Response(proc.stdout).text(),
      new Response(proc.stderr).text(),
      proc.exited,
    ]);
    const output = `${stdout}${stderr}`.trim();
    const redact = (value: string): string =>
      apiKey ? value.split(apiKey).join("[REDACTED_OPENLLM_API_KEY]") : value;
    const safeOutput = redact(output);
    if (proc.signalCode !== null) {
      logError("integrations", `${mode} ${kind} ${slug}: script killed`, {
        signal: proc.signalCode,
        output: safeOutput.slice(-2000),
      });
    } else if (code !== 0) {
      logError("integrations", `${mode} ${kind} ${slug} failed`, {
        code,
        output: safeOutput.slice(-2000),
      });
    } else if (mode === "state") {
      logDebug("integrations", `${mode} ${kind} ${slug}`, { ok: true, code });
    } else {
      logInfo("integrations", `${mode} ${kind} ${slug}`, { ok: true, code });
    }
    return {
      ok: code === 0 && proc.signalCode === null,
      code,
      output: safeOutput.slice(-4000),
      scriptSha256: pointer.scriptSha256,
    };
  } finally {
    fs.rmSync(scriptPath, { force: true });
  }
};
