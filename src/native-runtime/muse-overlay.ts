/**
 * Per-turn Muse execution overlay — fresh HOME + isolated XDG with ONLY a
 * symlink to the provider-owned auth.json and a gateway-written settings.json.
 *
 * Durable auth (delegation) lives at:
 *   `$providerHome/.config/muse/auth.json` (= cliConfigDir("muse")/auth.json)
 *
 * Callers MUST place `parentDir` OUTSIDE the MSP `workspaceRoot`. The auth
 * symlink lives under this overlay HOME; keeping it outside the workspace
 * is the enforceable read boundary against workspace-scoped known-safe
 * reads. Absolute-path reads of HOME are a residual host-policy risk.
 *
 * The serve child must NOT see ambient HOME skills/hooks (`.agents`, `.claude`,
 * `.codex`, `CODEX_HOME`) or user Muse settings/MCP. PATH is preserved from the
 * cleaned spawn env so the fixed muse binary resolution still works.
 */

import {
  chmodSync,
  lstatSync,
  mkdirSync,
  symlinkSync,
  writeFileSync,
} from "node:fs";
import { mkdir, mkdtemp, rm } from "node:fs/promises";
import { homedir, tmpdir } from "node:os";
import { join } from "node:path";
import type { TMuseMcpServer } from "./muse-mcp-server";

export type TMuseOverlay = {
  /**
   * Env overlay merged onto a cleaned Muse spawn env. Replaces HOME and all
   * XDG_* / CODEX_HOME so ambient skill roots cannot load.
   */
  readonly env: {
    readonly HOME: string;
    readonly XDG_CONFIG_HOME: string;
    readonly XDG_DATA_HOME: string;
    readonly XDG_STATE_HOME: string;
    readonly CODEX_HOME: string;
  };
  readonly cleanup: () => Promise<void>;
};

const isNodeError = (error: unknown): error is NodeJS.ErrnoException =>
  error instanceof Error && "code" in error;

/** Resolve the durable provider auth.json from the pre-overlay env. */
export const museAuthJsonPath = (
  env: NodeJS.ProcessEnv | Record<string, string>,
): string => {
  const home = env.HOME ?? homedir();
  const configHome = env.XDG_CONFIG_HOME ?? join(home, ".config");
  return join(configHome, "muse", "auth.json");
};

const linkAuthIfPresent = (sourceAuth: string, destAuth: string): void => {
  try {
    const st = lstatSync(sourceAuth);
    if (!st.isFile() && !st.isSymbolicLink()) return;
  } catch (error) {
    if (isNodeError(error) && error.code === "ENOENT") return;
    throw error;
  }
  symlinkSync(sourceAuth, destAuth);
};

/**
 * Create a mode-0700 turn overlay. Fresh HOME; auth.json symlinked from the
 * durable provider store; settings.json written with only caller MCP + model.
 * Never copies ambient settings/skills/hooks. Cleans up the root on any
 * setup failure so partial overlays do not leak.
 */
export const createMuseExecutionOverlay = async (params: {
  readonly baseEnv: NodeJS.ProcessEnv | Record<string, string>;
  readonly mcp: TMuseMcpServer | null;
  readonly modelId?: string;
  readonly providerId?: string;
  readonly parentDir?: string;
}): Promise<TMuseOverlay> => {
  const root = await mkdtemp(
    join(params.parentDir ?? tmpdir(), "muse-overlay-"),
  );
  chmodSync(root, 0o700);

  const cleanup = async (): Promise<void> => {
    await rm(root, { recursive: true, force: true });
  };

  try {
    // Fresh HOME — not the provider home — so ~/.agents, ~/.claude, ~/.codex
    // from the durable tree cannot load. Auth is the only durable link.
    const home = join(root, "home");
    const configHome = join(home, ".config");
    const dataHome = join(home, ".local", "share");
    const stateHome = join(home, ".local", "state");
    const codexHome = join(home, ".codex");
    await mkdir(home, { recursive: true, mode: 0o700 });
    await mkdir(configHome, { recursive: true, mode: 0o700 });
    await mkdir(dataHome, { recursive: true, mode: 0o700 });
    await mkdir(stateHome, { recursive: true, mode: 0o700 });
    await mkdir(codexHome, { recursive: true, mode: 0o700 });

    const museDir = join(configHome, "muse");
    mkdirSync(museDir, { mode: 0o700 });

    linkAuthIfPresent(
      museAuthJsonPath(params.baseEnv),
      join(museDir, "auth.json"),
    );

    const mcpServers =
      params.mcp === null
        ? {}
        : {
            [params.mcp.name]: {
              type: "http",
              mode: "required",
              url: params.mcp.url,
              headers: Object.fromEntries(
                params.mcp.headers.map(({ name, value }) => [name, value]),
              ),
            },
          };

    const settings: Record<string, unknown> = {
      schema_version: 1,
      mcpServers,
      ...(params.modelId !== undefined ? { model: params.modelId } : {}),
      ...(params.providerId !== undefined
        ? { provider: params.providerId }
        : {}),
    };
    const settingsPath = join(museDir, "settings.json");
    writeFileSync(settingsPath, `${JSON.stringify(settings, null, 2)}\n`, {
      mode: 0o600,
    });
    chmodSync(settingsPath, 0o600);

    return {
      env: {
        HOME: home,
        XDG_CONFIG_HOME: configHome,
        XDG_DATA_HOME: dataHome,
        XDG_STATE_HOME: stateHome,
        CODEX_HOME: codexHome,
      },
      cleanup,
    };
  } catch (error) {
    await cleanup().catch(() => {});
    throw error;
  }
};
