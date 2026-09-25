/**
 * Per-turn Muse execution overlay — fresh HOME + isolated XDG with ONLY a
 * symlink to the provider-owned auth.json and a gateway-written settings.json.
 *
 * Durable auth (delegation) lives at:
 *   `$providerHome/.config/muse/auth.json` (= cliConfigDir("muse")/auth.json)
 *
 * Official muse-bin has no `MUSE_SETTINGS_PATH` / `--settings` override (static
 * string scan of 1.3.0-R3401.1). Settings are only read from
 * `$XDG_CONFIG_HOME/muse/settings.json` (ACP mcp-overlay same contract). So
 * per-request MCP/model settings MUST be a real file under a private overlay
 * config home — never written into the durable provider settings.json
 * (concurrent turns would clobber each other and leave bearer tokens after
 * cleanup). Auth is the sole durable link (symlink), matching ACP's
 * mirror-except-settings pattern. Atomic replace of auth.json through a leaf
 * symlink can leave the durable file unchanged — accepted limitation without
 * an official split-config path; do not “fix” by sharing XDG_CONFIG_HOME.
 *
 * Callers MUST place `parentDir` OUTSIDE the MSP `workspaceRoot`. Absolute-path
 * reads of HOME are a residual host-policy risk.
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
   * XDG_* / CODEX_HOME so ambient skill roots cannot load. `MUSE_AUTH_PATH`
   * always points at the durable provider auth.json (symlink target) so the
   * official bash launcher (which reads `MUSE_AUTH_PATH`, then execs muse-bin)
   * cannot lose the store when overlay HOME differs; muse-bin itself resolves
   * credentials via XDG/`TBH_CREDENTIAL_BACKEND`, not `MUSE_AUTH_PATH`.
   */
  readonly env: {
    readonly HOME: string;
    readonly XDG_CONFIG_HOME: string;
    readonly XDG_DATA_HOME: string;
    readonly XDG_STATE_HOME: string;
    readonly CODEX_HOME: string;
    readonly MUSE_AUTH_PATH: string;
  };
  /** Absolute overlay muse/settings.json (tests / diagnostics). */
  readonly settingsPath: string;
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
 * Create a mode-0700 turn overlay. Fresh HOME + XDG config; auth.json
 * symlinked from the durable provider store; settings.json written ONLY in
 * the overlay (MCP + model). Never mutates durable settings.json. Cleans up
 * the root on any setup failure so partial overlays do not leak.
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

    const durableAuth = museAuthJsonPath(params.baseEnv);
    linkAuthIfPresent(durableAuth, join(museDir, "auth.json"));

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
        // Launcher-only override (muse-bin does not read this). Pin the durable
        // store so a launcher entrypoint never depends solely on the overlay symlink.
        MUSE_AUTH_PATH: durableAuth,
      },
      settingsPath,
      cleanup,
    };
  } catch (error) {
    await cleanup().catch(() => {});
    throw error;
  }
};
