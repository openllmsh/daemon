import { spawnSync } from "node:child_process";
import { closeSync, openSync, readSync } from "node:fs";
import {
  daemonEnv,
  resetDaemonEnvCacheForTest,
  serviceEnvFilePath,
  writeEnvFileVars,
} from "./env";

export type TCredentialGateMode = "human" | "machine";

export type TCredentialGateResult =
  | { readonly ok: true }
  | { readonly ok: false; readonly message: string };

export type TCredentialGateTerminal = {
  readonly isInteractive: () => boolean;
  readonly promptForKey: () => string | null;
  readonly write: (message: string) => void;
};

/** A local envelope check only; cloud authentication remains authoritative. */
export const isUsableApiKey = (value: string | null | undefined): boolean => {
  if (value === null || value === undefined) return false;
  const trimmed = value.trim();
  return (
    trimmed.length > "sk-llm-".length &&
    !/[\r\n\0\s]/.test(trimmed) &&
    /^sk-llm-[^.]+\.[^.]+$/.test(trimmed)
  );
};

const signInUrl = (): string => `${daemonEnv().cloudOrigin}/sign-in`;

export const missingKeyDiagnostic = (): string =>
  `[openllm] API key required.\nRun \`openllm start\` in an interactive terminal and sign in at ${signInUrl()}. New users receive a key during onboarding; returning users can open Keys after signing in. Paste the key when prompted.\n`;

const readHiddenLine = (): string | null => {
  let fd: number | null = null;
  try {
    fd = openSync("/dev/tty", "r+");
    const disabled = spawnSync("stty", ["-echo"], {
      stdio: [fd, fd, fd],
    });
    if (disabled.status !== 0) return null;
    try {
      const bytes: number[] = [];
      const buffer = Buffer.alloc(1);
      while (true) {
        const count = readSync(fd, buffer, 0, 1, null);
        if (count === 0) return null;
        if (buffer[0] === 10 || buffer[0] === 13) break;
        bytes.push(buffer[0]);
      }
      return Buffer.from(bytes).toString("utf8");
    } finally {
      spawnSync("stty", ["echo"], { stdio: [fd, fd, fd] });
      process.stderr.write("\n");
    }
  } catch {
    return null;
  } finally {
    if (fd !== null) closeSync(fd);
  }
};

const defaultTerminal: TCredentialGateTerminal = {
  isInteractive: (): boolean =>
    process.stdin.isTTY === true && process.stderr.isTTY === true,
  promptForKey: (): string | null => {
    process.stderr.write("API key: ");
    return readHiddenLine();
  },
  write: (message: string): void => {
    process.stderr.write(message);
  },
};

const persistServiceKey = (key: string): boolean => {
  if (!writeEnvFileVars({ OPENLLM_API_KEY: key }, serviceEnvFilePath())) {
    return false;
  }
  process.env.OPENLLM_API_KEY = key;
  resetDaemonEnvCacheForTest();
  return true;
};

/**
 * Resolve a usable service key without mutating service state. Human callers may
 * acquire a missing/malformed key from the controlling terminal; machine callers
 * receive one stable stderr-safe diagnostic instead.
 */
export const requireServiceApiKey = (
  mode: TCredentialGateMode,
  terminal: TCredentialGateTerminal = defaultTerminal,
): TCredentialGateResult => {
  const configured = daemonEnv().apiKey;
  if (configured !== null && isUsableApiKey(configured)) {
    if (persistServiceKey(configured.trim())) return { ok: true };
    return { ok: false, message: "[openllm] Could not save the API key.\n" };
  }

  if (mode === "machine" || !terminal.isInteractive()) {
    return { ok: false, message: missingKeyDiagnostic() };
  }

  terminal.write(
    `${configured === null ? "OpenLLM needs an API key." : "The configured API key format is invalid."}\nSign in at ${signInUrl()}.\nNew users will receive a key during onboarding. Already have an account? Open Keys after signing in.\n`,
  );
  while (true) {
    const pasted = terminal.promptForKey();
    if (pasted === null || pasted.trim().length === 0) {
      return { ok: false, message: "[openllm] API key setup cancelled.\n" };
    }
    if (!isUsableApiKey(pasted)) {
      terminal.write("The API key format is invalid. Please try again.\n");
      continue;
    }
    if (!persistServiceKey(pasted.trim())) {
      return { ok: false, message: "[openllm] Could not save the API key.\n" };
    }
    terminal.write(`Saved to ${serviceEnvFilePath()}.\n`);
    return { ok: true };
  }
};
