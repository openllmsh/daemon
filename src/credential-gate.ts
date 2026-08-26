import { spawnSync } from "node:child_process";
import { closeSync, openSync, readSync } from "node:fs";
import { isOpenllmApiKeySyntax } from "@openllmsh/protocol";
import {
  applyPersistedApiKey,
  daemonEnv,
  envFilePath,
  envFileValue,
  isDevMode,
  sharedEnvFilePath,
  writeEnvFileVars,
} from "./env";

export type TCredentialGateMode = "human" | "machine";

export type TCredentialGateResult =
  | { readonly ok: true }
  | { readonly ok: false; readonly message: string };

// A successful gate result is registered by identity, not by a forgeable boolean.
// Lifecycle internals use this boundary instead of a public skip flag.
const approvedGates = new WeakSet<object>();

export const hasCredentialProof = (result: TCredentialGateResult): boolean =>
  result.ok && approvedGates.has(result);

const approved = (): TCredentialGateResult => {
  const result: TCredentialGateResult = { ok: true };
  approvedGates.add(result);
  return result;
};

export type TCredentialGateTerminal = {
  readonly isInteractive: () => boolean;
  readonly promptForKey: () => string | null;
  readonly write: (message: string) => void;
};

/** A local envelope check only; cloud authentication remains authoritative. */
export const isUsableApiKey = (value: string | null | undefined): boolean =>
  value !== null && value !== undefined && isOpenllmApiKeySyntax(value.trim());

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

const persistServiceKey = (key: string, targetPath: string): boolean => {
  if (!writeEnvFileVars({ OPENLLM_API_KEY: key }, targetPath)) return false;
  applyPersistedApiKey(key);
  return true;
};

const persistedUsableKey = (targetPath: string): string | null => {
  const value = envFileValue(targetPath, "OPENLLM_API_KEY");
  return value !== null && isUsableApiKey(value) ? value.trim() : null;
};

const configuredUsableKey = (): string | null => {
  const value = daemonEnv().apiKey;
  return value !== null && isUsableApiKey(value) ? value.trim() : null;
};

const isReadOnlyDevKey = (key: string): boolean => {
  if (!isDevMode()) return false;
  const devKey = persistedUsableKey(envFilePath());
  const sharedKey = persistedUsableKey(sharedEnvFilePath());
  return devKey === key || sharedKey === key;
};

/**
 * Resolve a usable service key without mutating service state. Human callers may
 * acquire a missing/malformed key from the controlling terminal; machine callers
 * receive one stable stderr-safe diagnostic instead.
 */
export const requireServiceApiKey = (
  mode: TCredentialGateMode,
  terminal: TCredentialGateTerminal = defaultTerminal,
  targetPath: string = envFilePath(),
): TCredentialGateResult => {
  // A durable valid key is already authoritative. Never rewrite it just because
  // the process inherited the same (or another) valid value.
  if (persistedUsableKey(targetPath) !== null) return approved();

  const configured = configuredUsableKey();
  // Headless service boots are presence-only: no secret write and no prompt.
  if (mode === "machine") {
    return configured === null
      ? { ok: false, message: missingKeyDiagnostic() }
      : approved();
  }

  // A production service may inherit a key from its launching environment. Make
  // that transient value durable in the precise file its supervisor will read.
  // Do not copy dev's read-only shared-key fallback into any file.
  if (configured !== null && !isReadOnlyDevKey(configured)) {
    if (persistServiceKey(configured, targetPath)) return approved();
    return { ok: false, message: "[openllm] Could not save the API key.\n" };
  }

  if (!terminal.isInteractive()) {
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
    if (!persistServiceKey(pasted.trim(), targetPath)) {
      return { ok: false, message: "[openllm] Could not save the API key.\n" };
    }
    terminal.write(`Saved to ${targetPath}.\n`);
    return approved();
  }
};
