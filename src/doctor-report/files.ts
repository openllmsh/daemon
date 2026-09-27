/**
 * Owner-only atomic JSON/text writes for doctor-report state.
 * Interrupted writes must not leave a half-decoded checkpoint.
 *
 * NO-CREATE contract: writers here never create the parent directory. The
 * doctor state dir IS the daemon state dir, which daemon boot creates — a
 * missing parent at write time means the process outlived an
 * uninstall/teardown, and the write must be dropped rather than resurrect
 * the removed dir (TH-6 residual: an `existsSync` guard alone still loses to
 * a teardown landing between the check and the mkdir).
 */
import {
  chmodSync,
  closeSync,
  fsyncSync,
  openSync,
  readFileSync,
  renameSync,
  unlinkSync,
  writeFileSync,
} from "node:fs";
import { dirname, join } from "node:path";
import { stateDir } from "../env";

const FILE_MODE = 0o600;

export const doctorStateDir = (): string => stateDir();

export const doctorStatePath = (basename: string): string =>
  join(doctorStateDir(), basename);

type TAtomicWrite = (path: string, contents: string) => boolean;

let atomicWriteForTests: TAtomicWrite | null = null;

export const setAtomicWriteForTests = (fn: TAtomicWrite | null): void => {
  atomicWriteForTests = fn;
};

export const readTextFile = (path: string): string | null => {
  try {
    return readFileSync(path, "utf8");
  } catch {
    return null;
  }
};

/**
 * Atomic replace of `path` with `contents` — O_CREAT/O_TRUNC on the tmp file
 * then rename. The parent directory must ALREADY exist: this is the no-create
 * write mode used for every doctor-report write. When the state dir was
 * removed mid-process (uninstall/teardown), `openSync` fails ENOENT and the
 * write drops — the path contains no mkdir, so the dir can never resurrect,
 * even if it vanished between a caller's existence check and the open.
 */
export const atomicWriteText = (path: string, contents: string): boolean => {
  if (atomicWriteForTests !== null) return atomicWriteForTests(path, contents);
  try {
    const tmp = `${path}.${process.pid}.tmp`;
    const fd = openSync(tmp, "w", FILE_MODE);
    try {
      writeFileSync(fd, contents, { encoding: "utf8" });
      fsyncSync(fd);
    } finally {
      closeSync(fd);
    }
    try {
      chmodSync(tmp, FILE_MODE);
    } catch {
      // ignore
    }
    renameSync(tmp, path);
    try {
      chmodSync(path, FILE_MODE);
    } catch {
      // ignore
    }
    // The write landed inside the daemon state dir — re-pin that dir to
    // 0o700 too (it carries credentials and session state; a looser mode
    // left by an older bug or a manual fix must not persist past a write
    // that proves the dir is live). Best-effort: a chmod failure never
    // fails the write itself.
    try {
      chmodSync(dirname(path), 0o700);
    } catch {
      // ignore
    }
    return true;
  } catch {
    return false;
  }
};

export const removeFile = (path: string): void => {
  try {
    unlinkSync(path);
  } catch {
    // missing is fine
  }
};

export const parentDir = (path: string): string => dirname(path);
