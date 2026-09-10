import { opaqueDoctorCorrelation } from "../doctor-report/correlation";
import { logInfo, safeDiagnosticMessage } from "../logger";
import type { TNativeAuthProducer } from "./spawn";

/** Local phase labels. Not doctor-report fields. */
export type TNativeAuthLifecyclePhase =
  | "readiness_wait"
  | "readiness"
  | "start"
  | "child_wait"
  | "child"
  | "prep_wait"
  | "prep"
  | "verify_wait"
  | "verify"
  | "terminal";

export type TNativeAuthLifecycleConfig = {
  readonly scope: string;
  readonly producer: TNativeAuthProducer;
  readonly operationId?: string;
};

/** Bounded per-attempt logging; independent of doctor-report batching. */
const MAX_STAGE_RECORDS = 32;

const STAGE_MESSAGE: Record<
  TNativeAuthLifecyclePhase,
  ReturnType<typeof safeDiagnosticMessage>
> = {
  readiness_wait: safeDiagnosticMessage`Native authentication readiness waiting.`,
  readiness: safeDiagnosticMessage`Native authentication readiness completed.`,
  start: safeDiagnosticMessage`Native authentication started.`,
  child_wait: safeDiagnosticMessage`Native authentication child waiting.`,
  child: safeDiagnosticMessage`Native authentication child completed.`,
  prep_wait: safeDiagnosticMessage`Native authentication preparation waiting.`,
  prep: safeDiagnosticMessage`Native authentication preparation completed.`,
  verify_wait: safeDiagnosticMessage`Native authentication verification waiting.`,
  verify: safeDiagnosticMessage`Native authentication verification completed.`,
  terminal: safeDiagnosticMessage`Native authentication attempt finished.`,
};

/**
 * Bounded per-attempt stage recorder. Info stages never throw.
 * Durations are `performance.now()` deltas on both local meta and doctor timings.
 */
export const createNativeAuthLifecycle = (
  cfg: TNativeAuthLifecycleConfig,
): {
  readonly mark: () => number;
  readonly record: (
    phase: TNativeAuthLifecyclePhase,
    startedAtMs?: number,
  ) => void;
} => {
  const attemptStartedAtMs = performance.now();
  let remaining = MAX_STAGE_RECORDS;
  const correlation_id = opaqueDoctorCorrelation(cfg.operationId);
  return {
    mark: (): number => performance.now(),
    record: (phase, startedAtMs): void => {
      if (remaining <= 0) return;
      remaining -= 1;
      const elapsed_ms = Math.max(
        0,
        performance.now() - (startedAtMs ?? attemptStartedAtMs),
      );
      try {
        logInfo(
          cfg.scope,
          STAGE_MESSAGE[phase],
          {
            producer: cfg.producer,
            phase,
            clock: "performance.now",
            elapsed_ms,
            ...(correlation_id !== undefined
              ? { operation_id: correlation_id }
              : {}),
          },
          {
            timings: { elapsed_ms },
            ...(correlation_id !== undefined ? { correlation_id } : {}),
          },
        );
      } catch {
        // Reporting must never change login/logout outcome.
      }
    },
  };
};
