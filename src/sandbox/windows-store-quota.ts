/**
 * Windows writable-store quota accounting + bounded recovery — the
 * platform-independent decision logic for the quota-volume mount.
 *
 * Two things live here, deliberately split from the kernel side so they can
 * be exercised by `bun test` on any host (a kernel-backed volume needs a real
 * Windows kernel and admin privilege — SeManageVolumePrivilege — and is
 * exercised by a hardware probe instead, following the `repair/*-test.ts`
 * pattern used elsewhere in this codebase):
 *
 *  1. `CapacityLedger` — a backend-agnostic capacity accountant. Given a
 *     `VolumeBackend`, every `reserve()` call either fully commits or fully
 *     refuses: an over-budget write throws before any bytes are counted as
 *     landed, matching the real backend's ERROR_DISK_FULL semantics (the OS
 *     refuses, the caller never queries "is there room?" first). This is the
 *     GREEN counterpart to `UnboundedStore` below.
 *  2. `RecoveryLedger` — the state machine for interrupted/repeated
 *     recovery, broker/formatter death, and restart retention, plus
 *     `classifyLeaseRecord` for fail-closed record handling. It mirrors the
 *     shape of the launcher's `RecoverStaleLocked`/`RecoveryAcl`/`LeaseText`
 *     so the two recovery passes (task root,
 *     quota volume) reason about staleness the same way.
 */

export class QuotaExceededError extends Error {
  constructor(
    public readonly storeId: string,
    public readonly requestedBytes: number,
    public readonly budgetBytes: number,
  ) {
    super(
      `store "${storeId}" refused ${requestedBytes} bytes: budget is ${budgetBytes} bytes`,
    );
  }
}

/** What a kernel-backed store must provide. A real fixed-size NTFS volume
 *  satisfies this contract on the OS side; tests use
 *  `FakeKernelVolume` below. */
export interface VolumeBackend {
  readonly budgetBytes: number;
  readonly usedBytes: number;
  /** All-or-nothing: either every byte lands, or none do and a
   *  `QuotaExceededError` is thrown. Never "admits some, refuses the rest". */
  write(bytes: number): void;
}

/** Deterministic in-memory stand-in for a fixed-size kernel volume. Real
 *  disks refuse at the OS layer with zero partial writes; this backend
 *  reproduces exactly that contract for tests, without touching any disk. */
export class FakeKernelVolume implements VolumeBackend {
  #used = 0;
  constructor(
    public readonly storeId: string,
    public readonly budgetBytes: number,
  ) {
    if (!Number.isInteger(budgetBytes) || budgetBytes <= 0)
      throw new Error("budget must be a positive integer");
  }
  get usedBytes(): number {
    return this.#used;
  }
  write(bytes: number): void {
    if (!Number.isInteger(bytes) || bytes < 0)
      throw new Error("write size must be a nonnegative integer");
    if (this.#used + bytes > this.budgetBytes)
      throw new QuotaExceededError(this.storeId, bytes, this.budgetBytes);
    this.#used += bytes;
  }
}

/** RED fixture: a store with no capacity check at all — the shape of the
 *  defect this lane closes. Kept here (not deleted once GREEN lands) so the
 *  regression stays expressible: swapping `CapacityLedger`'s backend for this
 *  one is exactly the bug that let 256 small values write 1 MiB outside
 *  declared work in the registry store before its fix. */
export class UnboundedStore implements VolumeBackend {
  #used = 0;
  constructor(public readonly budgetBytes: number) {}
  get usedBytes(): number {
    return this.#used;
  }
  write(bytes: number): void {
    this.#used += bytes; // no check against budgetBytes — the bug
  }
}

/** Accounts writes against a `VolumeBackend`, refusing (via the backend) any
 *  write that would exceed budget. Thin on purpose: the interesting
 *  guarantee — refusal is external and all-or-nothing — lives in the backend
 *  contract, not here. */
export class CapacityLedger {
  constructor(private readonly backend: VolumeBackend) {}
  get usedBytes(): number {
    return this.backend.usedBytes;
  }
  get budgetBytes(): number {
    return this.backend.budgetBytes;
  }
  reserve(bytes: number): void {
    this.backend.write(bytes);
  }
}

// ---------------------------------------------------------------------------
// Bounded recovery
// ---------------------------------------------------------------------------

export type QuotaVolumeState = "creating" | "mounted" | "released";

export interface QuotaVolumeRecord {
  storeId: string;
  owner: string;
  budgetBytes: number;
  state: QuotaVolumeState;
  /** Lease text written to disk once mounted (`.quota-lease`), or undefined
   *  before mounting completes. Mirrors the launcher's `LeaseText`. */
  leaseText?: string;
}

export const quotaLeaseText = (storeId: string, owner: string): string =>
  `openllm-quota-volume-v1\n${owner}\n${storeId}\n`;

export type LeaseVerdict =
  | "ok"
  | "locked-invalid"
  | "malformed"
  | "alias-or-reparse"
  | "legacy";

/**
 * Fail-closed classification of an on-disk `.quota-lease` record found during
 * recovery. Only "ok" may proceed to release a volume; every other verdict
 * must leave the record — and everything behind it — untouched. `isReparse`
 * covers both "the marker file is a reparse point" and "its containing mount
 * point is aliased" (junction/symlink), matching the alias checks
 * `RecoverStaleLocked` already applies to task roots.
 */
export const classifyLeaseRecord = (input: {
  text: string | null; // null == open/read failed (locked by another handle, permissions, etc.)
  isReparse: boolean;
  expectedOwner: string;
  expectedStoreId: string;
}): LeaseVerdict => {
  if (input.isReparse) return "alias-or-reparse";
  if (input.text === null) return "locked-invalid";
  const lines = input.text.split("\n");
  if (lines.length !== 4 || lines[3] !== "") return "malformed";
  const [version, owner, storeId] = lines;
  if (version !== "openllm-quota-volume-v1")
    return version.startsWith("openllm-task-recovery") ? "legacy" : "malformed";
  if (owner !== input.expectedOwner || storeId !== input.expectedStoreId)
    return "malformed";
  return "ok";
};

/**
 * Recovery state for every quota volume a daemon instance knows about.
 * Serializable end to end so a restart resumes accounting exactly where a
 * prior process left off (numeric bar: "quota survives daemon restart").
 */
export class RecoveryLedger {
  private readonly records = new Map<string, QuotaVolumeRecord>();

  static fromJSON(json: string): RecoveryLedger {
    const ledger = new RecoveryLedger();
    const parsed = JSON.parse(json) as QuotaVolumeRecord[];
    for (const record of parsed)
      ledger.records.set(record.storeId, { ...record });
    return ledger;
  }
  toJSON(): string {
    return JSON.stringify([...this.records.values()]);
  }

  beginCreate(storeId: string, owner: string, budgetBytes: number): void {
    if (this.records.has(storeId))
      throw new Error(`store "${storeId}" already tracked`);
    this.records.set(storeId, {
      storeId,
      owner,
      budgetBytes,
      state: "creating",
    });
  }
  markMounted(storeId: string): void {
    const record = this.require(storeId);
    record.state = "mounted";
    record.leaseText = quotaLeaseText(storeId, record.owner);
  }
  /** Idempotent: releasing an already-released or never-tracked store is a
   *  no-op, not an error — repeated recovery (or a second broker/formatter
   *  death signal for the same store) must converge, never throw. */
  release(storeId: string): void {
    const record = this.records.get(storeId);
    if (!record) return;
    record.state = "released";
    delete record.leaseText;
  }
  get(storeId: string): QuotaVolumeRecord | undefined {
    const record = this.records.get(storeId);
    return record ? { ...record } : undefined;
  }
  private require(storeId: string): QuotaVolumeRecord {
    const record = this.records.get(storeId);
    if (!record) throw new Error(`store "${storeId}" not tracked`);
    return record;
  }

  /**
   * Reclaim every non-released record NOT in `liveOwners`, within
   * `deadlineMs`. Bounded like `RecoverStaleLocked`'s 5-second budget: a
   * recovery pass that can't finish in time throws rather than running
   * unbounded, and — because `release` is idempotent — killing the process
   * mid-pass and calling `recoverStale` again always reaches the same clean
   * state (interrupted recovery / repeated recovery, both covered by one
   * code path).
   */
  recoverStale(
    liveOwners: ReadonlySet<string>,
    deadlineMs: number,
    now: () => number = Date.now,
  ): string[] {
    const start = now();
    const recovered: string[] = [];
    for (const record of this.records.values()) {
      if (record.state === "released" || liveOwners.has(record.owner)) continue;
      if (now() - start > deadlineMs)
        throw new Error("quota recovery deadline exceeded");
      this.release(record.storeId);
      recovered.push(record.storeId);
    }
    return recovered;
  }

  /** True once every tracked record is released — the convergence point
   *  "repeated recovery is idempotent" must reach and stay at. */
  isFullyReleased(): boolean {
    return [...this.records.values()].every(
      (record) => record.state === "released",
    );
  }
}
