/**
 * Windows writable-store map — every physically-writable location the daemon
 * creates on behalf of a single confined task, with its capacity budget.
 *
 * This is written as data, not prose, on purpose: `windows-store-quota.ts`
 * (the accounting/recovery logic) and the retired kernel-volume mount
 * prototype (the *unwired* kernel-backed enforcement for the
 * filesystem-backed stores) both key off `id` here, so the declared bound
 * and the enforced bound cannot drift apart silently.
 *
 * `enforcement` records HOW a budget is made real, not just declared:
 *  - "kernel-volume": the store is mounted inside a fixed-size NTFS volume.
 *    Once the volume is full, the OS itself returns
 *    ERROR_DISK_FULL/STATUS_DISK_FULL to the write — no daemon polling is
 *    involved in the refusal, and zero bytes of an over-budget write land.
 *    The mount was prototyped but is NOT wired into the confined-task
 *    launcher: attaching/formatting a VHD-backed volume needs
 *    `SeManageVolumePrivilege`, which the daemon's default, non-admin
 *    (`RequireWin32kDenial=true`) path does not have. Integrating this
 *    without either elevating the daemon or finding a non-admin mechanism
 *    would break task creation for the common case, so it stays unwired
 *    until that's resolved — tracked by this store staying `qualified: false`.
 *  - "kernel-registry-hive": the launcher's package-registry seal ACLs the
 *    package's registry storage to read-only for the package token *before*
 *    the confined child is ever created (the `stage="seal_package_registry"`
 *    step runs before process creation). That makes further growth
 *    impossible, not just improbable — a stronger guarantee than a measured
 *    size cap, and the one `repair/windows-registry-boundary-test.ts`
 *    exercises against a real compiled daemon
 *    (`registry-write-open`/`registry-create` denied). `budgetBytes` here is
 *    the declared ceiling on what the OS may have written before the seal
 *    runs, not a metered runtime limit.
 *  - "fixed-write-once": a short, fixed-format record opened with
 *    `FileMode.CreateNew` semantics (the launcher's lease write), which fails
 *    if the file already exists. There is nothing to meter because the code
 *    shape rules out a second write, not because a kernel quota is attached.
 *  - "count-bound": no *byte* budget applies; the OS already bounds the
 *    number of live kernel objects here (Job Object membership is capped at
 *    16 active processes by the launcher), so there is nothing left to meter.
 */

export type WindowsStoreEnforcement =
  | "kernel-volume"
  | "kernel-registry-hive"
  | "fixed-write-once"
  | "count-bound";

export interface WindowsStoreBudget {
  /** Stable id. Used as the backing volume/hive's basename and in evidence
   *  records — renaming this is a breaking change for anything recovering a
   *  stale store created under the old id. */
  id: string;
  /** One-line description of what physically lands in this store. */
  description: string;
  /** Path relative to a task's root directory (the confined-task launcher's
   *  `root`), or `null` when the store isn't a filesystem path (registry,
   *  named kernel objects). */
  relativePath: string | null;
  enforcement: WindowsStoreEnforcement;
  /** Fixed physical budget in bytes, or `null` for count-bound/write-once stores. */
  budgetBytes: number | null;
  /** Whether a kernel-backed (or, for "fixed-write-once", code-shape-backed)
   *  bound actually exists in the confined-task launcher today — not
   *  whether one is designed or prototyped elsewhere. Kept separate from
   *  `enforcement` (the intended mechanism) so the map can honestly describe
   *  a store whose mechanism is chosen but not yet integrated, instead of
   *  that gap surviving silently until a hardware probe notices it. */
  qualified: boolean;
}

export const WINDOWS_STORE_MAP: readonly WindowsStoreBudget[] = [
  {
    id: "task-work-tree",
    description:
      "Confined command's writable work directory (HOME/USERPROFILE) plus its " +
      "AppData/Local, AppData/Roaming and tmp/TEMP/TMP scratch — everything under `work`. " +
      "Nothing in the confined-task launcher bounds its physical size today; disk usage " +
      "is unlimited until the quota-volume mount is wired in (see its `qualified: false`, " +
      "and the enforcement doc above for the admin-privilege blocker).",
    relativePath: "work",
    enforcement: "kernel-volume",
    budgetBytes: 512 * 1024 * 1024,
    qualified: false,
  },
  {
    id: "task-lease-record",
    description:
      "Fixed-format `.controller-lease` recovery marker written once directly under the task " +
      "root — a sibling of `work`, not inside it (the launcher's " +
      "`LeaseText`/`CreateLease`). `FileMode.CreateNew` rules out a second write.",
    relativePath: ".controller-lease",
    enforcement: "fixed-write-once",
    budgetBytes: null,
    qualified: true,
  },
  {
    id: "task-quota-lease-record",
    description:
      "Fixed-format `.quota-lease` marker the quota-volume mount would write next to " +
      "`.controller-lease` right after mounting a task-work-tree volume, so recovery can prove " +
      "ownership before releasing it (see `quotaLeaseText`/`classifyLeaseRecord` in " +
      "windows-store-quota.ts for the format both recovery passes share). No code creates this " +
      "file yet — it only exists once task-work-tree's mount is wired in.",
    relativePath: ".quota-lease",
    enforcement: "fixed-write-once",
    budgetBytes: null,
    qualified: false,
  },
  {
    id: "package-registry-storage",
    description:
      "Per-package AppContainer registry redirection " +
      "(HKCU\\...\\AppContainer\\Storage\\<name>). SealPackageRegistry ACLs it read-only for " +
      "the package token before the confined child is created, so no further growth is possible.",
    relativePath: null,
    enforcement: "kernel-registry-hive",
    budgetBytes: 1 * 1024 * 1024,
    qualified: true,
  },
  {
    id: "task-job-object",
    description: "Kill-on-close Job Object owning the task's process tree.",
    relativePath: null,
    enforcement: "count-bound",
    budgetBytes: null,
    qualified: true,
  },
  {
    id: "task-cancel-event",
    description: "Named cancellation Event (Local\\OpenLLM.TaskCancel.<pid>).",
    relativePath: null,
    enforcement: "count-bound",
    budgetBytes: null,
    qualified: true,
  },
] as const;

/** Sum of every declared byte budget (stores with no byte budget contribute 0). */
export const totalDeclaredBudgetBytes = (): number =>
  WINDOWS_STORE_MAP.reduce((sum, store) => sum + (store.budgetBytes ?? 0), 0);

export const findStore = (id: string): WindowsStoreBudget | undefined =>
  WINDOWS_STORE_MAP.find((store) => store.id === id);

/** Stores whose physical capacity is meant to come from a mounted, fixed-size
 *  NTFS volume (today, only `task-work-tree` — its two lease-record siblings
 *  live directly under the task root, outside that volume; see each store's
 *  `enforcement`). */
export const volumeBackedStoreIds = (): readonly string[] =>
  WINDOWS_STORE_MAP.filter(
    (store) => store.enforcement === "kernel-volume",
  ).map((store) => store.id);

/** Every store the map declares as still lacking a wired kernel (or
 *  code-shape) bound in the confined-task launcher today — see the
 *  `qualified` field's doc comment. Nonempty right now: `task-work-tree`'s
 *  mount is an unwired prototype blocked on the
 *  admin-privilege gap documented in `WindowsStoreEnforcement`'s doc comment,
 *  and `task-quota-lease-record` only exists once that mount is wired in.
 *  This is the gate contract's still-open half (P3.09-P3.15: "full-store
 *  quota, not just registry") — expressed as code instead of a claim that
 *  could silently go stale. */
export const unqualifiedStores = (): readonly WindowsStoreBudget[] =>
  WINDOWS_STORE_MAP.filter((store) => !store.qualified);
