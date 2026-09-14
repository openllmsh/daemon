// PROTOTYPE — NOT WIRED into native/windows-appcontainer.cs's Run(). Standalone
// on purpose, like repair/windows-appcontainer-probe.cs: this is exercised in
// isolation against a real Windows kernel before any integration decision, not
// compiled into the shipped daemon.
//
// Why unwired: mounting a fixed-size NTFS volume for `task-work-tree` (see
// src/sandbox/windows-store-map.ts) needs a disk to attach and format, which
// on Windows requires SeManageVolumePrivilege — administrator. The daemon's
// default path is the *non-admin* standard-user task
// (`RequireWin32kDenial=true` in native/windows-appcontainer.cs; the private
// window-station/desktop branch is explicitly the administrator-only case).
// Wiring this into `Run()` as-is would make every non-admin task fail at the
// mount stage — trading "quota unqualified" for "sandbox broken" for the
// common case, which is worse. It stays a prototype until one of: the daemon
// gains a documented admin requirement, a non-admin-compatible mechanism is
// found, or this path is made conditional on `!RequireWin32kDenial` with a
// tested, honest fallback for the non-admin case.
//
// Mechanism: a fixed-size VHDX is created, attached, partitioned, quick-
// formatted NTFS, and assigned as a folder mount point at the task's `work`
// directory, via `diskpart` scripts (its command surface is stable across
// supported Windows versions and avoids hand-rolled COM/format interop this
// file's author cannot verify without a Windows host). Once full, the volume
// itself returns ERROR_DISK_FULL/STATUS_DISK_FULL to the write — refusal is
// the kernel's, not a poll here — matching `FakeKernelVolume` in
// src/sandbox/windows-store-quota.ts, which is this prototype's tested
// decision-logic counterpart. `Mount`/`Release` below follow that file's
// `RecoveryLedger` contract exactly: the `.quota-lease` text this writes is
// `quotaLeaseText(storeId, owner)`'s format, and `Release` refuses to detach
// anything whose lease doesn't classify as "ok" under the same fail-closed
// rules as `classifyLeaseRecord` — see that file for the shared spec both
// sides must keep agreeing on.
//
// UNVERIFIED: no Windows host was available to compile or run this. Treat it
// as a reviewed design, not working code, until a hardware probe (following
// repair/windows-registry-boundary-test.ts's pattern: spawn the real probe
// binary, assert on its observed behavior) proves it end to end.
using System;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Text;
using System.Text.RegularExpressions;
using System.Web.Script.Serialization;

class QuotaVolumeHelper {
    const long MinBudgetBytes = 64L * 1024 * 1024; // below this, NTFS overhead dominates the quota
    const long MaxBudgetBytes = 4096L * 1024 * 1024; // sanity cap; no declared store needs more today
    static readonly JavaScriptSerializer Json = new JavaScriptSerializer { MaxJsonLength = 131072 };

    static void Check(bool ok, string name) { if (!ok) throw new InvalidOperationException(name); }

    static string LeaseText(string storeId, string owner) => "openllm-quota-volume-v1\n" + owner + "\n" + storeId + "\n";

    // Mirrors classifyLeaseRecord in src/sandbox/windows-store-quota.ts. Any
    // verdict other than "ok" must leave the volume and its lease untouched.
    static string ClassifyLease(string text, bool isReparse, string expectedOwner, string expectedStoreId) {
        if (isReparse) return "alias-or-reparse";
        if (text == null) return "locked-invalid";
        string[] lines = text.Split('\n');
        if (lines.Length != 4 || lines[3] != "") return "malformed";
        if (lines[0] != "openllm-quota-volume-v1") return lines[0].StartsWith("openllm-task-recovery") ? "legacy" : "malformed";
        if (lines[1] != expectedOwner || lines[2] != expectedStoreId) return "malformed";
        return "ok";
    }

    // A fresh diskpart script per call; diskpart does not accept concurrent
    // invocations against the same process, so each call gets its own script
    // file and process rather than a shared/long-lived session.
    static string RunDiskpart(string script) {
        string path = Path.Combine(Path.GetTempPath(), "openllm-quota-" + Guid.NewGuid().ToString("N") + ".diskpart");
        File.WriteAllText(path, script, Encoding.ASCII);
        try {
            var start = new ProcessStartInfo {
                FileName = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "diskpart.exe"),
                Arguments = "/s \"" + path + "\"",
                UseShellExecute = false,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                CreateNoWindow = true,
            };
            using (var process = Process.Start(start)) {
                string stdout = process.StandardOutput.ReadToEnd();
                string stderr = process.StandardError.ReadToEnd();
                if (!process.WaitForExit(60000)) { try { process.Kill(); } catch { } throw new TimeoutException("diskpart deadline exceeded"); }
                if (process.ExitCode != 0) throw new Win32Exception(process.ExitCode, "diskpart failed: " + stdout + stderr);
                return stdout;
            }
        } finally { try { File.Delete(path); } catch { } }
    }

    /// <summary>
    /// Creates a fixed-size VHDX, attaches, partitions, NTFS-quick-formats it,
    /// and mounts it at `<root>\work` (which must already exist as an empty
    /// directory owned by `owner` — see CreateOwnedDirectory in
    /// native/windows-appcontainer.cs; this function only takes over what
    /// happens to its contents, not its creation or ACL). Writes `.quota-lease`
    /// next to `.controller-lease` under `root` only after the mount succeeds,
    /// so a partially-mounted volume never looks recoverable.
    /// </summary>
    public static string Mount(string root, string storeId, long budgetBytes, string owner) {
        if (!Regex.IsMatch(storeId, "^[a-z][a-z0-9-]*$")) throw new ArgumentException("Invalid store id");
        if (budgetBytes < MinBudgetBytes || budgetBytes > MaxBudgetBytes) throw new ArgumentOutOfRangeException("budgetBytes");
        string work = Path.Combine(root, "work");
        Check(Directory.Exists(work) && Directory.GetFileSystemEntries(work).Length == 0, "work directory must exist and be empty before mount");
        string vhdPath = Path.Combine(root, "." + storeId + ".quota-volume.vhdx");
        Check(!File.Exists(vhdPath), "quota volume file already exists");
        long budgetMiB = budgetBytes / (1024 * 1024);
        RunDiskpart(
            "create vdisk file=\"" + vhdPath + "\" maximum=" + budgetMiB + " type=fixed\r\n" +
            "select vdisk file=\"" + vhdPath + "\"\r\n" +
            "attach vdisk\r\n" +
            "create partition primary\r\n" +
            "format fs=ntfs quick label=\"openllm-quota\"\r\n" +
            "assign mount=\"" + work + "\"\r\n");
        File.WriteAllText(Path.Combine(root, ".quota-lease"), LeaseText(storeId, owner), Encoding.ASCII);
        return vhdPath;
    }

    /// <summary>
    /// Detaches and deletes the volume `Mount` created for `storeId` under
    /// `root`, then removes the now-orphaned `work` mount-point placeholder
    /// and the `.quota-lease` record. Fail-closed: any lease-record verdict
    /// other than "ok" throws without touching the volume, matching
    /// RecoveryLedger's contract in src/sandbox/windows-store-quota.ts —
    /// idempotent on an already-released (missing) lease/volume, so repeated
    /// recovery and broker/formatter-death signals both converge safely.
    /// </summary>
    public static void Release(string root, string storeId, string owner) {
        string leasePath = Path.Combine(root, ".quota-lease");
        string vhdPath = Path.Combine(root, "." + storeId + ".quota-volume.vhdx");
        if (!File.Exists(leasePath) && !File.Exists(vhdPath)) return; // already released — no-op, not an error
        bool isReparse = File.Exists(leasePath) && (File.GetAttributes(leasePath) & FileAttributes.ReparsePoint) != 0;
        string text = null;
        if (File.Exists(leasePath) && !isReparse) { try { text = File.ReadAllText(leasePath, Encoding.ASCII); } catch (IOException) { text = null; } }
        string verdict = ClassifyLease(text, isReparse, owner, storeId);
        if (verdict != "ok") throw new InvalidDataException("Refusing to release quota volume: lease verdict is " + verdict);
        if (File.Exists(vhdPath)) {
            RunDiskpart("select vdisk file=\"" + vhdPath + "\"\r\ndetach vdisk\r\n");
            File.Delete(vhdPath);
        }
        string work = Path.Combine(root, "work");
        if (Directory.Exists(work) && (File.GetAttributes(work) & FileAttributes.ReparsePoint) != 0) Directory.Delete(work, false);
        File.Delete(leasePath);
    }

    // Manual hardware-probe entry point: `quota-volume-helper.exe --mount <root> <storeId> <budgetBytes> <owner>`
    // or `--release <root> <storeId> <owner>`. Not invoked by the shipped daemon.
    static int Main(string[] args) {
        try {
            if (args.Length == 5 && args[0] == "--mount") {
                string vhd = Mount(args[1], args[2], long.Parse(args[3]), args[4]);
                Console.WriteLine(Json.Serialize(new { result = "mounted", vhd }));
                return 0;
            }
            if (args.Length == 4 && args[0] == "--release") {
                Release(args[1], args[2], args[3]);
                Console.WriteLine(Json.Serialize(new { result = "released" }));
                return 0;
            }
            Console.Error.WriteLine("Usage: --mount <root> <storeId> <budgetBytes> <owner> | --release <root> <storeId> <owner>");
            return 2;
        } catch (Exception e) {
            Console.WriteLine(Json.Serialize(new { result = "error", message = e.Message }));
            return 1;
        }
    }
}
