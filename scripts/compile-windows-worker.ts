/** Native build entry without a PowerShell script-execution-policy dependency. */
import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { createHash } from "node:crypto";

export const compileWindowsWorker = (root: string, outDir: string, version: string): void => {
  if (process.platform !== "win32") throw new Error("Native worker compilation requires Windows");
  if (!/^\d+\.\d+\.\d+[-a-zA-Z0-9.]*$/.test(version)) throw new Error("Invalid release version");
  const windows = process.env.SystemRoot ?? process.env.WINDIR;
  if (!windows) throw new Error("Windows system root unavailable");
  mkdirSync(outDir, { recursive: true });
  const generated = join(outDir, "windows-worker.generated.cs");
  const source = readFileSync(join(root, "native", "windows-worker.cs"), "utf8");
  if (!source.includes("__OPENLLM_NATIVE_VERSION__")) throw new Error("Missing worker version placeholder");
  writeFileSync(generated, source.replaceAll("__OPENLLM_NATIVE_VERSION__", version));
  const target = join(outDir, "openllm-windows-worker.exe");
  const compiler = join(windows, "Microsoft.NET", "Framework64", "v4.0.30319", "csc.exe");
  const build = Bun.spawnSync([compiler, "/nologo", "/optimize+", "/platform:x64", "/target:exe", "/r:System.Web.Extensions.dll", "/r:System.ServiceProcess.dll", `/out:${target}`, generated, join(root, "native", "windows-appcontainer.cs")], { stdin: "ignore", stdout: "pipe", stderr: "pipe", timeout: 60000 });
  if (build.exitCode !== 0) throw new Error(`Native worker compilation failed: ${build.stdout.toString()} ${build.stderr.toString()}`);
  // Fresh CLR executables can take longer than five seconds on a busy guest.
  // Keep a finite startup deadline and require the exact version, without a
  // retry that could conceal a crashing or incorrectly versioned artifact.
  const started = performance.now();
  const probe = Bun.spawnSync([target, "--version"], { stdin: "ignore", stdout: "pipe", stderr: "pipe", timeout: 15000 });
  if (probe.exitCode !== 0 || probe.stdout.toString().trim() !== `openllm-windows-worker v${version}`) {
    throw new Error(`Native worker version probe failed: exit=${probe.exitCode} elapsed_ms=${Math.round(performance.now() - started)} stdout=${JSON.stringify(probe.stdout.toString().slice(0, 512))} stderr=${JSON.stringify(probe.stderr.toString().slice(0, 512))}`);
  }
  console.log(JSON.stringify({ artifact: target, version, sha256: createHash("sha256").update(readFileSync(target)).digest("hex") }));
};
