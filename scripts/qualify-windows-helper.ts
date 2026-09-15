import { Buffer } from "node:buffer";
import { createHash } from "node:crypto";
import {
  existsSync,
  mkdtempSync,
  readFileSync,
  renameSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join, relative, resolve } from "node:path";

type TArgumentValues = Map<string, string>;
type TRecord = Record<string, unknown>;

type TPtyCase = {
  name: string;
  executable: string;
  args: string[];
  expectedExit: number;
  expectedOutput: string;
};

type TPtyResult = {
  name: string;
  workerExit: number;
  output: string;
  childExit: number;
  admission: {
    limit: number;
    scope: string;
    prebirth: boolean;
    breakaway: boolean;
  };
};

const root = resolve(import.meta.dir, "../../..");

const readArguments = (): TArgumentValues => {
  const values = new Map<string, string>();
  const args = process.argv.slice(2);
  for (let index = 0; index < args.length; index += 2) {
    const key = args[index];
    const value = args[index + 1];
    if (key === undefined || value === undefined || !key.startsWith("--"))
      throw new Error(
        "Windows helper qualification arguments must be --key value pairs",
      );
    if (values.has(key))
      throw new Error(`duplicate qualification argument: ${key}`);
    values.set(key, value);
  }
  return values;
};

const required = (values: TArgumentValues, key: string): string => {
  const value = values.get(key);
  if (value === undefined || value.length === 0)
    throw new Error(`missing qualification argument: ${key}`);
  return value;
};

const hash = (path: string): string =>
  createHash("sha256").update(readFileSync(path)).digest("hex");

const asRecord = (value: unknown, context: string): TRecord => {
  if (typeof value !== "object" || value === null || Array.isArray(value))
    throw new Error(`${context} must be an object`);
  return value as TRecord;
};

const asString = (value: unknown, context: string): string => {
  if (typeof value !== "string") throw new Error(`${context} must be a string`);
  return value;
};

const asNumber = (value: unknown, context: string): number => {
  if (typeof value !== "number" || !Number.isInteger(value))
    throw new Error(`${context} must be an integer`);
  return value;
};

const asBoolean = (value: unknown, context: string): boolean => {
  if (typeof value !== "boolean")
    throw new Error(`${context} must be a boolean`);
  return value;
};

const run = (
  command: string[],
  context: string,
  expectedExit: number,
  timeout = 30_000,
): { stdout: string; stderr: string } => {
  const result = Bun.spawnSync(command, {
    stdin: "ignore",
    stdout: "pipe",
    stderr: "pipe",
    timeout,
  });
  const stdout = result.stdout.toString();
  const stderr = result.stderr.toString();
  if (result.exitCode !== expectedExit) {
    throw new Error(
      `${context} exit=${result.exitCode} expected=${expectedExit} stdout=${JSON.stringify(stdout.slice(0, 512))} stderr=${JSON.stringify(stderr.slice(0, 512))}`,
    );
  }
  return { stdout, stderr };
};

const runVersion = (
  binary: string,
  expected: string,
  context: string,
): void => {
  const result = run([binary, "--version"], context, 0, 15_000);
  if (result.stdout.trim() !== expected)
    throw new Error(
      `${context} version mismatch: ${JSON.stringify(result.stdout.trim())}`,
    );
};

const parsePty = (
  name: string,
  output: string,
  expectedExit: number,
  expectedOutput: string,
): TPtyResult => {
  let ready: TRecord | undefined;
  let childExit: number | undefined;
  let decoded = "";
  for (const line of output.split(/\r?\n/)) {
    if (line.trim().length === 0) continue;
    const frame = asRecord(JSON.parse(line), `ConPTY ${name} frame`);
    const type = asString(frame.t, `ConPTY ${name} frame.t`);
    if (type === "ready") ready = frame;
    if (type === "output")
      decoded += Buffer.from(
        asString(frame.data, `ConPTY ${name} output data`),
        "base64",
      ).toString("utf8");
    if (type === "exit")
      childExit = asNumber(frame.code, `ConPTY ${name} exit code`);
  }
  if (ready === undefined)
    throw new Error(`ConPTY ${name} omitted ready frame`);
  const admission = asRecord(ready.admission, `ConPTY ${name} admission`);
  const parsedAdmission = {
    limit: asNumber(admission.limit, `ConPTY ${name} admission.limit`),
    scope: asString(admission.scope, `ConPTY ${name} admission.scope`),
    prebirth: asBoolean(
      admission.prebirth,
      `ConPTY ${name} admission.prebirth`,
    ),
    breakaway: asBoolean(
      admission.breakaway,
      `ConPTY ${name} admission.breakaway`,
    ),
  };
  if (
    parsedAdmission.limit !== 16 ||
    parsedAdmission.scope !== "process-tree" ||
    !parsedAdmission.prebirth ||
    parsedAdmission.breakaway
  ) {
    throw new Error(
      `ConPTY ${name} did not prove required prebirth process-tree Job admission`,
    );
  }
  if (childExit !== expectedExit)
    throw new Error(
      `ConPTY ${name} child exit=${childExit} expected=${expectedExit}`,
    );
  if (expectedOutput.length > 0 && !decoded.includes(expectedOutput))
    throw new Error(
      `ConPTY ${name} output omitted ${JSON.stringify(expectedOutput)}`,
    );
  return { name, workerExit: 0, output, childExit, admission: parsedAdmission };
};

const runPty = (helper: string, item: TPtyCase): TPtyResult => {
  const result = run(
    [helper, "--pty", "80", "24", item.executable, ...item.args],
    `ConPTY ${item.name}`,
    0,
    30_000,
  );
  return parsePty(
    item.name,
    result.stdout,
    item.expectedExit,
    item.expectedOutput,
  );
};

const writeJson = (path: string, value: unknown): void => {
  const temporary = `${path}.tmp-${process.pid}`;
  writeFileSync(temporary, `${JSON.stringify(value)}\n`);
  renameSync(temporary, path);
};

const sourceClean = (): void => {
  const result = run(
    ["git", "status", "--porcelain=v1"],
    "Windows source clean gate",
    0,
  );
  if (result.stdout.trim().length > 0)
    throw new Error(
      `Windows source changed during helper qualification: ${result.stdout.trim()}`,
    );
};

const values = readArguments();
const version = required(values, "--version");
const helper = resolve(required(values, "--helper"));
const daemon = resolve(required(values, "--daemon"));
const cli = resolve(required(values, "--cli"));
const evidence = resolve(required(values, "--evidence"));

if (process.platform !== "win32")
  throw new Error("Windows helper qualification requires a Windows host");
if (!/^\d+\.\d+\.\d+$/.test(version))
  throw new Error(`invalid helper qualification version: ${version}`);
for (const path of [helper, daemon, cli]) {
  if (!existsSync(path))
    throw new Error(`required compiled Windows artifact is missing: ${path}`);
}

runVersion(
  helper,
  `openllm-windows-worker v${version}`,
  "Windows helper version probe",
);
runVersion(daemon, `openllmd v${version}`, "Windows daemon version probe");
runVersion(cli, `openllm v${version}`, "Windows CLI version probe");
run(
  [helper, "--identity", String(process.pid)],
  "Windows helper self identity",
  0,
);
run([helper, "--identity", "0"], "Windows helper invalid identity", 5);

const secureDirectory = mkdtempSync(join(tmpdir(), "openllm-windows-helper-"));
try {
  run(
    [helper, "--secure-directory", secureDirectory],
    "Windows helper secure directory",
    0,
  );
  run(
    [helper, "--check-directory", secureDirectory],
    "Windows helper check directory",
    0,
  );
} finally {
  rmSync(secureDirectory, { recursive: true, force: true });
}

const systemRoot = process.env.SystemRoot ?? process.env.WINDIR;
if (systemRoot === undefined)
  throw new Error("Windows system root is unavailable");
const cmd = join(systemRoot, "System32", "cmd.exe");
const results = [
  runPty(helper, {
    name: "whoami",
    executable: join(systemRoot, "System32", "whoami.exe"),
    args: [],
    expectedExit: 0,
    expectedOutput: "nt authority\\system",
  }),
  runPty(helper, {
    name: "echo",
    executable: cmd,
    args: ["/d", "/s", "/c", "echo CMD_ECHO"],
    expectedExit: 0,
    expectedOutput: "CMD_ECHO",
  }),
  runPty(helper, {
    name: "spaces",
    executable: cmd,
    args: ["/d", "/s", "/c", "echo SPACE VALUE"],
    expectedExit: 0,
    expectedOutput: "SPACE VALUE",
  }),
  runPty(helper, {
    name: "metachar",
    executable: cmd,
    args: ["/d", "/s", "/c", "echo META^&MARKER"],
    expectedExit: 0,
    expectedOutput: "META&MARKER",
  }),
  runPty(helper, {
    name: "nonzero",
    executable: cmd,
    args: ["/d", "/s", "/c", "exit /b 37"],
    expectedExit: 37,
    expectedOutput: "",
  }),
];

const nativeCmdTest = join(
  root,
  "tests",
  "daemon",
  "fleet-reconciliation",
  "native-cmd-quoting.test.ts",
);
const test = Bun.spawnSync([process.execPath, "test", nativeCmdTest], {
  cwd: root,
  env: { ...process.env, OPENLLM_WINDOWS_WORKER_TEST_BIN: helper },
  stdin: "ignore",
  stdout: "pipe",
  stderr: "pipe",
  timeout: 60_000,
});
const testOutput = `${test.stdout.toString()}${test.stderr.toString()}`;
if (test.exitCode !== 0)
  throw new Error(
    `native-cmd-quoting.test.ts exit=${test.exitCode}: ${testOutput.slice(0, 2_000)}`,
  );

sourceClean();
const workerSource = join(
  root,
  "packages",
  "daemon",
  "native",
  "windows-worker.cs",
);
const appContainerSource = join(
  root,
  "packages",
  "daemon",
  "native",
  "windows-appcontainer.cs",
);
const helperHash = hash(helper);
const workerSourceHash = hash(workerSource);
const appContainerSourceHash = hash(appContainerSource);
const daemonHash = hash(daemon);
const cliHash = hash(cli);
const commit = run(
  ["git", "rev-parse", "HEAD"],
  "Windows source revision",
  0,
).stdout.trim();

writeFileSync(join(evidence, "native-cmd-quoting.log"), testOutput);
writeJson(join(evidence, "cmdfix-build-receipt.json"), {
  compiler: join(
    systemRoot,
    "Microsoft.NET",
    "Framework64",
    "v4.0.30319",
    "csc.exe",
  ),
  targetSha256: helperHash,
  targetBytes: readFileSync(helper).byteLength,
  sourceSha256: workerSourceHash,
  sourcePath: relative(root, workerSource),
  builtFromCommit: commit,
});
writeJson(join(evidence, "cmdfix-source-receipt.json"), {
  release: version,
  source: { file: relative(root, workerSource), sha256: workerSourceHash },
  artifact: {
    file: relative(root, helper),
    bytes: readFileSync(helper).byteLength,
    sha256: helperHash,
  },
  buildReceipt: "cmdfix-build-receipt.json",
  smokeReceipt: "cmdfix-smoke-receipt.json",
  builtFromCommit: commit,
});
writeJson(join(evidence, "cmdfix-smoke-receipt.json"), {
  helperSha256: helperHash,
  version: `openllm-windows-worker v${version}`,
  versionExit: 0,
  results: results.map(({ name, workerExit, output }) => ({
    name,
    workerExit,
    output,
  })),
});
writeJson(join(evidence, "source-receipt.json"), {
  release: version,
  productCommit: commit,
  buildHost: "Windows host running the unified release build",
  artifact: {
    file: relative(root, helper),
    bytes: readFileSync(helper).byteLength,
    sha256: helperHash,
  },
  sources: [
    {
      file: "windows-worker.cs",
      bytes: readFileSync(workerSource).byteLength,
      sha256: workerSourceHash,
    },
    {
      file: "windows-appcontainer.cs",
      bytes: readFileSync(appContainerSource).byteLength,
      sha256: appContainerSourceHash,
    },
  ],
  checks: {
    helperVersion: `openllm-windows-worker v${version}`,
    daemonVersion: `openllmd v${version}`,
    cliVersion: `openllm v${version}`,
    daemonSha256: daemonHash,
    cliSha256: cliHash,
    conpty: results.map(({ name, childExit, admission }) => ({
      name,
      childExit,
      admission,
    })),
    nativeCmdQuotingLog: "native-cmd-quoting.log",
  },
});

console.log(JSON.stringify({ helper, helperSha256: helperHash, evidence }));
