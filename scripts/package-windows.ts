#!/usr/bin/env bun

/**
 * Build the Phase 2 Windows package.
 *
 * Usage:
 *   bun packages/daemon/scripts/package-windows.ts \
 *     --exe <openllmd-win32-x64.exe> --version <version> \
 *     --source-commit <sha> --raw-sha256 <hex> \
 *     --out <path>/openllmd-win32-x64-phase2.zip
 *
 * The package is deliberately a small, dependency-free ZIP writer. Its four
 * entries are fixed by the Phase 2 contract; the daemon is the only
 * executable entry.
 */
import { createHash } from "node:crypto";
import {
  existsSync,
  lstatSync,
  mkdirSync,
  readFileSync,
  writeFileSync,
} from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const PACKAGE_TARGET = "win32-x64" as const;
const DAEMON_ENTRY = "bin/openllmd.exe" as const;
const PACKAGE_ENTRY_NAMES = [
  DAEMON_ENTRY,
  "install.ps1",
  "manifest.json",
  "SHA256SUMS",
] as const;
const MAX_UINT32 = 0xffff_ffff;
const SCRIPT_DIR = dirname(fileURLToPath(import.meta.url));
const INSTALL_SCRIPT = resolve(SCRIPT_DIR, "..", "install.ps1");

export type TWindowsPackageManifest = {
  readonly target: typeof PACKAGE_TARGET;
  readonly version: string;
  readonly sourceCommit: string;
  readonly rawSha256: string;
  readonly byteLength: number;
  readonly ptyQualification: "unavailable-until-phase3";
  readonly executables: readonly [typeof DAEMON_ENTRY];
};

export type TWindowsPackageOptions = {
  readonly exePath: string;
  readonly version: string;
  readonly sourceCommit: string;
  readonly rawSha256: string;
  readonly outputPath: string;
};

export type TWindowsPackageResult = {
  readonly outputPath: string;
  readonly manifest: TWindowsPackageManifest;
  readonly zipByteLength: number;
};

export type TWindowsZipEntry = {
  readonly name: string;
  readonly bytes: Buffer;
};

const crc32Table = (): Uint32Array => {
  const table = new Uint32Array(256);
  for (let index = 0; index < table.length; index += 1) {
    let value = index;
    for (let bit = 0; bit < 8; bit += 1)
      value = (value & 1) === 0 ? value >>> 1 : (value >>> 1) ^ 0xedb88320;
    table[index] = value >>> 0;
  }
  return table;
};

const CRC32_TABLE = crc32Table();

const crc32 = (bytes: Uint8Array): number => {
  let value = 0xffffffff;
  for (const byte of bytes) {
    const tableValue = CRC32_TABLE[(value ^ byte) & 0xff];
    value = (value >>> 8) ^ tableValue;
  }
  return (value ^ 0xffffffff) >>> 0;
};

const assertZipUInt32 = (value: number, label: string): void => {
  if (!Number.isSafeInteger(value) || value < 0 || value > MAX_UINT32)
    throw new Error(`${label} does not fit in a ZIP32 archive: ${value}`);
};

const normalizeSha256 = (value: string, label: string): string => {
  if (!/^[0-9a-f]{64}$/i.test(value))
    throw new Error(
      `${label} must be a 64-character hexadecimal SHA-256 digest`,
    );
  return value.toLowerCase();
};

const requireText = (value: string, label: string): string => {
  if (
    value.length === 0 ||
    value.includes("\u0000") ||
    value.includes("\r") ||
    value.includes("\n")
  )
    throw new Error(
      `${label} is required and must not contain NULs or line breaks`,
    );
  return value;
};

const readUInt16LE = (bytes: Uint8Array, offset: number): number => {
  const low = bytes[offset];
  const high = bytes[offset + 1];
  if (low === undefined || high === undefined)
    throw new Error(`truncated little-endian uint16 at offset ${offset}`);
  return low | (high << 8);
};

const readUInt32LE = (bytes: Uint8Array, offset: number): number => {
  const first = bytes[offset];
  const second = bytes[offset + 1];
  const third = bytes[offset + 2];
  const fourth = bytes[offset + 3];
  if (
    first === undefined ||
    second === undefined ||
    third === undefined ||
    fourth === undefined
  )
    throw new Error(`truncated little-endian uint32 at offset ${offset}`);
  return (first | (second << 8) | (third << 16) | (fourth << 24)) >>> 0;
};

/** Recognize the required x64 PE image from its headers, not its filename. */
export const isWindowsX64Pe = (bytes: Uint8Array): boolean => {
  if (bytes.length < 0x40 || bytes[0] !== 0x4d || bytes[1] !== 0x5a)
    return false;
  const peOffset = readUInt32LE(bytes, 0x3c);
  if (peOffset < 0x40 || peOffset > bytes.length - 6) return false;
  return (
    bytes[peOffset] === 0x50 &&
    bytes[peOffset + 1] === 0x45 &&
    bytes[peOffset + 2] === 0 &&
    bytes[peOffset + 3] === 0 &&
    readUInt16LE(bytes, peOffset + 4) === 0x8664
  );
};

const assertRegularFile = (path: string, label: string): void => {
  if (!existsSync(path)) throw new Error(`${label} does not exist: ${path}`);
  const stat = lstatSync(path);
  if (!stat.isFile() || stat.isSymbolicLink())
    throw new Error(`${label} must be a regular file: ${path}`);
};

/** Reject anything outside the fixed four-file package inventory. */
export const assertWindowsPackageEntryNames = (
  names: readonly string[],
): void => {
  if (names.length !== PACKAGE_ENTRY_NAMES.length)
    throw new Error(
      `Windows package must contain exactly ${PACKAGE_ENTRY_NAMES.length} files; ` +
        `received ${names.length}`,
    );
  const allowed = new Set<string>(PACKAGE_ENTRY_NAMES);
  const seen = new Set<string>();
  for (const name of names) {
    if (seen.has(name))
      throw new Error(`duplicate Windows package entry: ${name}`);
    seen.add(name);
    if (!allowed.has(name))
      throw new Error(`unexpected Windows package entry: ${name}`);
    if (name.includes("\\") || name.endsWith("/"))
      throw new Error(`invalid Windows package entry path: ${name}`);
  }
  for (const name of PACKAGE_ENTRY_NAMES)
    if (!seen.has(name))
      throw new Error(`missing Windows package entry: ${name}`);
};

const localHeader = (nameBytes: Buffer, bytes: Buffer): Buffer => {
  const header = Buffer.alloc(30 + nameBytes.length);
  header.writeUInt32LE(0x04034b50, 0);
  header.writeUInt16LE(20, 4);
  header.writeUInt16LE(0, 6);
  header.writeUInt16LE(0, 8); // stored, not deflated
  header.writeUInt16LE(0, 10); // DOS time
  header.writeUInt16LE(0, 12); // DOS date
  header.writeUInt32LE(crc32(bytes), 14);
  assertZipUInt32(bytes.length, "ZIP entry size");
  header.writeUInt32LE(bytes.length, 18);
  header.writeUInt32LE(bytes.length, 22);
  header.writeUInt16LE(nameBytes.length, 26);
  header.writeUInt16LE(0, 28);
  nameBytes.copy(header, 30);
  return header;
};

const centralHeader = (
  nameBytes: Buffer,
  bytes: Buffer,
  localOffset: number,
): Buffer => {
  const header = Buffer.alloc(46 + nameBytes.length);
  header.writeUInt32LE(0x02014b50, 0);
  header.writeUInt16LE(20, 4); // version made by
  header.writeUInt16LE(20, 6);
  header.writeUInt16LE(0, 8);
  header.writeUInt16LE(0, 10); // stored
  header.writeUInt16LE(0, 12); // DOS time
  header.writeUInt16LE(0, 14); // DOS date
  header.writeUInt32LE(crc32(bytes), 16);
  assertZipUInt32(bytes.length, "ZIP entry size");
  header.writeUInt32LE(bytes.length, 20);
  header.writeUInt32LE(bytes.length, 24);
  header.writeUInt16LE(nameBytes.length, 28);
  header.writeUInt16LE(0, 30);
  header.writeUInt16LE(0, 32);
  header.writeUInt16LE(0, 34);
  header.writeUInt16LE(0, 36);
  header.writeUInt32LE(0, 38);
  assertZipUInt32(localOffset, "ZIP local-header offset");
  header.writeUInt32LE(localOffset, 42);
  nameBytes.copy(header, 46);
  return header;
};

/** Build a ZIP32 archive with stored entries and no implicit directory entry. */
export const buildWindowsZip = (
  entries: readonly TWindowsZipEntry[],
): Buffer => {
  assertWindowsPackageEntryNames(entries.map((entry) => entry.name));
  const localParts: Buffer[] = [];
  const centralParts: Buffer[] = [];
  let localOffset = 0;

  for (const entry of entries) {
    const nameBytes = Buffer.from(entry.name, "utf8");
    if (nameBytes.length > 0xffff)
      throw new Error(`Windows package entry name is too long: ${entry.name}`);
    const header = localHeader(nameBytes, entry.bytes);
    localParts.push(header, entry.bytes);
    centralParts.push(centralHeader(nameBytes, entry.bytes, localOffset));
    localOffset += header.length + entry.bytes.length;
    assertZipUInt32(localOffset, "ZIP local data size");
  }

  const localData = Buffer.concat(localParts);
  const centralData = Buffer.concat(centralParts);
  assertZipUInt32(localData.length, "ZIP central-directory offset");
  assertZipUInt32(centralData.length, "ZIP central-directory size");
  if (entries.length > 0xffff)
    throw new Error("Windows package has too many ZIP entries");

  const end = Buffer.alloc(22);
  end.writeUInt32LE(0x06054b50, 0);
  end.writeUInt16LE(0, 4);
  end.writeUInt16LE(0, 6);
  end.writeUInt16LE(entries.length, 8);
  end.writeUInt16LE(entries.length, 10);
  end.writeUInt32LE(centralData.length, 12);
  end.writeUInt32LE(localData.length, 16);
  end.writeUInt16LE(0, 20);
  return Buffer.concat([localData, centralData, end]);
};

export const packageWindows = (
  options: TWindowsPackageOptions,
): TWindowsPackageResult => {
  const exePath = resolve(requireText(options.exePath, "--exe"));
  const outputPath = resolve(requireText(options.outputPath, "--out"));
  const version = requireText(options.version, "--version");
  const sourceCommit = requireText(options.sourceCommit, "--source-commit");
  const expectedSha = normalizeSha256(options.rawSha256, "--raw-sha256");

  assertRegularFile(exePath, "Windows daemon input");
  assertRegularFile(INSTALL_SCRIPT, "Windows installer");
  const daemonBytes = readFileSync(exePath);
  if (!isWindowsX64Pe(daemonBytes))
    throw new Error("Windows daemon input is not a valid x64 PE executable");
  const actualSha = createHash("sha256").update(daemonBytes).digest("hex");
  if (actualSha !== expectedSha)
    throw new Error(
      `raw SHA256 mismatch: expected ${expectedSha}, computed ${actualSha}`,
    );

  const manifest: TWindowsPackageManifest = {
    target: PACKAGE_TARGET,
    version,
    sourceCommit,
    rawSha256: actualSha,
    byteLength: daemonBytes.length,
    ptyQualification: "unavailable-until-phase3",
    executables: [DAEMON_ENTRY],
  };
  const installBytes = readFileSync(INSTALL_SCRIPT);
  const manifestBytes = Buffer.from(
    `${JSON.stringify(manifest, null, 2)}\n`,
    "utf8",
  );
  const sumsBytes = Buffer.from(`${actualSha}  ${DAEMON_ENTRY}\n`, "utf8");
  const entries: readonly TWindowsZipEntry[] = [
    { name: DAEMON_ENTRY, bytes: daemonBytes },
    { name: "install.ps1", bytes: installBytes },
    { name: "manifest.json", bytes: manifestBytes },
    { name: "SHA256SUMS", bytes: sumsBytes },
  ];
  const zip = buildWindowsZip(entries);
  mkdirSync(dirname(outputPath), { recursive: true });
  writeFileSync(outputPath, zip);
  return { outputPath, manifest, zipByteLength: zip.length };
};

export const parseWindowsPackageArguments = (
  args: readonly string[],
): TWindowsPackageOptions => {
  const values = new Map<string, string>();
  const supported = new Set([
    "--exe",
    "--version",
    "--source-commit",
    "--raw-sha256",
    "--out",
  ]);
  for (let index = 0; index < args.length; index += 1) {
    const name = args[index];
    if (name === undefined) throw new Error("missing argument name");
    if (!supported.has(name)) throw new Error(`unknown argument: ${name}`);
    if (values.has(name)) throw new Error(`duplicate argument: ${name}`);
    const value = args[index + 1];
    if (value === undefined || value.startsWith("--"))
      throw new Error(`${name} requires a value`);
    values.set(name, value);
    index += 1;
  }
  const required = (name: string): string => {
    const value = values.get(name);
    if (value === undefined)
      throw new Error(`missing required argument: ${name}`);
    return value;
  };
  return {
    exePath: required("--exe"),
    version: required("--version"),
    sourceCommit: required("--source-commit"),
    rawSha256: required("--raw-sha256"),
    outputPath: required("--out"),
  };
};

const main = (): void => {
  const result = packageWindows(
    parseWindowsPackageArguments(process.argv.slice(2)),
  );
  console.log(
    `Wrote Phase 2 Windows package: ${result.outputPath} ` +
      `(4 files, 1 executable, ${result.zipByteLength} bytes)`,
  );
  console.log(`Daemon SHA256: ${result.manifest.rawSha256}`);
};

if (import.meta.main) {
  try {
    main();
  } catch (error) {
    console.error(error instanceof Error ? error.message : String(error));
    process.exitCode = 1;
  }
}
