/**
 * Per-daemon X25519 keypair + sealed-box transfer.
 *
 * Used to move a Claude SETUP-TOKEN between two of the user's own daemons
 * without the cloud ever reading it: the daemon on the machine with the
 * browser mints the token and SEALS it to the target daemon's public key; the
 * cloud relays only ciphertext (`/api/daemon/relay-credential`); the target
 * daemon opens it with its private key and stores it. See
 * docs/proposals/daemon-auth-loopback-forwarding.md §7.4.
 *
 * Sealed box = ephemeral X25519 + ECDH → HKDF-SHA256 → AES-256-GCM. The
 * private key is generated once and persisted `0600` under the state dir; only
 * the public key (SPKI DER, base64) ever leaves the box, on the status push.
 */
import {
  createCipheriv,
  createDecipheriv,
  createPrivateKey,
  createPublicKey,
  diffieHellman,
  generateKeyPairSync,
  hkdfSync,
  type KeyObject,
  randomBytes,
} from "node:crypto";
import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { stateDir } from "./env";
import { logError } from "./logger";

const privFile = (): string => join(stateDir(), "x25519-priv");
const HKDF_INFO = Buffer.from("openllm-cred-seal-v1");

let cachedPriv: KeyObject | null = null;
/** True iff `cachedPriv` was loaded from disk or written this run. */
let cachedPersisted = false;
let cachedPubB64: string | null = null;

const nodeErrno = (
  err: unknown,
): { readonly errno: number | null; readonly code: string | null } => {
  if (typeof err !== "object" || err === null) {
    return { errno: null, code: null };
  }
  const rec = err as { errno?: unknown; code?: unknown };
  return {
    errno: typeof rec.errno === "number" ? rec.errno : null,
    code: typeof rec.code === "string" ? rec.code : null,
  };
};

/**
 * Load (or mint) the daemon's long-lived X25519 identity.
 *
 * Caller contract (publishIdentity / bootstrap):
 * - Always returns a usable in-memory key for THIS run — mux, chat, seals, and
 *   subscriptions keep working even when the disk is full. Never process.exit.
 * - `persisted` is true iff the PKCS#8 private key is on disk under the state
 *   dir (loaded or written). When false, the caller MUST skip publishIdentity.
 *   The cloud pin is write-once; publishing an unpersisted pubkey plants a pin
 *   this process cannot reproduce, and the next boot 409s forever.
 * - Never auto-rotate the pin via the API key. A stolen `sk-llm-…` must not be
 *   able to rotate a device identity.
 */
export type TIdentityKey = {
  readonly publicKeyB64: string;
  readonly persisted: boolean;
};

const publicKeyB64Of = (privateKey: KeyObject): string => {
  if (cachedPubB64 !== null) return cachedPubB64;
  cachedPubB64 = Buffer.from(
    createPublicKey(privateKey).export({ format: "der", type: "spki" }),
  ).toString("base64");
  return cachedPubB64;
};

/** The daemon's own X25519 private key, generated + persisted on first use. */
const ownPrivate = (): KeyObject => {
  if (cachedPriv !== null) return cachedPriv;
  const path = privFile();
  try {
    const der = readFileSync(path);
    cachedPriv = createPrivateKey({ key: der, format: "der", type: "pkcs8" });
    cachedPersisted = true;
    return cachedPriv;
  } catch {
    // none yet — generate + persist below
  }
  const { privateKey } = generateKeyPairSync("x25519");
  try {
    mkdirSync(stateDir(), { recursive: true });
    writeFileSync(path, privateKey.export({ format: "der", type: "pkcs8" }), {
      mode: 0o600,
    });
    cachedPersisted = true;
  } catch (err) {
    cachedPersisted = false;
    const { errno, code } = nodeErrno(err);
    logError(
      "keypair",
      "identity private key was not persisted — skip publishIdentity this run",
      {
        errno,
        code,
        path,
        err: err instanceof Error ? err.message : String(err),
      },
    );
  }
  cachedPriv = privateKey;
  return privateKey;
};

export const loadIdentityKey = (): TIdentityKey => {
  const privateKey = ownPrivate();
  return {
    publicKeyB64: publicKeyB64Of(privateKey),
    persisted: cachedPersisted,
  };
};

/**
 * Whether the long-lived private key is on disk. False means skip
 * publishIdentity (see {@link loadIdentityKey}).
 */
export const identityKeyPersisted = (): boolean => loadIdentityKey().persisted;

/** This daemon's public key (SPKI DER, base64) — in-memory even if not persisted. */
export const daemonPublicKey = (): string => loadIdentityKey().publicKeyB64;

/** Drop memoized identity so a test can switch `OPENLLM_DAEMON_STATE_DIR`. */
export const resetIdentityKeyCacheForTests = (): void => {
  cachedPriv = null;
  cachedPersisted = false;
  cachedPubB64 = null;
};

const deriveKey = (shared: Buffer): Buffer =>
  Buffer.from(hkdfSync("sha256", shared, Buffer.alloc(0), HKDF_INFO, 32));

/**
 * Seal `plaintext` to a recipient daemon's public key (SPKI DER, base64).
 * Output is base64(JSON{ epk, iv, ct }) — the cloud relays it opaquely.
 */
export type TEphKeypair = {
  readonly privateKey: KeyObject;
  readonly publicKeyB64: string;
};

/** Generate an ephemeral X25519 keypair for a one-shot sealed-box reply. */
export const generateEphKeypair = (): TEphKeypair => {
  const { privateKey, publicKey } = generateKeyPairSync("x25519");
  return {
    privateKey,
    publicKeyB64: Buffer.from(
      publicKey.export({ format: "der", type: "spki" }),
    ).toString("base64"),
  };
};

/** Open a sealed blob with an explicit recipient private key. Null on failure. */
export const openSealedWith = (
  privateKey: KeyObject,
  sealedB64: string,
): string | null => {
  try {
    const { epk, iv, ct } = JSON.parse(
      Buffer.from(sealedB64, "base64").toString("utf8"),
    ) as { epk: string; iv: string; ct: string };
    const eph = createPublicKey({
      key: Buffer.from(epk, "base64"),
      format: "der",
      type: "spki",
    });
    const shared = diffieHellman({ privateKey, publicKey: eph });
    const key = deriveKey(shared);
    const ctBuf = Buffer.from(ct, "base64");
    const body = ctBuf.subarray(0, ctBuf.length - 16);
    const tag = ctBuf.subarray(ctBuf.length - 16);
    const decipher = createDecipheriv(
      "aes-256-gcm",
      key,
      Buffer.from(iv, "base64"),
    );
    decipher.setAuthTag(tag);
    return Buffer.concat([decipher.update(body), decipher.final()]).toString(
      "utf8",
    );
  } catch {
    return null;
  }
};

/** Open a sealed blob with this daemon's long-lived private key. */
export const openSealed = (sealedB64: string): string | null =>
  openSealedWith(ownPrivate(), sealedB64);

/** Seal plaintext to a recipient daemon's public key (SPKI DER, base64). */
export const sealTo = (recipientPubB64: string, plaintext: string): string => {
  const recipient = createPublicKey({
    key: Buffer.from(recipientPubB64, "base64"),
    format: "der",
    type: "spki",
  });
  const eph = generateEphKeypair();
  const shared = diffieHellman({
    privateKey: eph.privateKey,
    publicKey: recipient,
  });
  const key = deriveKey(shared);
  const iv = randomBytes(12);
  const cipher = createCipheriv("aes-256-gcm", key, iv);
  const body = Buffer.concat([
    cipher.update(plaintext, "utf8"),
    cipher.final(),
  ]);
  const packed = {
    epk: eph.publicKeyB64,
    iv: iv.toString("base64"),
    ct: Buffer.concat([body, cipher.getAuthTag()]).toString("base64"),
  };
  return Buffer.from(JSON.stringify(packed)).toString("base64");
};
