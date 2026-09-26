/**
 * OpenLLM local daemon — entrypoint.
 *
 * Headless. Boots a localhost `Bun.serve` that exposes the
 * OpenAI/Anthropic-compatible `/v1/*` inference surface (run locally against
 * `packages/core`'s pipeline for SUBSCRIPTION hops, credentials delegated to
 * the official vendor CLIs) plus a tiny read-only `/whoami` that returns this
 * daemon's opaque `device_id` so the dashboard can tell which key's daemon is
 * on THIS host (`docs/proposals/this-machine-detection-audit.md`). CONTROL
 * (status / connect / integrations) is NOT served on localhost: the daemon
 * dials OUT to the cloud relay over a WebSocket (`control-channel.ts`) and the
 * dashboard drives it from there. Both loopback routes share one cross-origin
 * CORS/PNA grant. See `docs/proposals/daemon-relay-websocket-push.md`.
 *
 * It holds NO DEK and decrypts NO vault credential. The only secret it
 * carries is the user's `sk-llm-...` key, used to authenticate cloud
 * control-plane calls (config pull + request-metadata recording) and to
 * forward API-key hops in a mixed chain to the cloud `/v1/*` surface.
 *
 * This file is compiled into a source-free standalone binary with
 * `bun build --compile --minify --bytecode` (see scripts/compile.ts).
 */

import "./scm-gate";
import { windowsScmServiceMode } from "./scm-gate";

// MUST be the entrypoint's FIRST substantive import after the SCM gate.
// `@peculiar/x509` (pulled in by `werift`, our RTC stack) constructs a
// `tsyringe` DI container at module load, and tsyringe THROWS unless
// `Reflect.getMetadata` already exists. x509's own ESM build imports this
// polyfill, but `bun build --compile` drops that side-effect-only import, so
// the compiled binary died on boot with "tsyringe requires a reflect polyfill"
// while `bun run` from source was fine. Importing it here — from the entry,
// ahead of the RTC import chain — is the fix the tsyringe error message itself
// prescribes. `tests/daemon/compiled-boot.test.ts` guards it.
import "reflect-metadata";
import "./windows-process-init";

import { runCli } from "./cli";
import { runDaemonMain } from "./daemon-runtime";

// Dispatch management subcommands (start/stop/status/completion/…); a bare
// service boot is always machine mode and must never consume terminal input.
if (!windowsScmServiceMode && !runCli()) void runDaemonMain();
