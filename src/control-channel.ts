/**
 * The WebSocket control transport — the daemon's ONLY control channel. Uses
 * `partysocket` for auto-reconnect + backoff; its url provider re-fetches a
 * fresh channel (ticket + wss url) before every (re)connect. Holds ONE socket to
 * the relay, runs pushed commands with `runCommandInner`, and acks + pushes
 * status over the socket. See `docs/proposals/daemon-relay-websocket-push.md`.
 */

import type { TDaemonCommandAck, TRelayFrame } from "@openllmsh/protocol";
import { RELAY_PROTOCOL_VERSION, RelayFrame } from "@openllmsh/protocol";
import { Schema } from "effect";
import { WebSocket as ReconnectingWebSocket } from "partysocket";
import { fetchChannel } from "./cloud-client";
import { runCommandInner } from "./control-relay";
import { daemonEnv } from "./env";
import { createHeartbeat } from "./heartbeat";
import { logDebug, logInfo, logWarn } from "./logger";
import { computeStatus } from "./status";
import {
  failAllConsumedTunnels,
  handleConsumedTunnelFrame,
  ownsTunnel,
  registerTunnelSender,
} from "./tunnel-client";
import {
  abortAllTunnels,
  handleTunnelFrame,
  isTunnelFrame,
} from "./tunnel-server";

const decodeFrame = Schema.decodeUnknownEither(RelayFrame);

const WATCH_MS = 2_500;
// Heartbeat: the daemon sends its OWN `ping` on this interval and arms the
// liveness watchdog off the relay's `pong` (not off arbitrary inbound frames),
// so it detects a dead daemon→relay direction itself and reconnects — rather
// than waiting for the relay to terminate the socket (a `1006`). See `heartbeat.ts`
// and R4 in docs/audit/2026-06-08-daemon-relay-websocket-stability.md.
const HEARTBEAT_MS = 20_000;
// Liveness window: if NO `pong` arrives within this, the link is a silent
// half-open (no `close` fired) → `reconnect()`. 3.5× the heartbeat, so a single
// slow round-trip never trips it. partysocket owns connect/backoff, not liveness.
const LIVENESS_TIMEOUT_MS = 70_000;
// Reconnect jitter: a relay redeploy closes EVERY daemon's socket at once, and
// partysocket's backoff is deterministic (no jitter of its own), so without this
// the whole fleet re-dials in lockstep and stampedes the successor box. Add up to
// this much random delay before a RE-dial (gated on `hasConnected`, so the first
// connect stays immediate). Small vs the 35s presence grace, so it never surfaces
// as a flap. See `docs/audit/presence-reconnect-prior-art.md` §3.
const RECONNECT_JITTER_MS = 3_000;
/** Check a healthy relay connection for a deploy handoff without waiting for
 * the five-minute bootstrap loop. Small jitter prevents fleet lockstep. */
const MIGRATION_CHECK_MS = 45_000;
const MIGRATION_JITTER_MS = 5_000;

const sleep = (ms: number): Promise<void> =>
  new Promise((resolve) => setTimeout(resolve, ms));

let ws: ReconnectingWebSocket | null = null;
let watchTimer: ReturnType<typeof setInterval> | null = null;
let migrationTimer: ReturnType<typeof setTimeout> | null = null;
let migrationInFlight: Promise<void> | null = null;
let migrationEnabled = false;
// The daemon's liveness heartbeat. `sendPing` and `onSilent` close over `ws`,
// which is reassigned per connection, so they read the live binding at call
// time. partysocket reuses one instance across reconnects, so this one heartbeat
// is started on each open and stopped on each close.
const heartbeat = createHeartbeat({
  sendPing: () => send({ type: "ping" }),
  onSilent: () => {
    logWarn(
      "control-channel",
      `no relay pong in ${LIVENESS_TIMEOUT_MS}ms; forcing reconnect`,
    );
    ws?.reconnect();
  },
  heartbeatMs: HEARTBEAT_MS,
  livenessMs: LIVENESS_TIMEOUT_MS,
});
/** Fresh connect ticket, stashed by the url provider for the next `hello`. */
let ticket = "";
/** Origin of the wss url the CURRENT connection dialed (set by `channelUrl`).
 *  `migrateIfRelayMoved` compares it to a fresh channel fetch to detect a
 *  deploy that moved the relay to a new content-addressed sandbox. */
let connectedWssOrigin: string | null = null;
let lastFingerprint = "";
/** Relay session negotiated by the current connection. Null until welcome. */
let daemonSessionId: string | null = null;
/** Null while handshake is pending; false for an older relay welcome. */
let supportsOrderedStatus: boolean | null = null;
let statusSeq = 0;
let statusPublishTail: Promise<void> = Promise.resolve();
/** Whether THIS connection's `hello` has been sent. The relay 4001-closes any
 *  connection whose FIRST frame isn't a hello, and an out-of-band status push
 *  (the bootstrap scheduler fires `pushStatusIfChanged` the moment
 *  `cloud_state` changes — e.g. the cloud coming up seconds after the daemon)
 *  can resolve its `computeStatus` between the socket opening and the hello's
 *  own snapshot resolving — putting a `status` frame on the wire first and
 *  killing the handshake. So `send` drops every non-hello frame until the
 *  hello is out; the dropped status is lossless (the hello carries a fresh
 *  snapshot, and the 2.5s watcher re-pushes on change). */
let helloSent = false;
/** Monotonic connection counter. The hello continuation awaits
 *  `computeStatus()`, and the socket can close + reopen while that's pending —
 *  the STALE continuation would then send an old-ticket hello on the NEW
 *  connection (which the relay 4003-rejects) and prematurely open the
 *  `helloSent` gate. Each `onopen` bumps this; a continuation whose captured
 *  generation no longer matches simply bails. */
let connectionGeneration = 0;
/** Whether the socket has opened at least once — lets `onopen` log a first
 *  "connected" vs a recovery "reconnected", so the log shows the channel coming
 *  back, not just dropping. */
let hasConnected = false;
/** Last logged socket error reason / close line, to SUPPRESS the per-dial repeat
 *  during a sustained outage (cloud down, keyless): partysocket re-dials forever,
 *  and an unguarded warn-per-attempt floods the log. We log a NEW reason once,
 *  then stay quiet until it changes; `onopen` resets both so the next outage logs
 *  fresh (paired with the `reconnected` line). */
let lastErrorReason = "";
let lastCloseLine = "";

const send = (frame: TRelayFrame): void => {
  if (ws === null || ws.readyState !== ws.OPEN) return;
  // Nothing may precede the hello on a fresh connection (see `helloSent`).
  if (!helloSent && frame.type !== "hello") return;
  try {
    ws.send(JSON.stringify(frame));
  } catch {
    // best-effort: a failed send means the socket is closing; partysocket reconnects
  }
};

const enqueueStatusPublish = (
  compute: () => Promise<{ status: unknown; fingerprint: string } | null>,
  active?: boolean,
): Promise<void> => {
  const generation = connectionGeneration;
  statusPublishTail = statusPublishTail
    .catch(() => {})
    .then(async () => {
      const snapshot = await compute();
      if (snapshot === null) return;
      // A reconnect or an un-negotiated legacy session cannot receive ordered
      // state from work that began on a prior socket.
      if (
        generation !== connectionGeneration ||
        supportsOrderedStatus === null ||
        ws === null ||
        ws.readyState !== ws.OPEN
      )
        return;
      const ordered = supportsOrderedStatus && daemonSessionId !== null;
      if (ordered) statusSeq += 1;
      send({
        type: "status",
        ...(active === undefined ? {} : { active }),
        status: snapshot.status,
        ...(ordered && daemonSessionId !== null
          ? { daemon_session_id: daemonSessionId, status_seq: statusSeq }
          : {}),
      });
      lastFingerprint = snapshot.fingerprint;
    });
  return statusPublishTail;
};

const pushStatus = async (active?: boolean): Promise<void> =>
  enqueueStatusPublish(async () => {
    const status = await computeStatus();
    return { status, fingerprint: JSON.stringify(status) };
  }, active);

/** Send a fresh snapshot only when it changed — surfaces out-of-band flips
 *  (a device-code login completing) while a command isn't in flight. Exported
 *  so the bootstrap scheduler can push a `cloud_state` change immediately. */
export const pushStatusIfChanged = async (): Promise<void> =>
  enqueueStatusPublish(async () => {
    const status = await computeStatus();
    const fingerprint = JSON.stringify(status);
    // Check inside the serialized publisher so concurrent probes cannot both
    // decide they are the next changed snapshot.
    if (fingerprint === lastFingerprint) return null;
    return { status, fingerprint };
  }).then(() => {});

const startWatcher = (): void => {
  if (watchTimer !== null) return;
  watchTimer = setInterval(() => {
    pushStatusIfChanged().catch(() => {
      // best-effort: a failed snapshot push retries on the next tick
    });
  }, WATCH_MS);
  watchTimer.unref?.();
};

const stopWatcher = (): void => {
  if (watchTimer !== null) {
    clearInterval(watchTimer);
    watchTimer = null;
  }
};

const scheduleMigrationCheck = (): void => {
  if (!migrationEnabled || migrationTimer !== null) return;
  migrationTimer = setTimeout(
    () => {
      migrationTimer = null;
      if (migrationInFlight === null) {
        // Fence the check to the generation it starts under — a reconnect while
        // its channel fetch is in flight must not bounce the newer session.
        migrationInFlight = migrateIfRelayMoved(connectionGeneration).finally(
          () => {
            migrationInFlight = null;
          },
        );
      }
      void migrationInFlight.finally(scheduleMigrationCheck);
    },
    MIGRATION_CHECK_MS + Math.random() * MIGRATION_JITTER_MS,
  );
  migrationTimer.unref?.();
};

const stopMigrationCheck = (): void => {
  migrationEnabled = false;
  if (migrationTimer !== null) clearTimeout(migrationTimer);
  migrationTimer = null;
};

const startMigrationCheck = (): void => {
  migrationEnabled = true;
  scheduleMigrationCheck();
};

// Command dedup. The SAME command id can arrive more than once: the relay's
// delivery is at-least-once — its connect-time replay can overlap a live push,
// and its periodic sweep re-pushes any row that hasn't reached a terminal ack
// within the redeliver window (a long-running command like a browser login is
// legitimately un-acked for a while). Commands like `connect` aren't idempotent
// (a second run spawns a second login), so we dedupe by id here. `null` = still
// running (skip the re-ack — the in-flight run will ack); an ack value =
// completed (re-ack with the REAL result so a lost first-ack still reaches a
// terminal state, without clobbering an `error` with `done`). The map is
// in-memory: a daemon RESTART forgets it, so a command that was delivered but
// never terminally acked is re-delivered and re-run after the redeliver window
// — by design (the command never completed; the cloud's stale reaper is the
// give-up bound).
const commandResults = new Map<string, TDaemonCommandAck | null>();
/** Commands change shared vendor CLI and integration state. Keep execution FIFO so
 * competing browser tabs cannot race login, logout, or install operations. */
let commandTail: Promise<void> = Promise.resolve();
const PROCESSED_CAP = 500;

/** Max chars of error detail carried into the log line — enough to name the
 *  failing step (integration output ends with the failing command), never a
 *  full transcript dump. */
const ERROR_DETAIL_MAX = 600;

/** Extract a loggable diagnostic from an error ack's `result`: prefer its
 *  `error` field, else the TAIL of its `output` (integration failures put the
 *  failing step last), else a compact JSON of the result. Never used for
 *  successful acks — success results can carry control-plane secrets.
 *
 *  Redacted before it hits the daemon log: `integrations.ts` returns the
 *  RAW `output` in the ack (it goes to the dashboard over the authed socket)
 *  and only redacts its own openllmd.err.log tail — so THIS log path must
 *  scrub the API key itself, or a failing script that echoes its env would
 *  persist the key to disk here. */
const ackErrorDetail = (result: unknown): string => {
  let detail: string;
  if (result === null || typeof result !== "object") {
    detail = String(result);
  } else {
    const r = result as { error?: unknown; output?: unknown };
    detail =
      typeof r.error === "string" && r.error.length > 0
        ? r.error
        : typeof r.output === "string" && r.output.length > 0
          ? r.output
          : JSON.stringify(result);
  }
  const apiKey = daemonEnv().apiKey;
  if (apiKey !== null && apiKey.length > 0) {
    detail = detail.split(apiKey).join("[REDACTED_OPENLLM_API_KEY]");
  }
  // Belt-and-suspenders: scrub anything shaped like a gateway key even if it
  // isn't THIS daemon's (a script may print another key it was handed).
  detail = detail.replace(/sk-llm-[A-Za-z0-9._-]+/g, "sk-llm-[REDACTED]");
  return detail.length > ERROR_DETAIL_MAX
    ? `…${detail.slice(-ERROR_DETAIL_MAX)}`
    : detail;
};

const onCommand = async (command: TRelayFrame): Promise<void> => {
  if (command.type !== "command") return;
  // The relay session this command arrived on. A reconnect can happen while
  // the command waits in the FIFO queue; work owned by that obsolete session
  // must not execute or ack through the replacement session.
  const generation = connectionGeneration;
  const id = command.command.id;
  const prior = commandResults.get(id);
  if (prior !== undefined) {
    logDebug("control-channel", "duplicate command ignored", {
      id,
      kind: command.command.kind,
    });
    if (prior !== null) send({ type: "ack", ack: prior });
    return;
  }
  commandResults.set(id, null); // mark in-flight
  if (commandResults.size > PROCESSED_CAP) {
    // Evict the oldest COMPLETED entry. Skipping in-flight (`null`) entries is
    // load-bearing: evicting one would let a duplicate delivery of a still-
    // running command slip past the dedup above and execute twice (a second
    // `connect` spawns a second login). Map iteration is insertion-ordered, so
    // the first non-null is the oldest completed. If EVERY entry is in-flight we
    // keep them all — the cap is a soft bound, not a hard guarantee.
    for (const [key, value] of commandResults) {
      if (value !== null) {
        commandResults.delete(key);
        break;
      }
    }
  }
  const run = async (): Promise<void> => {
    // Queued under a replaced session — skip, and drop the in-flight dedup
    // marker so the relay's redelivery of this id can run on the CURRENT
    // session (a retained `null` entry would suppress that valid redelivery).
    if (generation !== connectionGeneration) {
      commandResults.delete(id);
      logDebug("control-channel", "stale-session command dropped", {
        kind: command.command.kind,
        id,
      });
      return;
    }
    // Log only non-sensitive metadata — a command `payload` (e.g. `set_config`)
    // and an ack `result` can carry control-plane secrets, so they must not land
    // in the daemon's logs. Kind + id + status are enough to trace a command.
    logInfo("control-channel", "command received", {
      kind: command.command.kind,
      id: command.command.id,
    });
    // This daemon, not the relay's socket send, confirms execution has started.
    send({ type: "ack", ack: { id, status: "ack" } });
    const ack = await runCommandInner(command.command);
    commandResults.set(id, ack);
    // On SUCCESS the result stays out of the log (it can carry control-plane
    // secrets — see the received-side note above). On ERROR, surface the
    // diagnostic fields (`error` / the tail of `output`) — without them a
    // failed command logs only `status: "error"`, which is undebuggable from
    // the daemon log alone (field-reported). Truncated: diagnostics, not dumps.
    logInfo("control-channel", "command done", {
      kind: command.command.kind,
      id: command.command.id,
      status: ack.status,
      ...(ack.status === "error" ? { error: ackErrorDetail(ack.result) } : {}),
    });
    send({ type: "ack", ack });
    // Carry a fresh snapshot back so the dashboard reflects the result.
    await pushStatus();
  };
  commandTail = commandTail.catch(() => {}).then(run);
  await commandTail;
};

const onFrame = (frame: TRelayFrame): void => {
  switch (frame.type) {
    case "command":
      onCommand(frame).catch(() => {
        // best-effort: a command failure is reflected by the next status push
      });
      return;
    case "welcome":
      daemonSessionId = frame.daemon_session_id ?? null;
      supportsOrderedStatus = frame.daemon_session_id !== undefined;
      // Sequence 1 of the session is reserved for the hello snapshot the relay
      // publishes on this daemon's behalf, so our own publisher starts above it.
      statusSeq = 1;
      startMigrationCheck();
      void pushStatus();
      return;
    case "ping":
      // The relay's keepalive ping → answer so its missed-pong reap stays happy.
      send({ type: "pong" });
      return;
    case "pong":
      // The relay's answer to OUR heartbeat ping → the daemon→relay round-trip
      // is alive, so re-arm the liveness window (R4: arm off pong, not off any
      // inbound frame — that's how we notice a dead outbound direction).
      heartbeat.notePong();
      return;
    default:
      // Subscription tunnels. This daemon can be BOTH ends: the CONSUMER of
      // tunnels it opened (routed by tunnel-id ownership — acks/res frames)
      // and the SERVER of tunnels a fleet peer/browser opened (everything
      // else). Both run on their own async tasks — never the commandTail (a
      // streaming response would block every command).
      if (frame.type === "tunnel_open_ack") {
        handleConsumedTunnelFrame(frame);
        return;
      }
      if (isTunnelFrame(frame)) {
        if (frame.type !== "tunnel_open" && ownsTunnel(frame.tunnel_id)) {
          handleConsumedTunnelFrame(frame);
          return;
        }
        handleTunnelFrame(frame, send);
        return;
      }
      // others: nothing to do (partysocket owns reconnection)
      return;
  }
};

const onMessage = (data: unknown): void => {
  if (typeof data !== "string") return;
  let json: unknown;
  try {
    json = JSON.parse(data);
  } catch {
    return;
  }
  const r = decodeFrame(json);
  if (r._tag === "Right") onFrame(r.right);
};

/** partysocket calls this before every (re)connect — fetch a fresh channel so
 *  each connection presents a fresh short-lived ticket. Throws when keyless /
 *  unreachable; partysocket backs off and retries. */
const channelUrl = async (): Promise<string> => {
  // De-sync fleet reconnect storms (relay redeploy). First connect is immediate;
  // only re-dials are jittered. partysocket calls this before every (re)connect.
  if (hasConnected) await sleep(Math.random() * RECONNECT_JITTER_MS);
  const channel = await fetchChannel();
  ticket = channel.ticket;
  connectedWssOrigin = wssOrigin(channel.wss_url);
  return channel.wss_url;
};

/** Origin of a ws(s) url (`wss://host[:port]`), or null when unparseable. */
export const wssOrigin = (url: string): string | null => {
  try {
    return new URL(url).origin;
  } catch {
    return null;
  }
};

/**
 * Detect a relay that MOVED and reconnect to it. Relay sandboxes are
 * content-addressed (name = bundle hash), so a deploy whose relay bundle
 * changed provisions a NEW box at a new origin — but a daemon with a healthy
 * socket to the OLD box never re-fetches the channel on its own (partysocket
 * only calls `channelUrl` before a (re)connect), so it stays parked on the
 * superseded box while fresh dashboard connections land on the new one and
 * see this daemon as offline. Called on each healthy bootstrap tick
 * (`main.ts`), bounding that split-brain window to ~one tick (5 min).
 *
 * Best-effort: a failed channel fetch is swallowed (the next tick retries).
 * The fetch's side effects are free-or-useful — the minted ticket is a
 * stateless short-lived signature (unused when the origin matches), and the
 * cloud handler provisions + TTL-extends the CURRENT box, keeping the
 * successor warm before we (and the fleet) reconnect to it.
 *
 * Mid-command race: `reconnect()` can close the socket while a command runs;
 * its ack `send()` silently drops (socket not OPEN), the relay's
 * at-least-once redelivery re-pushes the command, and `commandResults` dedup
 * re-acks with the stored terminal result — no extra handling needed.
 *
 * `generation` fences a SCHEDULED check to the connection it was started
 * under: the socket can be replaced while `fetchChannel` is awaited (the
 * liveness check above only runs before it), and a stale check must not
 * `reconnect()` a newer healthy session. Callers without a generation (tests,
 * ad-hoc probes) keep the unfenced behavior.
 */
export const migrateIfRelayMoved = async (
  generation?: number,
): Promise<void> => {
  // Only act on a HEALTHY connection: while disconnected/reconnecting,
  // partysocket already re-fetches the channel itself — probing here would
  // double-dial and could hand the pending reconnect a stale ticket. Capture
  // the socket locally: `stopControlChannel` nulls the module binding, and a
  // shutdown racing the await below must not turn `ws.reconnect()` into a
  // null deref (a reconnect on a manually-closed partysocket is a no-op).
  const socket = ws;
  if (socket === null || socket.readyState !== socket.OPEN) return;
  const current = connectedWssOrigin;
  if (current === null) return;
  let freshUrl: string;
  try {
    freshUrl = (await fetchChannel()).wss_url;
  } catch {
    return; // keyless / cloud unreachable — nothing to migrate to
  }
  const fresh = wssOrigin(freshUrl);
  if (fresh === null || fresh === current) return;
  if (generation !== undefined && generation !== connectionGeneration) return;
  logInfo("control-channel", "relay moved to a new box; reconnecting", {
    from: current,
    to: fresh,
  });
  socket.reconnect();
};

/** Start the WebSocket control loop (idempotent). */
export const startControlChannel = (): void => {
  if (ws !== null) return;
  logInfo("control-channel", "connecting over websocket");
  // Give the tunnel CLIENT (walker → fleet peer) a frame sender without a
  // walker→control-channel import (which would close an import cycle via
  // tunnel-server → listener → walker).
  registerTunnelSender(send);
  const socket = new ReconnectingWebSocket(channelUrl, undefined, {
    WebSocket: globalThis.WebSocket,
    minReconnectionDelay: 1_000,
    maxReconnectionDelay: 30_000,
  });
  ws = socket;
  socket.onopen = (): void => {
    logInfo(
      "control-channel",
      hasConnected ? "reconnected over websocket" : "connected over websocket",
    );
    hasConnected = true;
    lastErrorReason = ""; // recovered — let the next outage log fresh
    lastCloseLine = "";
    helloSent = false; // a fresh connection — nothing may precede ITS hello
    connectionGeneration += 1;
    // The relay swept the old socket's tunnels; their frames can never route
    // again — abort the served dispatches so they stop streaming into a void,
    // and error the consumed ones so waiting walkers fail over.
    abortAllTunnels();
    failAllConsumedTunnels();
    daemonSessionId = null;
    supportsOrderedStatus = null;
    statusSeq = 0;
    // Drop the previous generation's publish queue: a slow probe it queued can
    // no longer send (its captured generation mismatches), so keeping it as
    // the tail would only delay this session's first status behind dead work.
    statusPublishTail = Promise.resolve();
    const generation = connectionGeneration;
    heartbeat.start(); // begin pinging + arm the liveness window off pong receipt
    // Do not block registration on provider/CLI probes. The relay needs identity
    // first; welcome supplies this connection's session before status starts.
    if (generation === connectionGeneration) {
      helloSent = true;
      send({
        type: "hello",
        ticket,
        protocol_version: RELAY_PROTOCOL_VERSION,
      });
      startWatcher();
    }
  };
  socket.onmessage = (ev: MessageEvent): void => {
    onMessage(ev.data);
  };
  socket.onerror = (ev): void => {
    // Surface connect failures (a timed-out channel fetch — message `TIMEOUT` —,
    // a thrown channel URL provider, a refused dial) at WARN so "I don't know
    // why it keeps dropping" is answerable from the log. partysocket still backs
    // off + retries; the matching `reconnected` line lands on recovery. The real
    // reason lives on `.message` (partysocket wraps the thrown error) but native
    // ws error events carry only `.error`, so read both.
    const e = ev as { message?: unknown; error?: unknown } | null;
    const reason =
      (typeof e?.message === "string" && e.message) ||
      (e?.error instanceof Error && e.error.message) ||
      "unknown";
    // Suppress the per-dial repeat of an UNCHANGED reason (sustained outage).
    if (reason !== lastErrorReason) {
      lastErrorReason = reason;
      logWarn("control-channel", `socket error: ${reason} (reconnecting)`);
    }
  };
  socket.onclose = (ev): void => {
    stopWatcher();
    stopMigrationCheck();
    helloSent = false; // the next connection must lead with its own hello
    heartbeat.stop(); // disarm until the next open re-starts it
    // 4003 = relay rejected our ticket (usually a NEON_AUTH_COOKIE_SECRET
    // mismatch); 1006 = relay unreachable. 1000/1001 = relay cycling. partysocket
    // reconnects automatically in all cases.
    const clean = ev.code === 1000 || ev.code === 1001;
    const line = `socket closed code=${ev.code}${ev.reason ? ` reason=${ev.reason}` : ""}${clean ? "" : " (reconnecting)"}`;
    // A clean close (relay cycling its box, or our own graceful stop) is routine
    // → debug. An abnormal close (1006 unreachable, 4003 rejected ticket) is a
    // real drop the user needs to see → warn, paired with the `reconnected` line
    // — but only ONCE per sustained outage (suppress the unchanged per-dial repeat).
    if (clean) {
      logDebug("control-channel", line);
    } else if (line !== lastCloseLine) {
      lastCloseLine = line;
      logWarn("control-channel", line);
    }
  };
};

/** Graceful-exit beacon: flip the key offline, then close. Best-effort. */
export const stopControlChannel = async (): Promise<void> => {
  if (ws === null) return;
  stopWatcher();
  stopMigrationCheck();
  heartbeat.stop();
  if (ws.readyState === ws.OPEN) send({ type: "status", active: false });
  ws.close(); // partysocket: a manual close() disables further reconnection
  ws = null;
};
