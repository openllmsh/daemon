#!/usr/bin/env bash
# OpenLLM installer — installs the local daemon (openllmd) AND the CLI
# (openllm, plus the `ollm` alias). A daemon service starts only when a usable
# API key is already supplied or persisted. For a keyless install the script does
# not reimplement onboarding — on a controlling terminal it hands straight off to
# `openllm start` (whose credential gate prompts on /dev/tty); with no terminal it
# just prints the `openllm start` next step and exits zero.
#
#   curl -fsSL https://www.openllm.sh/install | bash
#
#   # with a key, so the daemon is paired immediately:
#   curl -fsSL https://www.openllm.sh/install | OPENLLM_API_KEY=sk-llm-... bash
#
# Env (all optional):
#   OPENLLM_CLOUD_ORIGIN   gateway origin (env → existing ~/.openllm/.env →
#                          default https://www.openllm.sh; a re-run keeps your origin)
#   OPENLLM_API_KEY        pair the daemon now; otherwise pair from the dashboard
#   OPENLLM_DAEMON_PORT    local daemon port (default 8787; if unset AND
#                          nothing is already persisted, and 8787 is taken on
#                          this machine, the installer walks forward to the
#                          next free port nearby and persists that instead —
#                          an explicit or already-persisted port is never
#                          probed or changed)
#   OPENLLM_DAEMON_PTY_SESSIONS  enable remote terminal sessions (1/true; default off)
#
# This is the ONLY shell installer for the daemon. It also background-provisions
# any missing vendor subscription CLIs (claude / codex / kimi / grok / cursor-agent) via each
# vendor's official installer — skip if already present. It never edits a
# third-party client config: `openllm <client>` applies OpenLLM at run time
# instead. The only files it writes outside ~/.openllm (besides what a vendor
# installer itself does) are the PATH symlinks and the ONE marked block in your
# shell rc that `openllm setup` / `openllmd completion` manage.
set -euo pipefail

# ORIGIN is resolved in preflight (env → existing ~/.openllm/.env → default),
# mirroring the CLI's cliConfig() precedence — see below.
OPENLLM_DIR="$HOME/.openllm"
BIN_DIR="$OPENLLM_DIR/bin"
ENV_FILE="${OPENLLM_DAEMON_ENV_FILE:-$OPENLLM_DIR/.env}"
# DAEMON_PORT is resolved in preflight (env → existing env-file value → default),
# once `env_file_value`/`die` are defined — see below.
# `install` (default) is a first-time install; `update` is a manual full-product
# rerun (`openllm update`). Update mode converges the verified binaries + config
# but must NOT repeat first-install side effects: no vendor-CLI provisioning, no
# shell/PATH/completion edits, and no teardown of an existing healthy service.
# (Validated in preflight, once `die` is defined.)
INSTALL_MODE="${OPENLLM_INSTALL_MODE:-install}"
# Space-delimited list of components whose on-disk bytes were actually replaced
# this run (see install_component). Update mode reads it to skip a pointless
# daemon restart when nothing changed.
INSTALLED_COMPONENTS=""

has_command() { command -v "$1" >/dev/null 2>&1; }

die() { echo "Error: $*" >&2; exit 1; }

# Can we prompt the human running this install? A piped `curl … | bash` leaves
# the script's own stdin as the download stream, but the user's terminal is still
# addressable as /dev/tty. `openllm start`'s credential gate reads the key from
# /dev/tty yet decides interactivity from stdin/stderr being TTYs — so we only
# hand off to it when stderr is a real terminal AND /dev/tty is openable. In a
# non-interactive install (CI, a pipe with no terminal) this is false and we fall
# back to printing the manual `openllm start` next step.
has_controlling_tty() {
  [ -t 2 ] || return 1
  { true < /dev/tty; } 2>/dev/null
}

# Bash strings cannot contain NUL bytes: command substitution and shell variables
# discard them before this script can inspect a value. Do not add `$'\0'` to this
# glob — Bash expands it to an empty string, turning the glob into `**` and
# matching every input.
has_line_break() { [[ "$1" == *$'\n'* || "$1" == *$'\r'* ]]; }

trim_whitespace() {
  local value="$1"
  value="${value#"${value%%[![:space:]]*}"}"
  value="${value%"${value##*[![:space:]]}"}"
  printf '%s' "$value"
}

# Read one KEY's LAST-occurrence value from the shared env file, mirroring
# `parseEnvLines` (packages/daemon/src/env.ts): trim the whole line, skip
# blank/`#` lines, split at the first `=`, trim both sides. `parseEnvLines`
# folds lines into a `Map` via `.set(key, value)`, so a later duplicate
# OVERWRITES an earlier one — the last matching line must win here too (the
# bug this replaces: every reader below used to return on its first match).
# No quote/comment stripping here — that's a per-caller decision below.
env_file_lookup() {
  local wanted="$1" line trimmed key value result="" found=0
  [ -f "$ENV_FILE" ] || return 0
  while IFS= read -r line || [ -n "$line" ]; do
    trimmed="$(trim_whitespace "$line")"
    case "$trimmed" in ""|\#*) continue ;; esac
    case "$trimmed" in *=*) ;; *) continue ;; esac
    key="$(trim_whitespace "${trimmed%%=*}")"
    [ -n "$key" ] || continue
    [ "$key" = "$wanted" ] || continue
    value="$(trim_whitespace "${trimmed#*=}")"
    result="$value"
    found=1
  done < "$ENV_FILE"
  [ "$found" = 1 ] && printf '%s' "$result"
  return 0
}

# Read one KEY's value from the shared env file (last match wins — see
# `env_file_lookup`), additionally stripping one layer of surrounding quotes
# so it matches how the CLI resolves the same file (`parseEnvFile` in
# packages/cli/src/env.ts, which underlies `cliConfig()`). Used only to seed
# the effective origin below; empty/absent → empty string.
env_file_value() {
  local wanted="$1" value
  value="$(env_file_lookup "$wanted")"
  value="${value#[\"\']}"
  value="${value%[\"\']}"
  printf '%s' "$value"
}

# Read one KEY's RAW value from the shared env file (last match wins) —
# outer-whitespace trimmed only, no quote or comment stripping — for the
# port, whose protocol-compatible parsing (`normalize_daemon_port`) needs the
# untouched value: whether a comment sits inside or outside the quotes
# changes the correct strip order, so `env_file_value`'s single fixed order
# (quotes always stripped first) cannot be reused here.
env_file_raw_value() {
  env_file_lookup "$1"
}

is_usable_api_key() {
  local key="$1"
  # Minted keys are `sk-llm-` + a 10-byte base64url id (14 chars) + `.` +
  # a 32-byte base64url secret (43 chars). Restricting this shell boundary to
  # the wire grammar keeps values safe to persist in KEY=value config files.
  [[ "$key" =~ ^sk-llm-[A-Za-z0-9_-]{14}[.][A-Za-z0-9_-]{43}$ ]]
}

sha256_of() {
  if has_command shasum; then shasum -a 256 "$1" 2>/dev/null | cut -d' ' -f1
  elif has_command sha256sum; then sha256sum "$1" 2>/dev/null | cut -d' ' -f1
  fi
}

# --- preflight -------------------------------------------------------------
# A custom env-file override must be absolute: the daemon + CLI only honour
# OPENLLM_DAEMON_ENV_FILE when it is absolute (see packages/cli/src/env.ts), so a
# relative value here would write config the runtime never reads. Validate this
# BEFORE reading the file for the origin fallback, so we never read a relative
# path resolved against the caller's cwd.
if [ -n "${OPENLLM_DAEMON_ENV_FILE:-}" ]; then
  case "$OPENLLM_DAEMON_ENV_FILE" in
    /*) ;;
    *) die "OPENLLM_DAEMON_ENV_FILE must be an absolute path" ;;
  esac
fi
# Effective origin — process env, else the origin already recorded in the shared
# env file, else the compiled production default. This mirrors the CLI's
# cliConfig() precedence (packages/cli/src/env.ts), so re-running the installer
# (or `openllm update`) from a preview/self-host origin does NOT silently reset a
# user's persisted OPENLLM_CLOUD_ORIGIN back to production. An explicit
# OPENLLM_CLOUD_ORIGIN in the environment still wins.
ORIGIN="${OPENLLM_CLOUD_ORIGIN:-}"
[ -n "$ORIGIN" ] || ORIGIN="$(env_file_value OPENLLM_CLOUD_ORIGIN)"
[ -n "$ORIGIN" ] || ORIGIN="https://www.openllm.sh"
ORIGIN="${ORIGIN%/}"
has_line_break "$ORIGIN" && die "OPENLLM_CLOUD_ORIGIN must not contain a line break"
[ -n "$ORIGIN" ] || die "OPENLLM_CLOUD_ORIGIN must not be empty"
# Effective port — explicit env, else the port already persisted in the shared
# env file, else the default. Mirrors the ORIGIN precedence above. A malformed
# selected value falls back to the default rather than partially parsing.
#
# `normalize_daemon_port` mirrors packages/protocol/daemon-port.ts's
# `parseOpenllmDaemonPort` byte-for-byte: strip an inline `# comment` and one
# layer of quotes, in the order that depends on whether the comment sits
# INSIDE or OUTSIDE the quotes (`"59321 # local"` vs `"59321" # local` vs a
# bare `59321 # local`), then require a plain decimal in 1-65535. No eval, no
# sourcing, no octal interpretation (a leading-zero string like `"08787"`
# still parses as decimal here, matching `Number.parseInt(_, 10)`), and the
# digit-count bound below keeps `[ ... -ge ... ]` from ever seeing a string
# long enough to trip a shell integer-overflow diagnostic.
normalize_daemon_port() {
  local raw="$1" trimmed value decommented stripped
  trimmed="$(trim_whitespace "$raw")"
  if [[ "$trimmed" =~ ^\".*\"$ || "$trimmed" =~ ^\'.*\'$ ]] && [ "${#trimmed}" -ge 2 ]; then
    value="${trimmed:1:${#trimmed}-2}"
    if [[ "$value" =~ ^(.*)[[:space:]]#.*$ ]]; then
      value="$(trim_whitespace "${BASH_REMATCH[1]}")"
    fi
  else
    decommented="$trimmed"
    if [[ "$trimmed" =~ ^(.*)[[:space:]]#.*$ ]]; then
      decommented="$(trim_whitespace "${BASH_REMATCH[1]}")"
    fi
    if { [[ "$decommented" =~ ^\".*\"$ || "$decommented" =~ ^\'.*\'$ ]] && [ "${#decommented}" -ge 2 ]; }; then
      value="${decommented:1:${#decommented}-2}"
    else
      value="$decommented"
    fi
  fi
  stripped="$(trim_whitespace "$value")"
  case "$stripped" in
    ''|*[!0-9]*) return 1 ;;
  esac
  [ "${#stripped}" -le 7 ] || return 1
  { [ "$stripped" -ge 1 ] && [ "$stripped" -le 65535 ]; } || return 1
  printf '%s' "$stripped"
}

# Default port + the bounded range the auto-increment scan below may walk
# into (8787-8796) — only reached when no explicit/persisted port exists yet
# (see the DAEMON_PORT resolution below); an explicit or persisted port is
# never probed or reassigned.
DEFAULT_DAEMON_PORT=8787
PORT_SCAN_LIMIT=10

# Is 127.0.0.1:$port free to bind? Returns 0 free, 1 occupied, 2 unverifiable
# — a tier returns 2 (rather than falling through) the moment it gets an
# answer it cannot confidently classify, so a shaky result never gets
# silently reinterpreted as "free" by a later tier. No single tool is
# guaranteed present, so this tries, in order:
#   1. python3 — an actual bind() attempt; the only reliable tier. Its exit
#      code is explicit: 0 free, 1 EADDRINUSE (occupied), 2 any other error
#      (permission denied, missing socket support, …) — never guessed.
#   2. bash's /dev/tcp, bounded by `timeout` so a filtered/backlogged port
#      can't hang the install — skipped outright without `timeout`, since an
#      unbounded connect is not an acceptable fallback. A connect success or
#      a reset both mean something is already there (occupied); "Connection
#      refused" is the ordinary free-port result. Anything else (including a
#      build without /dev/tcp support) falls through to the next tier.
#   3. nc -z -v with a 1s timeout, tried only if 2 gave no answer. A ZERO
#      exit always means connected (occupied) regardless of output. A
#      nonzero exit is free ONLY on an explicit "Connection refused" in the
#      (C-locale, so the text is predictable) output; a reset is occupied;
#      anything else — timeout, an invalid flag this nc build rejected, a
#      permission failure — is unverifiable, NOT free.
#   4. no reliable probe at all — unverifiable; the caller refuses to
#      install rather than silently gamble.
# Every tier is TCP-only on 127.0.0.1 (never 0.0.0.0/UDP) and closes its probe
# socket immediately, so nothing here holds a port — a bind/start race
# against another process remains inherent to any check-then-act port pick.
port_is_free() {
  local port="$1"

  if has_command python3; then
    local py_rc
    # The heredoc runs as the tested command of this `if` so a nonzero exit
    # (1 = EADDRINUSE, 2 = any other error) is read via `$?` in the `else`
    # branch instead of tripping `set -e` — bash exempts the whole command a
    # conditional tests from errexit, including everything a function it
    # calls (here, none — it's a direct external command) runs.
    if python3 - "$port" >/dev/null 2>&1 <<'PY'
import errno
import socket
import sys

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
try:
    s.bind(("127.0.0.1", int(sys.argv[1])))
except OSError as e:
    sys.exit(1 if e.errno == errno.EADDRINUSE else 2)
else:
    sys.exit(0)
finally:
    s.close()
PY
    then
      py_rc=0
    else
      py_rc=$?
    fi
    case "$py_rc" in
      0) return 0 ;;
      1) return 1 ;;
      *) return 2 ;;
    esac
  fi

  if has_command timeout; then
    local probe
    probe="$(timeout 1 bash -c "exec 3<>'/dev/tcp/127.0.0.1/$port' && printf OK" 2>&1)" || true
    case "$probe" in
      OK) return 1 ;;
      *[Rr]efused*) return 0 ;;
      *"eset"*) return 1 ;;
    esac
  fi

  if has_command nc; then
    local out
    # Same if/else exit-code capture as the python3 tier above (a bare
    # failing assignment would otherwise trip `set -e` on the common "nc
    # exited nonzero because the port is free" case).
    if out="$(LC_ALL=C LANG=C nc -z -v -w 1 127.0.0.1 "$port" 2>&1)"; then
      return 1
    fi
    case "$out" in
      *"Connection refused"*) return 0 ;;
      *"onnection reset"*|*"eset by peer"*) return 1 ;;
    esac
    return 2
  fi

  return 2
}

# Bounded scan for a free port starting at $1, trying at most $2 candidates
# ($start, $start+1, … capped at 65535). Prints the first free port and
# returns 0; returns 1 once exhausted, or 2 the moment a probe can't verify.
find_available_port() {
  local start="$1" limit="$2" port attempt rc
  port="$start"
  attempt=0
  while [ "$attempt" -lt "$limit" ]; do
    port_is_free "$port"
    rc=$?
    [ "$rc" -eq 0 ] && { printf '%s' "$port"; return 0; }
    [ "$rc" -eq 2 ] && return 2
    attempt=$((attempt + 1))
    port=$((port + 1))
    [ "$port" -le 65535 ] || break
  done
  return 1
}

DAEMON_PORT="${OPENLLM_DAEMON_PORT:-}"
if [ -n "$DAEMON_PORT" ]; then
  NORMALIZED_PORT="$(normalize_daemon_port "$DAEMON_PORT")" && DAEMON_PORT="$NORMALIZED_PORT" || DAEMON_PORT=""
fi
if [ -z "$DAEMON_PORT" ]; then
  RAW_PERSISTED_PORT="$(env_file_raw_value OPENLLM_DAEMON_PORT)"
  if [ -n "$RAW_PERSISTED_PORT" ]; then
    NORMALIZED_PORT="$(normalize_daemon_port "$RAW_PERSISTED_PORT")" && DAEMON_PORT="$NORMALIZED_PORT"
  fi
fi
# Neither an explicit nor a persisted port exists yet — a genuinely
# first-ever choice, never a reassignment. Probe the default and, only here,
# walk forward to the next free port in a small bounded range.
if [ -z "$DAEMON_PORT" ]; then
  if RESOLVED_PORT="$(find_available_port "$DEFAULT_DAEMON_PORT" "$PORT_SCAN_LIMIT")"; then
    DAEMON_PORT="$RESOLVED_PORT"
  else
    SCAN_RC=$?
    if [ "$SCAN_RC" -eq 2 ]; then
      die "could not verify any port's availability near $DEFAULT_DAEMON_PORT (no python3, no timeout+/dev/tcp, no nc) — set OPENLLM_DAEMON_PORT to choose one explicitly"
    fi
    die "no free port found for the daemon in $DEFAULT_DAEMON_PORT-$((DEFAULT_DAEMON_PORT + PORT_SCAN_LIMIT - 1)) — set OPENLLM_DAEMON_PORT to choose one"
  fi
fi
case "$INSTALL_MODE" in
  install|update) ;;
  *) die "OPENLLM_INSTALL_MODE must be 'install' or 'update'" ;;
esac
case "$(uname -s)" in
  Darwin) OS="darwin" ;;
  Linux)  OS="linux" ;;
  *) die "unsupported OS $(uname -s) — OpenLLM supports macOS and Linux" ;;
esac
case "$(uname -m)" in
  arm64|aarch64) ARCH="arm64" ;;
  x86_64|amd64)  ARCH="x64-baseline" ;;
  *) die "unsupported architecture $(uname -m)" ;;
esac
TARGET="${OS}-${ARCH}"

has_command curl || die "curl is required"
# Checksum verification is mandatory — refuse rather than install unverified
# bytes.
if ! has_command shasum && ! has_command sha256sum; then
  die "shasum or sha256sum is required to verify the download"
fi

# Validate a supplied key before making the install directory or downloading either
# binary. Persisted values are deliberately read later, under the daemon's env-file
# lock: downloads can take long enough for the daemon or another installer to update
# the file in the meantime.
SUPPLIED_KEY="$(trim_whitespace "${OPENLLM_API_KEY:-}")"
if [ -n "$SUPPLIED_KEY" ]; then
  has_line_break "$SUPPLIED_KEY" && die "OPENLLM_API_KEY must not contain a line break"
  is_usable_api_key "$SUPPLIED_KEY" || die "OPENLLM_API_KEY has an invalid format"
fi
API_KEY=""

mkdir -p "$BIN_DIR" "$(dirname "$ENV_FILE")"

# --- the ONE install entry point ------------------------------------------
# /api/install validates the committed daemon + CLI release pins in TypeScript
# (allow-listed repo, well-formed digests, a published tag for this target) and
# fails closed. Hitting it first means a mis-pinned or half-published release is
# refused BEFORE we download anything. No query parameters.
echo "Resolving the current OpenLLM release..."
MANIFEST="$(curl -fsSL "$ORIGIN/api/install" 2>/dev/null)" \
  || die "could not reach $ORIGIN/api/install — check OPENLLM_CLOUD_ORIGIN and your network"

# Extract one "key": "value" string field. The document is small, flat, and
# machine-generated by us, so a scoped sed is enough — no jq dependency on a
# fresh machine.
json_field() {
  printf '%s' "$MANIFEST" \
    | tr -d '\n' \
    | sed -n "s/.*\"$1\"[[:space:]]*:[[:space:]]*\"\([^\"]*\)\".*/\1/p"
}

DAEMON_VERSION="$(json_field daemon_version)"
CLI_VERSION="$(json_field cli_version)"
[ -n "$DAEMON_VERSION" ] || die "no daemon release is published yet"

# --- fetch + verify + install one component -------------------------------
# Bytes come from the per-component binary routes, which 302 to the pinned
# GitHub release asset and serve the committed digest as a `.sha256` sibling —
# the same pair the daemon's own self-update verifies against.
install_component() {
  local name="$1" route="$2" version="$3"
  local dest="$BIN_DIR/$name"
  local url="$ORIGIN/$route/$TARGET"
  local published installed stamp="$BIN_DIR/.$name.sha256.stamp"

  published="$(curl -fsSL "$url.sha256" 2>/dev/null | cut -d' ' -f1 || true)"
  case "$published" in
    [0-9a-f]*)
      [[ "$published" =~ ^[0-9a-f]{64}$ ]] || die "malformed checksum for $name"
      ;;
    *) die "no published checksum for $name ($TARGET) — nothing to install" ;;
  esac

  # Skip a tens-of-MB download when what's installed already matches.
  # Developer-ID-signed + notarized binaries keep their published digest on
  # disk (we no longer force ad-hoc re-sign when codesign --verify passes).
  # The stamp remains for the fallback ad-hoc path (unsigned/invalid) where
  # re-signing rewrites bytes after the published digest check.
  if [ -x "$dest" ]; then
    installed="$(sha256_of "$dest" || true)"
    if [ -n "$installed" ]; then
      if [ "$installed" = "$published" ]; then
        echo "  $name is already up to date"
        return 0
      fi
      if [ -f "$stamp" ]; then
        local sp si
        read -r sp si < "$stamp" || true
        if [ "$sp" = "$published" ] && [ "$si" = "$installed" ]; then
          echo "  $name is already up to date"
          return 0
        fi
      fi
    fi
  fi

  echo "Downloading $name ${version:+$version }($TARGET)..."
  # Stage inside $BIN_DIR: same filesystem as $dest (so the final mv is an
  # atomic rename, not a cross-device copy) and on the roomy root disk — minimal
  # cloud images mount a tiny RAM-backed /tmp where a download this size fails.
  local dl="$BIN_DIR/.$name.download.$$"
  local bin="$BIN_DIR/.$name.bin.$$"
  trap 'rm -f "$dl" "$bin"' RETURN
  if [ -t 2 ]; then
    curl -fL --progress-bar "$url" -o "$dl" || die "download failed: $url"
  else
    curl -fsSL "$url" -o "$dl" || die "download failed: $url"
  fi

  # Assets are gzipped; the pinned digest is over the DECOMPRESSED binary, so
  # the integrity gate is independent of gzip's non-determinism.
  if gzip -t "$dl" >/dev/null 2>&1; then
    gzip -dc "$dl" > "$bin" || die "could not decompress $name"
  else
    mv "$dl" "$bin"
  fi

  local actual
  actual="$(sha256_of "$bin")"
  [ -n "$actual" ] || die "could not hash the downloaded $name"
  if [ "$actual" != "$published" ]; then
    die "checksum mismatch for $name (expected $published, got $actual) — refusing to install"
  fi

  chmod 0755 "$bin"
  mv -f "$bin" "$dest"

  # macOS: strip quarantine. Preserve a valid Developer ID / notarized
  # signature (codesign --verify). Only ad-hoc sign when the signature is
  # missing/invalid — force ad-hoc would strip notarization and rewrite bytes.
  if [ "$OS" = "darwin" ]; then
    xattr -d com.apple.quarantine "$dest" >/dev/null 2>&1 || true
    if ! codesign --verify "$dest" >/dev/null 2>&1; then
      codesign --force --sign - "$dest" >/dev/null 2>&1 || true
      printf '%s %s\n' "$published" "$(sha256_of "$dest")" > "$stamp" 2>/dev/null || true
    fi
  fi
  echo "  $name installed → $dest"
  INSTALLED_COMPONENTS="$INSTALLED_COMPONENTS $name"
}

install_component openllmd api/daemon/binary "$DAEMON_VERSION"
# The CLI rides the same install: one command gets you both, and the daemon's
# auto-update loop keeps them both current from here on.
if [ -n "$CLI_VERSION" ]; then
  install_component openllm api/cli/binary "$CLI_VERSION"
else
  echo "  note: no CLI release published yet — skipping openllm"
fi

# --- the shared config file ------------------------------------------------
# Re-read under the same exclusive `$ENV_FILE.lock` protocol as the daemon's
# writeEnvFileVars. Never rebuild this file from a pre-download snapshot: a daemon
# can mint a device id or update credentials while binaries are downloading.
# Delegates to `env_file_lookup` for the same last-match-wins, trim/skip
# semantics as `parseEnvLines` (packages/daemon/src/env.ts) — the values read
# here (API key, device id, PTY flag) are exactly what that parser resolves
# on the daemon's own next boot.
read_env_value() {
  env_file_lookup "$1"
}

write_env_file() {
  local lock="$ENV_FILE.lock" attempt=0 acquired=0
  # `noclobber` opens with O_EXCL. This intentionally uses the daemon's lock-file
  # shape rather than flock, which is unavailable on some supported fresh installs.
  while [ "$attempt" -lt 500 ]; do
    if (set -C; : > "$lock") 2>/dev/null; then acquired=1; break; fi
    attempt=$((attempt + 1))
    sleep 0.01
  done
  [ "$acquired" = 1 ] || die "could not acquire config lock: $lock"

  local current_key current_device current_pty desired_key desired_pty tmp line key
  current_key="$(trim_whitespace "$(read_env_value OPENLLM_API_KEY || true)")"
  current_device="$(read_env_value OPENLLM_DEVICE_ID || true)"
  current_pty="$(read_env_value OPENLLM_DAEMON_PTY_SESSIONS || true)"
  if [ -n "$SUPPLIED_KEY" ]; then
    desired_key="$SUPPLIED_KEY"
  else
    desired_key="$current_key"
    if [ -n "$desired_key" ] && ! is_usable_api_key "$desired_key"; then
      echo "Ignoring the persisted API key because its format is invalid; OpenLLM will install without starting the daemon." >&2
      desired_key=""
    fi
  fi
  case "${OPENLLM_DAEMON_PTY_SESSIONS:-}" in
    1|true) desired_pty="1" ;;
    0|false) desired_pty="0" ;;
    *) desired_pty="$current_pty" ;;
  esac

  tmp="$ENV_FILE.tmp.$$"
  # Install the RETURN cleanup only after all nested reads have completed: Bash
  # runs a RETURN trap for nested functions too.
  trap 'rm -f "$tmp" "$lock"' RETURN
  # Tighten umask only for the temp-file creation window (closing the race
  # before `chmod 0600`), then restore it so later installer steps and child
  # processes keep the caller's umask.
  local saved_umask
  saved_umask="$(umask)"
  umask 077
  : > "$tmp"
  # Keep unrelated lines byte-for-byte, but replace every installer-owned key with
  # one canonical occurrence. An ignored invalid persisted key is therefore removed.
  local wrote_origin=0 wrote_port=0 wrote_key=0 wrote_device=0 wrote_pty=0
  if [ -f "$ENV_FILE" ]; then
    while IFS= read -r line || [ -n "$line" ]; do
      key="${line%%=*}"
      case "$key" in
        OPENLLM_CLOUD_ORIGIN)
          [ "$wrote_origin" = 1 ] || { printf 'OPENLLM_CLOUD_ORIGIN=%s\n' "$ORIGIN" >> "$tmp"; wrote_origin=1; }
          ;;
        OPENLLM_DAEMON_PORT)
          [ "$wrote_port" = 1 ] || { printf 'OPENLLM_DAEMON_PORT=%s\n' "$DAEMON_PORT" >> "$tmp"; wrote_port=1; }
          ;;
        OPENLLM_API_KEY)
          if [ -n "$desired_key" ] && [ "$wrote_key" = 0 ]; then printf 'OPENLLM_API_KEY=%s\n' "$desired_key" >> "$tmp"; wrote_key=1; fi
          ;;
        OPENLLM_DEVICE_ID)
          if [ -n "$current_device" ] && [ "$wrote_device" = 0 ]; then printf 'OPENLLM_DEVICE_ID=%s\n' "$current_device" >> "$tmp"; wrote_device=1; fi
          ;;
        OPENLLM_DAEMON_PTY_SESSIONS)
          if [ -n "$desired_pty" ] && [ "$wrote_pty" = 0 ]; then printf 'OPENLLM_DAEMON_PTY_SESSIONS=%s\n' "$desired_pty" >> "$tmp"; wrote_pty=1; fi
          ;;
        *) printf '%s\n' "$line" >> "$tmp" ;;
      esac
    done < "$ENV_FILE"
  fi
  [ "$wrote_origin" = 1 ] || printf 'OPENLLM_CLOUD_ORIGIN=%s\n' "$ORIGIN" >> "$tmp"
  [ "$wrote_port" = 1 ] || printf 'OPENLLM_DAEMON_PORT=%s\n' "$DAEMON_PORT" >> "$tmp"
  [ -z "$desired_key" ] || [ "$wrote_key" = 1 ] || printf 'OPENLLM_API_KEY=%s\n' "$desired_key" >> "$tmp"
  [ -z "$current_device" ] || [ "$wrote_device" = 1 ] || printf 'OPENLLM_DEVICE_ID=%s\n' "$current_device" >> "$tmp"
  [ -z "$desired_pty" ] || [ "$wrote_pty" = 1 ] || printf 'OPENLLM_DAEMON_PTY_SESSIONS=%s\n' "$desired_pty" >> "$tmp"
  chmod 0600 "$tmp"
  # Abort with a clear error if the atomic replace fails — never fall through to
  # announce success (or set API_KEY) on a config that was not written. The
  # RETURN trap still cleans up the temp file + lock.
  mv -f "$tmp" "$ENV_FILE" || die "could not write config file: $ENV_FILE"
  chmod 0600 "$ENV_FILE"
  umask "$saved_umask"
  rm -f "$lock"
  trap - RETURN
  API_KEY="$desired_key"
  echo "  gateway config written → $ENV_FILE"
}

write_env_file

# --- shell wiring ----------------------------------------------------------
# Delegated to the binaries themselves so the installer and a human run the
# SAME code path: `openllm setup` creates the openllm + ollm PATH symlinks,
# writes the one marked rc block (PATH + `alias ollm=openllm`), and installs
# completion for both names. Best-effort — a sandboxed or read-only environment
# leaves the binary usable by absolute path.
# First-install only: a manual update must not touch PATH symlinks, the shell
# rc block, or completion — those are the user's environment, already wired.
if [ "$INSTALL_MODE" != update ]; then
  if [ -x "$BIN_DIR/openllm" ]; then
    "$BIN_DIR/openllm" setup || echo "  note: run '$BIN_DIR/openllm setup' yourself to finish shell setup"
  fi
  "$BIN_DIR/openllmd" completion install >/dev/null 2>&1 || true
fi

# --- start the service -----------------------------------------------------
# `openllmd start` owns service registration (launchd / systemd user unit,
# restart-on-crash, boot start, linger). With no persisted key the script never
# prompts inline — it either hands off to the gated `openllm start` on a
# controlling terminal (closing banner) or leaves no unpaired service behind.
reconcile_keyless_service() {
  # Older installers registered a daemon before the user had a usable key. Do
  # not merely skip `start` on upgrade: stop, disable, and remove that stale
  # registration so it cannot respawn later with an unpaired configuration.
  case "$OS" in
    darwin)
      local label="sh.openllm.daemon"
      local target="gui/${UID}/${label}"
      launchctl bootout "$target" >/dev/null 2>&1 || true
      launchctl disable "$target" >/dev/null 2>&1 || true
      rm -f "$HOME/Library/LaunchAgents/${label}.plist"
      ;;
    linux)
      systemctl --user disable --now openllmd.service >/dev/null 2>&1 || true
      rm -f "$HOME/.config/systemd/user/openllmd.service"
      systemctl --user daemon-reload >/dev/null 2>&1 || true
      ;;
  esac
}

if [ -n "$API_KEY" ]; then
  if [ "$INSTALL_MODE" = update ]; then
    # Only bounce the daemon when its binary actually changed. `openllmd
    # restart` (and even `start`) stop-then-start the running service, so an
    # unconditional restart would needlessly interrupt an already-current daemon
    # on every `openllm update` — the common no-op case. A changed CLI binary
    # alone needs no restart: the running daemon's bytes are unchanged and the
    # new CLI is picked up on its next invocation. Credentials are already
    # persisted, so the restart never prompts.
    case " $INSTALLED_COMPONENTS " in
      *" openllmd "*)
        echo "Restarting the daemon to pick up the new binary..."
        "$BIN_DIR/openllmd" restart || die "openllmd restart failed — run '$BIN_DIR/openllmd status' to diagnose"
        ;;
      *)
        echo "  daemon already current — no restart needed"
        ;;
    esac
  else
    echo "Starting the daemon..."
    "$BIN_DIR/openllmd" start || die "openllmd start failed — run '$BIN_DIR/openllmd status' to diagnose"
  fi
elif [ "$INSTALL_MODE" = update ]; then
  # Keyless update: converge binaries + config only. Never register/start an
  # unpaired daemon, and never tear down an existing service — that is a
  # first-install reconciliation, not an update action.
  echo "OpenLLM updated (no API key configured; daemon left as-is)."
else
  # Keyless first install: clear any stale unpaired registration now. The closing
  # banner then either runs the interactive credential gate (`openllm start` on a
  # controlling terminal) or prints the manual next step — see below.
  reconcile_keyless_service
fi

# --- provision the vendor subscription CLIs (background) -------------------
# The daemon RUNS the official vendor CLIs but never INSTALLS them (it runs
# under an OS sandbox that intentionally can't touch shell rc files). So THIS
# script — run by the user, unsandboxed, with a real HOME/PATH/rc — is where a
# missing CLI gets installed: fire-and-forget the official installer for each
# provider not already present. Each native installer does its own normal
# rc/PATH edit. The daemon only LINKS its isolated run-view to whatever lands
# (see cli-install.ts) — symlink self-heal is separate and needs no write grant
# on the host CLI dirs. Fully best-effort: guarded so a slow/failed vendor
# install never fails the daemon install, and logged to ~/.openllm/cli-install.log.
provision_clis() {
  # display | command | dest launcher | official installer URL.
  # These mirror sources of truth in TS that bash can't import: the dest
  # launchers match the VENDOR-DEFAULT entries of `hostCliCandidates` in
  # packages/daemon/src/cli-paths.ts (daemon-side detection additionally
  # scans PATH generically, mirroring the `has_command` check below — the two
  # layers agree on "installed" wherever the binary lives), and the URLs match
  # `VENDOR_CLI_INSTALL_CMD` in lib/hooks/use-daemon.ts + `installHint` in
  # packages/cli/src/clients/registry.ts. If a vendor path or installer URL
  # changes, update it in all those places too.
  local specs=(
    "Claude Code|claude|$HOME/.local/bin/claude|https://claude.ai/install.sh"
    "Codex|codex|$HOME/.local/bin/codex|https://chatgpt.com/codex/install.sh"
    "Kimi|kimi|$HOME/.kimi-code/bin/kimi|https://code.kimi.com/kimi-code/install.sh"
    "Grok|grok|$HOME/.grok/bin/grok|https://x.ai/cli/install.sh"
    # ⚠️ RESEARCH-UNVERIFIED: Cursor's official installer/launcher path.
    "Cursor Agent|cursor-agent|$HOME/.local/bin/cursor-agent|https://cursor.com/install"
    # Official Muse Code installer (https://dev.meta.ai/docs/muse-code/).
    "Muse Code|muse|$HOME/.local/bin/muse|https://dev.meta.ai/install.sh"
  )
  # Build a PATH that (a) puts the STANDARD system dirs FIRST — covering
  # curl/bash/tar/gzip/uname/sed/grep on macOS AND Linux (all live in
  # /usr/bin + /bin on both) plus Homebrew — so a real `curl` always wins over
  # any shim the OUTER process prepended, and (b) APPENDS the caller's own
  # PATH so Homebrew/nix/snap tools a vendor installer needs stay reachable.
  # The backgrounded jobs outlive this script, so they must not depend on the
  # outer PATH: the dev dist-installer prepends an ephemeral `curl` shim it
  # deletes on exit, and a bare `curl` in a detached job would then resolve to
  # nothing (or a coreutils multicall). Resolving curl absolutely + running the
  # job under this PATH makes the primitive robust on every major platform.
  local sys_path="/usr/local/bin:/usr/bin:/bin:/usr/local/sbin:/usr/sbin:/sbin:/opt/homebrew/bin"
  local run_path="${sys_path}:${PATH:-}"
  local curl_bin
  curl_bin="$(PATH="$run_path" command -v curl 2>/dev/null || true)"
  # Fallback: probe the canonical absolute locations directly (a pathological
  # PATH or a shell without a working `command -v` still resolves here).
  if [ -z "$curl_bin" ]; then
    local c
    for c in /usr/bin/curl /bin/curl /usr/local/bin/curl /opt/homebrew/bin/curl; do
      [ -x "$c" ] && { curl_bin="$c"; break; }
    done
  fi
  if [ -z "$curl_bin" ]; then
    echo "  Vendor CLIs: curl not found — install them by hand from their official installers." >&2
    return 0
  fi
  local spec name cmd dest url
  for spec in "${specs[@]}"; do
    IFS='|' read -r name cmd dest url <<<"$spec"
    if has_command "$cmd" || [ -x "$dest" ]; then
      echo "  $name CLI: already installed."
      # Mirror the skip into the log too — previously only the backgrounded
      # installer output landed there, so a skipped provider left the log
      # silent about why nothing was installed.
      echo "$name CLI: already installed ($(command -v "$cmd" 2>/dev/null || echo "$dest")) — skipping install." \
        >>"$OPENLLM_DIR/cli-install.log" 2>/dev/null || true
      continue
    fi
    echo "  $name CLI: installing in the background…"
    # Absolute curl entry + `run_path` for the piped installer and every inner
    # tool it spawns → a detached job is immune to the outer process's PATH
    # while the installer still writes under the real $HOME.
    (
      PATH="$run_path" "$curl_bin" -fsSL "$url" | PATH="$run_path" bash
    ) >>"$OPENLLM_DIR/cli-install.log" 2>&1 &
  done
}
# `|| true` + the subshell/background jobs keep this off the `set -euo
# pipefail` path — a vendor install can never abort the daemon install.
# Background jobs outlive this script. Skipped on a manual update: rerunning
# every vendor's installer is a first-install action the user didn't ask for.
if [ "$INSTALL_MODE" != update ]; then
  provision_clis || true
fi

if [ "$INSTALL_MODE" = update ]; then
  # A manual update did no shell wiring or vendor provisioning — keep the closing
  # note to what actually happened.
  cat <<EOF

OpenLLM is up to date.

  openllmd status          daemon service + run state
  openllm --help           everything else
EOF
else
  cat <<EOF

OpenLLM is installed.

  openllmd status          daemon service + run state
  openllm claude           run Claude Code through OpenLLM
  ollm codex               (short alias) run Codex through OpenLLM
  openllm --help           everything else

Open a new shell (or source your rc) so \`openllm\` and \`ollm\` are on PATH.
Any missing vendor CLIs are installing in the background
(see ~/.openllm/cli-install.log). Open the dashboard's Providers tab to
connect each vendor once its CLI is ready.
EOF
  if [ -z "$API_KEY" ]; then
    if has_controlling_tty && { [ -x "$BIN_DIR/openllm" ] || [ -x "$BIN_DIR/openllmd" ]; }; then
      # Single-step onboarding: hand straight to the gated `openllm start` instead
      # of asking the user to run a second command. Its credential gate prints the
      # sign-in guidance, reads the key hidden from /dev/tty, validates the format
      # (reprompting on a bad paste), persists it, then registers + starts the
      # service. We bind the child's stdin to /dev/tty so the gate sees an
      # interactive terminal even though this script's own stdin is the curl pipe.
      #
      # A cancel (Ctrl-C / empty paste) or any nonzero exit must NOT fail the
      # install — the binaries and config are already in place; we just point the
      # user back at the start command. `set -e` is suppressed by the `if`.
      # Prefer the public `openllm` mirror; fall back to `openllmd` when the CLI
      # release isn't published yet — and name the recovery command for whichever
      # binary this install actually has.
      starter="$BIN_DIR/openllm"; start_cmd="openllm"
      if [ ! -x "$starter" ]; then starter="$BIN_DIR/openllmd"; start_cmd="openllmd"; fi
      echo
      if ! "$starter" start < /dev/tty; then
        # `$start_cmd start` already printed the specific reason to the terminal
        # (key cancelled, save failed, or a service-registration error). Do NOT
        # re-attribute every nonzero exit to a missing key — the failure may be
        # operational. Stay cause-neutral and point back at the one command that
        # finishes setup, named for the binary we used.
        cat <<EOF

The daemon isn't running yet. Finish setup any time with: $start_cmd start
(If you still need an API key, sign in at $ORIGIN/sign-in.)
EOF
      fi
    else
      cat <<EOF

OpenLLM needs an API key before it can start.
Sign in at $ORIGIN/sign-in.
New users will receive a key during onboarding. Already have an account? Open Keys after signing in.
Then run: openllm start
EOF
    fi
  fi
fi
