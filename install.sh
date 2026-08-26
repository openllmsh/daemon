#!/usr/bin/env bash
# OpenLLM installer — installs the local daemon (openllmd) AND the CLI
# (openllm, plus the `ollm` alias). A daemon service starts only when a usable
# API key is already supplied or persisted; keyless onboarding belongs to
# `openllm start`, never this piped script.
#
#   curl -fsSL https://openllm.sh/install | bash
#
#   # with a key, so the daemon is paired immediately:
#   curl -fsSL https://openllm.sh/install | OPENLLM_API_KEY=sk-llm-... bash
#
# Env (all optional):
#   OPENLLM_CLOUD_ORIGIN   gateway origin (default https://openllm.sh)
#   OPENLLM_API_KEY        pair the daemon now; otherwise pair from the dashboard
#   OPENLLM_DAEMON_PORT    local daemon port (default 8787)
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

ORIGIN="${OPENLLM_CLOUD_ORIGIN:-https://openllm.sh}"
ORIGIN="${ORIGIN%/}"
OPENLLM_DIR="$HOME/.openllm"
BIN_DIR="$OPENLLM_DIR/bin"
ENV_FILE="${OPENLLM_DAEMON_ENV_FILE:-$OPENLLM_DIR/.env}"
DAEMON_PORT="${OPENLLM_DAEMON_PORT:-8787}"

has_command() { command -v "$1" >/dev/null 2>&1; }

die() { echo "Error: $*" >&2; exit 1; }

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
has_line_break "$ORIGIN" && die "OPENLLM_CLOUD_ORIGIN must not contain a line break"
[ -n "$ORIGIN" ] || die "OPENLLM_CLOUD_ORIGIN must not be empty"
# A custom env-file override must be absolute: the daemon + CLI only honour
# OPENLLM_DAEMON_ENV_FILE when it is absolute (see packages/cli/src/env.ts), so a
# relative value here would write config the runtime never reads.
if [ -n "${OPENLLM_DAEMON_ENV_FILE:-}" ]; then
  case "$OPENLLM_DAEMON_ENV_FILE" in
    /*) ;;
    *) die "OPENLLM_DAEMON_ENV_FILE must be an absolute path" ;;
  esac
fi
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
read_env_value() {
  local wanted="$1" line key
  [ -f "$ENV_FILE" ] || return 0
  while IFS= read -r line || [ -n "$line" ]; do
    key="${line%%=*}"
    [ "$key" = "$wanted" ] && { printf '%s' "${line#*=}"; return 0; }
  done < "$ENV_FILE"
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
if [ -x "$BIN_DIR/openllm" ]; then
  "$BIN_DIR/openllm" setup || echo "  note: run '$BIN_DIR/openllm setup' yourself to finish shell setup"
fi
"$BIN_DIR/openllmd" completion install >/dev/null 2>&1 || true

# --- start the service -----------------------------------------------------
# `openllmd start` owns service registration (launchd / systemd user unit,
# restart-on-crash, boot start, linger). A piped installer never prompts: with no
# persisted key it deliberately leaves no unpaired service behind.
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
  echo "Starting the daemon..."
  "$BIN_DIR/openllmd" start || die "openllmd start failed — run '$BIN_DIR/openllmd status' to diagnose"
else
  reconcile_keyless_service
  echo "OpenLLM is installed but not started."
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
# Background jobs outlive this script.
provision_clis || true

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
  cat <<EOF

OpenLLM needs an API key before it can start.
Sign in at $ORIGIN/sign-in.
New users will receive a key during onboarding. Already have an account? Open Keys after signing in.
Then run: openllm start
EOF
fi
