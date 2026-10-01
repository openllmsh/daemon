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
#                          default https://www.openllm.sh; a re-run keeps your origin).
#                          HTTPS only; http:// is refused. A loopback origin
#                          (127.0.0.1 / localhost / ::1) over http is allowed
#                          ONLY with OPENLLM_ALLOW_INSECURE_ORIGIN=1 (local dev).
#   OPENLLM_API_KEY        pair the daemon now; otherwise pair from the dashboard
#   OPENLLM_DAEMON_PORT    local daemon port (default 8787; if unset AND
#                          nothing is already persisted, and 8787 is taken on
#                          this machine, the installer walks forward to the
#                          next free port nearby and persists that instead —
#                          an explicit or already-persisted port is never
#                          probed or changed)
#   OPENLLM_DAEMON_PTY_SESSIONS  enable remote terminal sessions (1/true; default off)
#   OPENLLM_INSTALL_VENDOR_CLIS  opt-in: also install missing vendor CLIs in the
#                          background (1/true/yes; default OFF — the installer
#                          prints each vendor's official one-line installer
#                          instead of running it for you)
#   OPENLLM_SKIP_VENDOR_CLIS     hard opt-out: never provision vendor CLIs at all
#                          (set by CI/test harnesses)
#
# This is the ONLY shell installer for the daemon. On OPT-IN it can provision
# missing vendor subscription CLIs (claude / codex / kimi / grok / cursor-agent / muse)
# via each vendor's official installer — always skipped when already present.
# It never edits a
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

# --- arguments ---------------------------------------------------------------
# Private-prerelease path (NR2-3): `--from-file <path>` supplies a LOCAL daemon
# binary verified against the operator-provided `--sha256 <hex>` digest of
# THAT file (e.g. `sha256sum openllmd-darwin-arm64`), and
# `--cli-from-file`/`--cli-sha256` do the same for the CLI binary. When any of
# these is given NOTHING is downloaded — no manifest, no .sha256, no binary
# fetch — and components you did not supply are left untouched. All other
# arguments are rejected so a typo can never silently change an install.
FROM_FILE=""
FROM_SHA=""
CLI_FROM_FILE=""
CLI_SHA=""
# Publish-time tag binding: the release pipeline stamps the ONE literal below
# into the published copy of this script before it serves a prerelease tag.
# It is a fixed per-invocation assignment, NOT an environment default.
OPENLLM_PRERELEASE_TAG=''
PRERELEASE_OPT=""
PRERELEASE_SEEN=0
LOCAL_FILE_SEEN=0
LOCK_PARTICIPANTS="mixed"
usage() {
  cat <<'USAGE'
Usage: install.sh [options]
  --from-file <path>     install the openllmd binary from a local file
  --sha256 <hex>         sha256 digest of the --from-file file (required with it)
  --cli-from-file <path> install the openllm CLI binary from a local file too
  --cli-sha256 <hex>     sha256 digest of the --cli-from-file file (required with it)
  --prerelease <tag>     install the published prerelease tag (vX.Y.Z-label.N)
  --lock-participants=new-only  recover a tagged launch marker after excluding older installers
  -h, --help             show this text
USAGE
}
while [ $# -gt 0 ]; do
  case "$1" in
    --from-file)
      LOCAL_FILE_SEEN=1
      FROM_FILE="${2:-}"
      [ -n "$FROM_FILE" ] || die "--from-file needs a path"
      shift 2
      ;;
    --from-file=*) LOCAL_FILE_SEEN=1; FROM_FILE="${1#*=}"; shift ;;
    --sha256)
      LOCAL_FILE_SEEN=1
      FROM_SHA="${2:-}"
      [ -n "$FROM_SHA" ] || die "--sha256 needs a hex digest"
      shift 2
      ;;
    --sha256=*) LOCAL_FILE_SEEN=1; FROM_SHA="${1#*=}"; shift ;;
    --cli-from-file)
      LOCAL_FILE_SEEN=1
      CLI_FROM_FILE="${2:-}"
      [ -n "$CLI_FROM_FILE" ] || die "--cli-from-file needs a path"
      shift 2
      ;;
    --cli-from-file=*) LOCAL_FILE_SEEN=1; CLI_FROM_FILE="${1#*=}"; shift ;;
    --cli-sha256)
      LOCAL_FILE_SEEN=1
      CLI_SHA="${2:-}"
      [ -n "$CLI_SHA" ] || die "--cli-sha256 needs a hex digest"
      shift 2
      ;;
    --cli-sha256=*) LOCAL_FILE_SEEN=1; CLI_SHA="${1#*=}"; shift ;;
    --prerelease)
      [ "$PRERELEASE_SEEN" = 0 ] || die "--prerelease must not be repeated"
      PRERELEASE_SEEN=1
      PRERELEASE_OPT="${2:-}"
      [ -n "$PRERELEASE_OPT" ] || die "--prerelease needs a tag"
      shift 2
      ;;
    --prerelease=*)
      [ "$PRERELEASE_SEEN" = 0 ] || die "--prerelease must not be repeated"
      PRERELEASE_SEEN=1
      PRERELEASE_OPT="${1#*=}"
      [ -n "$PRERELEASE_OPT" ] || die "--prerelease needs a tag"
      shift
      ;;
    --lock-participants=new-only) LOCK_PARTICIPANTS="new-only"; shift ;;
    --lock-participants=mixed) LOCK_PARTICIPANTS="mixed"; shift ;;
    --lock-participants=*) die "invalid lock participant mode: ${1#*=}" ;;
    -h|--help) usage; exit 0 ;;
    *) die "unknown argument: $1 (supported: --from-file, --sha256, --cli-from-file, --cli-sha256, --prerelease, --lock-participants)" ;;
  esac
done
if [ "$PRERELEASE_SEEN" = 1 ] && [ "$LOCAL_FILE_SEEN" = 1 ]; then
  die "--prerelease cannot be combined with --from-file/--sha256/--cli-from-file/--cli-sha256"
fi
if [ -n "$FROM_FILE" ] || [ -n "$FROM_SHA" ]; then
  [ -n "$FROM_FILE" ] && [ -n "$FROM_SHA" ] \
    || die "--from-file and --sha256 must be given together"
fi
if [ -n "$CLI_FROM_FILE" ] || [ -n "$CLI_SHA" ]; then
  [ -n "$CLI_FROM_FILE" ] && [ -n "$CLI_SHA" ] \
    || die "--cli-from-file and --cli-sha256 must be given together"
  [ -n "$FROM_FILE" ] \
    || die "--cli-from-file requires --from-file (this installer must always install the daemon)"
fi

# --- prerelease tag selection ----------------------------------------------
# Tag grammar: vMAJOR.MINOR.PATCH-LABEL.N. Numeric fields are `0` or digits
# with NO leading zero. LABEL starts with a letter and holds only ASCII
# letters, digits or hyphens. A stable tag (vX.Y.Z) is NOT a prerelease tag —
# grammar and shape reject whitespace, paths, queries and shell syntax too.
is_prerelease_tag() {
  [[ "$1" =~ ^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)-[A-Za-z][A-Za-z0-9-]*\.(0|[1-9][0-9]*)$ ]]
}
# The selected prerelease tag, or "" for the normal stable flow. A resolved
# embedded marker supplies the default; an explicit --prerelease must equal it.
# Local-file mode never selects the marker.
PRERELEASE_TAG=""
if [ "$PRERELEASE_SEEN" = 1 ]; then
  is_prerelease_tag "$PRERELEASE_OPT" \
    || die "not a prerelease tag: $PRERELEASE_OPT (want vMAJOR.MINOR.PATCH-LABEL.N, e.g. v2.8.0-beta.3)"
  if [ -n "$OPENLLM_PRERELEASE_TAG" ]; then
    is_prerelease_tag "$OPENLLM_PRERELEASE_TAG" \
      || die "this script's embedded prerelease tag is invalid: $OPENLLM_PRERELEASE_TAG"
    [ "$PRERELEASE_OPT" = "$OPENLLM_PRERELEASE_TAG" ] \
      || die "--prerelease $PRERELEASE_OPT does not match this script's published tag $OPENLLM_PRERELEASE_TAG"
  fi
  PRERELEASE_TAG="$PRERELEASE_OPT"
elif [ -z "$FROM_FILE" ] && [ -z "$FROM_SHA" ] && [ -z "$CLI_FROM_FILE" ] && [ -z "$CLI_SHA" ] \
  && [ -n "$OPENLLM_PRERELEASE_TAG" ]; then
  is_prerelease_tag "$OPENLLM_PRERELEASE_TAG" \
    || die "this script's embedded prerelease tag is invalid: $OPENLLM_PRERELEASE_TAG"
  PRERELEASE_TAG="$OPENLLM_PRERELEASE_TAG"
fi

# Replacement policy: the version advertised by /api/install is the release of
# record — an advertised PRERELEASE is installable, and a prerelease install may
# move to a newer stable (or newer prerelease). The only refusal left is a
# DOWNGRADE: an installed build strictly newer than the advertised release.
# The --version probe bound (DR-7): TERM after PROBE_TIMEOUT_S, then KILL after
# PROBE_KILL_GRACE_S more, so a binary that ignores TERM can never hang the
# installer.
PROBE_TIMEOUT_S=10
PROBE_KILL_GRACE_S=2
# Bounded --version probe: TERM after PROBE_TIMEOUT_S, then KILL after
# PROBE_KILL_GRACE_S more. Sets PROBE_STATUS (the probe's exit code) and
# PROBE_OUT (its stdout). Never dies — the caller chooses the failure.
run_version_probe() {
  local binary="$1" probe_file pid watchdog
  probe_file="${TMPDIR:-/tmp}/openllmd-version-probe.$$"
  "$binary" --version >"$probe_file" 2>/dev/null &
  pid=$!
  (
    trap 'kill "$timer" 2>/dev/null || true; exit 0' TERM INT
    sleep "$PROBE_TIMEOUT_S" &
    local timer=$!
    wait "$timer"
    # The probe outlived its bound: TERM, then KILL after the grace window.
    kill -TERM "$pid" 2>/dev/null || true
    sleep "$PROBE_KILL_GRACE_S" &
    timer=$!
    wait "$timer"
    kill -KILL "$pid" 2>/dev/null || true
  ) &
  watchdog=$!
  if wait "$pid"; then PROBE_STATUS=0; else PROBE_STATUS=$?; fi
  kill -TERM "$watchdog" 2>/dev/null || true
  wait "$watchdog" 2>/dev/null || true
  PROBE_OUT="$(cat "$probe_file" 2>/dev/null || true)"
  rm -f "$probe_file"
}

# Extract the first dotted semver from probe output into PARSED_VERSION
# ("" when nothing parses).
parse_probe_version() {
  if [[ "$1" =~ (^|[^[:alnum:].+_-])v?([0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?([+][0-9A-Za-z.-]+)?)([^[:alnum:].+-]|$) ]]; then
    PARSED_VERSION="${BASH_REMATCH[2]}"
  else
    PARSED_VERSION=""
  fi
}

installed_version() {
  local binary="$1"
  [ -x "$binary" ] || return 1
  run_version_probe "$binary"
  [ "$PROBE_STATUS" -eq 0 ] \
    || die "version probe timed out or failed at $binary; refusing to overwrite it.
  To repair by hand: move the binary aside ('mv \"$binary\" \"$binary.bak\"') and re-run this installer."
  parse_probe_version "$PROBE_OUT"
  [ -n "$PARSED_VERSION" ] \
    || die "could not parse a version from $binary; refusing to overwrite"
  INSTALLED_VERSION="$PARSED_VERSION"
}

# SemVer numeric-identifier predicate: a numeric identifier is `0` or digits
# with NO leading zero. An all-digit identifier WITH a leading zero ("01") is
# not valid numeric — SemVer treats it as alphanumeric — so it must never be
# compared numerically ("beta.01" sorts lexically; it does not equal "beta.1").
semver_num() { [[ "$1" =~ ^(0|[1-9][0-9]*)$ ]]; }

# Compare two dotted versions; prints -1, 0 or 1 (a<b, a==b, a>b). One leading
# `v` is stripped (a manifest may advertise "v2.8.0"); build metadata is
# ignored; a prerelease sorts below its release (2.8.0-beta.1 < 2.8.0).
semver_cmp() {
  local a="${1#v}" b="${2#v}" am bm ap bp i
  a="${a%%+*}"; b="${b%%+*}"
  am="${a%%-*}"; bm="${b%%-*}"
  case "$a" in *-*) ap="${a#*-}" ;; *) ap="" ;; esac
  case "$b" in *-*) bp="${b#*-}" ;; *) bp="" ;; esac
  local -a an bn
  IFS='.' read -r -a an <<<"$am"
  IFS='.' read -r -a bn <<<"$bm"
  for i in 0 1 2; do
    local x="${an[i]:-0}" y="${bn[i]:-0}"
    [[ "$x" =~ ^[0-9]+$ ]] || x=0
    [[ "$y" =~ ^[0-9]+$ ]] || y=0
    [ "$x" -lt "$y" ] && { echo -1; return; }
    [ "$x" -gt "$y" ] && { echo 1; return; }
  done
  [ -z "$ap" ] && [ -z "$bp" ] && { echo 0; return; }
  [ -z "$ap" ] && { echo 1; return; }
  [ -z "$bp" ] && { echo -1; return; }
  local -a pa pb
  IFS='.' read -r -a pa <<<"$ap"
  IFS='.' read -r -a pb <<<"$bp"
  local n=$(( ${#pa[@]} > ${#pb[@]} ? ${#pa[@]} : ${#pb[@]} ))
  for ((i = 0; i < n; i++)); do
    local x="${pa[i]:-}" y="${pb[i]:-}"
    [ -z "$x" ] && { echo -1; return; }
    [ -z "$y" ] && { echo 1; return; }
    if semver_num "$x" && semver_num "$y"; then
      [ "$x" -lt "$y" ] && { echo -1; return; }
      [ "$x" -gt "$y" ] && { echo 1; return; }
    elif semver_num "$x"; then
      echo -1; return
    elif semver_num "$y"; then
      echo 1; return
    elif [[ "$x" < "$y" ]]; then
      echo -1; return
    elif [[ "$x" != "$y" ]]; then
      echo 1; return
    fi
  done
  echo 0
}

# The one remaining replacement refusal: an installed build NEWER than what the
# origin advertises. Fail closed with the manual remedy printed (DR-1).
refuse_downgrade() {
  local binary="$1" advertised="$2" installed
  [ -n "$advertised" ] || return 0
  installed_version "$binary" || return 0
  installed="$INSTALLED_VERSION"
  [ "$(semver_cmp "$installed" "$advertised")" = "1" ] || return 0
  die "installed $binary is $installed, newer than the advertised release $advertised — refusing to downgrade.
  To force the advertised version, remove $binary and re-run this installer."
}

ENV_LOCK_BINARY="$BIN_DIR/openllmd"
# >>> openllm-env-lock/v3 >>>
# The installed helper owns all lock metadata operations.
env_lock_acquire() {
  local target="$1" helper begin previous attempt code worker_pid
  ENV_LOCK_DIR=""
  helper="${LOCKLAB_HELPER_BIN:-${OPENLLM_LOCK_HELPER:-}}"
  if [ -z "$helper" ]; then
    helper="${ENV_LOCK_BINARY:-}"
  fi
  [ -n "$helper" ] && [ -x "$helper" ] || { echo 'lock helper is missing or incompatible' >&2; return 74; }
  worker_pid="${BASHPID:-$$}"
  ENV_LOCK_CHANNEL="$(mktemp -d "${TMPDIR:-/tmp}/openllm-lock.XXXXXXXX")" || return 74
  chmod 700 "$ENV_LOCK_CHANNEL" || { rmdir "$ENV_LOCK_CHANNEL" 2>/dev/null || true; return 74; }
  "$helper" --internal-lock-control e "$target.lock.d" "$worker_pid" \
    "$ENV_LOCK_CHANNEL/request" "$ENV_LOCK_CHANNEL/response" </dev/null >/dev/null &
  ENV_LOCK_HELPER_PID=$!
  begin=$SECONDS
  previous=$SECONDS
  code=74
  for ((attempt=0; attempt<120; attempt++)); do
    if [ "$SECONDS" -lt "$previous" ] || [ "$((SECONDS - begin))" -ge 12 ]; then break; fi
    previous=$SECONDS
    if [ -f "$ENV_LOCK_CHANNEL/response" ]; then
      case "$(cat "$ENV_LOCK_CHANNEL/response")" in
        '{"version":3,"code":0}') ENV_LOCK_DIR="$target.lock.d"; return 0 ;;
        '{"version":3,"code":73}') code=73; break ;;
        *) break ;;
      esac
    fi
    kill -0 "$ENV_LOCK_HELPER_PID" 2>/dev/null || break
    sleep 0.1 || break
  done
  printf 'release\n' > "$ENV_LOCK_CHANNEL/request"
  wait "$ENV_LOCK_HELPER_PID" 2>/dev/null || true
  rm -f "$ENV_LOCK_CHANNEL/request" "$ENV_LOCK_CHANNEL/response"
  rmdir "$ENV_LOCK_CHANNEL" 2>/dev/null || true
  ENV_LOCK_HELPER_PID=""
  return "$code"
}
env_lock_release() {
  local result=0
  [ -n "${ENV_LOCK_HELPER_PID:-}" ] || return 0
  ENV_LOCK_DIR=""
  printf 'release\n' > "$ENV_LOCK_CHANNEL/request" || result=74
  wait "$ENV_LOCK_HELPER_PID" || result=$?
  ENV_LOCK_HELPER_PID=""
  rm -f "$ENV_LOCK_CHANNEL/request" "$ENV_LOCK_CHANNEL/response"
  rmdir "$ENV_LOCK_CHANNEL" 2>/dev/null || true
  return "$result"
}
# <<< openllm-env-lock/v3 <<<

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

# Limit each output to 512 MiB. Release binaries are about 100 MiB.
is_gzip_asset() {
  LC_ALL=C head -c 2 "$1" | LC_ALL=C grep -q $'\x1f\x8b'
}

decompress_asset() {
  local input="$1" output="$2" name="$3"
  local max_bytes=536870912 status=0 size
  gzip -dc "$input" | head -c "$max_bytes" > "$output" || status=$?
  size="$(stat -c %s "$output" 2>/dev/null || stat -f %z "$output")" \
    || die "could not measure the decompressed $name"
  if [ "$size" -ge "$max_bytes" ]; then
    rm -f "$output"
    die "$name decompressed asset reaches the 512 MiB limit — refusing to install"
  fi
  if [ "$status" -ne 0 ]; then
    rm -f "$output"
    die "could not decompress $name: invalid gzip asset or output write failure"
  fi
}

# >>> openllm-prerelease/v1 (identical block in both shell installers) >>>>>>>
# Public-prerelease resolution. The manifest and the asset come from the SAME
# tag on the component's own repository: the manifest is tagged source, the
# asset is that tag's published release file. The digest gate is the manifest
# sha256 of the DECOMPRESSED bytes.
#
#   manifest:  https://raw.githubusercontent.com/<repo>/<tag>/manifest.ts
#   asset:     https://github.com/<repo>/releases/download/<tag>/<asset>
#
# OPENLLM_PRERELEASE_BASE_URL is a test-only override: it must parse to an
# http URL on a loopback host (127.0.0.1, localhost or [::1]); redirects are
# refused and the value is never persisted. The scheme list carries the
# redirect bound: production follows at most five, loopback follows none.
PRE_BASE=""
PR_SCHEME=(--proto "=https" --proto-redir "=https" --max-redirs 5)

# $1 = repository (openllmsh/daemon or openllmsh/cli), $2 = file in the tag's
# source tree. Prints the URL for that tagged file.
prerelease_repo_url() {
  if [ -n "$PRE_BASE" ]; then
    printf '%s/%s/%s/%s' "$PRE_BASE" "$1" "$PRERELEASE_TAG" "$2"
  else
    printf 'https://raw.githubusercontent.com/%s/%s/%s' "$1" "$PRERELEASE_TAG" "$2"
  fi
}

# $1 = repository, $2 = asset basename. Prints the release-asset URL.
prerelease_asset_url() {
  if [ -n "$PRE_BASE" ]; then
    prerelease_repo_url "$1" "$2"
  else
    printf 'https://github.com/%s/releases/download/%s/%s' "$1" "$PRERELEASE_TAG" "$2"
  fi
}

# Fetch one repository's tagged manifest and print the sha256 digest it pins
# for the host TARGET. Dies on any fetch, parse or content failure — the
# caller never picks another tag to recover.
prerelease_manifest_digest() {
  local repo="$1" export_name="$2" url body digest body_end
  url="$(prerelease_repo_url "$repo" manifest.ts)"
  # The trailing 'x' sentinel keeps command substitution from stripping the
  # manifest's final newlines, so the parser sees the exact served bytes.
  # Cap the pipe before Bash reads it. Older curl cannot cap chunked bodies.
  body="$(curl "${PR_SCHEME[@]}" "${CURL_META[@]}" --max-filesize 65536 -fsSL "$url" 2>/dev/null | head -c 65537 || exit; printf x)" \
    || die "could not fetch the $repo manifest for $PRERELEASE_TAG (manifest limit: 64 KiB)"
  body="${body%x}"
  [ "$(printf %s "$body" | LC_ALL=C wc -c)" -le 65536 ] \
    || die "manifest exceeds 64 KiB"
  # body_end tells the lexer whether the input ended in a newline — the
  # per-record buffer rebuild below hides one, which would let a `//` comment
  # cut off at EOF pass as terminated.
  body_end=0
  case "$body" in *$'\n') body_end=1 ;; esac
  digest="$(printf '%s' "$body" | LC_ALL=C awk \
    -v want_export="$export_name" -v want_repo="$repo" \
    -v want_tag="$PRERELEASE_TAG" -v want_target="$TARGET" \
    -v body_end="$body_end" '
function die(m) { printf "manifest: %s\n", m > "/dev/stderr"; exit 1 }
function hex2num(h,   i, v) {
  v = 0
  for (i = 1; i <= length(h); i++)
    v = v * 16 + index("0123456789abcdef", tolower(substr(h, i, 1))) - 1
  return v
}
function parse_object(   key, k2) {
  if (typ[p] != "{") die("release must be an object")
  p++
  while (1) {
    if (p > nt) die("unterminated object")
    if (typ[p] == "}") { p++; break }
    if (typ[p] != "id" && typ[p] != "str") die("bad field name")
    key = val[p]; p++
    if (typ[p] != ":") die("field " key " needs :")
    p++
    if (key == "repo" || key == "tag") {
      if (typ[p] != "str") die(key " must be a string")
      if (key == "repo") { if (f_repo++) die("duplicate repo"); v_repo = val[p] }
      else { if (f_tag++) die("duplicate tag"); v_tag = val[p] }
      p++
    } else if (key == "targets") {
      if (f_targets++) die("duplicate targets")
      if (typ[p] != "[") die("targets must be an array")
      p++
      while (1) {
        if (p > nt) die("unterminated targets")
        if (typ[p] == "]") { p++; break }
        if (typ[p] != "str") die("target must be a string")
        if (val[p] in targ) die("duplicate target " val[p])
        targ[val[p]] = 1; p++
        if (typ[p] == ",") { p++; continue }
        if (typ[p] == "]") { p++; break }
        die("bad targets array")
      }
    } else if (key == "sha256") {
      if (f_sha++) die("duplicate sha256")
      if (typ[p] != "{") die("sha256 must be an object")
      p++
      while (1) {
        if (p > nt) die("unterminated sha256")
        if (typ[p] == "}") { p++; break }
        if (typ[p] != "str") die("sha256 keys must be strings")
        k2 = val[p]; p++
        if (typ[p] != ":") die("sha256 field needs :")
        p++
        if (typ[p] != "str") die("sha256 value must be a string")
        if (k2 in dig) die("duplicate sha256 key " k2)
        if (length(val[p]) != 64 || val[p] !~ /^[0-9A-Fa-f]+$/)
          die("bad sha256 for " k2)
        dig[k2] = tolower(val[p]); p++
        if (typ[p] == ",") { p++; continue }
        if (typ[p] == "}") { p++; break }
        die("bad sha256 object")
      }
    } else die("unknown field " key)
    if (p > nt) die("unterminated object")
    if (typ[p] == ",") { p++; continue }
    if (typ[p] == "}") { p++; break }
    die("expected , or } after " key)
  }
}
{ buf = buf (NR == 1 ? "" : "\n") $0 }
END {
  s = buf
  if (body_end) s = s "\n"
  if (length(s) > 65536) die("manifest exceeds 64 KiB")
  if (substr(s, 1, 3) == sprintf("%c%c%c", 239, 187, 191)) s = substr(s, 4)
  n = length(s); i = 1; nt = 0
  while (i <= n) {
    c = substr(s, i, 1)
    if (c ~ /[[:space:]]/) { i++; continue }
    if (c == "/") {
      d = substr(s, i + 1, 1)
      if (d == "/") {
        j = index(substr(s, i + 2), "\n")
        if (j == 0) die("unterminated comment")
        i += j + 2; continue
      }
      if (d == "*") {
        j = index(substr(s, i + 2), "*/")
        if (j == 0) die("unterminated comment")
        i += j + 3; continue
      }
      die("unexpected /")
    }
    if (c == "\"") {
      i++; v = ""
      while (1) {
        if (i > n) die("unterminated string")
        c = substr(s, i, 1)
        if (c == "\"") { i++; break }
        if (c == "\n" || c == "\r") die("unterminated string")
        if (c == "\\") {
          e = substr(s, i + 1, 1)
          if (index("\"\\/", e) > 0) { v = v e; i += 2; continue }
          if (e == "n") { v = v "\n"; i += 2; continue }
          if (e == "t") { v = v "\t"; i += 2; continue }
          if (e == "r") { v = v "\r"; i += 2; continue }
          if (e == "b") { v = v "\b"; i += 2; continue }
          if (e == "f") { v = v "\f"; i += 2; continue }
          if (e == "u") {
            h = substr(s, i + 2, 4)
            if (length(h) != 4 || h !~ /^[0-9a-fA-F]+$/) die("bad \\u escape")
            cp = hex2num(h)
            if (cp < 32 || cp > 126) die("unsupported \\u escape")
            v = v sprintf("%c", cp); i += 6; continue
          }
          die("bad string escape")
        }
        v = v c; i++
      }
      nt++; typ[nt] = "str"; val[nt] = v; continue
    }
    if (c ~ /[A-Za-z_$]/) {
      j = i
      while (j <= n && substr(s, j, 1) ~ /[A-Za-z0-9_$]/) j++
      nt++; typ[nt] = "id"; val[nt] = substr(s, i, j - i); i = j; continue
    }
    if (index("{}[]:,;=", c) > 0) { nt++; typ[nt] = c; val[nt] = ""; i++; continue }
    die("unexpected character")
  }
  p = 1; seen = 0
  while (p <= nt) {
    if (typ[p] == "id" && val[p] == "import") {
      p++
      if (!(typ[p] == "id" && val[p] == "type")) die("only type imports are allowed")
      p++
      if (typ[p] == "{") {
        p++
        while (1) {
          if (p > nt) die("unterminated import")
          if (typ[p] == "}") { p++; break }
          if (typ[p] != "id") die("bad import")
          p++
          if (typ[p] == ",") { p++; continue }
          if (typ[p] == "}") { p++; break }
          die("bad import")
        }
      } else if (typ[p] == "id") {
        p++
      } else die("bad import")
      if (!(typ[p] == "id" && val[p] == "from")) die("import needs from")
      p++
      if (typ[p] != "str") die("import path must be a string")
      p++
      if (typ[p] == ";") p++
      continue
    }
    if (typ[p] == "id" && val[p] == "export") {
      p++
      if (!(typ[p] == "id" && val[p] == "const")) die("only const exports are allowed")
      p++
      if (typ[p] != "id") die("export needs a name")
      if (val[p] != want_export) die("unexpected export " val[p])
      p++
      if (seen) die("duplicate " want_export)
      seen = 1
      if (typ[p] != ":") die("export needs a type annotation")
      p++
      if (typ[p] != "id") die("export type must be a name")
      p++
      if (typ[p] != "=") die("export needs a value")
      p++
      parse_object()
      if (typ[p] == ";") p++
      continue
    }
    die("unexpected statement")
  }
  if (!seen) die("no " want_export " export")
  if (!f_repo || !f_tag || !f_targets || !f_sha) die("incomplete release record")
  if (v_repo != want_repo) die("repo is " v_repo ", want " want_repo)
  if (v_tag != want_tag) die("tag is " v_tag ", want " want_tag)
  if (!(want_target in targ)) die("no target " want_target " in targets")
  if (!(want_target in dig)) die("no sha256 for " want_target)
  for (k in dig) if (!(k in targ)) die("sha256 for undeclared target " k)
  print dig[want_target]
}')" || die "the $repo manifest for $PRERELEASE_TAG has no usable $TARGET digest"
  printf '%s' "$digest"
}

# Read 4 bytes at offset $2 of file $1 as a hex string, then as a number.
_pr_hex4() { od -An -tx1 -j "$2" -N 4 "$1" 2>/dev/null | tr -d ' \n'; }
_be32() {
  local h; h="$(_pr_hex4 "$1" "$2")"
  [[ "$h" =~ ^[0-9a-f]{8}$ ]] || die "short read checking the executable format"
  printf '%d' "$((16#$h))"
}
_le32() {
  local h; h="$(_pr_hex4 "$1" "$2")"
  [[ "$h" =~ ^[0-9a-f]{8}$ ]] || die "short read checking the executable format"
  printf '%d' "$((16#${h:6:2}${h:4:2}${h:2:2}${h:0:2}))"
}

# Executable-format check for a verified staged download: the published POSIX
# assets are 64-bit ELF (Linux/WSL2) or 64-bit Mach-O (macOS) matching the host
# architecture. Anything else — a script, a PE file, a truncated download — is
# refused before it is ever executed. On macOS this gate is also what makes the
# codesign step safe: only a Mach-O file ever reaches it.
verify_exec_format() {
  local file="$1" magic cls enc lo hi machine want_m ct ct_want nfat i esz
  magic="$(od -An -tx1 -N4 "$file" 2>/dev/null | tr -d ' \n')"
  case "$OS" in
    linux)
      [ "$magic" = "7f454c46" ] || die "downloaded $file is not an ELF executable for $TARGET"
      cls="$(od -An -tx1 -j4 -N1 "$file" 2>/dev/null | tr -d ' \n')"
      [ "$cls" = "02" ] || die "downloaded $file is not a 64-bit executable"
      enc="$(od -An -tx1 -j5 -N1 "$file" 2>/dev/null | tr -d ' \n')"
      lo="$(od -An -tx1 -j18 -N1 "$file" 2>/dev/null | tr -d ' \n')"
      hi="$(od -An -tx1 -j19 -N1 "$file" 2>/dev/null | tr -d ' \n')"
      case "$enc" in
        01) machine=$((16#${hi}${lo})) ;;
        02) machine=$((16#${lo}${hi})) ;;
        *) die "downloaded $file has an invalid ELF encoding" ;;
      esac
      # e_machine: x86-64 = 62, AArch64 = 183.
      if [ "$ARCH" = "x64-baseline" ]; then want_m=62; else want_m=183; fi
      [ "$machine" = "$want_m" ] \
        || die "downloaded $file is built for ELF machine $machine, not $TARGET"
      ;;
    darwin)
      # cputype: x86_64 = 0x01000007, arm64 = 0x0100000c.
      if [ "$ARCH" = "x64-baseline" ]; then ct_want=16777223; else ct_want=16777228; fi
      case "$magic" in
        cffaedfe) ct="$(_le32 "$file" 4)" ;;   # 64-bit Mach-O, little-endian
        feedfacf) ct="$(_be32 "$file" 4)" ;;   # 64-bit Mach-O, big-endian
        cafebabe|cafebabf)
          # Fat/universal header: scan the arch list for the host slice.
          nfat="$(_be32 "$file" 4)"
          ct=-1; i=0; esz=20
          [ "$magic" = "cafebabf" ] && esz=32
          while [ "$i" -lt "$nfat" ] && [ "$i" -lt 64 ]; do
            ct="$(_be32 "$file" $((8 + i * esz)))"
            [ "$ct" = "$ct_want" ] && break
            i=$((i + 1))
          done
          ;;
        bebafeca|bfbafeca)
          nfat="$(_le32 "$file" 4)"
          ct=-1; i=0; esz=20
          [ "$magic" = "bfbafeca" ] && esz=32
          while [ "$i" -lt "$nfat" ] && [ "$i" -lt 64 ]; do
            ct="$(_le32 "$file" $((8 + i * esz)))"
            [ "$ct" = "$ct_want" ] && break
            i=$((i + 1))
          done
          ;;
        *) die "downloaded $file is not a Mach-O executable for $TARGET" ;;
      esac
      [ "$ct" = "$ct_want" ] \
        || die "downloaded $file has no $TARGET slice"
      ;;
  esac
}
# <<< openllm-prerelease/v1 <<<

# Bounded --version probe for a staged prerelease download: the binary must
# exit 0 and report EXACTLY the selected version — never an older manifest pin.
probe_staged_version() {
  local binary="$1" want="$2"
  run_version_probe "$binary"
  [ "$PROBE_STATUS" -eq 0 ] \
    || die "the downloaded $binary failed its --version probe — refusing to install"
  parse_probe_version "$PROBE_OUT"
  [ "$PARSED_VERSION" = "$want" ] \
    || die "the downloaded $binary reports '${PARSED_VERSION:-no parseable version}', not $want — refusing to install"
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
# HTTPS only (NET-4): the manifest, the .sha256 digests and the binaries all
# come from this origin, and the persisted value later carries the API key on
# every daemon call — a plain-http origin hands both to a network MITM. A
# loopback http origin is tolerated ONLY with the explicit dev opt-in.
INSECURE_DEV_ORIGIN=0
case "$ORIGIN" in
  https://*) ;;
  http://127.0.0.1|http://127.0.0.1:*|http://127.0.0.1/*|\
http://localhost|http://localhost:*|http://localhost/*|\
http://\[::1\]|http://\[::1\]:*|http://\[::1\]/*)
    if [ "${OPENLLM_ALLOW_INSECURE_ORIGIN:-}" = "1" ]; then
      INSECURE_DEV_ORIGIN=1
    else
      die "insecure origin $ORIGIN — http is refused except for loopback development; set OPENLLM_ALLOW_INSECURE_ORIGIN=1 to override"
    fi
    ;;
  *) die "insecure origin $ORIGIN — OPENLLM_CLOUD_ORIGIN must be an https:// origin" ;;
esac
# And belt-and-suspenders at the transport layer: every fetch is restricted to
# the allowed schemes so an https→http redirect can never be followed. The dev
# loopback opt-in widens the list to what that origin needs.
if [ "$INSECURE_DEV_ORIGIN" = 1 ]; then
  CURL_SCHEME=(--proto "=http,https" --proto-redir "=http,https")
else
  CURL_SCHEME=(--proto "=https" --proto-redir "=https")
fi
# And bound every call (NET-7): a stalled TCP connection must never hang the
# installer. The manifest, the digest fetches and the capability probe are
# tiny, so they get the short bound; binary downloads get the long one.
CURL_META=(--connect-timeout 10 --max-time 60)
CURL_GET=(--connect-timeout 10 --max-time 300)
# Public-prerelease transport (P): fixed GitHub URLs over HTTPS with at most
# five redirects. OPENLLM_PRERELEASE_BASE_URL is a test-only override — it must
# parse to an http URL on a loopback host, refuses redirects, and is never
# persisted. Checked BEFORE the first fetch so a bad value fails early.
if [ -n "$PRERELEASE_TAG" ]; then
  has_command awk || die "awk is required to parse the release manifest"
  has_command gzip || die "gzip is required to unpack the release asset"
  has_command od || die "od is required to check the executable format"
  if [ -n "${OPENLLM_PRERELEASE_BASE_URL:-}" ]; then
    pre_authority="${OPENLLM_PRERELEASE_BASE_URL#http://}"
    [ "$pre_authority" != "$OPENLLM_PRERELEASE_BASE_URL" ] \
      || die "OPENLLM_PRERELEASE_BASE_URL must be an http:// URL on a loopback host (127.0.0.1, localhost or [::1])"
    pre_authority="${pre_authority%%[/?#]*}"
    case "$pre_authority" in
      127.0.0.1|localhost|\[::1\]) ;;
      \[::1\]:*)
        # The port follows `]:` — ${var#*:} would stop at the first ':' INSIDE
        # the brackets and reject the documented [::1]:port form.
        pre_port="${pre_authority#*\]:}"
        [[ "$pre_port" =~ ^[0-9]+$ ]] \
          || die "OPENLLM_PRERELEASE_BASE_URL has a bad port" ;;
      127.0.0.1:*|localhost:*)
        pre_port="${pre_authority#*:}"
        [[ "$pre_port" =~ ^[0-9]+$ ]] \
          || die "OPENLLM_PRERELEASE_BASE_URL has a bad port" ;;
      *) die "OPENLLM_PRERELEASE_BASE_URL must be an http:// URL on a loopback host (127.0.0.1, localhost or [::1])" ;;
    esac
    PRE_BASE="${OPENLLM_PRERELEASE_BASE_URL%/}"
    PR_SCHEME=(--proto "=http" --proto-redir "=http" --max-redirs 0)
  fi
fi
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
  if NORMALIZED_PORT="$(normalize_daemon_port "$DAEMON_PORT")"; then
    DAEMON_PORT="$NORMALIZED_PORT"
  else
    # Warn, but never echo the raw value: it is untrusted external input
    # (env var content) and could carry control/escape sequences into the
    # user's terminal.
    echo "Warning: ignoring an invalid OPENLLM_DAEMON_PORT (must be a plain port number 1-65535); falling back" >&2
    DAEMON_PORT=""
  fi
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

if [ -z "$FROM_FILE" ]; then
  has_command curl || die "curl is required"
  # --proto/--proto-redir need a curl new enough to know the options (≈7.21):
  # an older system curl fails the FIRST fetch with an opaque option error, so
  # detect support once and fail with the upgrade remedy up front.
  curl "${CURL_SCHEME[@]}" "${CURL_META[@]}" -V >/dev/null 2>&1 \
    || die "this curl does not support --proto/--proto-redir — upgrade to curl 7.21.0 or newer and re-run"
fi
# Checksum verification is mandatory — refuse rather than install unverified
# bytes (this is ALSO the --from-file integrity gate).
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

# Use a separate lock for binary replacement. Keep config lock state unchanged.
# >>> openllm-binary-lock/v1 >>>
BINARY_LOCK_STALE_SECS="${OPENLLM_BINARY_LOCK_STALE_SECS:-600}"
BINARY_LOCK_WAIT_SECS="${OPENLLM_BINARY_LOCK_WAIT_SECS:-10}"
BINARY_LOCK_ORPHAN_SECS="${OPENLLM_BINARY_LOCK_ORPHAN_SECS:-30}"
[[ "$BINARY_LOCK_STALE_SECS" =~ ^[0-9]+$ ]] || BINARY_LOCK_STALE_SECS=0
BINARY_LOCK_STALE_SECS=$((10#$BINARY_LOCK_STALE_SECS))
[ "$BINARY_LOCK_STALE_SECS" -gt 0 ] || BINARY_LOCK_STALE_SECS=600
[[ "$BINARY_LOCK_WAIT_SECS" =~ ^[0-9]+$ ]] || BINARY_LOCK_WAIT_SECS=0
BINARY_LOCK_WAIT_SECS=$((10#$BINARY_LOCK_WAIT_SECS))
[ "$BINARY_LOCK_WAIT_SECS" -gt 0 ] || BINARY_LOCK_WAIT_SECS=10
[[ "$BINARY_LOCK_ORPHAN_SECS" =~ ^[0-9]+$ ]] || BINARY_LOCK_ORPHAN_SECS=0
BINARY_LOCK_ORPHAN_SECS=$((10#$BINARY_LOCK_ORPHAN_SECS))
[ "$BINARY_LOCK_ORPHAN_SECS" -gt 0 ] || BINARY_LOCK_ORPHAN_SECS=30
BINARY_LOCK_DIR=""
BINARY_LOCK_NONCE=""
BINARY_LOCK_QSEQ=0
BINARY_LOCK_OWNER_STATE="" BINARY_LOCK_OWNER_PID=""
BINARY_LOCK_OWNER_START="" BINARY_LOCK_OWNER_NONCE=""

binary_lock_pid_alive() {
  [[ "$1" =~ ^[0-9]+$ ]] || return 1
  local pid=$((10#$1)) stat state
  if [ -r "/proc/$pid/stat" ]; then
    stat="$(cat "/proc/$pid/stat" 2>/dev/null || true)"
    stat="${stat##*) }"
    read -r state _ <<< "$stat"
    [ "$state" = "Z" ] && return 1
  fi
  [ "$pid" -gt 0 ] && kill -0 "$pid" 2>/dev/null
}

binary_lock_legacy_start_identity() {
  local out
  out="$(LC_ALL=C TZ=UTC ps -o lstart= -p "$1" 2>/dev/null)" || out=""
  out="$(printf '%s' "$out" | tr -s '[:space:]' ' ')"
  out="${out# }"
  out="${out% }"
  printf '%s' "$out"
}

binary_lock_is_boot_identity() {
  local re='^boot:[0-9a-f-]{36}:[0-9]+$'
  [[ "$1" =~ $re ]]
}

binary_lock_normalize_identity() {
  local out
  out="$(printf '%s' "$1" | tr -s '[:space:]' ' ')"
  out="${out# }"
  out="${out% }"
  printf '%s' "$out"
}

binary_lock_start_identity() {
  local pid="$1" boot stat rest ticks
  if [ "$(uname -s 2>/dev/null)" = "Linux" ]; then
    boot="$(cat /proc/sys/kernel/random/boot_id 2>/dev/null || true)"
    boot="$(printf '%s' "$boot" | tr -d '[:space:]' | tr '[:upper:]' '[:lower:]')"
    local re='^[0-9a-f-]{36}$'
    [[ "$boot" =~ $re ]] || return 0
    stat="$(cat "/proc/$pid/stat" 2>/dev/null || true)"
    [ -n "$stat" ] || return 0
    rest="${stat##*) }"
    [ "$rest" = "$stat" ] && rest="${stat:1}"
    local -a f
    read -r -a f <<< "$rest"
    ticks="${f[19]:-}"
    [[ "$ticks" =~ ^[0-9]+$ && "$ticks" =~ [1-9] ]] || return 0
    printf 'boot:%s:%s' "$boot" "$((10#$ticks))"
    return 0
  fi
  binary_lock_legacy_start_identity "$pid"
}

binary_lock_read_owner() {
  local dir="$1" line rest
  BINARY_LOCK_OWNER_STATE="unmarked"
  BINARY_LOCK_OWNER_PID="" BINARY_LOCK_OWNER_START="" BINARY_LOCK_OWNER_NONCE=""
  line="$(cat "$dir/owner" 2>/dev/null || true)"
  line="${line#"${line%%[![:space:]]*}"}"
  line="${line%"${line##*[![:space:]]}"}"
  case "$line" in
    kind=openllm-binary-lock/v1\ pid=*\ start=*\ nonce=*)
      rest="${line#kind=openllm-binary-lock/v1 pid=}"
      BINARY_LOCK_OWNER_PID="${rest%% *}"
      BINARY_LOCK_OWNER_START="${rest#* start=}"
      BINARY_LOCK_OWNER_START="${BINARY_LOCK_OWNER_START% nonce=*}"
      BINARY_LOCK_OWNER_NONCE="${rest##* nonce=}"
      if [[ "$BINARY_LOCK_OWNER_PID" =~ ^[0-9]+$ ]] \
        && [ -n "$BINARY_LOCK_OWNER_START" ] \
        && [[ "$BINARY_LOCK_OWNER_START" != *$'\n'* \
          && "$BINARY_LOCK_OWNER_START" != *$'\r'* ]] \
        && [[ "$BINARY_LOCK_OWNER_NONCE" =~ ^[0-9a-fA-F]+$ ]]; then
        BINARY_LOCK_OWNER_PID=$((10#$BINARY_LOCK_OWNER_PID))
        BINARY_LOCK_OWNER_STATE="marked"
      fi
      ;;
  esac
  if [ "$BINARY_LOCK_OWNER_STATE" != "marked" ]; then
    BINARY_LOCK_OWNER_PID="" BINARY_LOCK_OWNER_START="" BINARY_LOCK_OWNER_NONCE=""
    if [[ "$line" =~ (^|[[:space:]])pid=([0-9]+)([[:space:]]|$) ]]; then
      BINARY_LOCK_OWNER_PID="${BASH_REMATCH[2]}"
    elif [[ "$line" =~ ^([0-9]+)([[:space:]]|$) ]]; then
      BINARY_LOCK_OWNER_PID="${BASH_REMATCH[1]}"
    fi
    if [ -n "$BINARY_LOCK_OWNER_PID" ]; then
      BINARY_LOCK_OWNER_PID=$((10#$BINARY_LOCK_OWNER_PID))
      [ "$BINARY_LOCK_OWNER_PID" -gt 0 ] || BINARY_LOCK_OWNER_PID=""
    fi
  fi
}

binary_lock_dir_age_secs() {
  local mtime="${2:-}" now
  [[ "$mtime" =~ ^[0-9]+$ ]] || \
    mtime="$(stat -c %Y "$1" 2>/dev/null || stat -f %m "$1" 2>/dev/null || true)"
  now="$(date +%s 2>/dev/null || true)"
  if [[ "$mtime" =~ ^[0-9]+$ && "$now" =~ ^[0-9]+$ ]]; then
    printf '%s\n' $((10#$now - 10#$mtime))
  else
    printf '%s\n' -1
  fi
}

binary_lock_path_ino() {
  stat -c %d:%i "$1" 2>/dev/null || stat -f %d:%i "$1" 2>/dev/null || true
}

binary_lock_is_stale_dir() {
  local dir="$1" as_of="${2:-}" current bridged recorded age
  binary_lock_read_owner "$dir"
  age="$(binary_lock_dir_age_secs "$dir" "$as_of")"
  if [ "$BINARY_LOCK_OWNER_STATE" = "marked" ]; then
    binary_lock_pid_alive "$BINARY_LOCK_OWNER_PID" || return 0
    recorded="$(binary_lock_normalize_identity "$BINARY_LOCK_OWNER_START")"
    if [ "$recorded" = "-" ]; then
      return 1
    fi
    current="$(binary_lock_start_identity "$BINARY_LOCK_OWNER_PID")"
    if [ -z "$current" ]; then
      if binary_lock_pid_alive "$BINARY_LOCK_OWNER_PID"; then return 1; else return 0; fi
    fi
    [ "$current" = "$recorded" ] && return 1
    binary_lock_is_boot_identity "$current" || return 0
    binary_lock_is_boot_identity "$recorded" && return 0
    bridged="$(binary_lock_legacy_start_identity "$BINARY_LOCK_OWNER_PID")"
    if [ -z "$bridged" ]; then
      if binary_lock_pid_alive "$BINARY_LOCK_OWNER_PID"; then return 1; else return 0; fi
    fi
    if [ "$bridged" = "$recorded" ]; then return 1; else return 0; fi
  fi
  { [ "$age" -ge 0 ] && [ "$age" -ge "$BINARY_LOCK_ORPHAN_SECS" ]; } || return 1
  if [[ "$BINARY_LOCK_OWNER_PID" =~ ^[0-9]+$ ]] && binary_lock_pid_alive "$BINARY_LOCK_OWNER_PID"; then
    return 1
  fi
  return 0
}

binary_lock_steal() {
  local lockdir="$1" stem="$2" marker q ino_before ino_after q_ino mtime before_owner after_owner
  ino_before="$(binary_lock_path_ino "$lockdir")"
  mtime="$(stat -c %Y "$lockdir" 2>/dev/null || stat -f %m "$lockdir" 2>/dev/null || true)"
  [ -n "$ino_before" ] || return 0  # vanished — the outer acquire retries
  before_owner="$(cat "$lockdir/owner" 2>/dev/null || true)"
  marker="$lockdir/steal.$$.$BINARY_LOCK_NONCE"
  [ "$(binary_lock_path_ino "$lockdir")" = "$ino_before" ] || return 0
  if ! (set -C; : > "$marker") 2>/dev/null; then
    if [ -f "$lockdir" ]; then
      BINARY_LOCK_QSEQ=$((BINARY_LOCK_QSEQ + 1))
      mv "$lockdir" "$stem.stale.$$.$BINARY_LOCK_NONCE.$BINARY_LOCK_QSEQ" \
        2>/dev/null || true
    fi
    return 0
  fi
  ino_after="$(binary_lock_path_ino "$lockdir")"
  after_owner="$(cat "$lockdir/owner" 2>/dev/null || true)"
  if [ -n "$ino_after" ] && [ "$ino_after" = "$ino_before" ] \
    && [ "$after_owner" = "$before_owner" ] \
    && binary_lock_is_stale_dir "$lockdir" "$mtime"; then
    BINARY_LOCK_QSEQ=$((BINARY_LOCK_QSEQ + 1))
    q="$stem.stale.$$.$BINARY_LOCK_NONCE.$BINARY_LOCK_QSEQ"
    if mv "$lockdir" "$q" 2>/dev/null; then
      q_ino="$(binary_lock_path_ino "$q")"
      if [ "$q_ino" != "$ino_before" ] \
        || { [ -e "$q/owner" ] \
          && [ "$(cat "$q/owner" 2>/dev/null || true)" != "$before_owner" ]; }; then
        binary_lock_restore_dir "$q" "$lockdir"
        rm -f "$marker" "$q/steal.$$.$BINARY_LOCK_NONCE" 2>/dev/null || true
        return 0  # Retry acquisition. This steal did not claim the lock.
      fi
      return 0  # committed — the marker (and dir) are parked with it
    fi
  fi
  rm -f "$marker" 2>/dev/null || true
  return 0
}

binary_lock_sweep() {
  local stem="$1" entry child age ok has_owner
  for entry in "$stem".stale.* "$stem".rel.*; do
    [ -d "$entry" ] || continue
    age="$(binary_lock_dir_age_secs "$entry")"
    { [ "$age" -ge 0 ] && [ "$age" -ge "$BINARY_LOCK_STALE_SECS" ]; } || continue
    ok=1
    has_owner=0
    for child in "$entry"/*; do
      [ -e "$child" ] || continue
      case "${child##*/}" in
        owner) has_owner=1 ;;
        owner.tmp.*|steal.*) ;;
        *) ok=0 ;;
      esac
    done
    [ "$ok" = 1 ] || continue
    if [ "$has_owner" = 1 ]; then
      binary_lock_read_owner "$entry"
      [ "$BINARY_LOCK_OWNER_STATE" = "marked" ] || continue
    fi
    for child in "$entry"/*; do rm -f "$child" 2>/dev/null || true; done
    rmdir "$entry" 2>/dev/null || true
  done
  return 0
}

binary_lock_legacy_resolve() {
  local q="$1" legacy="$2" moved rest age
  moved=""
  read -r moved rest < "$q" 2>/dev/null || moved=""
  if [[ "$moved" =~ ^[0-9]+$ ]] && binary_lock_pid_alive "$moved"; then
    age="$(binary_lock_dir_age_secs "$q")"
    if [ "$age" -lt 0 ] || [ "$age" -lt "$BINARY_LOCK_ORPHAN_SECS" ]; then
      if ln "$q" "$legacy" 2>/dev/null; then
        rm -f "$q" 2>/dev/null || true
      elif (set -C; : > "$legacy") 2>/dev/null; then
        local l_sz q_sz
        cat "$q" >> "$legacy" 2>/dev/null || true
        l_sz="$(stat -c %s "$legacy" 2>/dev/null || stat -f %z "$legacy" 2>/dev/null || true)"
        q_sz="$(stat -c %s "$q" 2>/dev/null || stat -f %z "$q" 2>/dev/null || true)"
        if [ -n "$q_sz" ] && [ "$q_sz" = "$l_sz" ] \
          && [ "$(cat "$legacy" 2>/dev/null)" = "$(cat "$q" 2>/dev/null)" ]; then
          rm -f "$q" 2>/dev/null || true
        else
          rm -f "$legacy" 2>/dev/null || true
        fi
      elif [ -e "$legacy" ] || [ -L "$legacy" ]; then
        rm -f "$q" 2>/dev/null || true
      fi
      return 0
    fi
  fi
  rm -f "$q" 2>/dev/null || true
  return 1
}

binary_lock_legacy_held() {
  local legacy="$1" lpid rest q attempt=0 age
  while [ -f "$legacy" ]; do
    attempt=$((attempt + 1))
    [ "$attempt" -gt 4 ] && return 0
    lpid=""
    read -r lpid rest < "$legacy" 2>/dev/null || lpid=""
    if [[ "$lpid" =~ ^[0-9]+$ ]] && ! binary_lock_pid_alive "$lpid"; then
      : # a proven-dead pid is reclaimed regardless of the lock's age
    else
      age="$(binary_lock_dir_age_secs "$legacy")"
      if [ "$age" -lt 0 ] || [ "$age" -lt "$BINARY_LOCK_ORPHAN_SECS" ]; then
        return 0
      fi
    fi
    BINARY_LOCK_QSEQ=$((BINARY_LOCK_QSEQ + 1))
    q="$legacy.stale.$$.$BINARY_LOCK_NONCE.$BINARY_LOCK_QSEQ"
    mv "$legacy" "$q" 2>/dev/null || continue
    binary_lock_legacy_resolve "$q" "$legacy" && return 0
  done
  return 1
}

binary_lock_publish_owner() {
  local lockdir="$1" want_ino="${2:-}" start stolen same_gen marker now_ino
  for marker in "$lockdir"/steal.*; do
    [ -e "$marker" ] && return 1
  done
  start="$(binary_lock_start_identity "$$")"
  if [ -z "$start" ]; then
    if [ -n "$want_ino" ] \
      && [ "$(binary_lock_path_ino "$lockdir")" = "$want_ino" ]; then
      rmdir "$lockdir" 2>/dev/null || true
    fi
    return 1
  fi
  printf 'kind=openllm-binary-lock/v1 pid=%s start=%s nonce=%s\n' \
    "$$" "$start" "$BINARY_LOCK_NONCE" > "$lockdir/owner.tmp.$$" 2>/dev/null \
    || return 2
  if ln "$lockdir/owner.tmp.$$" "$lockdir/owner" 2>/dev/null \
    || (set -C; cat "$lockdir/owner.tmp.$$" > "$lockdir/owner") 2>/dev/null; then
    rm -f "$lockdir/owner.tmp.$$" 2>/dev/null
    stolen=1
    same_gen=0
    if [ -d "$lockdir" ]; then
      now_ino="$(binary_lock_path_ino "$lockdir")"
      if [ -z "$want_ino" ] \
        || { [ -n "$now_ino" ] && [ "$now_ino" = "$want_ino" ]; }; then
        same_gen=1
        stolen=0
        for marker in "$lockdir"/steal.*; do
          if [ -e "$marker" ]; then stolen=1; break; fi
        done
      fi
    fi
    if [ "$stolen" = 1 ]; then
      binary_lock_read_owner "$lockdir"
      if [ "$BINARY_LOCK_OWNER_STATE" = "marked" ] \
        && [ "$BINARY_LOCK_OWNER_NONCE" = "$BINARY_LOCK_NONCE" ]; then
        rm -f "$lockdir/owner" 2>/dev/null
      fi
      [ "$same_gen" = 1 ] && rmdir "$lockdir" 2>/dev/null || true
      return 1
    fi
    binary_lock_read_owner "$lockdir"
    [ "$BINARY_LOCK_OWNER_STATE" = "marked" ] \
      && [ "$BINARY_LOCK_OWNER_NONCE" = "$BINARY_LOCK_NONCE" ]
    return
  fi
  rm -f "$lockdir/owner.tmp.$$" 2>/dev/null
  return 1
}

binary_lock_acquire() {
  local envfile="$1" stem lockdir deadline attempts pub_rc ino
  stem="$envfile.lock"
  lockdir="$stem.d"
  deadline=$((SECONDS + BINARY_LOCK_WAIT_SECS))
  BINARY_LOCK_NONCE="$(printf '%x%x%x' "$$" "$RANDOM" "$(date +%s 2>/dev/null || echo 0)")"
  attempts=0
  binary_lock_sweep "$stem"
  while [ "$SECONDS" -lt "$deadline" ]; do
    if ! binary_lock_legacy_held "$stem"; then
      if mkdir "$lockdir" 2>/dev/null; then
        ino="$(binary_lock_path_ino "$lockdir")"
        if [ -z "$ino" ]; then
          rmdir "$lockdir" 2>/dev/null || true
          continue
        fi
        binary_lock_publish_owner "$lockdir" "$ino"
        pub_rc=$?
        if [ "$pub_rc" = 0 ]; then
          BINARY_LOCK_DIR="$lockdir"
          return 0
        elif [ "$pub_rc" = 2 ]; then
          if [ -n "$ino" ] && [ "$(binary_lock_path_ino "$lockdir")" = "$ino" ]; then
            rm -f "$lockdir/owner.tmp.$$" 2>/dev/null
            rmdir "$lockdir" 2>/dev/null || true
          fi
          return 1
        fi
      fi
      attempts=$((attempts + 1))
      [ $((attempts % 25)) -eq 0 ] && binary_lock_sweep "$stem"
      if binary_lock_is_stale_dir "$lockdir"; then
        binary_lock_steal "$lockdir" "$stem"
      fi
    fi
    sleep 0.01 2>/dev/null || sleep 1
  done
  return 1
}

binary_lock_restore_dir() {
  local rel="$1" lockdir="$2" child base dst ok=1 l_sz q_sz
  set --
  mkdir "$lockdir" 2>/dev/null || return 0
  for child in "$rel"/*; do
    [ -f "$child" ] || continue
    base="${child##*/}"
    dst="$lockdir/$base"
    if (set -C; : > "$dst") 2>/dev/null; then
      cat "$child" >> "$dst" 2>/dev/null || true
      l_sz="$(stat -c %s "$dst" 2>/dev/null || stat -f %z "$dst" 2>/dev/null || true)"
      q_sz="$(stat -c %s "$child" 2>/dev/null || stat -f %z "$child" 2>/dev/null || true)"
      if [ -n "$q_sz" ] && [ "$q_sz" = "$l_sz" ] \
        && [ "$(cat "$child" 2>/dev/null)" = "$(cat "$dst" 2>/dev/null)" ]; then
        set -- "$@" "$base"
        continue
      fi
      rm -f "$dst" 2>/dev/null || true
    fi
    ok=0
    break
  done
  if [ "$ok" = 1 ]; then
    command -v sync >/dev/null 2>&1 && sync 2>/dev/null || true
  else
    for base in "$@"; do rm -f "$lockdir/$base" 2>/dev/null || true; done
    rmdir "$lockdir" 2>/dev/null || true
    return 0
  fi
  for base in "$@"; do rm -f "$rel/$base" 2>/dev/null || true; done
  rmdir "$rel" 2>/dev/null || true
  return 0
}

binary_lock_release() {
  local lockdir="${BINARY_LOCK_DIR:-}" stem rel
  [ -n "$lockdir" ] || return 0
  BINARY_LOCK_DIR=""
  stem="${lockdir%.d}"
  rel="$stem.rel.$$.$BINARY_LOCK_NONCE"
  binary_lock_read_owner "$lockdir"
  if [ "$BINARY_LOCK_OWNER_STATE" = "marked" ] \
    && [ "$BINARY_LOCK_OWNER_NONCE" = "$BINARY_LOCK_NONCE" ]; then
    if mv "$lockdir" "$rel" 2>/dev/null; then
      binary_lock_read_owner "$rel"
      if [ "$BINARY_LOCK_OWNER_STATE" = "marked" ] && [ "$BINARY_LOCK_OWNER_NONCE" = "$BINARY_LOCK_NONCE" ]; then
        local child
        for child in "$rel"/*; do rm -f "$child" 2>/dev/null || true; done
        rmdir "$rel" 2>/dev/null || true
      else
        binary_lock_restore_dir "$rel" "$lockdir"
      fi
    fi
  fi
  return 0
}
# <<< openllm-binary-lock/v1 <<<

# Installer-owned directories are private state. A permissive caller umask
# (or a group-writable ~/.openllm left by an older build) would otherwise make
# the lock parent writable by another user, which the lock protocol refuses.
# Create under a private umask; with repair=1 (the default) also chmod a
# directory the invoking user owns — never a symlink or a foreign directory.
# A tightened dir is reported with one "note: tightened" line on stderr.
private_dir() {
  local d="$1" repair="${2:-1}" was
  [ -d "$d" ] || (umask 077 && mkdir -p "$d") \
    || die "could not create directory: $d"
  if [ "$repair" = "1" ] && [ -d "$d" ] && [ ! -L "$d" ] && [ -O "$d" ]; then
    was="$(ls -ld "$d" 2>/dev/null | cut -c1-10)"
    if [ "$was" != "drwx------" ]; then
      # A shared dir may have had foreign entries planted while it was
      # group/other-writable. Refuse to seal them inside private state.
      foreign="$(find "$d" -xdev ! -user "$(id -u)" -print 2>/dev/null | head -n 1)"
      if [ -n "$foreign" ]; then
        die "refusing to tighten $d: $foreign is owned by another user; remove it, then re-run"
      fi
      chmod 700 "$d" || die "could not secure directory: $d"
      echo "  note: tightened $d from ${was#d} to 0700 (OpenLLM keeps its state private)" >&2
    fi
  fi
}

# Keep the caller's traps while the binary transaction owns the install lock.
install_lock_acquire() {
  local saved_exit
  INSTALL_SAVED_TRAPS="$(trap -p EXIT INT TERM)"
  saved_exit="$(trap -p EXIT)"
  INSTALL_SAVED_EXIT=""
  INSTALL_ROLLBACK=""
  if [ -n "$saved_exit" ]; then
    saved_exit="${saved_exit#trap -- }"
    saved_exit="${saved_exit% EXIT}"
    # Bash supplies this quoted command. It does not come from a manifest.
    eval "INSTALL_SAVED_EXIT=$saved_exit"
  fi
  binary_lock_acquire "$OPENLLM_DIR/install" \
    || die "could not acquire install lock: $OPENLLM_DIR/install.lock.d"
  trap 'install_lock_exit $?' EXIT
  trap 'exit 130' INT
  trap 'exit 143' TERM
}

install_lock_exit() {
  local status="$1"
  trap - EXIT
  if [ -n "$INSTALL_ROLLBACK" ]; then "$INSTALL_ROLLBACK"; fi
  binary_lock_release
  # Supply the original exit status to the caller's saved EXIT command.
  (exit "$status") && :
  eval "$INSTALL_SAVED_EXIT"
  exit "$status"
}

install_lock_release() {
  binary_lock_release
  trap - EXIT INT TERM
  eval "$INSTALL_SAVED_TRAPS"
}

# The lock excludes other installers. The version checks validate each destination.
# Remove files left by an interrupted transaction only after those checks pass.
prerelease_discard_stale() {
  local name file
  for name in openllmd openllm; do
    for file in "$BIN_DIR/.$name.pr-dl."* "$BIN_DIR/.$name.pr-bin."* \
                "$BIN_DIR/.$name.pr-staged."* "$BIN_DIR/.$name.pr-old."*; do
      [ -e "$file" ] || [ -L "$file" ] || continue
      case "$file" in
        *.pr-old.*)
          [ -x "$BIN_DIR/$name" ] \
            || die "restore $file to $BIN_DIR/$name before you retry this install" ;;
      esac
      rm -f "$file" || die "could not remove interrupted install file: $file"
    done
  done
}

private_dir "$OPENLLM_DIR"
private_dir "$BIN_DIR"
env_dir="$(dirname "$ENV_FILE")"
# A custom OPENLLM_DAEMON_ENV_FILE directory is the operator's, not ours:
# create it private when missing, but never chmod a pre-existing custom dir.
[ "$env_dir" = "$OPENLLM_DIR" ] || private_dir "$env_dir" 0
install_lock_acquire

# --- the ONE install entry point ------------------------------------------
# /api/install validates the committed daemon + CLI release pins in TypeScript
# (allow-listed repo, well-formed digests, a published tag for this target) and
# fails closed. Hitting it first means a mis-pinned or half-published release is
# refused BEFORE we download anything. No query parameters.
# Prerelease mode does NOT call it: the selected tag's own manifests pin both
# digests, and --prerelease never requests a stable checksum route.
DAEMON_VERSION=""
CLI_VERSION=""
PRE_SHA_DAEMON=""
PRE_SHA_CLI=""
if [ -n "$PRERELEASE_TAG" ]; then
  DAEMON_VERSION="${PRERELEASE_TAG#v}"
  CLI_VERSION="$DAEMON_VERSION"
  # The requested version is known without the network — refuse a downgrade of
  # any managed component before any fetch.
  refuse_downgrade "$BIN_DIR/openllmd" "$DAEMON_VERSION"
  refuse_downgrade "$BIN_DIR/openllm" "$CLI_VERSION"
  refuse_downgrade "$BIN_DIR/openllmc" "$CLI_VERSION"
  prerelease_discard_stale
  echo "Resolving the OpenLLM prerelease $PRERELEASE_TAG..."
  PRE_SHA_DAEMON="$(prerelease_manifest_digest openllmsh/daemon DAEMON_RELEASE)" || exit 1
  PRE_SHA_CLI="$(prerelease_manifest_digest openllmsh/cli CLI_RELEASE)" || exit 1
elif [ -z "$FROM_FILE" ]; then
  echo "Resolving the current OpenLLM release..."
  MANIFEST="$(curl "${CURL_SCHEME[@]}" "${CURL_META[@]}" -fsSL "$ORIGIN/api/install" 2>/dev/null)" \
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
  # Whatever /api/install advertises is the release of record — a PRERELEASE is
  # installable too (TCB-1/DR-1), and a prerelease install may move to a newer
  # stable. The only refusal is an actual DOWNGRADE of a managed component.
  refuse_downgrade "$BIN_DIR/openllmd" "$DAEMON_VERSION"
  refuse_downgrade "$BIN_DIR/openllm" "$CLI_VERSION"
  refuse_downgrade "$BIN_DIR/openllmc" "$CLI_VERSION"
fi

private_dir "$OPENLLM_DIR"
private_dir "$BIN_DIR"
env_dir="$(dirname "$ENV_FILE")"
# A custom OPENLLM_DAEMON_ENV_FILE directory is the operator's, not ours:
# create it private when missing, but never chmod a pre-existing custom dir.
[ "$env_dir" = "$OPENLLM_DIR" ] || private_dir "$env_dir" 0

# --- fetch + verify + install one component -------------------------------
# Bytes come from the per-component binary routes, which 302 to the pinned
# GitHub release asset and serve the committed digest as a `.sha256` sibling —
# the same pair the daemon's own self-update verifies against.
install_component() {
  local name="$1" route="$2" version="$3"
  local local_file="${4:-}" local_sha="${5:-}"
  local dest="$BIN_DIR/$name"
  local url="$ORIGIN/$route/$TARGET"
  local published installed stamp="$BIN_DIR/.$name.sha256.stamp"

  if [ -n "$local_file" ]; then
    # Private-prerelease path: the OPERATOR supplies both the bytes and the
    # digest — no network fetch of either. The checksum covers the file as
    # handed to us (a gzipped asset is decompressed after verification,
    # exactly like the download path).
    published="$(printf '%s' "$local_sha" | tr '[:upper:]' '[:lower:]')"
    [[ "$published" =~ ^[0-9a-f]{64}$ ]] \
      || die "malformed --sha256 digest for $name (expected 64 hex chars)"
    [ -f "$local_file" ] && [ -r "$local_file" ] \
      || die "--from-file path is not a readable regular file: $local_file"
  else
    published="$(curl "${CURL_SCHEME[@]}" "${CURL_META[@]}" -fsSL "$url.sha256" 2>/dev/null | cut -d' ' -f1 || true)"
    case "$published" in
      [0-9a-f]*)
        [[ "$published" =~ ^[0-9a-f]{64}$ ]] || die "malformed checksum for $name"
        ;;
      *) die "no published checksum for $name ($TARGET) — nothing to install" ;;
    esac
  fi

  # Skip a tens-of-MB download when what's installed already matches.
  # Developer-ID-signed + notarized binaries keep their published digest on
  # disk (we no longer force ad-hoc re-sign when codesign --verify passes).
  # The stamp remains for the fallback ad-hoc path (unsigned/invalid) where
  # re-signing rewrites bytes after the published digest check.
  # NEVER in local mode: the operator's file must always be hashed and
  # verified — a shortcut here would accept a wrong local file whenever the
  # installed binary already carries the expected digest.
  if [ -x "$dest" ] && [ -z "$local_file" ]; then
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

  if [ -n "$local_file" ]; then
    echo "Installing $name from $local_file..."
  else
    echo "Downloading $name ${version:+$version }($TARGET)..."
  fi
  # Stage inside $BIN_DIR: same filesystem as $dest (so the final mv is an
  # atomic rename, not a cross-device copy) and on the roomy root disk — minimal
  # cloud images mount a tiny RAM-backed /tmp where a download this size fails.
  local dl="$BIN_DIR/.$name.download.$$"
  local bin="$BIN_DIR/.$name.bin.$$"
  # The download+verify+swap runs in a SUBSHELL: its EXIT trap (temp-file
  # cleanup) is scoped there and is never installed on the main shell — so it
  # can neither replace an outer EXIT trap nor erase one with `trap - EXIT`
  # (the generated dist installer relies on its staging cleanup surviving our
  # exit on EVERY path, including a die here).
  (
    trap 'rm -f "$dl" "$bin"' EXIT
    local actual
    if [ -n "$local_file" ]; then
      cp "$local_file" "$dl" || die "could not stage local binary: $local_file"
      # The operator's digest covers the FILE as supplied — verify BEFORE any
      # decompression so the gate is on exactly the bytes they checksummed.
      actual="$(sha256_of "$dl")"
      [ -n "$actual" ] || die "could not hash $local_file"
      if [ "$actual" != "$published" ]; then
        die "checksum mismatch for $name (expected $published, got $actual) — refusing to install"
      fi
    elif [ -t 2 ]; then
      curl "${CURL_SCHEME[@]}" "${CURL_GET[@]}" -fL --progress-bar "$url" -o "$dl" || die "download failed: $url"
    else
      curl "${CURL_SCHEME[@]}" "${CURL_GET[@]}" -fsSL "$url" -o "$dl" || die "download failed: $url"
    fi

    # Assets are gzipped; the pinned digest is over the DECOMPRESSED binary, so
    # the integrity gate is independent of gzip's non-determinism. A local
    # digest was already checked over the supplied file bytes.
    if is_gzip_asset "$dl"; then
      decompress_asset "$dl" "$bin" "$name"
    else
      mv "$dl" "$bin"
    fi

    if [ -z "$local_file" ]; then
      actual="$(sha256_of "$bin")"
      [ -n "$actual" ] || die "could not hash the downloaded $name"
      if [ "$actual" != "$published" ]; then
        die "checksum mismatch for $name (expected $published, got $actual) — refusing to install"
      fi
    fi

    chmod 0755 "$bin"

    # macOS: strip quarantine. Preserve a valid Developer ID / notarized
    # signature (codesign --verify). Only ad-hoc sign when the signature is
    # missing/invalid — force ad-hoc would strip notarization and rewrite bytes.
    if [ "$OS" = "darwin" ]; then
      xattr -d com.apple.quarantine "$bin" >/dev/null 2>&1 || true
      if ! codesign --verify --strict "$bin" >/dev/null 2>&1; then
        codesign --force --sign - "$bin" >/dev/null 2>&1 \
          || die "could not sign $name — refusing to install"
        codesign --verify --strict "$bin" >/dev/null 2>&1 \
          || die "signature verification failed for $name — refusing to install"
        printf '%s %s\n' "$published" "$(sha256_of "$bin")" > "$stamp" 2>/dev/null || true
      fi
    fi
    # Re-probe immediately before replacement in case another installer or
    # operator changed the destination during the download — still only refusing
    # a true downgrade (a newer installed build over the advertised one). For a
    # local file there is no advertised release: the staged binary's own
    # reported version is the reference, so an older build still can't silently
    # overwrite a newer install.
    local check_version="$version"
    if [ -n "$local_file" ]; then
      installed_version "$bin"
      check_version="$INSTALLED_VERSION"
    fi
    if [ -n "$check_version" ] && installed_version "$dest"; then
      installed="$INSTALLED_VERSION"
      [ "$(semver_cmp "$installed" "$check_version")" != "1" ] \
        || die "installed $name is $installed, newer than the install target $check_version — refusing to downgrade.
  To force this version, remove $dest and re-run this installer."
    fi
    mv -f "$bin" "$dest"
  ) || exit 1
  echo "  $name installed → $dest"
  INSTALLED_COMPONENTS="$INSTALLED_COMPONENTS $name"
}

# --- prerelease: stage BOTH components, then commit -------------------------
# The published tag is single-shot: a missing manifest, missing asset, bad
# digest or wrong target fails the run. Both components are downloaded,
# digested, format-checked and version-probed into staging BEFORE either one
# replaces an installed file, so a failure never leaves a half-swapped pair.
prerelease_cleanup() {
  rm -f "$BIN_DIR"/.openllmd.pr-dl.$$ "$BIN_DIR"/.openllmd.pr-bin.$$ \
        "$BIN_DIR"/.openllmd.pr-staged.$$ \
        "$BIN_DIR"/.openllm.pr-dl.$$ "$BIN_DIR"/.openllm.pr-bin.$$ \
        "$BIN_DIR"/.openllm.pr-staged.$$
}
# PR_ASIDE lists saved binaries. PR_PLACED lists installed replacements.
# Commit helpers return failure so the caller can restore the saved binaries.
PR_ASIDE=""
PR_PLACED=""
PR_HASH_DAEMON=""
PR_HASH_CLI=""
prerelease_abort() { exit 1; }

prerelease_rollback() {
  local name expected actual backup
  for name in $PR_PLACED; do
    backup="$BIN_DIR/.$name.pr-old.$$"
    case "$name" in
      openllmd) expected="$PR_HASH_DAEMON" ;;
      openllm) expected="$PR_HASH_CLI" ;;
    esac
    actual="$(sha256_of "$BIN_DIR/$name" 2>/dev/null || true)"
    if [ -n "$expected" ] && [ "$actual" = "$expected" ]; then
      case " $PR_ASIDE " in
        *" $name "*)
          mv -f "$backup" "$BIN_DIR/$name" 2>/dev/null \
            || echo "Error: rollback failed — the previous $name is still at $backup" >&2 ;;
        *) rm -f "$BIN_DIR/$name" 2>/dev/null || true ;;
      esac
    elif [ -n "$actual" ]; then
      # Another writer changed this path, or placement failed before the rename.
      # Keep the canonical binary. It does not belong to this transaction.
      rm -f "$backup"
    else
      echo "Error: could not verify $name for rollback; keep $backup for recovery" >&2
    fi
  done
  for name in $PR_ASIDE; do
    case " $PR_PLACED " in *" $name "*) continue ;; esac
    rm -f "$BIN_DIR/.$name.pr-old.$$"
  done
  prerelease_cleanup
}

# Download + verify one component into $BIN_DIR/.$name.pr-staged.$$ — every
# gate runs inside a subshell whose EXIT trap removes its own temp files.
prerelease_stage() {
  local name="$1" published="$2" url="$3" version="$4"
  local dest="$BIN_DIR/$name" stamp="$BIN_DIR/.$name.sha256.stamp"
  local staged="$BIN_DIR/.$name.pr-staged.$$"
  local dl="$BIN_DIR/.$name.pr-dl.$$" bin="$BIN_DIR/.$name.pr-bin.$$"
  local installed sp si

  # Same skip rule as the stable path: identical bytes already in place mean a
  # tag re-run does no binary work — only missing managed setup is repaired.
  if [ -x "$dest" ]; then
    installed="$(sha256_of "$dest" || true)"
    if [ -n "$installed" ]; then
      if [ "$installed" = "$published" ]; then
        probe_staged_version "$dest" "$version"
        echo "  $name is already up to date"
        return 0
      fi
      if [ -f "$stamp" ]; then
        read -r sp si < "$stamp" || true
        if [ "$sp" = "$published" ] && [ "$si" = "$installed" ]; then
          probe_staged_version "$dest" "$version"
          echo "  $name is already up to date"
          return 0
        fi
      fi
    fi
  fi

  echo "Downloading $name $version ($TARGET)..."
  (
    trap 'rm -f "$dl" "$bin"' EXIT
    local actual
    if [ -t 2 ]; then
      curl "${PR_SCHEME[@]}" "${CURL_GET[@]}" -fL --progress-bar "$url" -o "$dl" || die "download failed: $url"
    else
      curl "${PR_SCHEME[@]}" "${CURL_GET[@]}" -fsSL "$url" -o "$dl" || die "download failed: $url"
    fi
    # The published asset is ALWAYS a gzip member — there is no raw fallback.
    is_gzip_asset "$dl" || die "downloaded $name is not a valid gzip asset"
    decompress_asset "$dl" "$bin" "$name"
    rm -f "$dl"
    actual="$(sha256_of "$bin")"
    [ -n "$actual" ] || die "could not hash the downloaded $name"
    [ "$actual" = "$published" ] \
      || die "checksum mismatch for $name (expected $published, got $actual) — refusing to install"
    verify_exec_format "$bin"
    chmod 0755 "$bin"
    # macOS: verify the digest BEFORE signature handling, then keep the stable
    # path's rules — a valid Developer ID signature survives, otherwise ad-hoc.
    if [ "$OS" = "darwin" ]; then
      xattr -d com.apple.quarantine "$bin" >/dev/null 2>&1 || true
      if ! codesign --verify --strict "$bin" >/dev/null 2>&1; then
        codesign --force --sign - "$bin" >/dev/null 2>&1 \
          || die "could not sign $name — refusing to install"
        codesign --verify --strict "$bin" >/dev/null 2>&1 \
          || die "signature verification failed for $name — refusing to install"
        printf '%s %s\n' "$published" "$(sha256_of "$bin")" > "$stamp" 2>/dev/null || true
      fi
    fi
    probe_staged_version "$bin" "$version"
    mv -f "$bin" "$staged" || die "could not stage $name"
  ) || return 1
}

# Pre-commit re-probe of the destination (same rule as the stable path): the
# installed binary may have changed while the downloads were in flight. This
# is installed_version() minus the die()s — the commit phase must return so
# prerelease_abort can roll back and clean up.
prerelease_commit_check() {
  local name="$1" check_version="$2"
  local staged="$BIN_DIR/.$name.pr-staged.$$" dest="$BIN_DIR/$name" installed
  [ -f "$staged" ] || return 0
  [ -x "$dest" ] || return 0
  run_version_probe "$dest"
  if [ "$PROBE_STATUS" -ne 0 ]; then
    echo "Error: version probe timed out or failed at $dest; refusing to overwrite it.
  To repair by hand: move the binary aside ('mv \"$dest\" \"$dest.bak\"') and re-run this installer." >&2
    return 1
  fi
  parse_probe_version "$PROBE_OUT"
  if [ -z "$PARSED_VERSION" ]; then
    echo "Error: could not parse a version from $dest; refusing to overwrite" >&2
    return 1
  fi
  installed="$PARSED_VERSION"
  if [ "$(semver_cmp "$installed" "$check_version")" = "1" ]; then
    echo "Error: installed $name is $installed, newer than the install target $check_version — refusing to downgrade.
  To force this version, remove $dest and re-run this installer." >&2
    return 1
  fi
  return 0
}

# Save a hard link to the old binary. Rename the new binary over the old path.
# A crash before or after the rename leaves the canonical path in place.
prerelease_commit_place() {
  local name="$1"
  local staged="$BIN_DIR/.$name.pr-staged.$$" dest="$BIN_DIR/$name"
  local backup="$BIN_DIR/.$name.pr-old.$$"
  local expected
  [ -f "$staged" ] || return 0
  expected="$(sha256_of "$staged")" || return 1
  [ -n "$expected" ] || return 1
  case "$name" in
    openllmd) PR_HASH_DAEMON="$expected" ;;
    openllm) PR_HASH_CLI="$expected" ;;
  esac
  if [ -e "$dest" ] || [ -L "$dest" ]; then
    if ! ln "$dest" "$backup" 2>/dev/null; then
      echo "Error: could not back up $dest — refusing to replace it" >&2
      return 1
    fi
    PR_ASIDE="$PR_ASIDE $name"
  fi
  # Record the digest before the rename so a signal can also roll it back.
  PR_PLACED="$PR_PLACED $name"
  if ! mv -f "$staged" "$dest"; then
    echo "Error: could not install $name → $dest" >&2
    return 1
  fi
  echo "  $name installed → $dest"
  INSTALLED_COMPONENTS="$INSTALLED_COMPONENTS $name"
}

if [ -n "$PRERELEASE_TAG" ]; then
  INSTALL_ROLLBACK=prerelease_rollback
  prerelease_stage openllmd "$PRE_SHA_DAEMON" \
    "$(prerelease_asset_url openllmsh/daemon "openllmd-$TARGET.gz")" "$DAEMON_VERSION" \
    || prerelease_abort
  prerelease_stage openllm "$PRE_SHA_CLI" \
    "$(prerelease_asset_url openllmsh/cli "openllm-$TARGET.gz")" "$CLI_VERSION" \
    || prerelease_abort
  # Both components verified in staging — check both destinations, then place.
  prerelease_commit_check openllmd "$DAEMON_VERSION" || prerelease_abort
  prerelease_commit_check openllm "$CLI_VERSION" || prerelease_abort
  prerelease_commit_place openllmd || prerelease_abort
  prerelease_commit_place openllm || prerelease_abort
  INSTALL_ROLLBACK=""
  # Both renames succeeded. Remove the backups.
  rm -f "$BIN_DIR"/.openllmd.pr-old.$$ "$BIN_DIR"/.openllm.pr-old.$$
else
  install_component openllmd api/daemon/binary "$DAEMON_VERSION" "$FROM_FILE" "$FROM_SHA"
  # The CLI rides the same install: one command gets you both, and the daemon's
  # auto-update loop keeps them both current from here on.
  if [ -n "$CLI_FROM_FILE" ]; then
    install_component openllm api/cli/binary "$CLI_VERSION" "$CLI_FROM_FILE" "$CLI_SHA"
  elif [ -n "$CLI_VERSION" ]; then
    install_component openllm api/cli/binary "$CLI_VERSION"
  elif [ -z "$FROM_FILE" ]; then
    echo "  note: no CLI release published yet — skipping openllm"
  else
    echo "  note: no --cli-from-file given — leaving any installed CLI untouched"
  fi
fi

install_lock_release

# The native PTY backend is compiled into the daemon binary in v2.8 (G1), so
# there is no third component to install.

# --- the shared config file ------------------------------------------------
# Re-read under the same exclusive `$ENV_FILE.lock` protocol as the daemon's
# writeEnvFileVars. Never rebuild this file from a pre-download snapshot: a daemon
# can mint a device id or update credentials while binaries are downloading.
# Delegates to `env_file_lookup` for the same last-match-wins, trim/skip
# semantics as `parseEnvLines` (packages/daemon/src/env.ts) — the values read
# here (device id, PTY flag) are exactly what that parser resolves on the
# daemon's own next boot. For OPENLLM_API_KEY only, ONE layer of surrounding
# quotes is stripped — the same KEY="value" / KEY='value' parsing
# env_file_value (and packages/cli/src/env.ts) applies, so a quoted persisted
# key is read as the credential every runtime actually sees (FS-7). Every
# other key is copied exactly as resolved: the daemon's parser keeps quote
# characters, so stripping them here would change OPENLLM_DEVICE_ID or flip
# OPENLLM_DAEMON_PTY_SESSIONS on the next installer run.
read_env_value() {
  local wanted="$1" value
  value="$(env_file_lookup "$wanted")"
  if [ "$wanted" = "OPENLLM_API_KEY" ]; then
    value="${value#[\"\']}"
    value="${value%[\"\']}"
  fi
  printf '%s' "$value"
}

write_env_file() {
  # IMPORTANT — this function runs inside `$(...)` command substitution,
  # where `set -e` DOES NOT APPLY: a failing command does not abort the
  # subshell. EVERY fallible step below is therefore guarded explicitly with
  # `|| die`. A half-written tmp must never reach the rename — a full disk
  # otherwise drops the API key / device id while the installer exits 0.
  #
  # The lock is the `<envfile>.lock.d` DIRECTORY of the shared
  # openllm-env-lock/v1 protocol above — the same protocol the daemon's
  # withEnvFileLock (packages/daemon/src/env.ts) and the CLI installer
  # implement, so a crashed holder is recovered (dead or reused pid owner,
  # or an ownerless publish past the orphan bound) instead of wedging every
  # later install on "could not acquire config lock" — while a live
  # holder's lock can never be stolen or deleted mid-write.
  local current_key current_device current_pty desired_key desired_pty tmp line key
  # An existing-but-unreadable env file would silently drop every preserved
  # key — fail loudly instead of merging against an empty read. Checked BEFORE
  # the lock: a die here must not strand a lock dir the EXIT trap isn't
  # installed yet to release.
  [ ! -f "$ENV_FILE" ] || [ -r "$ENV_FILE" ] \
    || die "cannot read existing config file: $ENV_FILE"
  env_lock_acquire "$ENV_FILE" || { lock_status=$?; exit "$lock_status"; }
  # Any exit while the lock is held — die, a set -e failure, Ctrl-C, SIGTERM —
  # must release the lock AND remove the temp file (it may carry the API key).
  # A RETURN trap never fires on exit, so cleanup lives on EXIT/INT/TERM.
  # env_lock_release deletes only a dir that still holds OUR owner record.
  # `${tmp:-}`: at a normal function return the locals are already out of
  # scope when this subshell's EXIT trap fires — an unbound $tmp under
  # set -u would abort the trap before env_lock_release ran.
  trap 'rm -f "${tmp:-}"; env_lock_release' EXIT
  trap 'exit 130' INT
  trap 'exit 143' TERM

  current_key="$(trim_whitespace "$(read_env_value OPENLLM_API_KEY || true)")"
  current_device="$(read_env_value OPENLLM_DEVICE_ID || true)"
  current_pty="$(read_env_value OPENLLM_DAEMON_PTY_SESSIONS || true)"
  if [ -n "$SUPPLIED_KEY" ]; then
    desired_key="$SUPPLIED_KEY"
  else
    desired_key="$current_key"
    if [ -n "$desired_key" ] && ! is_usable_api_key "$desired_key"; then
      # The value is not a key we can use — but it is still the user's line.
      # Keep it in the file (below) and only skip the daemon start; NEVER
      # silently drop a credential the user may repair or that a different
      # runtime may still parse (FS-7).
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
  # Tighten umask only for the temp-file creation window (closing the race
  # before `chmod 0600`), then restore it so later installer steps and child
  # processes keep the caller's umask.
  local saved_umask
  saved_umask="$(umask)" || die "could not read the umask"
  umask 077 || die "could not tighten the umask"
  : > "$tmp" || die "could not create temp config file: $tmp"
  # Keep unrelated lines byte-for-byte, but replace every installer-owned key with
  # one canonical occurrence. A key line with no desired value is kept verbatim —
  # dropping it would silently delete a credential the user may repair (FS-7).
  local wrote_origin=0 wrote_port=0 wrote_key=0 wrote_device=0 wrote_pty=0
  if [ -f "$ENV_FILE" ]; then
    while IFS= read -r line || [ -n "$line" ]; do
      key="${line%%=*}"
      case "$key" in
        OPENLLM_CLOUD_ORIGIN)
          [ "$wrote_origin" = 1 ] || { printf 'OPENLLM_CLOUD_ORIGIN=%s\n' "$ORIGIN" >> "$tmp" || die "write failed: $tmp"; wrote_origin=1; }
          ;;
        OPENLLM_DAEMON_PORT)
          [ "$wrote_port" = 1 ] || { printf 'OPENLLM_DAEMON_PORT=%s\n' "$DAEMON_PORT" >> "$tmp" || die "write failed: $tmp"; wrote_port=1; }
          ;;
        OPENLLM_API_KEY)
          if [ -n "$desired_key" ]; then
            [ "$wrote_key" = 1 ] || { printf 'OPENLLM_API_KEY=%s\n' "$desired_key" >> "$tmp" || die "write failed: $tmp"; wrote_key=1; }
          else
            # No usable key to write — keep the existing line verbatim rather
            # than dropping the user's credential (FS-7).
            printf '%s\n' "$line" >> "$tmp" || die "write failed: $tmp"
          fi
          ;;
        OPENLLM_DEVICE_ID)
          if [ -n "$current_device" ] && [ "$wrote_device" = 0 ]; then printf 'OPENLLM_DEVICE_ID=%s\n' "$current_device" >> "$tmp" || die "write failed: $tmp"; wrote_device=1; fi
          ;;
        OPENLLM_DAEMON_PTY_SESSIONS)
          if [ -n "$desired_pty" ] && [ "$wrote_pty" = 0 ]; then printf 'OPENLLM_DAEMON_PTY_SESSIONS=%s\n' "$desired_pty" >> "$tmp" || die "write failed: $tmp"; wrote_pty=1; fi
          ;;
        *) printf '%s\n' "$line" >> "$tmp" || die "write failed: $tmp" ;;
      esac
    done < "$ENV_FILE" || die "could not read config file: $ENV_FILE"
  fi
  [ "$wrote_origin" = 1 ] || printf 'OPENLLM_CLOUD_ORIGIN=%s\n' "$ORIGIN" >> "$tmp" || die "write failed: $tmp"
  [ "$wrote_port" = 1 ] || printf 'OPENLLM_DAEMON_PORT=%s\n' "$DAEMON_PORT" >> "$tmp" || die "write failed: $tmp"
  [ -z "$desired_key" ] || [ "$wrote_key" = 1 ] || printf 'OPENLLM_API_KEY=%s\n' "$desired_key" >> "$tmp" || die "write failed: $tmp"
  [ -z "$current_device" ] || [ "$wrote_device" = 1 ] || printf 'OPENLLM_DEVICE_ID=%s\n' "$current_device" >> "$tmp" || die "write failed: $tmp"
  [ -z "$desired_pty" ] || [ "$wrote_pty" = 1 ] || printf 'OPENLLM_DAEMON_PTY_SESSIONS=%s\n' "$desired_pty" >> "$tmp" || die "write failed: $tmp"
  chmod 0600 "$tmp" || die "could not chmod temp config file: $tmp"
  # Abort with a clear error if the atomic replace fails — never fall through to
  # announce success (or set API_KEY) on a config that was not written. The
  # EXIT trap still cleans up the temp file + lock on that die.
  mv -f "$tmp" "$ENV_FILE" || die "could not write config file: $ENV_FILE"
  chmod 0600 "$ENV_FILE" || die "could not chmod config file: $ENV_FILE"
  umask "$saved_umask" || die "could not restore the umask"
  env_lock_release || { lock_status=$?; exit "$lock_status"; }
  # The ONLY stdout line: the resolved key — the caller captures it as API_KEY.
  printf '%s' "$desired_key" || die "could not report the API key"
}

# The whole write runs inside command substitution: the EXIT/INT/TERM traps
# write_env_file installs are scoped to that subshell and cannot replace an
# outer EXIT trap — the generated dist installer relies on its staging cleanup
# surviving ANY exit of ours, including a die while the lock is held.
PRIOR_ENV_SHA=""
if [ -n "$PRERELEASE_TAG" ] && [ -z "$INSTALLED_COMPONENTS" ] && [ -f "$ENV_FILE" ]; then
  PRIOR_ENV_SHA="$(sha256_of "$ENV_FILE" || true)"
fi
API_KEY="$(write_env_file)" || exit "$?"
echo "  gateway config written → $ENV_FILE"

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

# Keep a healthy service when the prerelease binaries and config did not change.
# Require live health and a running version that matches the installed binary.
prerelease_service_healthy() {
  local status version
  [ -n "$PRIOR_ENV_SHA" ] || return 1
  [ "$PRIOR_ENV_SHA" = "$(sha256_of "$ENV_FILE" || true)" ] || return 1
  status="$("$BIN_DIR/openllmd" status 2>/dev/null)" || return 1
  run_version_probe "$BIN_DIR/openllmd"
  [ "$PROBE_STATUS" -eq 0 ] || return 1
  parse_probe_version "$PROBE_OUT"
  version="$PARSED_VERSION"
  [ -n "$version" ] || return 1
  printf '%s\n' "$status" | awk -v version="$version" '
    $1 == "service:" && $2 == "registered" { registered=1 }
    $1 == "supervisor:" && ($2 == "running" || ($2 == "active" && $3 == "(running)")) { supervised=1 }
    $1 == "health:" && $2 == "serving" { serving=1 }
    $1 == "running" && $2 == "version:" && NF == 3 && $3 == version { current=1 }
    END { exit !(registered && supervised && serving && current) }
  '
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
  elif prerelease_service_healthy; then
    echo "  daemon already current and healthy — no restart needed"
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

# --- provision the vendor subscription CLIs (opt-in, background) -----------
# The daemon RUNS the official vendor CLIs but never INSTALLS them (it runs
# under an OS sandbox that intentionally can't touch shell rc files). THIS
# script — run by the user, unsandboxed, with a real HOME/PATH/rc — is the one
# place a missing CLI can be installed. But a detached `curl | bash` against a
# third-party host is a real ask: it runs unverified code, inherits the
# installer's env (OPENLLM_API_KEY included), and historically had no timeout,
# no lock and no log bound (LEAK-1/2, RG-1, NET-5, SP-7). So it is OPT-IN:
#   OPENLLM_INSTALL_VENDOR_CLIS=1  → bounded background jobs for missing CLIs
#   default                       → print each vendor's official one-liner
#   OPENLLM_SKIP_VENDOR_CLIS=1    → hard no-op (CI/test harnesses — TEST-1)
# Opted-in jobs are launched WHOLE through `env -u <every exported OPENLLM_*>`
# so no intermediate process ever holds the API key, run under
# `timeout -k 15 600` — or a process-group watchdog that kills the job's own
# process group (setsid on Linux, `set -m` on macOS) where timeout(1) doesn't
# exist — fetch only over https with --proto-redir + connect/total curl
# deadlines, take a per-vendor pid+start-identity pidfile lock so re-runs
# never double-start, and stream their output through a bounded writer into
# a size-capped per-vendor log under ~/.openllm/cli-install/.
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
  # NOTE: tests/api/support/script-sandbox.ts derives its seeded launchers
  # from this array — a vendor added here is covered automatically.
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
  if [ -n "${OPENLLM_SKIP_VENDOR_CLIS:-}" ]; then
    return 0
  fi
  local opt_in=0
  case "${OPENLLM_INSTALL_VENDOR_CLIS:-}" in
    1|true|yes) opt_in=1 ;;
  esac
  VENDOR_JOBS_STARTED=0
  VENDOR_MISSING_PRINTED=0
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
  # Test/injection hooks (OPENLLM_VENDOR_CLI_CURL_BIN / _TIMEOUT_BIN): an
  # absolute path wins over every resolution path — a PATH stub can never
  # reach the detached job, but these can.
  local curl_bin="${OPENLLM_VENDOR_CLI_CURL_BIN:-}"
  if [ -z "$curl_bin" ]; then
    curl_bin="$(PATH="$run_path" command -v curl 2>/dev/null || true)"
  fi
  # Fallback: probe the canonical absolute locations directly (a pathological
  # PATH or a shell without a working `command -v` still resolves here).
  if [ -z "$curl_bin" ]; then
    local c
    for c in /usr/bin/curl /bin/curl /usr/local/bin/curl /opt/homebrew/bin/curl; do
      [ -x "$c" ] && { curl_bin="$c"; break; }
    done
  fi
  if [ -z "$curl_bin" ]; then
    if [ "$opt_in" = 1 ]; then
      echo "  Vendor CLIs: curl not found — install them by hand from their official installers." >&2
    fi
    curl_bin=""
  fi
  # The vendor download pins --proto/--proto-redir — a curl too old to know
  # the options would fail mid-job with an opaque error, so check the resolved
  # binary once and degrade to the printed one-liner instead (vendor installs
  # are opt-in nicety, never required for the install to succeed).
  local curl_bin_scheme_ok=1
  if [ -n "$curl_bin" ] \
    && ! "$curl_bin" --proto "=https" --proto-redir "=https" -V >/dev/null 2>&1; then
    curl_bin_scheme_ok=0
  fi
  # A hard bound around the whole `curl | bash` pipeline — GNU `timeout` where
  # it exists (gtimeout covers brew coreutils on macOS), else a bash watchdog.
  # OPENLLM_VENDOR_CLI_TIMEOUT_BIN=none forces the watchdog path (test hook).
  local timeout_bin="${OPENLLM_VENDOR_CLI_TIMEOUT_BIN:-}"
  if [ "$timeout_bin" = "none" ]; then
    timeout_bin=""
  elif [ -z "$timeout_bin" ]; then
    local t
    for t in timeout gtimeout; do
      timeout_bin="$(PATH="$run_path" command -v "$t" 2>/dev/null || true)"
      [ -n "$timeout_bin" ] && break
    done
  fi
  # The watchdog path's group-kill needs the job in its OWN process group:
  # `setsid` where it exists (Linux) so the leader's pid IS the pgid, else the
  # `set -m` job-control group (macOS). OPENLLM_VENDOR_CLI_SETSID_BIN=none
  # forces the set -m path (test hook).
  local setsid_bin="${OPENLLM_VENDOR_CLI_SETSID_BIN:-}"
  if [ "$setsid_bin" = "none" ]; then
    setsid_bin=""
  elif [ -z "$setsid_bin" ]; then
    setsid_bin="$(PATH="$run_path" command -v setsid 2>/dev/null || true)"
  fi
  local job_timeout="${OPENLLM_VENDOR_CLI_TIMEOUT:-600}"
  [[ "$job_timeout" =~ ^[0-9]+$ ]] || job_timeout=600
  # 0 would mean "no deadline" to GNU timeout and the sleep watchdog — a hung
  # vendor job would then hold its pidfile forever. Always bounded.
  job_timeout=$((10#$job_timeout))
  [ "$job_timeout" -gt 0 ] || job_timeout=600
  local helper_wait=$((job_timeout + 30))
  [ "$helper_wait" -le 3600 ] || helper_wait=3600
  # The launch marker covers the spawn-to-publish gap for a bounded window:
  # a marker younger than this means "a job is launching" even before its
  # own pidfile exists — so a second installer never double-starts.
  local job_launch_grace="${OPENLLM_VENDOR_CLI_LAUNCH_GRACE:-60}"
  # Leading zeros are decimal ("08" is 8) — [[ -gt ]] would read them as
  # invalid octal, so canonicalise through 10# first (same rule as the
  # env-lock knobs).
  [[ "$job_launch_grace" =~ ^[0-9]+$ ]] || job_launch_grace=0
  job_launch_grace=$((10#$job_launch_grace))
  [ "$job_launch_grace" -gt 0 ] || job_launch_grace=60
  # Per-vendor log bound — enforced DURING the run by a bounded writer (RG-1),
  # not just by trimming the file after the job exits.
  local log_cap="${OPENLLM_VENDOR_LOG_CAP:-262144}"
  [[ "$log_cap" =~ ^[0-9]+$ ]] || log_cap=0
  log_cap=$((10#$log_cap))
  [ "$log_cap" -gt 0 ] || log_cap=262144
  # SP-7/M3: the WHOLE vendor job — wrapper `bash -c`, timeout, watchdog — is
  # launched through `env -u <every exported OPENLLM_*>`, so no intermediate
  # process in its tree ever holds the API key (the log writer is a separate
  # `env -i`). The unexport list is built with the compgen BUILTIN — spawning
  # `env` to enumerate would itself carry the secrets. Everything the job
  # needs is passed as positional arguments to `bash -c` below.
  local -a vendor_scrub=()
  local _openllm_var
  for _openllm_var in $(compgen -A export 2>/dev/null); do
    case "$_openllm_var" in OPENLLM_*) vendor_scrub+=(-u "$_openllm_var") ;; esac
  done
  unset _openllm_var
  # The vendor install job, run verbatim by the sanitized `bash -c` below.
  # $1 pidfile  $2 timeout_bin  $3 job_timeout  $4 curl_bin  $5 url
  # $6 setsid_bin  $7 tagged launchfile  $8 absolute helper
  # $9 launch nonce  $10 helper wait seconds
  local job_body
  job_body="$(cat <<'OPENLLM_VENDOR_JOB'
pidfile="$1"; timeout_bin="$2"; job_timeout="$3"; curl_bin="$4"; url="$5"; setsid_bin="$6"; launchfile="$7"; helper="$8"; launch_nonce="$9"; max_wait="${10}"
lockd="$pidfile.d"
# The native helper owns the vendor descriptor and persists this actual Bash
# worker before its first owner-temp mutation. It uses the launch helper's
# association for the after-mkdir and before-grant checks.
[ -x "$helper" ] || exit 74
worker_pid="${BASHPID:-$$}"
request="$pidfile.v3.${BASHPID:-$$}.$RANDOM.request"
ready="$pidfile.v3.${BASHPID:-$$}.$RANDOM.ready"
"$helper" --internal-lock-control v "$lockd" "$worker_pid" \
  "$request" "$ready" "$launchfile" "$launch_nonce" "$max_wait" < /dev/null &
leasepid=$!
ready_begin=$SECONDS
ready_previous=$SECONDS
for ((ready_attempt=0; ready_attempt<200; ready_attempt++)); do
  [ -f "$ready" ] && break
  kill -0 "$leasepid" 2>/dev/null || break
  if [ "$SECONDS" -lt "$ready_previous" ] || [ "$((SECONDS - ready_begin))" -ge 10 ]; then break; fi
  ready_previous=$SECONDS
  sleep 0.05 2>/dev/null || sleep 1
done
if [ ! -f "$ready" ] || [ "$(cat "$ready" 2>/dev/null || true)" != '{"version":3,"code":0}' ]; then
  ( set -C; printf 'release\n' > "$request" ) 2>/dev/null || { kill "$leasepid" 2>/dev/null || true; }
  wait "$leasepid" 2>/dev/null || true
  rm -f "$request" 2>/dev/null || true
  printf 'vendor lock helper could not verify the launch handoff for %s; preserving evidence\n' "$pidfile" >&2
  exit 74
fi
rm -f "$ready" 2>/dev/null || true
# The launch helper's handoff record is durable before the vendor helper
# acknowledges this lease. The publisher then removes its own exact marker.
group_confirmed_gone=0
group_id_proven=0
# The vendor claim stays held until the entire observed process group has
# ended. An uncertain group leaves the worker association for safe recovery.
trap 'if [ "${group_confirmed_gone:-0}" = 1 ] || { \
  { [ "${group_observed:-0}" = 1 ] || [ "${group_id_proven:-0}" = 1 ]; } \
  && [ -n "${pgid:-}" ] && ! kill -0 -- -"$pgid" 2>/dev/null; }; then
  action=release
else
  action=preserve
fi
( set -C; printf "%s\n" "$action" > "$request" ) 2>/dev/null || { kill "$leasepid" 2>/dev/null || true; }
wait "$leasepid" 2>/dev/null || true
rm -f "$request" 2>/dev/null || true' EXIT
pipeline='"$2" --internal-lock-control vendor-group "$3" "$4" || exit 74
"$0" --proto "=https" --proto-redir "=https" --connect-timeout 10 --max-time 300 -fsSL "$1" | bash'
pgid=""
group_observed=0
leader_pid=""
if [ -n "$timeout_bin" ]; then
  # GNU timeout usually leads its own process group, but do not assume that.
  # Observe the group before and after waiting. If it was never visible, use
  # the timeout leader's liveness instead of treating an empty probe as proof.
  "$timeout_bin" -k 15 "$job_timeout" bash -c "$pipeline" "$curl_bin" "$url" "$helper" "$lockd" "$worker_pid" &
  twait=$!
  leader_pid="$twait"
  if kill -0 -- -"$twait" 2>/dev/null \
    || [ "$(ps -o pgid= -p "$twait" 2>/dev/null | tr -d ' ')" = "$twait" ]; then
    pgid="$twait"
    group_observed=1
  fi
  wait "$twait" 2>/dev/null || true
  if [ "$group_observed" != 1 ] && kill -0 -- -"$twait" 2>/dev/null; then
    pgid="$twait"
    group_observed=1
  fi
  if [ "$group_observed" = 1 ] && kill -0 -- -"$pgid" 2>/dev/null; then
    kill -TERM -- -"$pgid" 2>/dev/null || true
    sleep 1
    kill -KILL -- -"$pgid" 2>/dev/null || true
  elif [ "$group_observed" != 1 ] && ! kill -0 "$leader_pid" 2>/dev/null; then
    group_confirmed_gone=1
  fi
elif [ -n "$setsid_bin" ]; then
  # setsid(1) starts the pipeline as its own session + process-group leader,
  # so the leader pid IS the pgid — `$!` after the pipeline would NOT be it.
  "$setsid_bin" bash -c "$pipeline" "$curl_bin" "$url" "$helper" "$lockd" "$worker_pid" &
  leader=$!
  leader_pid="$leader"
  pgid="$leader"
  group_id_proven=1
  if kill -0 -- -"$pgid" 2>/dev/null \
    || [ "$(ps -o pgid= -p "$leader" 2>/dev/null | tr -d ' ')" = "$pgid" ]; then
    group_observed=1
  fi
  # The deadline watchdog. Its sleeps run as NAMED children under a TERM
  # trap — `kill "$watchdog"` below then stands the whole watchdog down
  # cleanly; a plain `( sleep …; kill …)` subshell would orphan its
  # foreground `sleep`, leaving it to hold the log pipe open for the full
  # timeout.
  (
    sleeper=""
    # Kill EVERY background child via the job table, not just $sleeper: a TERM
    # landing after `sleep &` forks but before `sleeper=$!` is assigned would
    # otherwise orphan the sleep, which holds the log pipe open until the
    # deadline.
    trap 'kill $(jobs -p) 2>/dev/null || true
          exit 0' TERM
    sleep "$job_timeout" & sleeper=$!
    wait "$sleeper" 2>/dev/null
    kill -TERM -- -"$pgid" 2>/dev/null || true
    sleep 5 & sleeper=$!
    wait "$sleeper" 2>/dev/null
    kill -KILL -- -"$pgid" 2>/dev/null || true
  ) &
  watchdog=$!
  wait "$leader" 2>/dev/null || true
  # `wait` returns when the leader exits — a TERM-ignoring vendor child keeps
  # the GROUP alive (and the log pipe open). Finish a surviving group here
  # too, or the watchdog's pending KILL is stood down with nothing sent.
  if kill -0 -- -"$pgid" 2>/dev/null; then
    group_observed=1
    kill -TERM -- -"$pgid" 2>/dev/null || true
    sleep 1
    kill -KILL -- -"$pgid" 2>/dev/null || true
  fi
  kill "$watchdog" 2>/dev/null || true
  wait "$watchdog" 2>/dev/null || true
else
  # macOS has no setsid(1): job control (`set -m`) puts each background job
  # in its OWN process group. Record the REAL pgid via ps — never assume $!
  # is a group id.
  set -m
  bash -c "$pipeline" "$curl_bin" "$url" "$helper" "$lockd" "$worker_pid" &
  leader=$!
  leader_pid="$leader"
  group_id_proven=1
  pgid="$(ps -o pgid= -p "$leader" 2>/dev/null | tr -d ' ')"
  [[ "$pgid" =~ ^[0-9]+$ ]] || pgid=""
  # Under `set -m` a background job leads its own group, so its pgid is the
  # leader pid. When ps cannot report it, confirm that with the kernel (a
  # group with that id exists) rather than assume it — then the whole
  # pipeline is still signalled and reaped as one group.
  if [ -z "$pgid" ] && kill -0 -- -"$leader" 2>/dev/null; then
    pgid="$leader"
  fi
  [ -n "$pgid" ] && group_observed=1
  # Check the group again after the leader ends. A child can still run.
  # Release the lease only when both checks show no process.
  if [ -z "$pgid" ] && ! kill -0 "$leader" 2>/dev/null && ! kill -0 -- -"$leader" 2>/dev/null; then
    group_confirmed_gone=1
  fi
  # Still unverified: signal the leader alone and leave pgid empty, so the
  # EXIT trap keeps the pidfile (the group cannot be confirmed gone).
  if [ -n "$pgid" ]; then sig_target="-$pgid"; else sig_target="$leader"; fi
  # Same self-cleaning watchdog as the setsid branch: the TERM trap kills the
  # in-flight `sleep`, so standing the watchdog down never orphans a sleeper
  # that would hold the log pipe open until the deadline.
  (
    sleeper=""
    # Kill EVERY background child via the job table, not just $sleeper: a TERM
    # landing after `sleep &` forks but before `sleeper=$!` is assigned would
    # otherwise orphan the sleep, which holds the log pipe open until the
    # deadline.
    trap 'kill $(jobs -p) 2>/dev/null || true
          exit 0' TERM
    sleep "$job_timeout" & sleeper=$!
    wait "$sleeper" 2>/dev/null
    kill -TERM -- "$sig_target" 2>/dev/null || true
    sleep 5 & sleeper=$!
    wait "$sleeper" 2>/dev/null
    kill -KILL -- "$sig_target" 2>/dev/null || true
  ) &
  watchdog=$!
  wait "$leader" 2>/dev/null || true
  if kill -0 -- "$sig_target" 2>/dev/null; then
    kill -TERM -- "$sig_target" 2>/dev/null || true
    sleep 1
    kill -KILL -- "$sig_target" 2>/dev/null || true
  fi
  kill "$watchdog" 2>/dev/null || true
  wait "$watchdog" 2>/dev/null || true
  set +m
fi
# Reap the group before exit so the pidfile check above usually sees it
# gone — bounded, and the file is LEFT when the group cannot be confirmed
# dead: a pid+start-identity record a re-run can safely reap beats a missing
# lock next to a live vendor process.
if [ -n "$pgid" ]; then
  reap_begin=$SECONDS
  reap_previous=$SECONDS
  for ((reap_attempt=0; reap_attempt<100; reap_attempt++)); do
    kill -0 -- -"$pgid" 2>/dev/null || break
    if [ "$SECONDS" -lt "$reap_previous" ] || [ "$((SECONDS - reap_begin))" -ge 10 ]; then break; fi
    reap_previous=$SECONDS
    sleep 0.1 2>/dev/null || sleep 1
  done
fi
OPENLLM_VENDOR_JOB
)"
  local job_dir="$OPENLLM_DIR/cli-install"
  local spec name cmd dest url pidfile job_log launchfile
  # Legacy residue is held for explicit doctor clearance by the native helper.
  for spec in "${specs[@]}"; do
    IFS='|' read -r name cmd dest url <<<"$spec"
    # The spec stores $HOME literally (bash never re-expands inside a variable
    # value) — expand it here so a launcher at its default path counts as
    # installed even when it is not on PATH.
    case "$dest" in \$HOME/*) dest="$HOME/${dest#\$HOME/}" ;; esac
    if has_command "$cmd" || [ -x "$dest" ]; then
      echo "  $name CLI: already installed."
      # Mirror the skip into the log too — previously only the backgrounded
      # installer output landed there, so a skipped provider left the log
      # silent about why nothing was installed.
      echo "$name CLI: already installed ($(command -v "$cmd" 2>/dev/null || echo "$dest")) — skipping install." \
        >>"$OPENLLM_DIR/cli-install.log" 2>/dev/null || true
      continue
    fi
    if [ "$opt_in" = 0 ]; then
      # OPT-IN ONLY: never start a detached third-party installer unasked.
      echo "  $name CLI: not installed; run: curl --proto \"=https\" --proto-redir \"=https\" -fsSL $url | bash"
      VENDOR_MISSING_PRINTED=$((VENDOR_MISSING_PRINTED + 1))
      continue
    fi
    if [ -z "$curl_bin" ] || [ "$curl_bin_scheme_ok" = 0 ]; then
      echo "  $name CLI: not installed; run: curl --proto \"=https\" --proto-redir \"=https\" -fsSL $url | bash"
      VENDOR_MISSING_PRINTED=$((VENDOR_MISSING_PRINTED + 1))
      continue
    fi
    (umask 077 && mkdir -p "$job_dir") 2>/dev/null || true
    pidfile="$job_dir/$cmd.pid"
    job_log="$job_dir/$cmd.log"
    [ -x "$BIN_DIR/openllmd" ] || {
      echo "  $name CLI: native lock helper unavailable — skipping."
      continue
    }
    : > "$job_log" 2>/dev/null || true
    # The actual native launch helper publishes a complete tagged marker and
    # stays alive until the detached child commits its handoff. Older launch
    # evidence is a persistent legacy hold; the helper reports it without
    # age-based deletion.
    launchfile="$job_dir/$cmd.launch.v3"
    local launch_ready launch_helper_pid launch_nonce launch_reply launch_begin launch_previous launch_attempt
    launch_ready="$job_dir/$cmd.launch.v3.${BASHPID:-$$}.$RANDOM.ready"
    "$BIN_DIR/openllmd" --internal-lock-control launch "$launchfile" \
      "$LOCK_PARTICIPANTS" "$launch_ready" < /dev/null >>"$job_dir/$cmd.log" 2>&1 &
    launch_helper_pid=$!
    trap 'wait "$launch_helper_pid" 2>/dev/null || true; exit 129' HUP
    trap 'wait "$launch_helper_pid" 2>/dev/null || true; exit 130' INT
    trap 'wait "$launch_helper_pid" 2>/dev/null || true; exit 143' TERM
    launch_begin=$SECONDS
    launch_previous=$SECONDS
    for ((launch_attempt=0; launch_attempt<200; launch_attempt++)); do
      [ -f "$launch_ready" ] && break
      kill -0 "$launch_helper_pid" 2>/dev/null || break
      if [ "$SECONDS" -lt "$launch_previous" ] || [ "$((SECONDS - launch_begin))" -ge 10 ]; then break; fi
      launch_previous=$SECONDS
      sleep 0.05 2>/dev/null || sleep 1
    done
    launch_reply="$(cat "$launch_ready" 2>/dev/null || true)"
    launch_nonce="$(printf '%s\n' "$launch_reply" | sed -n 's/^{"version":3,"code":0,"nonce":"\([0-9a-f]\{32\}\)"}$/\1/p')"
    rm -f "$launch_ready" 2>/dev/null || true
    if [[ ! "$launch_nonce" =~ ^[0-9a-f]{32}$ ]]; then
      wait "$launch_helper_pid" 2>/dev/null || true
      trap - HUP INT TERM
      echo "  $name CLI: launch held or incomplete; preserving its marker and skipping."
      continue
    fi
    echo "  $name CLI: installing in the background (timeout ${job_timeout}s; log: $job_log)…"
    # The whole job is exec'd through `env -u` (SP-7/M3): no intermediate
    # process — wrapper, timeout or watchdog — ever holds the key, and the
    # awk log writer runs under `env -i`. Output is bounded DURING the run
    # by the awk writer: the first bytes (which show why an install failed)
    # are kept, the rest dropped — a noisy or TERM-ignoring vendor job
    # cannot grow the log without bound (RG-1).
    # The log writer's stdout AND stderr are redirected away from the
    # caller: an inherited stderr would keep `ssh … | bash`, `| tee` and CI
    # captures waiting on this detached process for the job's whole bound.
    env "${vendor_scrub[@]}" PATH="$run_path" \
      bash -c "$job_body" -- \
      "$pidfile" "$timeout_bin" "$job_timeout" "$curl_bin" "$url" "$setsid_bin" "$launchfile" \
      "$BIN_DIR/openllmd" "$launch_nonce" "$helper_wait" \
      2>&1 | env -i PATH="$run_path" awk -v cap="$log_cap" '
      truncated { next }
      kept + length($0) + 1 > cap {
        truncated = 1
        print "--- output truncated at " cap " bytes (job kept running) ---"
        next
      }
      { kept += length($0) + 1; print }
    ' >>"$job_log" 2>/dev/null &
    if wait "$launch_helper_pid"; then
      VENDOR_JOBS_STARTED=$((VENDOR_JOBS_STARTED + 1))
    else
      echo "  $name CLI: launch handoff is incomplete; preserving its evidence."
      echo "  $name CLI: stop older installers and workers, then rerun with --lock-participants=new-only."
    fi
    trap - HUP INT TERM
  done
  # The shared skip-note log is append-only across runs — keep only its tail
  # (RG-1: nothing under ~/.openllm may grow without bound).
  local shared_log="$OPENLLM_DIR/cli-install.log"
  if [ -f "$shared_log" ]; then
    ( tail -c 262144 "$shared_log" >"$shared_log.tmp" \
        && mv -f "$shared_log.tmp" "$shared_log" ) 2>/dev/null || true
    rm -f "$shared_log.tmp" 2>/dev/null || true
  fi
}
# `|| true` + the subshell/background jobs keep this off the `set -euo
# pipefail` path — a vendor install can never abort the daemon install.
# Skipped on a manual update: rerunning every vendor's installer is a
# first-install action the user didn't ask for. Also skipped ENTIRELY in
# --from-file local mode (NR2-3): a private-prerelease install must never
# touch the network — not even an opted-in vendor provisioning job.
VENDOR_JOBS_STARTED=0
VENDOR_MISSING_PRINTED=0
if [ "$INSTALL_MODE" != update ] && [ -z "$FROM_FILE" ]; then
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
EOF
  if [ "$VENDOR_JOBS_STARTED" -gt 0 ]; then
    cat <<EOF
Vendor CLIs are installing in the background (per-vendor logs and pidfiles in
~/.openllm/cli-install/). Open the dashboard's Providers tab to connect each
vendor once its CLI is ready.
EOF
  elif [ "$VENDOR_MISSING_PRINTED" -gt 0 ]; then
    cat <<EOF
Vendor CLIs were NOT auto-installed — run the printed one-line installers
yourself, or re-run with OPENLLM_INSTALL_VENDOR_CLIS=1 to let the installer
provision them. Then open the dashboard's Providers tab to connect each vendor.
EOF
  fi
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
