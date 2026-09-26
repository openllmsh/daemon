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
#   OPENLLM_DAEMON_PORT    local daemon port (default 8787)
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
DAEMON_PORT="${OPENLLM_DAEMON_PORT:-8787}"
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

# Replacement policy: the version advertised by /api/install is the release of
# record — an advertised PRERELEASE is installable, and a prerelease install may
# move to a newer stable (or newer prerelease). The only refusal left is a
# DOWNGRADE: an installed build strictly newer than the advertised release.
installed_version() {
  local binary="$1" output version probe_file pid watchdog status
  [ -x "$binary" ] || return 1
  probe_file="${TMPDIR:-/tmp}/openllmd-version-probe.$$"
  "$binary" --version >"$probe_file" 2>/dev/null &
  pid=$!
  (
    sleep 3 &
    local timer=$!
    trap 'kill "$timer" 2>/dev/null || true; exit 0' TERM INT
    wait "$timer"
    kill "$pid" 2>/dev/null || true
  ) &
  watchdog=$!
  if wait "$pid"; then status=0; else status=$?; fi
  kill -TERM "$watchdog" 2>/dev/null || true
  wait "$watchdog" 2>/dev/null || true
  output="$(cat "$probe_file" 2>/dev/null || true)"
  rm -f "$probe_file"
  [ "$status" -eq 0 ] \
    || die "version probe timed out or failed at $binary; refusing to overwrite it"
  if [[ "$output" =~ (^|[^[:alnum:].+_-])v?([0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?([+][0-9A-Za-z.-]+)?)([^[:alnum:].+-]|$) ]]; then
    version="${BASH_REMATCH[2]}"
  else
    die "could not parse installed version at $binary; refusing to overwrite it"
  fi
  INSTALLED_VERSION="$version"
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

# >>> openllm-env-lock/v1 (shared protocol — identical block in both >>>
# >>> installers; the SAME rules as packages/daemon/src/env.ts)        >>>
#
# The lock is the DIRECTORY "<envfile>.lock.d": `mkdir` is atomic on every
# POSIX filesystem (flock does not exist on macOS). Ownership is a record
# published atomically INSIDE the directory — written to `owner.tmp.$$`
# then renamed to `owner`:
#
#   kind=openllm-env-lock/v1 pid=<pid> start=<start identity> nonce=<hex>
#
# `start` is the owner's `ps -o lstart=` identity under LC_ALL=C TZ=UTC
# with whitespace collapsed to single spaces — the same value the daemon's
# `processStartIdentity` reads. It distinguishes a LIVE-but-reused pid from
# the real owner (PID reuse). `-` records an owner that could not read its
# own identity.
#
# A held lock is STALE only when its marked owner names a dead pid, or a
# live pid whose current start identity differs. A dir with no, unreadable
# or unmarked owner is HELD — the one exception is a dir older than the
# stale window that still has no complete owner (a holder killed between
# `mkdir` and publish), which may be reclaimed.
#
# Reclaim is an atomic `mv .lock.d .lock.stale.<pid>.<nonce>` — exactly one
# contender wins the rename. The winner re-reads the owner INSIDE the
# quarantine: if it turns out to be live after all it is moved back, but
# only when `.lock.d` still does not exist (no-replace); otherwise it stays
# quarantined. Acquisition is retried either way. Quarantine dirs older
# than the stale window are swept when their contents are only `owner.tmp.*`
# publish residue (or empty — the crash-between-mkdir-and-publish shape) or
# a complete marked owner record.
#
# Release is `mv .lock.d .lock.rel.<pid>.<nonce>` first, then the record's
# nonce is verified before deleting — a holder whose lock was stolen or
# replaced finds a successor's record and puts it back instead of deleting.
#
# The pre-dir `.env.lock` FILE is still honoured for one release: HELD
# while its recorded pid is alive or its content is unparseable. A dead-pid
# record is reclaimed ONLY by atomic rename to a unique quarantine name —
# the live path is never unlinked directly — then re-read there: a record
# that turns out to be live is put back with a no-replace link, never over
# a successor lock file.
ENV_LOCK_STALE_SECS="${OPENLLM_ENV_LOCK_STALE_SECS:-600}"
ENV_LOCK_WAIT_SECS="${OPENLLM_ENV_LOCK_WAIT_SECS:-10}"
# Same knob rule as the daemon: decimal digits AND > 0 — "0" or junk falls
# back to the defaults, never a zero-length window. Leading zeros are
# DECIMAL on the daemon side (Number("08") is 8) but invalid octal to
# [[ -gt ]]/$(( )) — canonicalise through 10# before the value is ever
# compared or added.
[[ "$ENV_LOCK_STALE_SECS" =~ ^[0-9]+$ ]] || ENV_LOCK_STALE_SECS=0
ENV_LOCK_STALE_SECS=$((10#$ENV_LOCK_STALE_SECS))
[ "$ENV_LOCK_STALE_SECS" -gt 0 ] || ENV_LOCK_STALE_SECS=600
[[ "$ENV_LOCK_WAIT_SECS" =~ ^[0-9]+$ ]] || ENV_LOCK_WAIT_SECS=0
ENV_LOCK_WAIT_SECS=$((10#$ENV_LOCK_WAIT_SECS))
[ "$ENV_LOCK_WAIT_SECS" -gt 0 ] || ENV_LOCK_WAIT_SECS=10
ENV_LOCK_DIR=""
ENV_LOCK_NONCE=""
ENV_LOCK_QSEQ=0
ENV_LOCK_OWNER_STATE="" ENV_LOCK_OWNER_PID=""
ENV_LOCK_OWNER_START="" ENV_LOCK_OWNER_NONCE=""

# Liveness check — `kill -0 0` would probe the CALLER'S own process group
# (and report it alive), so a non-positive or non-decimal pid is never
# probed. Same rule as the daemon: pids must be positive integers.
env_lock_pid_alive() {
  # "08" is invalid octal to [[ -gt ]] but decimal pid 8 to the daemon's
  # Number() — validate digits, convert through 10#, compare in decimal [ ].
  [[ "$1" =~ ^[0-9]+$ ]] || return 1
  local pid=$((10#$1))
  [ "$pid" -gt 0 ] && kill -0 "$pid" 2>/dev/null
}

# `ps -o lstart=` under the fixed locale/timezone the daemon's
# processStartIdentity uses, whitespace collapsed to single spaces.
env_lock_start_identity() {
  local out
  out="$(LC_ALL=C TZ=UTC ps -o lstart= -p "$1" 2>/dev/null)" || out=""
  out="$(printf '%s' "$out" | tr -s '[:space:]' ' ')"
  out="${out# }"
  out="${out% }"
  printf '%s' "$out"
}

# Read <dir>/owner into ENV_LOCK_OWNER_{STATE,PID,START,NONCE}. STATE is
# "marked" (a complete v1 record) or "unmarked" (missing, unreadable or
# foreign — including the crash-between-mkdir-and-publish shape). The field
# rules are IDENTICAL to the daemon's parser: digit pid, NON-EMPTY start,
# hex-only nonce; an unmarked record surfaces a pid only as a
# whitespace-bounded `pid=<digits>` token or a leading bare pid.
env_lock_read_owner() {
  local dir="$1" line rest
  ENV_LOCK_OWNER_STATE="unmarked"
  ENV_LOCK_OWNER_PID="" ENV_LOCK_OWNER_START="" ENV_LOCK_OWNER_NONCE=""
  line="$(cat "$dir/owner" 2>/dev/null || true)"
  # The daemon trims the record before parsing — same here, so
  # leading/trailing whitespace cannot split the verdicts.
  line="${line#"${line%%[![:space:]]*}"}"
  line="${line%"${line##*[![:space:]]}"}"
  case "$line" in
    kind=openllm-env-lock/v1\ pid=*\ start=*\ nonce=*)
      rest="${line#kind=openllm-env-lock/v1 pid=}"
      ENV_LOCK_OWNER_PID="${rest%% *}"
      ENV_LOCK_OWNER_START="${rest#* start=}"
      ENV_LOCK_OWNER_START="${ENV_LOCK_OWNER_START% nonce=*}"
      ENV_LOCK_OWNER_NONCE="${rest##* nonce=}"
      if [[ "$ENV_LOCK_OWNER_PID" =~ ^[0-9]+$ ]] \
        && [ -n "$ENV_LOCK_OWNER_START" ] \
        && [[ "$ENV_LOCK_OWNER_START" != *$'\n'* \
          && "$ENV_LOCK_OWNER_START" != *$'\r'* ]] \
        && [[ "$ENV_LOCK_OWNER_NONCE" =~ ^[0-9a-fA-F]+$ ]]; then
        # Canonicalise to base-10 ("08" is pid 8 — the daemon's Number()).
        ENV_LOCK_OWNER_PID=$((10#$ENV_LOCK_OWNER_PID))
        ENV_LOCK_OWNER_STATE="marked"
      fi
      ;;
  esac
  if [ "$ENV_LOCK_OWNER_STATE" != "marked" ]; then
    ENV_LOCK_OWNER_PID="" ENV_LOCK_OWNER_START="" ENV_LOCK_OWNER_NONCE=""
    if [[ "$line" =~ (^|[[:space:]])pid=([0-9]+)([[:space:]]|$) ]]; then
      ENV_LOCK_OWNER_PID="${BASH_REMATCH[2]}"
    elif [[ "$line" =~ ^([0-9]+)([[:space:]]|$) ]]; then
      ENV_LOCK_OWNER_PID="${BASH_REMATCH[1]}"
    fi
    # A non-positive pid is no pid (the daemon returns null for it, and
    # `kill -0 0` would probe the wrong target anyway). Canonicalise to
    # base-10 first so "08" is pid 8 exactly like the daemon's Number().
    if [ -n "$ENV_LOCK_OWNER_PID" ]; then
      ENV_LOCK_OWNER_PID=$((10#$ENV_LOCK_OWNER_PID))
      [ "$ENV_LOCK_OWNER_PID" -gt 0 ] || ENV_LOCK_OWNER_PID=""
    fi
  fi
}

env_lock_dir_age_secs() {
  local mtime now
  mtime="$(stat -c %Y "$1" 2>/dev/null || stat -f %m "$1" 2>/dev/null || true)"
  now="$(date +%s 2>/dev/null || true)"
  if [[ "$mtime" =~ ^[0-9]+$ && "$now" =~ ^[0-9]+$ ]]; then
    printf '%s\n' $((10#$now - 10#$mtime))
  else
    printf '%s\n' -1
  fi
}

# The ONE staleness predicate — identical rules on the daemon side.
# $1 = the lock dir (or a quarantined dir).
env_lock_is_stale_dir() {
  local dir="$1" current age
  env_lock_read_owner "$dir"
  if [ "$ENV_LOCK_OWNER_STATE" = "marked" ]; then
    env_lock_pid_alive "$ENV_LOCK_OWNER_PID" || return 0
    if [ "$ENV_LOCK_OWNER_START" = "-" ]; then
      # The start identity can never be proven ("-"): the lock is held only
      # inside the same bounded window an ownerless dir gets — past it a
      # live-but-unidentifiable pid no longer wedges the lock.
      age="$(env_lock_dir_age_secs "$dir")"
      { [ "$age" -ge 0 ] && [ "$age" -ge "$ENV_LOCK_STALE_SECS" ]; }
      return
    fi
    current="$(env_lock_start_identity "$ENV_LOCK_OWNER_PID")"
    # PID reuse is proven ONLY by a live-but-different identity; anything
    # unreadable keeps the lock held.
    [ -n "$current" ] && [ "$current" != "$ENV_LOCK_OWNER_START" ]
    return
  fi
  # Unmarked: HELD unless old AND still unclaimed — and never while a
  # parseable pid inside it is still alive.
  age="$(env_lock_dir_age_secs "$dir")"
  { [ "$age" -ge 0 ] && [ "$age" -ge "$ENV_LOCK_STALE_SECS" ]; } || return 1
  if [[ "$ENV_LOCK_OWNER_PID" =~ ^[0-9]+$ ]] && env_lock_pid_alive "$ENV_LOCK_OWNER_PID"; then
    return 1
  fi
  return 0
}

# Reclaim = `mv .lock.d .lock.stale.<pid>.<nonce>` — atomic; exactly one
# contender wins the rename. A re-read owner that turns out to be live is
# restored, but never over an existing `.lock.d` (no-replace).
env_lock_quarantine() {
  local lockdir="$1" stem="$2" q
  q="$stem.stale.$$.$ENV_LOCK_NONCE"
  mv "$lockdir" "$q" 2>/dev/null || return 0
  env_lock_is_stale_dir "$q" && return 0
  if [ ! -e "$lockdir" ] && [ ! -L "$lockdir" ]; then
    mv "$q" "$lockdir" 2>/dev/null || true
  fi
  return 0
}

# Delete old quarantine/release dirs whose contents are only `owner.tmp.*`
# publish residue (or EMPTY — a holder killed between mkdir and publish,
# then quarantined) or a complete marked owner record. Anything foreign is
# kept.
env_lock_sweep() {
  local stem="$1" entry child age ok has_owner
  for entry in "$stem".stale.* "$stem".rel.*; do
    [ -d "$entry" ] || continue
    age="$(env_lock_dir_age_secs "$entry")"
    { [ "$age" -ge 0 ] && [ "$age" -ge "$ENV_LOCK_STALE_SECS" ]; } || continue
    ok=1
    has_owner=0
    for child in "$entry"/*; do
      [ -e "$child" ] || continue
      case "${child##*/}" in
        owner) has_owner=1 ;;
        owner.tmp.*) ;;
        *) ok=0 ;;
      esac
    done
    [ "$ok" = 1 ] || continue
    if [ "$has_owner" = 1 ]; then
      env_lock_read_owner "$entry"
      [ "$ENV_LOCK_OWNER_STATE" = "marked" ] || continue
    fi
    for child in "$entry"/*; do rm -f "$child" 2>/dev/null || true; done
    rmdir "$entry" 2>/dev/null || true
  done
  return 0
}

# Adjudicate a legacy lock file ALREADY moved into quarantine: re-read the
# CAPTURED record (it may have been swapped between the caller's read and
# the rename). A live pid is restored NO-REPLACE — `ln` fails outright on an
# existing successor, and on filesystems without hardlinks a noclobber
# create (O_EXCL) carries the same guarantee where `mv`/rename would
# silently overwrite — but ONLY inside the bounded window: the record
# carries no provable start identity, so a live pid PAST the window is
# dropped like a dead one. A dead/unparseable record is deleted inside the
# quarantine, never on the live path. Returns 0 while the legacy path still
# blocks acquisition (a live record was found), 1 once clear.
env_lock_legacy_resolve() {
  local q="$1" legacy="$2" moved rest age
  moved=""
  read -r moved rest < "$q" 2>/dev/null || moved=""
  if [[ "$moved" =~ ^[0-9]+$ ]] && env_lock_pid_alive "$moved"; then
    age="$(env_lock_dir_age_secs "$q")"
    if [ "$age" -lt 0 ] || [ "$age" -lt "$ENV_LOCK_STALE_SECS" ]; then
      if ln "$q" "$legacy" 2>/dev/null; then
        rm -f "$q" 2>/dev/null || true
      elif (set -C; cat "$q" > "$legacy") 2>/dev/null; then
        rm -f "$q" 2>/dev/null || true
      elif [ -e "$legacy" ] || [ -L "$legacy" ]; then
        # A successor holds the path — the captured copy is obsolete.
        rm -f "$q" 2>/dev/null || true
      fi
      return 0
    fi
  fi
  rm -f "$q" 2>/dev/null || true
  return 1
}

# The legacy pre-dir `.env.lock` FILE: the record can never prove its
# owner's start identity, so it is HELD only inside the bounded reclaim
# window — while a recorded pid is alive or its content is unparseable —
# and reclaimed past the window even on a live pid. Reclaim is ONLY an
# atomic rename to a unique quarantine name — never an unlink of the live
# path — then {@link env_lock_legacy_resolve} re-reads the captured file.
# Returns 0 while it still blocks acquisition, 1 once clear.
env_lock_legacy_held() {
  local legacy="$1" lpid rest q attempt=0 age
  while [ -f "$legacy" ]; do
    attempt=$((attempt + 1))
    [ "$attempt" -gt 4 ] && return 0
    lpid=""
    read -r lpid rest < "$legacy" 2>/dev/null || lpid=""
    if [[ "$lpid" =~ ^[0-9]+$ ]] && ! env_lock_pid_alive "$lpid"; then
      : # a proven-dead pid is reclaimed regardless of the lock's age
    else
      # A live pid — or a record that cannot be parsed at all — can never
      # prove the owner's start identity, so the lock is held ONLY inside
      # the bounded reclaim window (an unreadable age stays held); past it
      # we reclaim below like any stale dir.
      age="$(env_lock_dir_age_secs "$legacy")"
      if [ "$age" -lt 0 ] || [ "$age" -lt "$ENV_LOCK_STALE_SECS" ]; then
        return 0
      fi
    fi
    # Reclaimable (dead pid, or a record past the bounded window): move the
    # file aside atomically — exactly one contender wins — then adjudicate
    # the CAPTURED record before deleting anything.
    ENV_LOCK_QSEQ=$((ENV_LOCK_QSEQ + 1))
    q="$legacy.stale.$$.$ENV_LOCK_NONCE.$ENV_LOCK_QSEQ"
    mv "$legacy" "$q" 2>/dev/null || continue
    env_lock_legacy_resolve "$q" "$legacy" && return 0
    # Verified dead and deleted — loop and re-check for a successor file.
  done
  return 1
}

# Publish OUR owner record inside the just-mkdir'd lock dir — NO-REPLACE:
# a publisher paused between the mkdir and here may have been quarantined
# and its path re-taken by a successor, and `mv` would silently stamp over
# the successor's record. `ln` fails outright on an existing owner; the
# noclobber create carries the same guarantee where hardlinks do not work.
# rc 0 = published AND the live record still carries OUR nonce (the dir may
# be swapped even after a successful link — verify before believing the
# lock is held); 1 = did not acquire, the caller retries from the top;
# 2 = the tmp write itself failed, the caller drops its own dir.
env_lock_publish_owner() {
  local lockdir="$1" start
  start="$(env_lock_start_identity "$$")"
  [ -n "$start" ] || start="-"
  printf 'kind=openllm-env-lock/v1 pid=%s start=%s nonce=%s\n' \
    "$$" "$start" "$ENV_LOCK_NONCE" > "$lockdir/owner.tmp.$$" 2>/dev/null \
    || return 2
  if ln "$lockdir/owner.tmp.$$" "$lockdir/owner" 2>/dev/null \
    || (set -C; cat "$lockdir/owner.tmp.$$" > "$lockdir/owner") 2>/dev/null; then
    rm -f "$lockdir/owner.tmp.$$" 2>/dev/null
    env_lock_read_owner "$lockdir"
    [ "$ENV_LOCK_OWNER_STATE" = "marked" ] \
      && [ "$ENV_LOCK_OWNER_NONCE" = "$ENV_LOCK_NONCE" ]
    return
  fi
  rm -f "$lockdir/owner.tmp.$$" 2>/dev/null
  return 1
}

# Acquire `<envfile>.lock.d` and publish our marked owner record. On
# success sets ENV_LOCK_DIR + ENV_LOCK_NONCE (env_lock_release consumes
# them) and returns 0.
env_lock_acquire() {
  local envfile="$1" stem lockdir deadline attempts pub_rc
  stem="$envfile.lock"
  lockdir="$stem.d"
  deadline=$((SECONDS + ENV_LOCK_WAIT_SECS))
  ENV_LOCK_NONCE="$(printf '%x%x%x' "$$" "$RANDOM" "$(date +%s 2>/dev/null || echo 0)")"
  attempts=0
  # Bounded cleanup once per acquire so quarantined residue cannot linger
  # until the next contested acquire (identical trigger in the daemon).
  env_lock_sweep "$stem"
  while [ "$SECONDS" -lt "$deadline" ]; do
    if ! env_lock_legacy_held "$stem"; then
      if mkdir "$lockdir" 2>/dev/null; then
        env_lock_publish_owner "$lockdir"
        pub_rc=$?
        if [ "$pub_rc" = 0 ]; then
          ENV_LOCK_DIR="$lockdir"
          return 0
        elif [ "$pub_rc" = 2 ]; then
          # The tmp write failed — drop the dir WE made rather than hold it
          # unmarked.
          rm -f "$lockdir/owner.tmp.$$" 2>/dev/null
          rmdir "$lockdir" 2>/dev/null || true
          return 1
        fi
        # pub_rc=1 — a successor owns the dir at this path (or it was
        # swapped mid-publish): NOT ours to remove. Fall through to the
        # staleness pass and retry acquisition from the top.
      fi
      attempts=$((attempts + 1))
      [ $((attempts % 25)) -eq 0 ] && env_lock_sweep "$stem"
      if env_lock_is_stale_dir "$lockdir"; then
        env_lock_quarantine "$lockdir" "$stem"
      fi
    fi
    sleep 0.01 2>/dev/null || sleep 1
  done
  return 1
}

# Release OUR lock: move `.lock.d` to `.lock.rel.<pid>.<nonce>` first, then
# delete only when the owner record inside is provably ours — a stolen or
# replaced lock holds a successor's record, which is put back (no-replace)
# instead of deleted.
env_lock_release() {
  local lockdir="${ENV_LOCK_DIR:-}" stem rel
  [ -n "$lockdir" ] || return 0
  ENV_LOCK_DIR=""
  stem="${lockdir%.d}"
  rel="$stem.rel.$$.$ENV_LOCK_NONCE"
  if mv "$lockdir" "$rel" 2>/dev/null; then
    env_lock_read_owner "$rel"
    if [ "$ENV_LOCK_OWNER_STATE" = "marked" ] && [ "$ENV_LOCK_OWNER_NONCE" = "$ENV_LOCK_NONCE" ]; then
      local child
      for child in "$rel"/*; do rm -f "$child" 2>/dev/null || true; done
      rmdir "$rel" 2>/dev/null || true
    elif [ ! -e "$lockdir" ] && [ ! -L "$lockdir" ]; then
      mv "$rel" "$lockdir" 2>/dev/null || true
    fi
  fi
  return 0
}
# <<< openllm-env-lock/v1 <<<

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

# Read one KEY's value from the shared env file (first match wins), trimming
# whitespace and one layer of surrounding quotes so it matches how the CLI and
# daemon parse the same file (packages/cli/src/env.ts). Used only to seed the
# effective origin below; empty/absent → empty string.
env_file_value() {
  local wanted="$1" line key value
  [ -f "$ENV_FILE" ] || return 0
  while IFS= read -r line || [ -n "$line" ]; do
    case "$line" in ""|\#*) continue ;; esac
    key="${line%%=*}"
    [ "$key" = "$wanted" ] || continue
    value="$(trim_whitespace "${line#*=}")"
    value="${value#[\"\']}"
    value="${value%[\"\']}"
    printf '%s' "$value"
    return 0
  done < "$ENV_FILE"
  return 0
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
# --proto/--proto-redir need a curl new enough to know the options (≈7.21):
# an older system curl fails the FIRST fetch with an opaque option error, so
# detect support once and fail with the upgrade remedy up front.
curl "${CURL_SCHEME[@]}" -V >/dev/null 2>&1 \
  || die "this curl does not support --proto/--proto-redir — upgrade to curl 7.21.0 or newer and re-run"
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

# --- the ONE install entry point ------------------------------------------
# /api/install validates the committed daemon + CLI release pins in TypeScript
# (allow-listed repo, well-formed digests, a published tag for this target) and
# fails closed. Hitting it first means a mis-pinned or half-published release is
# refused BEFORE we download anything. No query parameters.
echo "Resolving the current OpenLLM release..."
MANIFEST="$(curl "${CURL_SCHEME[@]}" -fsSL "$ORIGIN/api/install" 2>/dev/null)" \
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

mkdir -p "$BIN_DIR" "$(dirname "$ENV_FILE")"

# --- fetch + verify + install one component -------------------------------
# Bytes come from the per-component binary routes, which 302 to the pinned
# GitHub release asset and serve the committed digest as a `.sha256` sibling —
# the same pair the daemon's own self-update verifies against.
install_component() {
  local name="$1" route="$2" version="$3"
  local dest="$BIN_DIR/$name"
  local url="$ORIGIN/$route/$TARGET"
  local published installed stamp="$BIN_DIR/.$name.sha256.stamp"

  published="$(curl "${CURL_SCHEME[@]}" -fsSL "$url.sha256" 2>/dev/null | cut -d' ' -f1 || true)"
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
  # The download+verify+swap runs in a SUBSHELL: its EXIT trap (temp-file
  # cleanup) is scoped there and is never installed on the main shell — so it
  # can neither replace an outer EXIT trap nor erase one with `trap - EXIT`
  # (the generated dist installer relies on its staging cleanup surviving our
  # exit on EVERY path, including a die here).
  (
    trap 'rm -f "$dl" "$bin"' EXIT
    if [ -t 2 ]; then
      curl "${CURL_SCHEME[@]}" -fL --progress-bar "$url" -o "$dl" || die "download failed: $url"
    else
      curl "${CURL_SCHEME[@]}" -fsSL "$url" -o "$dl" || die "download failed: $url"
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
    # a true downgrade (a newer installed build over the advertised one).
    if installed_version "$dest"; then
      installed="$INSTALLED_VERSION"
      [ "$(semver_cmp "$installed" "$version")" != "1" ] \
        || die "installed $name is $installed, newer than the advertised release $version — refusing to downgrade.
  To force the advertised version, remove $dest and re-run this installer."
    fi
    mv -f "$bin" "$dest"
  ) || exit 1
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

# The native PTY backend is compiled into the daemon binary in v2.8 (G1), so
# there is no third component to install.

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
  # The lock is the `<envfile>.lock.d` DIRECTORY of the shared
  # openllm-env-lock/v1 protocol above — the same protocol the daemon's
  # withEnvFileLock (packages/daemon/src/env.ts) and the CLI installer
  # implement, so a crashed holder is recovered (dead or reused pid owner,
  # or a >10-min ownerless publish) instead of wedging every later install
  # on "could not acquire config lock" — while a live holder's lock can
  # never be stolen or deleted mid-write.
  env_lock_acquire "$ENV_FILE" \
    || die "could not acquire config lock: $ENV_FILE.lock.d (remove it manually if no installer or daemon is running)"

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
  # EXIT trap still cleans up the temp file + lock on that die.
  mv -f "$tmp" "$ENV_FILE" || die "could not write config file: $ENV_FILE"
  chmod 0600 "$ENV_FILE"
  umask "$saved_umask"
  env_lock_release
  # The ONLY stdout line: the resolved key — the caller captures it as API_KEY.
  printf '%s' "$desired_key"
}

# The whole write runs inside command substitution: the EXIT/INT/TERM traps
# write_env_file installs are scoped to that subshell and cannot replace an
# outer EXIT trap — the generated dist installer relies on its staging cleanup
# surviving ANY exit of ours, including a die while the lock is held.
API_KEY="$(write_env_file)" || exit 1
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
  # $6 setsid_bin  $7 launchfile
  local job_body
  job_body="$(cat <<'OPENLLM_VENDOR_JOB'
pidfile="$1"; timeout_bin="$2"; job_timeout="$3"; curl_bin="$4"; url="$5"; setsid_bin="$6"; launchfile="$7"
# The pidfile holds "<job leader pid> <start identity>" so a re-run can tell
# a live job from a stale — or PID-REUSED — owner (same lstart identity the
# env-file lock uses). It is published ATOMICALLY (temp + no-replace ln) only now that
# the job's real identity is known — the parent's fresh launch marker covers
# the spawn-to-publish gap, so a second installer sees "launch in progress"
# rather than a dead placeholder. The marker is dropped once the pidfile is
# up; the pidfile itself is removed only after the whole process group is
# CONFIRMED gone (the EXIT trap below re-probes after the reap poll — and
# NEVER when the pgid is unknown, e.g. the timeout branch or a ps failure:
# an unverifiable group leaves the pid+start record for a re-run to reap).
job_start="$(LC_ALL=C TZ=UTC ps -o lstart= -p $$ 2>/dev/null | tr -s '[:space:]' ' ')"
job_start="${job_start# }"; job_start="${job_start% }"
# "<pid> <start>" record → live? (pid alive and, when both are known, the
# recorded start identity still matches — a reused pid is not the owner).
job_owner_live() {
  local p="${1%% *}" s="${1#* }" now
  [[ "$p" =~ ^[0-9]+$ ]] || return 1
  kill -0 "$p" 2>/dev/null || return 1
  if [ "$s" = "$1" ] || [ -z "$s" ] || [ "$s" = "-" ]; then return 0; fi
  now="$(LC_ALL=C TZ=UTC ps -o lstart= -p "$p" 2>/dev/null | tr -s '[:space:]' ' ')"
  now="${now# }"; now="${now% }"
  [ -z "$now" ] || [ "$now" = "$s" ]
}
myrec="$$ ${job_start:--}"
pidtmp="$pidfile.tmp.$$"
published=0
# The pidfile IS the mutex: publish it NO-REPLACE (`ln` never overwrites), so
# a job paused before publishing can never stamp over a successor's live
# record. A dead leftover is moved aside, re-read (it must still be the record
# judged dead — otherwise a live owner published in between and it goes
# straight back, no-replace), then deleted and the link retried.
if printf '%s\n' "$myrec" > "$pidtmp" 2>/dev/null; then
  for _try in 1 2 3; do
    if ln "$pidtmp" "$pidfile" 2>/dev/null; then published=1; break; fi
    seen="$(cat "$pidfile" 2>/dev/null || true)"
    [ -n "$seen" ] || continue
    job_owner_live "$seen" && break
    q="$pidfile.tmp.$$.s$_try"
    mv "$pidfile" "$q" 2>/dev/null || continue
    if [ "$(cat "$q" 2>/dev/null || true)" != "$seen" ]; then
      ln "$q" "$pidfile" 2>/dev/null || true
      rm -f "$q" 2>/dev/null || true
      break
    fi
    rm -f "$q" 2>/dev/null || true
  done
fi
rm -f "$pidtmp" "$launchfile" 2>/dev/null || true
# Not published → another live job owns this vendor install. Never run a
# duplicate.
[ "$published" = 1 ] || exit 0
# The pidfile is removed only when it is still OURS and the process group is
# CONFIRMED gone — never when the pgid is unknown (timeout branch, ps
# failure): an unverifiable group leaves the pid+start record for a re-run.
trap 'if [ -n "${pgid:-}" ] && ! kill -0 -- -"$pgid" 2>/dev/null \
  && [ "$(cat "$pidfile" 2>/dev/null || true)" = "$myrec" ]; then
  rm -f "$pidfile" 2>/dev/null || true
fi' EXIT
pipeline='"$0" --proto "=https" --proto-redir "=https" --connect-timeout 10 --max-time 300 -fsSL "$1" | bash'
pgid=""
if [ -n "$timeout_bin" ]; then
  # GNU timeout runs the command as its own process-group leader and signals
  # the GROUP — the `bash -c` wrapper AND the curl|bash pipeline it spawns —
  # when the deadline hits.
  "$timeout_bin" -k 15 "$job_timeout" bash -c "$pipeline" "$curl_bin" "$url"
elif [ -n "$setsid_bin" ]; then
  # setsid(1) starts the pipeline as its own session + process-group leader,
  # so the leader pid IS the pgid — `$!` after the pipeline would NOT be it.
  "$setsid_bin" bash -c "$pipeline" "$curl_bin" "$url" &
  leader=$!
  pgid="$leader"
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
  bash -c "$pipeline" "$curl_bin" "$url" &
  leader=$!
  pgid="$(ps -o pgid= -p "$leader" 2>/dev/null | tr -d ' ')"
  [[ "$pgid" =~ ^[0-9]+$ ]] || pgid=""
  # Under `set -m` a background job leads its own group, so its pgid is the
  # leader pid. When ps cannot report it, confirm that with the kernel (a
  # group with that id exists) rather than assume it — then the whole
  # pipeline is still signalled and reaped as one group.
  if [ -z "$pgid" ] && kill -0 -- -"$leader" 2>/dev/null; then
    pgid="$leader"
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
  reap_deadline=$((SECONDS + 10))
  while kill -0 -- -"$pgid" 2>/dev/null && [ "$SECONDS" -lt "$reap_deadline" ]; do
    sleep 0.1 2>/dev/null || sleep 1
  done
fi
OPENLLM_VENDOR_JOB
)"
  local job_dir="$OPENLLM_DIR/cli-install"
  local spec name cmd dest url pidfile job_log launchfile launch_age in_progress owner owner_pid owner_start owner_live owner_start_now self_start
  self_start="$(env_lock_start_identity "$$")"
  [ -n "$self_start" ] || self_start="-"
  # Publish residue: a job SIGKILLed between the pidfile tmp write and the
  # mv leaves `<cmd>.pid.tmp.<pid>` behind — bounded growth across repeated
  # crashes. Sweep only files past the bounded window whose embedded pid is
  # DEAD; a fresh or live-owned tmp may be mid-publish.
  local residue residue_pid residue_age
  for residue in "$job_dir"/*.pid.tmp.*; do
    [ -f "$residue" ] || continue
    residue_pid="${residue##*.pid.tmp.}"
    residue_pid="${residue_pid%%.*}"
    [[ "$residue_pid" =~ ^[0-9]+$ ]] || continue
    env_lock_pid_alive "$residue_pid" && continue
    residue_age="$(env_lock_dir_age_secs "$residue")"
    { [ "$residue_age" -ge 0 ] \
      && [ "$residue_age" -ge "$job_launch_grace" ]; } || continue
    rm -f "$residue" 2>/dev/null || true
  done
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
    mkdir -p "$job_dir" 2>/dev/null || true
    pidfile="$job_dir/$cmd.pid"
    job_log="$job_dir/$cmd.log"
    launchfile="$job_dir/$cmd.launch"
    # Duplicate suppression across re-runs (LEAK-3). Two artifacts, never a
    # parent-written placeholder pidfile: the LAUNCH marker is created
    # O_EXCL here before the job is spawned, and the JOB publishes the
    # pidfile itself (temp + no-replace ln) once its real "<pid> <start identity>" is
    # known. A live pidfile owner (PID-reuse-safe via the same lstart check
    # as the env-file lock) or a launch marker with a LIVE launcher means
    # "in progress" — covering the spawn-to-publish gap where the first
    # installer may already have exited; stale leftovers are reclaimed.
    owner="$(cat "$pidfile" 2>/dev/null || true)"
    owner_pid="${owner%% *}"
    owner_start="${owner#* }"
    [ "$owner_start" = "$owner" ] && owner_start=""
    owner_live=0
    if [[ "$owner_pid" =~ ^[0-9]+$ ]] && env_lock_pid_alive "$owner_pid"; then
      owner_live=1
      if [ -n "$owner_start" ] && [ "$owner_start" != "-" ]; then
        owner_start_now="$(env_lock_start_identity "$owner_pid")"
        if [ -n "$owner_start_now" ] && [ "$owner_start_now" != "$owner_start" ]; then
          owner_live=0
        fi
      fi
    fi
    in_progress=0
    if [ "$owner_live" = 1 ]; then
      in_progress=1
    elif [ -f "$launchfile" ]; then
      # The marker records the LAUNCHING installer's "<pid> <start
      # identity>" (same grammar as the pidfile). A live launcher means a
      # job is mid-spawn — even PAST the grace window — so age alone never
      # reclaims a marker; a stalled-but-alive installer is still
      # launching. The marker may be deleted only when the launcher is
      # proven dead (pid dead, or pid reused = recorded start vs a
      # successfully-read current identity) AND the job pidfile is absent.
      # Unreadable marker content falls back to the bounded age cap as a
      # last resort.
      owner="$(cat "$launchfile" 2>/dev/null || true)"
      owner_pid="${owner%% *}"
      owner_start="${owner#* }"
      [ "$owner_start" = "$owner" ] && owner_start=""
      if [[ "$owner_pid" =~ ^[0-9]+$ ]]; then
        owner_live=0
        if env_lock_pid_alive "$owner_pid"; then
          owner_live=1
          if [ -n "$owner_start" ] && [ "$owner_start" != "-" ]; then
            owner_start_now="$(env_lock_start_identity "$owner_pid")"
            if [ -n "$owner_start_now" ] && [ "$owner_start_now" != "$owner_start" ]; then
              owner_live=0
            fi
          fi
        fi
        if [ "$owner_live" = 1 ]; then
          in_progress=1
        else
          # Launcher proven dead — drop the marker only. A leftover pidfile
          # is never deleted here (a job may publish between this check and
          # an rm); the next job's no-replace publish adjudicates it.
          rm -f "$launchfile" 2>/dev/null || true
        fi
      else
        launch_age="$(env_lock_dir_age_secs "$launchfile")"
        if [ "$launch_age" -ge 0 ] && [ "$launch_age" -lt "$job_launch_grace" ]; then
          in_progress=1
        else
          rm -f "$launchfile" 2>/dev/null || true
        fi
      fi
    fi
    if [ "$in_progress" = 1 ]; then
      echo "  $name CLI: install already in progress — skipping."
      continue
    fi
    if ! (set -C; printf '%s %s\n' "$$" "$self_start" > "$launchfile") 2>/dev/null; then
      echo "  $name CLI: install already in progress — skipping."
      continue
    fi
    echo "  $name CLI: installing in the background (timeout ${job_timeout}s; log: $job_log)…"
    : > "$job_log" 2>/dev/null || true
    # The whole job is exec'd through `env -u` (SP-7/M3): no intermediate
    # process — wrapper, timeout or watchdog — ever holds the key, and the
    # awk log writer runs under `env -i`. Output is bounded DURING the run
    # by the awk writer: the first bytes (which show why an install failed)
    # are kept, the rest dropped — a noisy or TERM-ignoring vendor job
    # cannot grow the log without bound (RG-1).
    env "${vendor_scrub[@]}" PATH="$run_path" \
      bash -c "$job_body" -- \
      "$pidfile" "$timeout_bin" "$job_timeout" "$curl_bin" "$url" "$setsid_bin" "$launchfile" \
      2>&1 | env -i PATH="$run_path" awk -v cap="$log_cap" '
      truncated { next }
      kept + length($0) + 1 > cap {
        truncated = 1
        print "--- output truncated at " cap " bytes (job kept running) ---"
        next
      }
      { kept += length($0) + 1; print }
    ' >>"$job_log" &
    VENDOR_JOBS_STARTED=$((VENDOR_JOBS_STARTED + 1))
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
# first-install action the user didn't ask for.
VENDOR_JOBS_STARTED=0
VENDOR_MISSING_PRINTED=0
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
