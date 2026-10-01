<p align="center">
  <picture>
    <source media="(prefers-color-scheme: light)" srcset="./assets/openllm-light.svg">
    <img alt="OpenLLM" src="./assets/openllm.svg" width="300">
  </picture>
</p>

<p align="center"><b>openllmd</b> — the local OpenLLM daemon.</p>

<p align="center">
  <a href="./LICENSE"><img alt="License: BUSL-1.1" src="https://img.shields.io/badge/license-BUSL--1.1-blue.svg"></a>
  <img alt="source-available" src="https://img.shields.io/badge/source-available-informational.svg">
  <img alt="stable targets" src="https://img.shields.io/badge/stable_targets-darwin%20%C2%B7%20linux%20(arm64%2Fx64)-lightgrey.svg">
</p>

---

> [!WARNING]
> **Beta software.** OpenLLM 2.8.0-beta.4 is a prerelease. It can contain bugs.
> Its behavior can change before the stable 2.8.0 release. The Windows build is
> not signed. For production use, install the stable release with the stable
> installer in this README.

The local service for OpenLLM's **subscription providers**. Requests run on your
machine through the vendors' official clients and their local credentials:

| Provider | Official client |
| --- | --- |
| `claude_code` | Claude Code (`claude`) |
| `chatgpt` | Codex (`codex`) |
| `kimi_code` | Kimi Code (`kimi`) |
| `grok` | Grok Build (`grok`) |
| `cursor` | Cursor Agent (`cursor-agent`) |

Subscription credentials stay on your machine, rather than being stored by the
hosted gateway. The daemon establishes an outbound control connection so the
dashboard can manage the device. API-key (BYOK) providers can run on the hosted
gateway; subscription requests require a reachable daemon with the relevant
provider connected.

The daemon does not import the cloud proxy pipeline. It shares the public
[protocol](https://github.com/openllmsh/protocol),
[wire transforms](https://github.com/openllmsh/wire), and
[tunnel transport](https://github.com/openllmsh/tunnel) packages, using Effect
and provider-specific dependencies locally.

## Install

Use the **shared installer**, which installs both **`openllmd` and the `openllm`
CLI** (also available as `ollm`):

```sh
curl -fsSL https://www.openllm.sh/install | bash
openllm version
openllm status
```

Stable releases support **macOS and Linux, arm64 and x64**.
Prereleases add an unsigned `win32-x64` build.
Published binaries are
compiled and SHA-256-verified during installation; Bun is not required to run
them. Vendor clients have their own requirements; follow the installer or
provider-connect guidance for any missing client.

### Preview install

The current preview is `v2.8.0-beta.4`. The installer script at the tag
installs only that tag. The preview also ships a `win32-x64` build
(unsigned; no PTY). A prerelease never moves `main` and never overwrites
an earlier prerelease's branch or tag. Do not use `openllm update` to
move a stable install to the preview.

#### Install the preview on macOS or Linux

1. Install the daemon and the CLI:

   ```sh
   curl -fsSL https://raw.githubusercontent.com/openllmsh/daemon/v2.8.0-beta.4/install.sh | bash
   ```

2. Check the version:

   ```sh
   openllm version
   ```

3. If credential setup did not run, start it:

   ```sh
   openllm start
   ```

Or download the script and name the tag yourself:
`bash install.sh --prerelease v2.8.0-beta.4`.

#### Install the preview on Windows (unsigned)

PowerShell:

```powershell
iex (irm https://raw.githubusercontent.com/openllmsh/daemon/v2.8.0-beta.4/install.ps1)
```

If PowerShell cannot find `openllm` after the install, open a new PowerShell
window. A window that was open before the install does not get the new PATH.

Command Prompt (CMD):

```bat
curl.exe -fsSLo install.cmd https://raw.githubusercontent.com/openllmsh/daemon/v2.8.0-beta.4/install.cmd
install.cmd
```

The CMD commands download `install.cmd` from the release tag and run it.

#### Go back to stable

On macOS and Linux:

```sh
~/.openllm/bin/openllmd stop
rm -f ~/.openllm/bin/openllmd ~/.openllm/bin/openllm
curl -fsSL https://www.openllm.sh/install | bash
```

The first command uses the full path. If the preview install did not
finish, `openllm` is not on your PATH. If `~/.openllm/bin/openllmd` does
not exist, no preview daemon is installed; skip that command.

The `rm` step removes only the preview binaries. Your settings in
`~/.openllm/.env` stay. The install step installs the stable daemon and
CLI. With a saved key, it starts the daemon again. Windows has no stable
release. Stable releases support macOS and Linux only.

A key is optional when you download the binaries. On macOS and Linux, the
installer can start credential setup in an interactive terminal.
If setup did not run on these platforms, continue with:

```sh
openllm start
```

For automation on macOS and Linux, provide `OPENLLM_API_KEY` in the installer's environment—not a
`--key` argument. For example, if the variable is already set in your shell:

```sh
curl -fsSL https://www.openllm.sh/install | OPENLLM_API_KEY="$OPENLLM_API_KEY" bash
```

On macOS and Linux, the installer saves shared configuration in
`~/.openllm/.env`. Set `OPENLLM_CLOUD_ORIGIN` as well to select a different
gateway. With a usable key, the installer starts the daemon.
A separate `openllmd start` is not normally needed on these platforms.
Service management uses launchd or systemd where supported.

On Windows, the beta.4 installer installs the binaries, alias and user PATH.
Native Windows credential entry is not available in this build.
The installer reports incomplete startup; it does not start the daemon.
The installer defers credential setup even in an interactive terminal.

> If the commands are not on PATH, run `~/.openllm/bin/openllm setup` and open a
> new terminal. Both binaries live under `~/.openllm/bin`.

Once the daemon is connected, configure subscription providers from the
OpenLLM dashboard and run a client, for example `openllm claude` or
`openllm codex`.

## Operate and update

Prefer `openllm` for full-product lifecycle and credential setup. `openllmd`
provides daemon-specific controls; every command accepts `-h` / `--help`.

| Command | What |
| --- | --- |
| `openllm start` / `restart` | Start/restart; on macOS and Linux, guide credential setup when needed |
| `openllmd start` / `stop` / `restart` | Manage the daemon service |
| `openllmd status` | Show daemon status |
| `openllmd logs` | Read daemon logs |
| `openllmd auto-update <on\|off\|status>` | Control daemon automatic updates (enabled by default) |
| `openllmd sessions` | Inspect/manage local sessions; use `--help` for subcommands |
| `openllmd completion <bash\|zsh\|fish\|install>` | Shell completion |
| `openllmd version` | Print the daemon version |
| `openllm update` | Update the **full product** from the configured gateway |
| `openllm self-update` | Update the CLI binary only—not the daemon |
| `openllm doctor` | Diagnostics; see `--help` for reporting preferences |
| `openllm uninstall` | Remove daemon + CLI |
| `openllmd uninstall` | Remove the daemon and its state, leaving the CLI installed |

Bare `openllmd` runs the foreground daemon process, as used by its service
manager. Do not launch a second foreground instance alongside the installed
service.

## Build from source

The public source mirror pins its shared packages to published GitHub refs;
the monorepo uses workspace dependencies instead. `main` tracks stable releases;
for a prerelease, check out its `v...` tag or its own bare-version branch
(for example `v2.8.0-beta.4` or `2.8.0-beta.4`)
before installing dependencies. From the public mirror:

```sh
git clone https://github.com/openllmsh/daemon
cd daemon
bun install
bun run compile:host        # → dist/openllmd (this machine's target)
./dist/openllmd version
bun run compile             # build the default targets for this host
```

The default build selects the four POSIX targets on Linux and macOS.
On Windows, it also selects `win32-x64`.
Windows targets require a native Windows host.

Bun is required for these build commands. Compiling does not install the service
or register credentials. Run `--help` on the resulting binary before using it;
normal installs should use the verified shared installer above.

## Verify

Published binaries are pinned by SHA-256 in [`manifest.ts`](./manifest.ts).
From a source checkout, compare downloaded or installed bytes to those pins:

```sh
bun install
bun run verify                          # every published target
bun run verify -- --host                # this machine's target
bun run verify -- --file ./openllmd      # a local binary
bun run verify -- --installed           # the openllmd on PATH
```

Exit code is `0` only when every checked binary matches its pinned digest. Use
the source revision carrying the pins for the release you intend to verify.

The binary is **not byte-reproducible**: `bun build --compile --bytecode` embeds
non-deterministic bytecode. A source rebuild will not hash-match the release.
These checks establish consistency with the committed release digest; they do
not eliminate the need to trust the release source and publisher.

## License

**Source-available** under the [Business Source License 1.1](./LICENSE)
(© OpenLLM, INC) — converts to MIT on the Change Date. Not OSI open-source.

---

> **Read-only mirror.** Regenerated from the OpenLLM monorepo each release.
> PRs welcome — ingested upstream with your authorship preserved. BUSL
> contributions require the CLA (the bot will prompt you).
