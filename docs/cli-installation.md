# CLI installation

[Back to the overview](../README.md). Commands below run from the repository root unless stated otherwise.

## Install the CLI

Choose **one** installation method. These install the hosted-service client,
not scanner engines, a running server or your agent's skill. For the independent
local `scan` / `source-scan` commands, use the [local engine](../README.md#quick-start-local-dependency-analysis)
instead. Both CLIs use the name `offense`; avoid installing them over each other.

### Homebrew — macOS and Linux

Use the public repository as a custom tap; the explicit Git URL is required:

```sh
brew tap offense-research/offense https://github.com/offense-research/offense.git
brew install offense-research/offense/offense
offense --version
offense --help
```

The [formula](../Formula/offense.rb) installs the bundled CLI from the **versioned,
SHA-256-checked [CLI 0.2.0 release](https://github.com/offense-research/offense/releases/tag/cli-v0.2.0)**
and brings its own Homebrew Node dependency.
It does not run npm install scripts or download scanner images. This is a project
tap, not a formula in Homebrew/core. Review the tap before installing it.

### Stable GitHub release — Node.js 20+

Download `offense-cli-0.2.0.tgz` and `SHA256SUMS` from the
[release page](https://github.com/offense-research/offense/releases/tag/cli-v0.2.0).
In the download directory, verify the checksum before installing:

```sh
shasum -a 256 -c SHA256SUMS
# On Linux, sha256sum --check SHA256SUMS is also supported.
npm install --global ./offense-cli-0.2.0.tgz
offense --version
```

Continue only if verification reports `offense-cli-0.2.0.tgz: OK`. This installs
the GitHub release archive, not a package from the npm registry. Homebrew performs
the checksum check automatically. The hosted-download commands below use a
separate, mutable channel and may install an older version.

### Ubuntu and Arch Linux

Install Node and npm using the instructions for your distribution, then run the
shared Offense install below. If you already have **Node.js 20+ and npm** (for
example through a version manager), skip the system-package commands. Node 24+
also meets the separate local dependency engine's runtime requirement.

**Ubuntu 22.04 / 24.04 — Node.js 24 via NodeSource (amd64 or arm64):**

Ubuntu's default `nodejs` package can be too old for this CLI. The following
[NodeSource instructions](https://github.com/nodesource/distributions/wiki/Repository-Manual-Installation)
add a third-party signed apt repository and install Node system-wide, including
npm. Review that trust decision first. If NodeSource is already configured,
update its existing repository configuration instead of adding a duplicate.

```sh
sudo apt-get update
sudo apt-get install -y ca-certificates curl gnupg
sudo install -d -m 755 /etc/apt/keyrings
curl -fsSL https://deb.nodesource.com/gpgkey/nodesource-repo.gpg.key \
  | sudo gpg --dearmor -o /etc/apt/keyrings/nodesource.gpg
sudo chmod 644 /etc/apt/keyrings/nodesource.gpg
printf '%s\n' \
  'Types: deb' \
  'URIs: https://deb.nodesource.com/node_24.x/' \
  'Suites: nodistro' \
  'Components: main' \
  "Architectures: $(dpkg --print-architecture)" \
  'Signed-By: /etc/apt/keyrings/nodesource.gpg' \
  | sudo tee /etc/apt/sources.list.d/nodesource.sources >/dev/null
sudo apt-get update
sudo apt-get install -y nodejs
node --version
npm --version
```

**Arch Linux — official Node.js and npm packages:**

This performs a full system upgrade as well as installing the prerequisites;
Arch does not support partial upgrades. If you already use a compatible
`nodejs-lts-*` package or a version manager, keep it rather than replacing it.

```sh
sudo pacman -Syu --needed nodejs npm
node --version
npm --version
```

**Install Offense on either distribution, without `sudo npm`:**

```sh
npm install --global --prefix "$HOME/.local" --ignore-scripts \
  https://offense.sh/downloads/offense-cli.tgz
export PATH="$HOME/.local/bin:$PATH"
offense --version
offense --help
```

Add `export PATH="$HOME/.local/bin:$PATH"` to your `~/.bashrc` or `~/.zshrc` once
to keep the command available in new terminals. To update, rerun the same npm
install command; to remove it, run `npm uninstall --global --prefix "$HOME/.local"
@offense-security/cli`. This uses the mutable hosted download described below,
not a native `.deb`, Arch package or AUR package. Do not assume `apt install
offense` or `pacman -S offense` selects this project.

### npx / npm exec — run without a global install

With **Node.js 20+** and npm installed:

```sh
npx --yes --package=https://offense.sh/downloads/offense-cli.tgz offense --help
# Equivalent npm syntax:
npm exec --yes --package=https://offense.sh/downloads/offense-cli.tgz -- offense --help
```

Replace `--help` with the desired CLI arguments on subsequent runs. `npx` caches
the downloaded package; “no global install” does not mean no files are downloaded.
`--yes` accepts npm's installation prompt, not authorization to upload or spend.

### npm — install the command globally

```sh
npm install --global https://offense.sh/downloads/offense-cli.tgz
offense --version
offense --help
```

Use a user-owned Node installation rather than adding `sudo`. On Windows, npm
creates an `offense` command shim; use WSL for workflows requiring Linux tools.

### pnpm or Bun — one-off execution

With pnpm or Bun already installed, choose either command. Keep Node.js 20+
available: the CLI's executable uses Node, including when launched by Bun.

```sh
pnpm --package=@offense-security/cli@https://offense.sh/downloads/offense-cli.tgz dlx offense --help
bunx --package https://offense.sh/downloads/offense-cli.tgz offense --help
```

**Hosted download versus stable release:** these npm/npx/pnpm/Bun commands use the existing
hosted archive, not an npm registry release. At verification on 2026-10-30 the
archive was **0.1.0**, while Homebrew and the GitHub release install **0.2.0**.
The hosted URL can change independently of this repository; check `--version`
and `--help` before relying on a command. Do not assume `npx offense` or
`npm install -g offense` refers to this project. No npm registry package is
published by these instructions.

### From a reviewed checkout — no package manager install

With Git and Node.js 20+:

```sh
git clone https://github.com/offense-research/offense.git
cd offense
node public/skills/offense/scripts/cli.mjs --version
node public/skills/offense/scripts/cli.mjs --help
```

The bundle already includes its dependencies. No root `npm ci` is necessary for
this client. Pin your checkout to a reviewed commit for reproducible automation;
keep the checkout accessible and invoke the bundle by absolute path from agents.

### After installation

`--help` and `--version` need no account and do not submit scans. When you choose
to connect to the hosted service, run `offense login` (or replace `offense` with
your one-off runner), approve the browser login, and inspect `offense tools`.
For a self-hosted service, set `OFFENSE_API_URL` before logging in. Authentication
does not authorize paid calls: preview inputs, inspect a quote and approve a
spending ceiling before submission. Install the [Agent Skill](../README.md#install-the-offensesh-agent-skill)
separately to teach your agent this workflow.

To update Homebrew, run `brew update` then `brew upgrade offense-research/offense/offense`.
The release formula has Homebrew revision 1 so users of the earlier source-pinned
0.2.0 formula receive the published archive too; `offense --version` stays 0.2.0.
For a global npm install, rerun its URL-based install command; `npm update` is not
a promise to refresh a mutable download URL. Remove with
`brew uninstall offense-research/offense/offense` or
`npm uninstall --global @offense-security/cli`, respectively. Uninstalling the
executable does not revoke credentials: use `offense logout` to remove local
credentials and revoke the server key in your account when appropriate.
