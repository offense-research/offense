# Contributing to Offense

Start with a small change you can explain and verify. Documentation improvements,
reproducible bug fixes, and synthetic test fixtures are all useful contributions.

## Choose your first contribution

| If you want to… | Start here | A useful first change |
| --- | --- | --- |
| Improve documentation | [README](README.md) and [docs](docs/) | Clarify a setup step you found confusing or fix an example against the current commands. |
| Fix the app or API | `src/`, `server/`, `shared/`, and `test/` | Reproduce a small bug, add a regression test, and fix the owning component or helper. |
| Improve local dependency analysis | [Local engine guide](offense/CONTRIBUTING.md) | Add a synthetic fixture for an unsupported edge case or improve an error message. |
| Improve a scanner or tool listing | [Tool contribution guide](docs/contributing-tools.md) | Correct coverage information or add positive/safe test evidence for an existing tool. |
| Improve the public site | [Site README](site/README.md) | Clarify a page or improve an accessibility issue. |

Browse [existing issues](https://github.com/offense-research/offense/issues) for
related work before starting. For a larger feature or new scanner integration,
open an issue describing the problem and proposed scope first. You can ask setup
questions in [Discord](https://discord.gg/xP7GCnyF). Keep examples sanitized; report
vulnerabilities privately through [SECURITY.md](SECURITY.md).

## Get a checkout

Fork the repository on GitHub, clone your fork, and create a branch for your change:

```sh
git clone https://github.com/YOUR-USERNAME/offense.git
cd offense
git switch -c improve-contributor-setup
```

Replace `YOUR-USERNAME` with your GitHub username. All commands below run from
this repository root unless stated otherwise. Use **Node.js 24 or newer** and npm:

```sh
node --version
npm --version
```

### Documentation only

You can edit Markdown and preview it without installing dependencies, configuring
an account, or starting the app. Check relative links and verify any commands you
change against the relevant package scripts. If your change affects generated
site content, follow the [site guide](site/README.md) to build it.

### App, API, and shared code

Install the locked root dependencies:

```sh
npm ci
```

For tests and builds, start with the commands in [Check your change](#check-your-change).
To run the development app, copy `.env.example` to `.env` **only if you do not
already have a local `.env`**. Generate a local encryption key:

```sh
openssl rand -hex 32
```

Set `ENCRYPTION_KEY` in `.env` to that value. Set `DATA_DIR` to an absolute path
outside the checkout for your local database, such as `/absolute/path/offense-dev-data`.
Keep the default loopback host and ports. Leave optional provider credentials
unset and billing disabled unless your particular work needs those integrations.
Never commit `.env`, keys, session files, or databases.

```sh
npm run dev
```

This starts Vite at `http://localhost:5173` and the watched API at
`http://localhost:3217`. Open the Vite URL; its `/api`, `/mcp`, and `/v1` requests
proxy to the API. Check the terminal for startup errors in either process. Stop
both with Ctrl+C.

A running page does not mean external integrations are configured. Browser
account features need an operator-owned GitHub OAuth app; local operator API
keys do not sign you into the browser. For the supported API/MCP self-hosted
profile and scanner prerequisites, follow [self-hosting](docs/self-hosting.md).

### Local dependency engine

The `offense/` directory is a separate package with its own dependencies and
checks. Root `npm ci` does not install it:

```sh
npm --prefix offense ci --ignore-scripts --no-audit --no-fund
npm --prefix offense test
npm --prefix offense run check
```

You do not need the app's `.env` or browser login for the engine's default checks.
Read [its contributor guide](offense/CONTRIBUTING.md) for package-specific rules.

## Find the owning files

- `src/`: React UI and styles; `public/`: static assets and distributed skills.
- `server/`: Express API and services; `shared/`: logic reused across runtimes.
- `test/`: root tests, synthetic fixtures, and helpers.
- `agent/` and `workers/`: scanner runtimes and Cloudflare integration.
- `scripts/`: builds and CLI entry points; `sdk/` and `cli/`: client packages.
- `site/`: public website; `offense/`: independent local engine.

Follow neighboring code: ES modules, two-space indentation, single-quoted
JavaScript strings, and semicolons. Use PascalCase for React components,
camelCase for functions, and kebab-case for service/helper filenames. Keep shared
logic in `shared/`. Preserve existing Purple aliases and identifiers where they
provide compatibility.

### Maintained sources and generated distributions

- `offense/` is an independent local dependency engine with its own manifest,
  CLI, MCP server, skill, tests, and contributor guide. It is not a generated
  copy of the root app.
- The hosted CLI implementation starts at `scripts/offense-cli.mjs`.
  `scripts/build-offense-cli.mjs` bundles it into `cli/dist/` and
  `public/skills/offense/scripts/cli.mjs`; `cli/package.json` and `cli/README.md`
  are maintained package metadata and documentation.
- `sdk/index.mjs`, `sdk/node.mjs`, their declarations, and `sdk/README.md` are
  maintained sources. `scripts/build-agent-sdk.mjs` produces `sdk/dist/` and
  downloadable archives under `public/downloads/`.
- `public/skills/` mixes maintained instructions and references with generated
  helpers. Check `scripts/build-skill.mjs` and `scripts/build-offense-cli.mjs`
  before editing a helper; do not treat the entire directory as build output.
- `scripts/build-offense-plugin.mjs` packages `public/skills/offense/` into
  `plugins/offense/`, including a Codex-specific installation overlay. Update
  the source skill or that overlay, then rebuild the plugin.
- `.agents/skills/scanning-with-offense/SKILL.md` is the maintained portable
  project skill linked from the README; it is distinct from the packaged skills.
- `site/dist/`, `site/.cloudflare-build/`, and the client bundles above are
  generated. The [tool guide](docs/contributing-tools.md) identifies the owning
  sources for catalog and scanner changes.

The root README is the checkout entry point. `docs/public-readme.md` is the
source-export candidate README template, not a competing overview: the export
places it at the candidate root. Its candidate restrictions and root-relative
links are intentional. See the [release preparation record](docs/release-preparation.md).

## Check your change

During development, run the closest tests first. Root tests use `node:test` and
`node:assert/strict`; for example:

```sh
node --test test/dependency-graph.test.js
```

Direct `node --test` skips npm's `pretest` hook. If a test needs generated Worker
sources, prepare them with `node scripts/build-worker-sources.mjs`, or run
`npm test`, which does that automatically.

Before submitting code changes, run the verification sequence used by the
[CI verification job](.github/workflows/ci.yml):

```sh
npm ci
npm run build
npm test
npm --prefix offense ci --ignore-scripts --no-audit --no-fund
npm --prefix offense test
npm --prefix offense run check
```

The root build generates skills, the agent SDK, frontend assets, and the site.
Root `npm test` runs the root suite and site tests; it does **not** run the separate
engine suite. Successful commands exit with status zero; inspect failed-test
output rather than treating a partial run as a pass. CI also runs audit, CLI, and
applicable runtime jobs; the sequence above reproduces its verification job.

Default tests use synthetic fixtures and mocked providers. Add a focused
regression for behavior changes and preserve partial/error outcomes. Docker
scanner checks are opt-in; live scanner, payment, deployment, and production
tests require separate authorization. For Markdown-only edits, check rendering,
links, and command accuracy and report those checks in the PR.

## When setup fails

| Symptom | What to check |
| --- | --- |
| Node APIs or syntax are unavailable | Confirm `node --version` is 24+ in the terminal running the command. |
| Dependencies cannot be found | Run the install for the package you are changing; root and `offense/` installs are separate. |
| A script is missing | Run from the repository root and check its `package.json`; use `--prefix offense` for engine commands. |
| Vite opens but API requests fail | Check API startup output and port 3217. If you change the API port, update the local Vite proxy accordingly. |
| The browser asks you to sign in | Browser account features require GitHub OAuth configuration; use mocked tests for changes that do not need a real account. |
| A focused test cannot find generated Worker sources | Run the preparation command above or the full `npm test` entry point. |

When asking for help, include your Node version, revision, working directory,
exact command, and sanitized error output. Never include secrets or private reports.

## Submit a pull request

- Keep the change focused and use a short imperative commit subject, such as
  “Clarify local engine setup.”
- Explain the problem, resulting behavior, and checks you ran; link the relevant
  issue and state any checks you could not run.
- Include rendered evidence for UI changes and check keyboard and mobile use.
- For tool changes, follow the [tool guide](docs/contributing-tools.md) and optional
  [tool PR template](.github/PULL_REQUEST_TEMPLATE/tool.md).
- Review your diff for generated artifacts, secrets, and unrelated changes before
  pushing your branch and opening a PR against `main`.

## License and release boundaries

This repository contains the approved source-only release. Do not import private
operational history, customer evidence, or the deferred assessment integrations.

Contribute only work you have the right to license. Identify copied code, rules,
datasets, and assets with upstream revision, license, and required notices. New
Offense-owned contributions use Apache-2.0 unless modifying a separately licensed
component; preserve that component's terms. No copyright assignment or exclusive
commercial license is required. See [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md)
for exceptions.

Report vulnerabilities privately using [SECURITY.md](SECURITY.md), not a public
pull request. Publication, package/image releases, and deployments are separate
approvals.
