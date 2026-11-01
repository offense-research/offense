# Offense CLI 0.2.0

First stable, versioned open-source CLI release for macOS and Linux, with
Node.js 20+ support and a SHA-256-verified Homebrew installation.

## Included

- Standalone Node.js CLI with bundled dependencies and third-party license texts.
- Dependency advisory audits, tool discovery, price quotes and bounded hosted jobs.
- Device login, endpoint-bound credentials, job recovery and optional MCP setup
  for Codex, Claude Code and Cursor.
- Offline PDF reports from saved audits and hosted-job receipts, with plain-English
  attacker prerequisites, business impact, recommended fixes and review priorities.
  Application severity remains unknown unless a complete, attributed review is supplied.
- Local stack evidence and Kubernetes inventory commands with offline previews.
- npm-compatible archive, SHA-256 checksum and a Homebrew formula.

## Requirements and boundaries

- Node.js 20 or newer. Homebrew supplies its own Node dependency.
- This is a client distribution, not a scanner image, self-hosted server,
  independent local dependency engine or automatic Agent Skill installation.
- Hosted calls require a configured endpoint and authorization. Paid calls need
  an explicit spending ceiling; active testing needs its separate approvals.
- Self-hosted deployments can disable billing. Configure your own API origin and
  key; installing this client does not select or start that server.
- No npm registry publication, hosted download replacement or deployment is
  included in this release.
- `offense audit` currently saves one response and exits 2 for partial coverage or
  unfinished planning. Automatic scan/planning continuation and `--resume` belong
  to the separate downloadable `offense.mjs` helper, not this CLI command. Do not
  treat a partial CLI report as a completed audit.
- PDF export does not perform a scan or establish exploitability. Exit 0 means
  export succeeded; the PDF preserves the input scan status. Reports are not
  redacted, encrypted or signed.

The earlier mutable `offense.sh/downloads/offense-cli.tgz` channel may have a
different version. Use `offense --version` and `offense --help` to inspect the
client actually installed.
