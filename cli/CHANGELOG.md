# Offense CLI 0.2.0

First versioned open-source CLI release candidate. Publication is pending owner
approval and successful macOS/Linux installation checks; this document is not a
release announcement.

## Included

- Standalone Node.js CLI with bundled dependencies and third-party license texts.
- Dependency advisory audits, tool discovery, price quotes and bounded hosted jobs.
- Device login, endpoint-bound credentials, job recovery and optional MCP setup
  for Codex, Claude Code and Cursor.
- Local stack evidence and Kubernetes inventory commands with offline previews.
- npm-compatible archive, SHA-256 checksum and a prepared Homebrew formula.

## Requirements and boundaries

- Node.js 20 or newer. Homebrew supplies its own Node dependency.
- This is a client distribution, not a scanner image, self-hosted server,
  independent local dependency engine or automatic Agent Skill installation.
- Hosted calls require a configured endpoint and authorization. Paid calls need
  an explicit spending ceiling; active testing needs its separate approvals.
- Self-hosted deployments can disable billing. Configure your own API origin and
  key; installing this client does not select or start that server.
- No npm registry publication, hosted download replacement or deployment is
  included in this release preparation.

The earlier mutable `offense.sh/downloads/offense-cli.tgz` channel may have a
different version. Use `offense --version` and `offense --help` to inspect the
client actually installed.
