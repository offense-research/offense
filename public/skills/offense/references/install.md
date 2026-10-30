# Install Offense for this agent

Install only in the requested scope; project scope is the default. Preserve
unrelated settings, customized Offense files and the selected account/repository.
Company: **Offense Security**. Product: **Offense**, https://offense.sh.

Fetch this skill's `manifest.json` and the listed files from the same release:
`SKILL.md`, `references/install.md`, `references/verification.md`,
`references/tools.md`, `references/local-tools.md`, `scripts/offense.mjs`, `scripts/cli.mjs` and
`scripts/update.mjs`. Inspect executable files before running them. Use the
client's documented project skill directory: `.agents/skills/offense/` for Codex,
`.claude/skills/offense/` for Claude Code, or its supported project skill directory
for Cursor. Do not replace existing instructions or silently install globally.

Validate downloaded checksums with `node /installed/offense/scripts/update.mjs
--skill offense` and preserve the updater's customization/staging behavior.
An applied update requires a new session; do not continue under stale instructions.

## CLI login and all hosted tools

Run `node /installed/offense/scripts/cli.mjs login` (or `--no-browser`). The human
completes sign-in, verifies the short comparison code and approves the displayed
account. The CLI receives its API key once and saves it privately. No key belongs
in a project instruction, checked-in environment file, transcript or MCP entry.
Use the existing authenticated Offense CLI account when equivalent; do not switch
accounts or extract another provider's connector credentials.

Then run the selected project-only installer:

```sh
node /installed/offense/scripts/cli.mjs mcp install --client codex --project /project
node /installed/offense/scripts/cli.mjs mcp install --client claude --project /project
node /installed/offense/scripts/cli.mjs mcp install --client cursor --project /project
```

Choose one command for the actual client. The MCP entry uses Node plus the
installed CLI's `mcp` command. This is a real stdio-to-hosted MCP proxy; it reads
the private credential at runtime. The installer merges only `offense`, preserves
comments and unrelated entries, and reports customized entries as incomplete.
An existing anonymous HTTP URL alone does not unlock paid tools. Inspect and
explicitly migrate that entry with `--replace-offense` if authorized; do not overwrite a custom connection.

Respect the client's ordinary project-trust and tool permission prompts. Verify
initialization and tool discovery with the supported client workflow. CLI
`whoami`, `tools` and `balance` can verify account access without a paid scan.
Do not claim the active coding-agent session has loaded tools from a config write
or another client's initialization probe.

End setup by telling the user exactly: **Start a new coding-agent session in this
same project to load the installed skill and MCP configuration.** Give a full
application/extension restart instruction as well if that client requires it.
The CLI is immediately usable while the new agent session is pending.

## Free dependency capability or constrained clients

Basic dependency advisory checks remain free and require no sign-in. The existing
Streamable HTTP server `https://offense.sh/mcp` exposes `offense.audit_dependencies`
anonymously. A documented native HTTP connection can keep that capability; do not
mistake it for authenticated access to all hosted tools. Codex HTTP entries use
`url`; Claude Code uses `{"type":"http","url":"https://offense.sh/mcp"}`.
Preserve existing native project approvals and supported client configuration.

When MCP cannot load, use the installed `scripts/offense.mjs` helper or
`cli.mjs audit` for the same free HTTPS advisory capability. For paid hosted tools,
use the authenticated CLI. Report missing Node/filesystem/network/account access
concretely; do not claim MCP is connected. Provider safeguard failures remain
subject to their supported review process; do not change models, permissions or
transport to work around a refused operation.

## Scope and updates

Read [local capabilities](local-tools.md) when a later task needs source/workflow
checks, dependency applicability, upgrade rehearsal, local API testing or
container migration. These reuse the existing advanced helper release and the
agent's environment; the standalone CLI does not silently install scanners or
upload source. Install optional helpers only when the requested task needs them.

Installation verifies files, configuration and discovery only. It does not scan,
edit application code, buy credit, publish or deploy. Top-ups open Whop for human
payment approval; no browser return grants credit. Use [tool calling](tools.md)
only when later work actually needs hosted security tools.

Managed unchanged files update together; customized/unknown installations stage
a release for review. Keep unrelated project instructions intact. Always explain
the required new session after installation or updating, even if a CLI probe worked.

Official client references: https://developers.openai.com/codex/mcp,
https://code.claude.com/docs/en/mcp, https://cursor.com/docs/mcp.
