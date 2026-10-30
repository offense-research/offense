# Project-scoped agent setup

Use a reviewed, authorized checkout of this repository and Node.js 24+.
The 0.2.0 engine is published as source in the `offense/` directory of
https://github.com/offense-research/offense; npm publication remains on hold. Run
`npm ci --ignore-scripts` in the package directory. Use the actual absolute path
to `bin/offense.mjs` in client configuration. Installing a skill does not install
its package or prove that the current agent session has discovered it.

## Skill locations

| Client | Project skill directory |
| --- | --- |
| Codex | `.agents/skills/offense/` |
| Claude Code | `.claude/skills/offense/` |
| Pi | `.pi/skills/offense/` |

For another client, use its documented project skill directory. Copy
`skills/offense/SKILL.md` and its `references/` together. Keep the package checkout
available for the commands referenced by the skill. Record its actual CLI path
in the client's supported project instructions, preserving unrelated content.
Do not replace an existing customized Offense skill; review and merge it or use
a distinct client-supported name. A hosted Offense skill is not an equivalent
local-engine skill. Do not overwrite it or assume both editions are active under one skill
name; review which edition and namespace the project should use. An equivalent existing
MCP connection can be reused; preserve the selected account and repository scope. An authenticated
hosted Offense connection is different from this local engine. The local server
uses the `offense-community` name so an optional hosted `offense` entry can
coexist. Preserve any existing non-equivalent entry and review the namespace
before changing it.

Legacy `skills/purple`, `bin/purple.mjs` and `purple.audit_dependencies` remain
compatibility resources. Use the canonical Offense names for new installations,
and review customized legacy files before migration. The report schema remains
`purple.audit.v1`.

## Stdio MCP

Merge only the `offense-community` entry in an existing project configuration.
Do not replace the file or install globally. A JSON-style MCP entry is:

```json
{
  "mcpServers": {
    "offense-community": {
      "command": "node",
      "args": ["/actual/absolute/package/path/bin/offense.mjs", "mcp"]
    }
  }
}
```

For Codex, the equivalent project `.codex/config.toml` entry is:

```toml
[mcp_servers.offense-community]
command = "node"
args = ["/actual/absolute/package/path/bin/offense.mjs", "mcp"]
```

Claude Code uses the project's `.mcp.json` for its project server configuration.
Review any existing entry and its effective scope before changing it. Project
MCP configuration can contain sensitive information from unrelated servers;
do not print or upload it while merging this entry.

Verify the server initializes and lists `offense.audit_dependencies`. Tool
discovery performs no dependency scan. A successful endpoint/process probe is
different from discovery by the active agent session. If a client cannot load
the server, keep the skill and report the limitation; the local CLI remains
available for a separately requested scan.

## Optional hosted-client connection

`node /actual/absolute/package/path/bin/offense-hosted.mjs login` starts the
separate hosted-client sign-in. The person opens the first-party link, compares
the terminal code and approves the displayed account. Use `--no-browser` for a
remote terminal. Do not ask for passwords, provider tokens or API keys in chat.
The credential is saved privately; it does not belong in project MCP settings.

Use `offense-hosted.mjs tools` and `balance` to inspect access without a scan.
`topup` opens a Whop checkout for human payment approval. A checkout URL or browser
return is not payment confirmation. Hosted tool calls need a reviewed maximum
price and explicit input scope; these commands do not replace the local engine.

To configure its authenticated MCP proxy, use the actual project and client:

```sh
node /actual/absolute/package/path/bin/offense-hosted.mjs mcp install --client codex --project /actual/project
```

The installer writes a local command and merges only its Offense entry. It
preserves an existing customized, anonymous or local-engine entry and reports
when that entry is not an equivalent authenticated hosted connection. Review
which connection should use the `offense` name before explicitly authorizing
`--replace-offense`, or register the hosted proxy with a distinct supported name.
Do not claim local and hosted connections both loaded after replacing one.

Use the same new-session requirement below for either connection. The normal
client trust prompts and provider safeguards still apply. Configuring the proxy
does not establish that a previously refused provider operation has been cleared.

## Reload after installation or updates

Tell the user: **Start a new coding-agent session in this same project to load
the installed skill and MCP configuration.** End the current conversation/session
and open a fresh one with this same project selected. If the client requires an
application or extension restart, follow its documented restart/reconnect step
and verify the new session's actual tool list.

Do not claim that copying files or probing the server hot-loaded an existing
session. Do not disable client permissions or provider safeguards as part of
installation. Read [provider safeguards](provider-safeguards.md) if a later task
is blocked.
