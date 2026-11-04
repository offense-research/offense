# Agent setup

[Back to the overview](../README.md). Commands below run from the repository root unless stated otherwise.

### Connect your coding agent

The local engine exposes `offense.audit_dependencies` over stdio MCP:

```sh
node offense/bin/offense.mjs mcp
```

Configure your client to launch that command using the **absolute path** to the
entrypoint; it is an MCP server, not an interactive terminal session. The
[agent setup guide](../offense/docs/install.md) covers project-scoped MCP and skill
installation for Codex, Claude Code and other clients. Preserve existing client
configuration and start a new agent session after installing.

For a client using an `mcpServers` JSON configuration, merge this entry into its
existing configuration rather than replacing other servers:

```json
{
  "mcpServers": {
    "offense-community": {
      "command": "node",
      "args": ["/absolute/path/to/offense/offense/bin/offense.mjs", "mcp"]
    }
  }
}
```

For Codex, the equivalent project `.codex/config.toml` entry is:

```toml
[mcp_servers.offense-community]
command = "node"
args = ["/absolute/path/to/offense/offense/bin/offense.mjs", "mcp"]
```

The two `offense` path segments above are intentional: the repository contains
a nested `offense/` package. Replace the example with your actual checkout path.
Claude Code uses project `.mcp.json`; other clients may use a different location
or schema. No API key belongs in this local-engine configuration.

After restarting the client, verify it discovers `offense.audit_dependencies`.
Discovery is not a scan. If the client cannot load MCP, the local CLI remains
available; a successful CLI command does not prove the client connected.

Once connected, choose an [audit, fix or tool-selection prompt](../README.md#ask-for-the-outcome-you-want).
Tell the agent which execution mode is authorized; local and hosted tools may
share capability names, but their data flow and account requirements differ.

### Install the offense.sh Agent Skill

The portable [scanning-with-offense skill](../.agents/skills/scanning-with-offense/SKILL.md)
uses the [Agent Skills format](https://agentskills.io/skill-creation/quickstart).
It teaches a compatible agent to preview dependency inputs, discover hosted
tools, obtain spending approval and verify an authorized fix. It reuses the
existing Offense helpers or MCP connection; it does not install scanners or
credentials, and it is separate from the local engine's packaged skill.

The skill is already in this checkout's `.agents/skills/` directory. Hermes can
install it into its active profile using the native Skills Hub commands below.
For **project-local installation**, choose your agent's directory in the table.
Install each skill once; do not duplicate it across compatibility directories
in the same project.

#### Hermes Agent — native skill installation

Use a current [Hermes Agent](https://hermes-agent.nousresearch.com/docs/user-guide/features/skills)
with Skills Hub support. Inspect the source-qualified skill before installing:

```sh
hermes skills inspect offense-research/offense/.agents/skills/scanning-with-offense
```

After reviewing it, install and confirm it appears in the hub-installed list:

```sh
hermes skills install offense-research/offense/.agents/skills/scanning-with-offense
hermes skills list --source hub
```

This installs the same portable skill into your **active Hermes profile**, normally
under `~/.hermes/skills/`, rather than into the target repository. Hermes scans
third-party skills and asks for confirmation. Review any warning; do not add
`--force` just to bypass it. An existing customized installation should be reviewed,
not overwritten. A trusted project-local skill with the same name takes precedence.

Make the [existing Offense helpers available](#make-the-existing-helpers-available),
then start Hermes in the project you want to check. In Hermes chat:

```text
/scanning-with-offense Preview this project's dependency audit. Do not upload anything, install project dependencies or run paid tools.
```

Verify Hermes loaded `scanning-with-offense` and actually ran the preview; a prose
description is not a scan. The skill works through the existing CLI helpers or an
already configured MCP connection. Installing it does **not** install the Offense
runtime, configure MCP, sign in, buy credit or authorize source uploads.

For an authorized audit, use `/scanning-with-offense Audit this project's supported
lockfiles and report coverage gaps; do not change files or run paid tools.` For a
hosted source review, ask it to quote the selected files first and wait for your
upload and spending approval. See the [recipes](recipes.md) for scoped examples.

Manage the profile installation with `hermes skills check`,
`hermes skills update scanning-with-offense` after reviewing upstream changes, or
`hermes skills uninstall scanning-with-offense`. For a repo-only installation,
use the project-local copy and trust instructions below instead of a profile install.

#### Choose your agent

Each directory below is relative to the **target project's root**. The final file
must be `<directory>/scanning-with-offense/SKILL.md`. Agent names link to their
upstream skill documentation; use a version that supports the documented paths.

| Agent | Project skill directory | Discover or invoke after starting a new session |
| --- | --- | --- |
| [Pi](https://pi.dev/docs/latest/skills) | `.pi/skills/` | `/skill:scanning-with-offense`; accept the normal project-trust prompt |
| [Oh My Pi (OMP)](https://github.com/can1357/oh-my-pi/blob/main/docs/skills.md) | `.omp/skills/` | `/skill:scanning-with-offense` when skill commands are enabled |
| [Hermes Agent](https://hermes-agent.nousresearch.com/docs/user-guide/features/skills) | `.hermes/skills/` | Review and trust the project as below, then `/scanning-with-offense` |
| [OpenAI Codex](https://developers.openai.com/codex/skills) | `.agents/skills/` | `/skills` to discover; `$scanning-with-offense` to invoke |
| [Claude Code](https://code.claude.com/docs/en/skills) | `.claude/skills/` | `/scanning-with-offense` |
| [Charm Crush](https://github.com/charmbracelet/crush#agent-skills) | `.crush/skills/` | Ask it to load `scanning-with-offense`; this skill does not enable Crush's optional command-palette invocation |
| [Cursor](https://cursor.com/docs/skills) | `.cursor/skills/` | Select `scanning-with-offense` from the `/` menu in Agent chat |
| [OpenCode](https://opencode.ai/docs/skills) | `.opencode/skills/` | Ask it to load `scanning-with-offense` through its skill tool |
| [GitHub Copilot CLI](https://docs.github.com/en/copilot/how-tos/copilot-cli/customize-copilot/add-skills) | `.github/skills/` | Ask it to use `scanning-with-offense` for the preview request below |
| [VS Code Copilot](https://agentskills.io/skill-creation/quickstart) | `.agents/skills/` | In Agent mode, use `/skills` to confirm discovery |
| [Gemini CLI](https://geminicli.com/docs/cli/skills/) | `.gemini/skills/` | `/skills list`, then request the preview and review the activation prompt |

Several agents also read `.agents/skills/`, so a shared installation may already
be sufficient. Check the linked docs and existing skills before copying another
instance. Do not disable trust checks or tool approvals to make a skill load.

#### Copy the skill without replacing custom instructions

In a POSIX shell (macOS, Linux or WSL), run this from the Offense repository root.
Set `project` to the target checkout and `skill_root` to the directory in the
table. This example selects **Pi**; change `.pi/skills` for another agent.

```sh
project=/absolute/path/to/your-project
skill_root=.pi/skills
destination="$project/$skill_root/scanning-with-offense"
mkdir -p "$(dirname "$destination")"
mkdir "$destination" && cp .agents/skills/scanning-with-offense/SKILL.md "$destination/SKILL.md"
```

`mkdir` deliberately fails if the skill directory exists, preventing the copy
from overwriting customized instructions. Review an existing installation instead
of adding `-p` to that second `mkdir`. Windows users can copy the same `SKILL.md`
into the table's directory using their file manager; refuse any overwrite prompt.

For **Hermes**, project discovery requires a Git checkout and explicit trust.
After reviewing the repo's skills, run:

```sh
hermes skills trust /absolute/path/to/your-project
```

This trusts the project's skills, not just Offense. Do not trust an unreviewed
repository. Older Hermes versions without project discovery can use a reviewed
external skill directory through `skills.external_dirs`; follow the linked docs
rather than assuming `.hermes/skills/` is recognized.

#### Make the existing helpers available

Skills contain instructions, not a CLI or a scanner runtime. Keep the reviewed
Offense checkout accessible to the agent. The bundled hosted helpers require
**Node.js 20+** and no root `npm install` for these commands:

```sh
export OFFENSE_HELPERS=/absolute/path/to/offense/public/skills/offense/scripts
node "$OFFENSE_HELPERS/cli.mjs" --help
node "$OFFENSE_HELPERS/offense.mjs" audit /absolute/path/to/your-project --preview
```

Launch the agent from a shell that inherits this variable, or tell it the actual
absolute helper path in its session. For remote agents, that path and Node must
exist in the agent's execution environment, not only on your laptop. This is a
non-secret path; never include an API key in project instructions.

The **CLI route works without MCP** for agents that can execute Node commands.
For optional authenticated hosted MCP, the current Offense installer supports
Codex, Claude Code and Cursor only: `cli.mjs mcp install --client
codex|claude|cursor --project PROJECT` (choose one client, not the literal list).
Do not invent `--client pi`, `omp`, `hermes` or `crush` options. Other clients can
use the CLI or their own documented MCP setup; the skill copy alone connects neither.
The independent local engine still requires Node.js 24+ and the separate
[local setup](../README.md#quick-start-local-dependency-analysis).

Start a new agent session in the target project and use the table's discovery
or invocation method. Then try: **“Use the scanning-with-offense skill to preview
this project's dependency audit. Do not upload anything or run paid tools yet.”**
Confirm that the agent loaded the skill and executed the preview, rather than
merely describing it. Preview makes no advisory request and needs no login.
Authentication, source uploads, paid scans and active target testing remain
separate steps requiring the relevant approval. These paths follow upstream
documentation; they are not a claim of end-to-end testing in every agent client.

