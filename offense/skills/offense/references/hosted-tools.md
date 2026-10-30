# Optional hosted tools

Read this only when the user asks to connect a hosted Offense account or run a
prepaid security tool. Local `offense scan` and `offense mcp` do not need this.
Use the packaged `offense-hosted` command or its actual absolute
`bin/offense-hosted.mjs` entrypoint. The hosted service is https://offense.sh.

Run `offense-hosted login` (or `--no-browser` remotely). The human signs in in
their browser, compares the terminal code and approves the displayed workspace.
Never ask for passwords, provider tokens, authorization codes or API keys in chat.
Reuse an equivalent existing authorized account. `whoami`, `tools` and `balance`
can verify the account without running a scan. The client stores the key privately;
project MCP settings contain a local command, not the credential.

`offense-hosted mcp install --client codex --project /actual/project` supports
Codex, Claude Code and Cursor. It merges the project entry named `offense`.
The independent local server uses `offense-community`, so both can coexist.
A customized existing entry is preserved; inspect it before explicitly approving
entry-only replacement with `--replace-offense`. Do not claim that the current
agent session loaded tools from a settings write. Tell the user to start a new
coding-agent session in the same project after installation or updates.

Before a paid call, inspect `tools show TOOL` and `quote TOOL --input request.json`.
Only submit with the user-approved maximum price, for example
`call TOOL --input request.json --max-price 0.10 --idempotency-key request-0001 --wait`.
Review source/artifact scope first. Keep the same key and exact input for an
uncertain submission, rather than accidentally creating another job or charge.
Partial/failed results remain incomplete and release the service reservation.

`topup` returns a Whop checkout link. The human approves payment there; opening
a link or returning from checkout does not grant credit. No hosted backend or
payment credential is distributed here. Hosted requests may send the explicitly
selected tool input; this is a separate data boundary from the local engine.

Respect native client trust prompts and provider decisions. Do not replay a
provider-blocked setup through a different model, transport or permission setting.
