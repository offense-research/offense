# Changelog

## 0.2.0 — local candidate, unpublished update

- Rename the product to Offense, maintained by Offense Security.
- Add canonical Offense CLI, skill and MCP names while preserving Purple
  compatibility entrypoints and the existing report schema.
- Refresh shared advisory context with available CWE identifiers and plain-language
  impact, keeping metadata matches separate from exploitability evidence.
- Include the optional `offense-hosted` source client for browser-approved login,
  quoted hosted tool calls and project MCP setup. Hosting, billing implementation
  and production credentials remain excluded.
- Keep dependency analysis independent of company sign-in, model accounts,
  production infrastructure and company-hosted analysis.
- Preserve project-scoped installation, customized client settings and the
  required new agent session after a skill or MCP update.
- Retain the publication hold. The source candidate and package remain private;
  this update does not publish a repository, release or npm package.

The existing remote repository slug remains `imranye/purple-community`.
