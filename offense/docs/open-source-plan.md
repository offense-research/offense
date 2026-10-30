# Offense: scope and release plan

## Current source release

The 0.2.0 engine is published as source in `offense-research/offense` under `offense/`.
It uses Offense branding, the `offense` CLI and the `offense-community`
local MCP server, with legacy
Purple entrypoints and report schemas retained for compatibility. The source
release has a clean history; original private repositories remain private.
The package stays marked private to prevent unapproved npm publication.

## Product boundary

The community edition contains an independently runnable dependency engine,
CLI, stdio MCP server and coding-agent skill. It can inventory npm and pnpm
lockfiles, query public advisories, plan coordinated upgrades and prepare a
repository remediation prompt. Local reachability, upgrade rehearsal, static
security checks, API sandbox testing and hardened-image acquisition extend that
workflow when their explicit runtime prerequisites are available.

The coding agent retains its own model and authorized repository connections.
The deterministic dependency engine does not require a model key, company
sign-in, GitHub App, Cloudflare account or company-hosted analysis service.
OSV and the public npm registry remain external metadata providers.

The optional `offense-hosted` CLI is a source client for explicit requests to
the hosted service. It does not make the local engine depend on that service.
Managed hosting, the billing backend, customer operations, production deployment
tooling, private support material and production datasets remain outside this
package. Public client code must contain no embedded production credentials.

## Release checklist

1. Extract the graph, advisory adapter, upgrade planner and prompt generator
   from application authentication, quotas, tracing and operational databases.
2. Provide a CLI and stdio MCP interface with bounded provider requests,
   sanitized dependency input, explicit coverage and consistent results.
3. Adapt local helper entrypoints and the skill to use the independent engine.
   Keep application execution explicit and sandbox ownership clear.
4. Remove production constants, automatic company-hosted update behavior,
   customer evidence and local machine settings from the public file set.
5. Add a project license, retained upstream notices, setup documentation,
   contribution guidance, security reporting and reproducible default tests.
6. Exercise synthetic dependency, MCP and local-tool workflows. Review the
   complete release tree and package contents for private data and secrets.
7. Only after explicit publication authorization, publish the reviewed snapshot
   without private Git history. Verify a clean clone, installation, tests,
   package contents and the intended repository visibility.

## Publication controls

The owner approved this source-only publication on 2026-10-30. That approval
does not include npm packages, images, tags or production deployments. Local
edits, checks and packaging do not grant those separate approvals.

Release a deliberate allowlist of source, tests, docs and license files. Do not
copy the private repository's Git history, operational reports, ignored files,
credentials, databases, private-key files, dependency installations or machine
settings. Synthetic cases document behavior without carrying customer evidence.

No production deployment is required to publish this edition. Creating the
public repository does not grant its CI access to production secrets or cloud
resources. Changes to the community release must pass the same checks before
future publication.

External tools retain their upstream licenses. This source release does not
redistribute prebuilt third-party scanner binaries or scanner images. A future
binary/image release needs its own complete component-license/source review.

## Verification and limits

Default tests use synthetic fixtures and deterministic provider responses.
Explicit integration checks may contact OSV/npm or use a disposable local
container. Preserve failed, partial and omitted checks in the result.

Source reachability is bounded evidence. A matching advisory is not a confirmed
vulnerability; an upgrade rehearsal is not a security reproduction. The agent
must establish normal baseline checks and issue-specific before/after evidence
before describing an issue as reproduced and fixed.

Provider safeguards are separate from application permissions. See
[provider safeguards](provider-safeguards.md) for diagnosis and legitimate next
steps. No release can guarantee that an independent model provider accepts
every security task.
