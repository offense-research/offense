# Offense

Offense is a security-tool platform for coding agents, with a Node API, MCP,
CLI, web console, scanner adapters and an independently runnable dependency
engine. The operated service at https://offense.sh charges for hosted execution.
Self-hosted source execution does not require an Offense account or credit.

**This is the initial Apache-2.0 source release.** See
[release preparation](docs/release-preparation.md) for its reviewed scope,
verification and exclusions. It contains no private Git history.

## Start

Use Node.js 24+ and npm:

```sh
npm ci
npm run build
npm test
```

Follow [self-hosting](docs/self-hosting.md) to build the local isolated scanner,
create private operator state and run the API. The initial profile supports
dependency advisory analysis, Opengrep and Zizmor; other execution families
remain disabled, not implicitly installed by their directory listing.

This first release is **source only**. Other scanner adapters and
container recipes, where included, are unsupported reference source in this
self-hosted profile. The MobSF/SSLyze integrations and shared network/offline
assessment runtimes are deferred from this export pending licensing review;
catalog listings and project-owned rules do not imply an included runtime.
No scanner images, engine binaries, package archives or downloaded datasets are
included or approved for publication. Local build outputs are validation products,
not release artifacts. Source inclusion does not certify hosted GPL/AGPL compliance.

The separate `offense/` package provides local dependency analysis and stdio MCP.
The web console's browser account features require your own GitHub OAuth setup;
the local operator bootstrap supplies an API/MCP key, not browser authentication.

## Contribute and report issues

Read [CONTRIBUTING.md](CONTRIBUTING.md) and the
[tool contribution guide](docs/contributing-tools.md). Report vulnerabilities
privately following [SECURITY.md](SECURITY.md). Tests use synthetic data; live
assessments need explicit authorization. Never attach customer data or secrets.

## License

Included Offense-owned code is Apache-2.0; the disputed GPL/AGPL integrations
are excluded from this export. Imran Muthuvappa's identified original artwork is also Apache-2.0;
trademark rights remain separate. Commercial hosting and forks are allowed.
Third-party source, fonts, rules and data retain their own terms.
See [LICENSE](LICENSE), [NOTICE](NOTICE) and
[THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md). Image/package publication has
separate requirements. There is no proprietary feature edition in this source tree.
