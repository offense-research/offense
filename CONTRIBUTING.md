# Contributing to Offense

This repository contains the approved source-only release. Do not import private
operational history, customer evidence or the deferred assessment integrations.

Use Node.js 24+, run `npm ci`, `npm run build`, and `npm test`. The separately
packaged local engine uses `npm --prefix offense ci` and `npm --prefix offense test`.
Default tests use synthetic fixtures; live scanner, payment, deployment and
production tests require separate authorization. Never include private evidence.

For tools, follow [the tool contribution guide](docs/contributing-tools.md) and
the optional `.github/PULL_REQUEST_TEMPLATE/tool.md`. Make focused changes,
preserve compatibility and partial/error results, and include tests through the
public interface. UI changes need rendered evidence and keyboard/mobile checks.

Contribute only work you have the right to license. Identify copied code, rules,
datasets and assets with upstream revision, license and required notices. New
Offense-owned contributions use Apache-2.0 unless modifying a separately licensed
component; preserve that component's terms. No copyright assignment or exclusive
commercial license is required. See THIRD_PARTY_NOTICES.md for exceptions.

Report vulnerabilities privately using SECURITY.md, not a public pull request.
Publication, package/image releases and deployments are separate approvals.
