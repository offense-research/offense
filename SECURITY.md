# Security reporting

Do not post vulnerabilities, credentials, customer source or raw scan reports in
public issues. Use GitHub's **Security → Report a vulnerability**:
https://github.com/offense-research/offense/security/advisories/new.
Private vulnerability reporting is enabled for this repository. If the route
is unavailable, ask the maintainer for a private channel before sending details;
do not substitute a public issue or an unconfirmed email address.

Include the affected revision, expected/observed behavior and a minimal synthetic
reproduction. Distinguish advisory matches, static findings and demonstrated
vulnerabilities. Incomplete or failed scans are not clean results.

Self-hosting operators must secure their Docker daemon, API keys, encryption
keys and backups. Docker access is effectively host-administrator access.
Use isolated infrastructure for untrusted inputs, keep scanner data current,
and run only authorized target assessments. See docs/self-hosting.md.

There is no community security-support SLA. Keep external scanners and
vulnerability databases current.
