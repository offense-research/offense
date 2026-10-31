# Add Offense with a pull request

[**Use the workflow template →**](../site/public/templates/offense.yml)

Copy the template into `.github/workflows/offense.yml` in a new branch of your
repository, then open a pull request. See [manual installation and updates](#manual-installation-and-updates)
for existing workflows and future upgrades.

## Web installer (pending deployment)

The browser-based installer is prepared in `site/public/install.html` but has
**not been deployed**. Its intended URL is `https://offense.sh/install`; use the
manual instructions above until deployment is approved. Once live:

Enter your GitHub repository and existing base branch. The installer prepares
a link to GitHub's new-file editor with `.github/workflows/offense.yml` filled
in. No Offense account, GitHub token or GitHub App installation is required.
Private repositories work with your own GitHub permissions. The installer does
not query your repository or create a PR on your behalf.

1. Review the workflow in GitHub, then select **Commit changes**.
2. Select **Create a new branch for this commit and start a pull request**.
   Do not commit directly to your base branch.
3. Propose the change, review the PR and merge when you approve its behavior.
4. After merging, open **Actions → Offense dependency audit → Run workflow**
   for a baseline. Subsequent pull requests trigger it automatically.

GitHub may require sign-in, a fork, organization approval or Actions enablement.
For a private fork or external contributor, normal GitHub access and workflow
approval rules apply. An empty repository needs an initial commit first.

## What merging enables

The [reviewable workflow template](../site/public/templates/offense.yml) installs
the independent dependency engine at a pinned Offense commit and uses pinned
GitHub Actions. It scans npm v2/v3 and pnpm v6/v9 lockfiles. It does **not** install
the target application's dependencies, run application scripts, edit files,
comment on PRs or use paid Offense tools. Only `contents: read` is requested;
checkout credentials are not persisted. No application secrets are passed.

**Data boundary:** sanitized dependency names/versions are queried against
OSV/npm; this is not an offline scan. Reports can contain dependency names,
paths and advisory details. `scan.json` and `remediation.md` are uploaded to
GitHub Actions artifacts with seven-day retention. Review repository/artifact
access before enabling it for sensitive projects. GitHub Actions minutes and
storage remain subject to GitHub's limits and billing.

**Check policy:** advisories are report-only, not confirmed exploitable
vulnerabilities and not an automatic merge gate. Scan errors, missing supported
lockfiles, incomplete provider responses and coverage warnings fail the check.
A green run means the dependency audit completed without recorded coverage
warnings, not that the entire application is secure. Download the run's
`offense-report` artifact for evidence. Upgrade planning is disabled; ask your
agent to investigate and verify a fix using the [dependency recipe](recipes.md#dependency-audit-and-reviewed-upgrades).

Yarn, Bun, Python, Go and other ecosystems are not covered by this starter.
Mixed repositories may need the `scan project` target narrowed to a supported
subdirectory after reviewing coverage. Source scans, secrets checks, automated
fixes and hosted tools need separate configuration and authorization.

## Manual installation and updates

If the link builder is unavailable, copy the template's contents into
`.github/workflows/offense.yml` in a new branch of your repository and open a PR.
If that file already exists, compare and update it in your branch rather than
overwriting custom settings. GitHub's prefilled editor is a convenience; the
template file is the source of truth if GitHub changes its URL behavior.

Offense and Action versions do not float automatically. Review upstream changes
before updating their pinned commit SHAs in a PR. To remove this integration,
delete the workflow in a PR and remove retained artifacts if necessary.

Want tools inside your coding agent instead? Use the
[project-local Agent Skill or MCP instructions](../README.md#choose-your-agent).
This starter adds a CI dependency check, not an agent skill or the full hosted
scanner catalog.
