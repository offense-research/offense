# Versioned CLI release procedure

The first stable CLI target is **0.2.0**, with planned tag `cli-v0.2.0`. It is
currently a local candidate, not a published release. Source publication approval does
not automatically approve CLI artifacts, npm publication or deployment.

## Build without modifying the hosted downloads

From the repository root with Node.js 24+ and the locked dependencies installed:

```sh
npm ci
node scripts/build-offense-cli.mjs --release-dir dist/cli-release
node scripts/test-cli-release.mjs dist/cli-release
```

The destination must not exist. Use a new directory for each candidate rather
than replacing reviewed bytes. The release build does **not** rewrite tracked
skill bundles, the live formula or `public/downloads/`. The older `npm run
build:cli` command still prepares the mutable hosted download channel; do not
use that command for an immutable release candidate.

Candidate files:

- `offense-cli-0.2.0.tgz`: standalone npm-compatible client, package metadata,
  README, Apache license, project notice and bundled third-party license texts.
- `SHA256SUMS`: SHA-256 of that exact archive.
- `offense.rb`: prepared Homebrew formula with the versioned GitHub release URL
  and archive checksum. Its URL will not work until publication.
- `RELEASE-NOTES.md`: draft release notes copied from `cli/CHANGELOG.md`.

The archive contains no scanner binaries, Docker images, server runtime, keys
or install-time dependency resolution. `private: true` remains an npm registry
publication guard, while local/tarball installations continue to work.

## Checks before calling the candidate stable

The `CLI release checks` workflow runs on `ubuntu-latest` and `macos-latest` for
pushes and pull requests. It has read-only repository permissions and no release,
tag, npm-publish or deployment step. It:

1. Tests reproducible builds, refusal to overwrite candidates and checksum-tamper
   rejection, without modifying existing client distributions.
2. Installs the archive into a temporary npm prefix and tests it on Node 24 and
   the minimum supported Node 20. Checks include version/help, signed-out status,
   an explicit custom API origin and a Kubernetes preview that needs no cluster.
   It also exports a partial synthetic audit as a PDF, checks private permissions,
   preserves the source JSON and rejects overwriting an existing PDF, without login.
3. Creates a disposable Homebrew tap and changes only the candidate's download
   URL to the local archive. Homebrew still verifies the actual SHA-256.
4. Installs with Homebrew's Node dependency, runs the formula tests, checks style,
   audits the prepared release formula and uninstalls it.
5. Retains the candidate as a short-lived CI artifact for review, not a GitHub
   Release. Both operating-system jobs must pass. A final comparison job verifies
   each checksum and requires every candidate file to be byte-identical across
   macOS and Linux. The gzip OS marker is normalized; CI artifacts remain tied
   to their source SHA.

The offline tests do not certify login, hosted payments or every server feature.
They never run paid calls, active assessments or cluster collection. The macOS
job tests the architecture provided by `macos-latest`, not every Mac model or
every macOS version. A Linux-only local check is not a substitute for that job.

Known first-release limitation: `offense audit` saves one hosted response. It
does not automatically follow advisory scan or planning cursors. Large audits
remain partial (exit 2); the separate downloadable `offense.mjs` helper provides
automatic continuation and interrupted-scan recovery. Keep this distinction in
the release notes rather than advertising helper-only features as CLI features.

## Publication gate — owner approval required

Before publishing, review the package contents and third-party notices, the
draft notes, both platform checks and the exact source commit/archive checksum.
Confirm that the owner approves **this CLI artifact release**, separate from
the earlier source-only release. Remove candidate-only wording from the notes
as part of the final review, then rebuild and recheck the final commit.

After approval:

1. Create the immutable `cli-v0.2.0` tag at the tested source commit. Never move
   an existing release tag or replace published archive bytes; use a new version.
2. Publish a non-prerelease GitHub Release in `offense-research/offense` with
   that archive, `SHA256SUMS` and the approved release notes. Do not publish the
   package to npm or replace the `offense.sh` download as an implicit side effect.
3. Download the published archive and verify its checksum and installation.
4. Copy the generated `offense.rb` into `Formula/offense.rb`, preserving its
   archive layout paths. Commit/push the formula update only after the URL works.
5. Check `brew livecheck offense-research/offense/offense`, which looks for stable
   `cli-vX.Y.Z` GitHub releases, and repeat the Homebrew install/test/audit checks
   against the public release URL. Update README installation/version guidance.

Until step 4, the public tap keeps its working commit-pinned source URL. Preparing
a release must not break existing installations by pointing at an absent asset.

## Future releases and Homebrew/core

Update `OFFENSE_CLI_VERSION` in `scripts/offense-cli.mjs`, `cli/package.json`, the
packaged README example and the release notes together. The builder rejects a
package/implementation version mismatch. The generated formula inherits the
maintained formula's install logic and tests, adjusting only its release URL,
version, checksum and the two archive layout paths.

Homebrew/core submission is separate from maintaining this tap. Once its
[acceptance criteria](https://docs.brew.sh/Acceptable-Formulae) and
[public-interest policy](https://docs.brew.sh/Package-Acceptance-Policy) are met,
run the additional `brew audit --strict --new --online` checks and request
maintainer review. Until accepted, a new machine still needs the custom tap;
the project must not advertise bare `brew install offense` as a no-setup install.
