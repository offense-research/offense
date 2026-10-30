# Get a hardened base for a customer application

Use this workflow when the user asks Purple to acquire a hardened container base or migrate their application's Dockerfile. The coding agent owns the migration and application checks. The bundled helper inventories the chosen Dockerfile, can explicitly acquire a selected provider image, and prepares local review artifacts; it does not build or run the application. A hardened base reduces the base image's attack surface. It does not guarantee zero CVEs or establish that the resulting application image is secure.

Use the installed helper at `tools/hardened-image.mjs` in the community package, or `offense hardened-image`. The community CLI requires Node.js 24+. Image acquisition also needs an existing Docker CLI connection. No Purple account, hosted scan key, model key or new provider connection is required.

## Select the image and stage

Inspect the existing Dockerfile and application requirements before choosing a replacement: runtime major/minor, Linux distribution and libc, target architecture, native dependencies, startup command, user permissions and required build/runtime tools. Preserve an existing supported runtime version where the provider offers it; do not combine a hardening migration with an unreviewed language upgrade.

The helper accepts only explicit image references under these provider prefixes:

| Provider | Accepted prefix | Selection and access |
| --- | --- | --- |
| Docker Hardened Images (DHI) | `dhi.io/` | Community images are free, but pulls require existing Docker authentication for `dhi.io`. Choose an available versioned tag or digest and the appropriate Debian/glibc or Alpine/musl variant. Build variants normally use `-dev`; runtime variants have fewer tools. |
| Chainguard public images | `cgr.dev/chainguard/` | Free images can be pulled without authentication. Their free tags are `latest` and `latest-dev`, which track the newest build and can change runtime majors. Version-specific Production images require separate entitlements and organization registry references, which this helper does not accept. |
| Google Distroless | `gcr.io/distroless/` | Select a documented runtime and distribution, such as a matching `nodejs22-debian13` image, and an explicit variant tag such as `nonroot`. Runtime images omit shells and package managers; prepare dependencies in a compatible builder. Do not assume every Python minor or Node major is available. |

Check the provider's current catalog before selecting a tag. The prefix allowlist identifies a supported source, not a verified publisher signature or a compatibility guarantee. Both a tag (`dhi.io/node:22-debian13`) and a digest (`dhi.io/node@sha256:...`) must be explicit; do not invent a digest or use the ellipsis example literally. The Node tag used below appears in Docker's [official Node 22 catalog definition](https://github.com/docker-hardened-images/catalog/blob/main/image/node/debian-13/22.yaml); the helper still needs acquisition evidence to establish its current digest and platform.

DHI documents its [authentication and variants](https://docs.docker.com/dhi/how-to/use/), [live catalog interfaces](https://docs.docker.com/dhi/how-to/search-evaluate/) and [glibc/musl choices](https://docs.docker.com/dhi/explore/security-concepts/glibc-musl/). Chainguard documents [registry access](https://edu.chainguard.dev/chainguard/containers/registry/) and [free-tier version limits](https://edu.chainguard.dev/chainguard/containers/migration/migrations-overview/). Distroless lists [currently supported runtimes, distributions and architectures](https://github.com/GoogleContainerTools/distroless#what-images-are-available).

`--project` selects the application root. `--dockerfile` is a path relative to that root and defaults to `Dockerfile`; its name accepts ASCII letters, digits, underscores, periods, slashes and hyphens, with no whitespace, control characters, parent traversal or symlinks. The final stage is selected by default; use `--stage` with an existing stage alias or its zero-based index to select another stage. Targeting a builder stage does not establish that the final runtime stage was hardened.

The parser supports ordinary `FROM [--platform=...] IMAGE [AS alias]` instructions, including supported line continuations. It declines ambiguous or unsupported targets, including unresolved `ARG` image references and stages that inherit a local stage alias. Read the recorded blockers instead of treating the absence of a candidate as a successful migration. A generated candidate changes the selected `FROM`; it is not a complete multi-stage migration.

## Preview, then acquire explicitly

Preview inventories the local Dockerfile and selected reference without running Docker, contacting registries, checking for skill updates or writing artifacts:

```sh
offense hardened-image \
  --project /absolute/path/to/application \
  --image dhi.io/node:22-debian13 \
  --platform linux/amd64 --preview
```

Choose `linux/amd64` or `linux/arm64` explicitly. Confirm the selected tag supports that platform; support in a provider's catalog does not mean every tag has both architectures. A `FROM --platform` constraint must agree with the requested platform or be resolved in the migration review.

Without `--pull`, normal mode checks the skill updater and writes a migration plan without invoking Docker, inspecting a local image or acquiring one. Add `--pull` when acquiring the selected image is within the user's requested task:

```sh
offense hardened-image \
  --project /absolute/path/to/application \
  --dockerfile Dockerfile --stage runtime \
  --image dhi.io/node:22-debian13 \
  --platform linux/amd64 --pull \
  --output /tmp/application-hardened-base
```

Omit `--stage runtime` if that alias does not exist or to select the final stage. Output must be a fresh directory outside the application checkout; omitting `--output` chooses a temporary directory. Keep these reports outside the build context.

`--pull` uses the existing Docker CLI, current context and registry authentication. The helper does not log in, read tokens or credential-store contents, create subscriptions, build an application, start a container, export an image or deploy anything. Preserve the selected account and Docker context. If the registry denies access, report that acquisition failure and the specific access required; do not read secrets, initiate an account flow or silently substitute an unrelated image. A remote Docker context stores the acquired image on that remote daemon.

For DHI, the operator must already have authenticated Docker to `dhi.io`; a free Docker account is sufficient for Community access. Treat registry authentication and publisher verification as separate checks. The helper does not upload project source, reports or image bytes to Purple.

Community tools do not contact a company update service or replace installed files automatically. Update the package explicitly through your chosen package/repository manager. Start a new coding-agent session after changing installed skill instructions. Help and `--preview` stay offline.

## Read the evidence before migrating

Read `hardened-image.json` and `remediation.md` in the reported output directory. A safely targetable `FROM` and a supplied digest or digest resolved by acquisition may also produce `Dockerfile.candidate` and `migration.patch`. A supplied digest can produce an unverified plan without `--pull`; it remains `supplied_not_resolved`, with metadata unassessed. The helper leaves application files unchanged. The candidate can still have compatibility blockers; its presence is not a passed migration check.

Keep the evidence states separate:

| Report field | States and limits |
| --- | --- |
| `acquisition.status` | `not_requested`, `acquired` or `failed`. Acquisition requires the pull and matching immutable metadata to succeed; preserve failures even if some layers downloaded. A plan without `--pull` invokes no Docker commands. |
| `digest.status` | `not_resolved`, `supplied_not_resolved` or `resolved`. A supplied digest is not evidence that the image exists or supports the requested platform. A resolved digest binds content; it does not identify a trusted publisher. |
| `metadata.status` | `not_assessed`, `available` or `failed`. Available metadata records matching immutable reference, image configuration digest, platform and a bounded configuration summary. Environment variables, labels and raw command arguments are excluded. |
| `signature.status` | `not_assessed`. Record independent signature checks against the exact selected digest and expected publisher. Verify the relevant provenance attestation separately before claiming verified build provenance. |
| `compatibility.status` | `blocked` or `requires_review`, based on bounded static inspection. Matching a runtime name is not proof that native libraries, interpreter paths or application startup work. |
| `applicationBuilds.status` | `not_run`, including baseline and candidate. Record the agent's separate baseline and candidate build results. |
| `applicationTests.status` | `not_run`, including baseline and candidate. Record the same application checks on both; absent or failed checks are not passes. |
| `vulnerabilityScan.status` | `not_run`. Neither acquisition nor a candidate Dockerfile is vulnerability-scan evidence. |
| `proposal.status` | `unavailable`, `not_generated` for preview, or `available_requires_review`. A proposal can retain compatibility blockers and has never been applied or tested by the helper. |

The configuration summary retains a numeric or recognized user, its known privilege state, a recognized entrypoint executable, argument counts and a bounded working directory. Named-user UIDs and the full configuration still require independent local inspection through the agent's existing tools. Avoid exporting environment values or raw inspection output. Do not hardcode one UID or assume that every provider variant has identical tools. DHI's generic migration checklist and individual image variants can specify different users. Chainguard Node has standard, slim, dev and full variants with different tool sets; inspect the chosen variant. See [DHI migration considerations](https://docs.docker.com/dhi/migration/checklist/) and [Chainguard Node compatibility notes](https://images.chainguard.dev/directory/image/node/overview).

## Verify the publisher and SBOM separately

Resolve the selected tag to an immutable digest, then verify and use that exact digest. For a multi-platform image, record the index digest, selected platform and platform manifest digest when available. Verify the artifact to which each signature or attestation applies; do not substitute an image configuration ID or borrow evidence from another platform. A mutable tag checked later can refer to different bytes. Pinning also prevents automatic receipt of future fixes, so record how reviewed digest updates will be tested.

The helper records signature verification as unassessed. The agent can use already available provider tools to perform the following checks without reading credentials. Tool absence, registry access failure, missing attestations and verification failure stay explicit; do not convert them into a passed state.

### Docker Hardened Images

DHI image layers are served by `dhi.io`, while signed attestations are stored in `registry.scout.docker.com`. Use Docker Scout to discover the attestations for the pinned reference and selected platform, then retrieve and verify the required SBOM/provenance attestation. For example, with `IMAGE_REF` set to the exact acquired digest reference:

```sh
docker scout attest list "$IMAGE_REF" --platform linux/amd64
docker scout attest get "$IMAGE_REF" \
  --predicate-type https://cyclonedx.org/bom/v1.6 --verify \
  --platform linux/amd64
```

For registry evidence when the image exists locally, follow Scout's documented `registry://` reference form. The alternative is to discover the attestation artifact and verify its signature with Cosign against Docker's published DHI key at `https://registry.scout.docker.com/keyring/dhi/latest.pub`. Check that the verified attestation's subject matches the selected image digest and platform; verifying an unrelated signed artifact does not verify the acquired base.

Some DHI attestations omit public Rekor entries. Docker documents explicit `--skip-tlog`/`--insecure-ignore-tlog=true` modes that still validate its key signature. Record such an exception and its reason rather than silently weakening a failed verification. Registry access for Cosign may require existing authentication to both DHI and Scout. Follow the current [DHI verification guide](https://docs.docker.com/dhi/how-to/verify/) rather than assuming that a generic `cosign verify dhi.io/...` invocation verifies these external attestations.

### Chainguard public images

For public `cgr.dev/chainguard/` images, constrain Cosign to the exact documented issuer and release-workflow identity:

```sh
cosign verify \
  --certificate-oidc-issuer=https://token.actions.githubusercontent.com \
  --certificate-identity=https://github.com/chainguard-images/images/.github/workflows/release.yaml@refs/heads/main \
  "$IMAGE_REF"
cosign verify-attestation \
  --type https://spdx.dev/Document \
  --certificate-oidc-issuer=https://token.actions.githubusercontent.com \
  --certificate-identity=https://github.com/chainguard-images/images/.github/workflows/release.yaml@refs/heads/main \
  "$IMAGE_REF"
```

Use the selected platform's image manifest digest where required and check the attestation subject. Organization Production images use different Enforce signing identities; the public identity cannot verify those images, and those organization references are outside this helper's allowlist. Follow [Chainguard signature verification](https://edu.chainguard.dev/chainguard/containers/security-and-compliance/verifying-chainguard-images-and-metadata-signatures-with-cosign/).

Chainguard also supports downloading an SPDX SBOM with `cosign download attestation --platform ... --predicate-type https://spdx.dev/Document`. Downloading or decoding an attestation is not signature verification; use `verify-attestation` and validate its subject before treating its contents as publisher-verified. See [SBOM retrieval](https://edu.chainguard.dev/chainguard/containers/security-and-compliance/retrieve-image-sboms/).

### Google Distroless

Verify the exact selected image digest with its documented keyless identity:

```sh
cosign verify \
  --certificate-oidc-issuer=https://accounts.google.com \
  --certificate-identity=keyless@distroless.iam.gserviceaccount.com \
  "$IMAGE_REF"
```

The [official Distroless verification instructions](https://github.com/GoogleContainerTools/distroless#how-do-i-verify-distroless-images) document this image-signature check. Do not infer a verified publisher SBOM from an image signature. Discover and verify a publisher SBOM separately if one is available for the selected digest; otherwise record it as unavailable or unassessed. An SBOM generated locally from the final application image is useful inventory, but it is different evidence from a verified publisher attestation for the base image.

## Complete the agent-owned migration

Use `remediation.md` as the handoff to the current coding agent. Review the candidate diff and recorded blockers before applying changes within the user's authorized scope. Preserve unrelated work. If safe parsing or immutable resolution failed, prepare a manual migration from the original Dockerfile and explain the blocker; do not claim the helper produced a valid candidate.

For Node, move dependency installation and compilation into a compatible builder, copy production dependencies and built assets into the runtime, and review native addons and shell/npm startup wrappers. For Python, build dependencies in a matching dev environment and preserve the virtual environment's absolute paths. Distroless Python has specific ABI and interpreter-path constraints documented in its [Python reference](https://github.com/GoogleContainerTools/distroless/blob/main/python3/README.md). Do not copy musl-built native modules into a glibc runtime or mix architectures. Install required operating-system libraries deliberately; a minimal runtime may not include them.

Before executing any application build or test, inspect the existing build context and both `.dockerignore` and Dockerfile-specific ignore files. Preserve their exclusions. Use the existing authorized builder/context and test environment; do not silently switch to a remote builder, widen the source context, pass real application secrets, or mount host credentials. Keep the local evidence directory outside every build context. A remote builder can receive the chosen source context, so preserve the user's source-sharing scope. The acquisition helper itself never sends that context.

Establish the original image's passing build and normal application tests in an isolated test environment with synthetic configuration. Run the same build, startup/health and normal test commands against the exact candidate image, covering dependency loading, native extensions, permissions and expected application behavior. Keep baseline and candidate evidence tied to their source trees, Dockerfiles, image digests and target platform. Inspect both successful and failed results; do not weaken or remove checks to make a hardening change pass.

Generate or scan the final application image when requested, with explicit coverage and current database information. Base-image metadata or an SBOM-only scan cannot establish the final image's vulnerability status. A complete current scan with no known matches is bounded evidence, not a zero-CVE guarantee or a proof of security. Any hosted image/artifact scan is a separate explicit upload workflow; acquiring a hardened base does not authorize uploading application images or source.

Return the acquired/pinned reference, provider, platform, selected stage, actual migration diff, independent verification results, baseline/candidate build and test results, and remaining blockers. Claim acquisition only when its recorded checks succeeded, distinguish a publisher signature from a verified build-provenance attestation, and claim a passing application migration only when its separate checks passed. Leave production deployment to an explicitly requested deployment workflow.
