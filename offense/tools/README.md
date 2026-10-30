# Editing the local tools

These modules are the readable source shipped by the community package. They do not require the private application repository or a company build service.

- `syntax.mjs` imports the installed, version-pinned Babel parser and traversal packages. Their licenses ship with those dependencies. No minified parser copy needs regeneration.
- `source-scan.mjs`, `internal/zizmor.mjs` and `internal/scan-findings.mjs` are ordinary editable JavaScript. The Opengrep rules live in `internal/scan-rules.yml`; the scanner reads this file directly.
- `api-image/Dockerfile`, `api-image/schemathesis-sandbox.py` and `api-image/.dockerignore` are the preferred editable API-sandbox image sources. After reviewing a change, run `node scripts/build-api-image-resource.mjs` from the package checkout to regenerate the pure-data `api-test-image.mjs`. Generation performs no network request, container build or application execution. `purple api-test --write-image-context DIRECTORY` materializes the same inspected inputs for an explicitly requested local build.
- `purple.mjs`, `reachability.mjs`, `evidence.mjs`, `workflow.mjs` and `rehearsal-runner.mjs` contain the local dependency workflow. The npm/pnpm metadata parsers are readable modules under `public/skills/purple/scripts/`; the small `metadata.mjs` and `pnpm.mjs` adapters here re-export them.
- `hardened-image.mjs` acquires a user-selected provider image only after explicit `--pull`; normal image planning never builds the application.

Run `npm test` after editing. The default suite uses synthetic inputs and mocked public providers; it does not run production targets or the optional API attack exercise. Keep provider refusals and incomplete verification visible as described in `../docs/provider-safeguards.md`.
