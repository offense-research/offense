# Third-party notices

Project-owned code is Apache 2.0. Upstream dependencies and source excerpts retain their own licenses. Installing dependencies is separate from redistributing a bundled binary or image.

## Direct runtime dependencies

| Package | Version | License | Text |
| --- | --- | --- | --- |
| @babel/parser | 7.29.9 | MIT | [License](licenses/babel_parser-7.29.9-LICENSE) |
| @babel/traverse | 7.29.10 | MIT | [License](licenses/babel_traverse-7.29.10-LICENSE) |
| @modelcontextprotocol/sdk | 1.32.1 | MIT | [License](licenses/modelcontextprotocol_sdk-1.32.1-LICENSE) |
| jsonc-parser | 3.3.1 | MIT | [License](licenses/jsonc-parser-3.3.1-LICENSE) |
| semver | 7.8.5 | ISC | [License](licenses/semver-7.8.5-LICENSE) |
| smol-toml | 1.9.1 | BSD-3-Clause | [License](licenses/smol-toml-1.9.1-LICENSE) |
| yaml | 2.9.1 | ISC | [License](licenses/yaml-2.9.1-LICENSE) |
| zod | 4.6.6 | MIT | [License](licenses/zod-4.6.6-LICENSE) |

## Source excerpts

The reference mitigation in `server/braces-remediation.js` contains context from braces 3.0.3, licensed MIT. The modification is a proposed reference patch, not an upstream fixed release or a verified fix for any application. Its upstream license is retained in [the braces license](licenses/braces-3.0.3-LICENSE).

## Scanner-rule provenance remains unresolved

`tools/internal/scan-rules.yml` is a byte-identical copy of the full platform's
`agent/scan-rules.yml`. The five original patterns first appeared in the private
platform history on 2026-10-22; eight request-to-sink rules and this package copy
were added on 2026-10-27. The commits record `ronny` / `imranye` as the author
identity, but do not establish independent creation or identify an upstream
source. The available Amp reconciliation history only witnesses integration of
pre-existing work. This is not evidence of copying from a particular upstream,
nor a clearance of the rules under the project license. Confirm original
authorship or any upstream sources, licenses and notices before publication;
otherwise replace or exclude the unresolved rules. The publication hold remains.

## Optional separately installed tools

This repository does not include scanner binaries or prebuilt scanner images. Local integrations can invoke Opengrep 1.32.0 (LGPL-2.1), Zizmor 1.31.1 (MIT), Schemathesis 4.32.4 (MIT), and an existing Docker/OCI runtime. Their original license and distribution requirements apply to those tools. A future bundled binary/image release needs an artifact-level inventory, notices and corresponding-source handling where applicable. Hardened base-image contents and terms depend on the exact selected provider artifact.

## Locked dependency inventory

This inventory describes the current npm lockfile, including transitive dependencies installed from the registry. Their package distributions retain upstream license texts. Regenerate this inventory when changing the lockfile.

| Package | Version | Declared license |
| --- | --- | --- |
| @babel/code-frame | 7.29.7 | MIT |
| @babel/generator | 7.29.8 | MIT |
| @babel/helper-globals | 7.29.7 | MIT |
| @babel/helper-string-parser | 7.29.11 | MIT |
| @babel/helper-validator-identifier | 7.29.7 | MIT |
| @babel/parser | 7.29.9 | MIT |
| @babel/template | 7.29.7 | MIT |
| @babel/traverse | 7.29.10 | MIT |
| @babel/types | 7.29.11 | MIT |
| @hono/node-server | 2.1.5 | MIT |
| @jridgewell/gen-mapping | 0.3.13 | MIT |
| @jridgewell/resolve-uri | 3.1.2 | MIT |
| @jridgewell/sourcemap-codec | 1.6.0 | MIT |
| @jridgewell/trace-mapping | 0.3.31 | MIT |
| @modelcontextprotocol/sdk | 1.32.1 | MIT |
| accepts | 2.0.0 | MIT |
| ajv | 8.20.0 | MIT |
| ajv-formats | 3.0.1 | MIT |
| body-parser | 2.4.0 | MIT |
| content-type | 2.1.0 | MIT |
| bytes | 3.1.2 | MIT |
| call-bind-apply-helpers | 1.0.2 | MIT |
| call-bound | 1.0.4 | MIT |
| content-disposition | 2.0.1 | MIT |
| content-type | 1.0.5 | MIT |
| cookie | 0.7.2 | MIT |
| cookie-signature | 1.2.2 | MIT |
| cors | 2.8.6 | MIT |
| cross-spawn | 7.0.6 | MIT |
| debug | 4.4.3 | MIT |
| depd | 2.0.0 | MIT |
| dunder-proto | 1.0.1 | MIT |
| ee-first | 1.1.1 | MIT |
| encodeurl | 2.0.0 | MIT |
| es-define-property | 1.0.1 | MIT |
| es-errors | 1.3.0 | MIT |
| es-object-atoms | 1.1.2 | MIT |
| escape-html | 1.0.3 | MIT |
| etag | 1.8.1 | MIT |
| eventsource | 3.0.7 | MIT |
| eventsource-parser | 3.1.1 | MIT |
| express | 5.3.0 | MIT |
| express-rate-limit | 8.7.1 | MIT |
| content-type | 2.1.0 | MIT |
| fast-deep-equal | 3.1.3 | MIT |
| fast-uri | 3.1.9 | BSD-3-Clause |
| finalhandler | 2.1.1 | MIT |
| forwarded | 0.2.0 | MIT |
| fresh | 2.0.0 | MIT |
| function-bind | 1.1.2 | MIT |
| get-intrinsic | 1.3.0 | MIT |
| get-proto | 1.0.1 | MIT |
| gopd | 1.2.0 | MIT |
| has-symbols | 1.1.0 | MIT |
| hasown | 2.0.4 | MIT |
| hono | 4.13.14 | MIT |
| http-errors | 2.0.1 | MIT |
| iconv-lite | 0.7.3 | MIT |
| inherits | 2.0.4 | ISC |
| ip-address | 10.7.5 | MIT |
| ipaddr.js | 1.9.1 | MIT |
| is-promise | 4.0.0 | MIT |
| isexe | 2.0.0 | ISC |
| jose | 6.2.13 | MIT |
| js-tokens | 4.0.0 | MIT |
| jsesc | 3.1.0 | MIT |
| json-schema-traverse | 1.0.0 | MIT |
| json-schema-typed | 8.0.2 | BSD-2-Clause |
| jsonc-parser | 3.3.1 | MIT |
| math-intrinsics | 1.1.0 | MIT |
| media-typer | 1.1.1 | MIT |
| merge-descriptors | 2.0.0 | MIT |
| mime-db | 1.54.0 | MIT |
| mime-types | 3.0.2 | MIT |
| ms | 2.1.3 | MIT |
| negotiator | 1.1.0 | MIT |
| content-type | 2.1.0 | MIT |
| object-assign | 4.1.1 | MIT |
| object-inspect | 1.13.4 | MIT |
| on-finished | 2.4.2 | MIT |
| once | 1.4.0 | ISC |
| parseurl | 1.3.3 | MIT |
| path-key | 3.1.1 | MIT |
| path-to-regexp | 8.4.2 | MIT |
| picocolors | 1.1.1 | ISC |
| pkce-challenge | 5.0.1 | MIT |
| proxy-addr | 2.0.8 | MIT |
| qs | 6.16.1 | BSD-3-Clause |
| range-parser | 1.3.0 | MIT |
| raw-body | 3.0.2 | MIT |
| require-from-string | 2.0.2 | MIT |
| router | 2.2.0 | MIT |
| safer-buffer | 2.1.2 | MIT |
| semver | 7.8.5 | ISC |
| send | 1.2.1 | MIT |
| serve-static | 2.2.1 | MIT |
| setprototypeof | 1.2.0 | ISC |
| shebang-command | 2.0.0 | MIT |
| shebang-regex | 3.0.0 | MIT |
| side-channel | 1.1.1 | MIT |
| side-channel-list | 1.0.1 | MIT |
| side-channel-map | 1.0.1 | MIT |
| side-channel-weakmap | 1.0.2 | MIT |
| smol-toml | 1.9.1 | BSD-3-Clause |
| statuses | 2.0.2 | MIT |
| toidentifier | 1.0.1 | MIT |
| type-is | 2.1.0 | MIT |
| content-type | 2.1.0 | MIT |
| unpipe | 1.0.0 | MIT |
| vary | 1.1.2 | MIT |
| which | 2.0.2 | ISC |
| wrappy | 1.0.2 | ISC |
| yaml | 2.9.1 | ISC |
| zod | 4.6.6 | MIT |
| zod-to-json-schema | 3.25.2 | ISC |
