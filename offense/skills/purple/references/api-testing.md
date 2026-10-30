# API tests in a local sandbox

Use this mode when the user asks to exercise an API and you can prepare a disposable Node/Python app with an OpenAPI 3.0/3.1 schema. It complements static source, dependency and specification checks. It executes the chosen application and generates requests, so use synthetic data and test-only dependencies. It is not a hosted production-target scanner.

## Prepare the runtime once

The installed skill includes a pure-data `tools/api-test-image.mjs` resource containing the inspected Dockerfile, Python runner and ignore file. Materialize them in a fresh directory outside the project, inspect them, then build the pinned Schemathesis 4.32.4 image explicitly:

```sh
offense api-test --write-image-context /tmp/purple-api-test-image
docker build -t purple-api-test:4.32.4 /tmp/purple-api-test-image
```

Writing the context executes no Docker command or application code. Existing customized or unrelated context files are preserved; choose a new directory when they differ. Building fetches the pinned base/package and their dependencies. Runs never pull images or install project packages. If local Docker is unavailable, report that concrete limitation; do not substitute an unisolated run or a production URL.

## Run the selected test app

Prepare a small self-contained app directory. Include only the runtime files and prepared dependencies it needs. The image includes Node 24 and Python 3; it does not include the project's package installations, external database or service connections. Environment variables from the user's machine are not forwarded. Hidden files, credential filenames, symlinks and unsupported names are omitted and counted; do not treat omitted files as tested.

The helper first previews its input and bounds without executing the app or contacting any service:

```sh
offense api-test \
  --project /tmp/my-test-app --schema /tmp/my-test-app/openapi.json \
  -- node server.mjs
```

Then execute the same snapshot:

```sh
offense api-test \
  --project /tmp/my-test-app --schema /tmp/my-test-app/openapi.json \
  --run --output /tmp/api-evidence --seconds 20 --examples 10 --max-requests 200 \
  -- node server.mjs
```

The app must listen on `127.0.0.1` using the supplied `PORT` (default 8765). `--port` can select another unprivileged port. The startup command is an argv list after `--`; supported executables are `node` and `python3`, with no shell interpolation. The helper starts separate disposable app and scanner containers. They share only the app's network-disabled namespace; their filesystems and process namespaces are separate, so application code cannot rewrite scanner reports, disable its guard or terminate its processes. Both use a nonroot user, dropped capabilities, a read-only image, memory/CPU/process limits and bounded temporary storage, with no host filesystem mounts or published ports. Source bytes pass only to the local app container through standard input. The scanner receives only its local schema, bounds and generated synthetic test token.

Schemathesis may connect only to the chosen literal loopback address and port. Redirect following is disabled. Remote and filesystem `$ref` values, callbacks, webhooks and unsupported schema versions are rejected; schema server URLs are replaced with the local target. A request counter and time budget bound execution. The snapshot is capped at 5,000 regular files, 32 MiB total, 8 MiB per file; the schema is capped at 256 KiB and 25 operations. No networked dependency installation or production scan occurs.

The runner supplies a freshly generated `PURPLE_TEST_TOKEN` to the app and uses that synthetic bearer token for test requests. A test-only app fixture can recognize it to exercise authenticated routes. Applications requiring another login method or real credentials need a purpose-built synthetic authentication fixture; unreachable protected routes keep the report partial. Object-level authorization and cross-operation stateful testing are explicitly unassessed in this version. Do not infer they passed.

## Interpret and verify

Read the local `api-test.json` output. It retains fixed rule codes, operation indices/methods, bounded coverage counts, the seed and a local snapshot hash. It omits API paths, titles from the schema, raw requests/responses, tokens, headers, application output and free-form scanner errors. Map a zero-based `operationIndex` to the schema's path/method insertion order locally. The same snapshot, schema, command and seed can rerun the bounded test generation; timing and shrinking mean this is not a byte-exact exploit replay artifact.

- `ignored_auth` is a **security candidate**: confirm that the operation should require authentication and write a focused missing/invalid-auth regression.
- `not_a_server_error` is a **robustness candidate**: a generated input produced a 5xx. Determine security impact; a server error alone is not a confirmed vulnerability.
- `negative_data_rejection` is a **validation candidate**: decide whether the schema or implementation is wrong before proposing a fix.
- `failed` means invalid setup, input, startup or scanner execution. `partial` means some coverage, credentials, generation or execution was incomplete. Neither establishes a clean scan.

`complete` means the selected bounded checks ran with valid inputs accepted for each declared operation; it does not mean the API is secure. All reports keep `confirmedVulnerabilities: 0`. Process and filesystem isolation protect the scanner's evidence, but a scanner result still requires application-specific review and a focused regression before security confirmation.

For a fix, preserve the before report, write a focused security regression, patch the issue, run normal tests, and run this helper again against the patched snapshot with the same seed. Preserve the after report separately. Keep candidate and confirmed evidence distinct in the remediation prompt or PR. Source, reports and test identities stay local; there is no automatic upload.

Community tools do not perform automatic company-hosted updates. Help and preview stay offline. After explicitly updating installed skill instructions, **start a new agent session** before your next task.
