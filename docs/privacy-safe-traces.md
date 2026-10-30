# Privacy-minimized skill diagnostics

Offense 0.5 adds structured diagnostics to help explain failed scans and unfinished upgrade plans. It is live at `app.purpleteam.sh`; deployment and verification evidence is recorded in `docs/e2e/privacy-safe-skill-traces-production.json`. It does not collect coding-agent conversations or introduce a transcript-upload service.

Separate [skill usage aggregates](operations-metrics.md#anonymous-skill-and-mcp-usage)
retain only daily counts and fixed channel/operation labels, with no request
identifiers, dependency names or identities. These durable counters are not
trace records and are not subject to the seven-day trace expiry. Disabling trace
collection leaves aggregate usage collection enabled. Prior trace history is
not backfilled as lifetime audit statistics.

## Record only what diagnostics need

`shared/offense-trace.js` constructs events from a fixed vocabulary. The serializers accept only records created by that module; arbitrary input objects cannot become trace events. This boundary runs before a server database write or local trace export, rather than trying to remove PII from an already collected transcript.

Allowed fields are:

- Random UUIDv4 identifiers created inside the recorder for this run, request and event. There is no persistent installation, device, account or user identifier.
- Trusted helper/server release versions and fixed component, transport, stage, outcome, error and evidence-source codes.
- Internally generated timestamps rounded to the minute, and durations rounded to 100 milliseconds.
- Bounded numeric measurements: counts of packages, matches, plans, blockers, coverage warnings and planning pages.

Excluded fields include names, emails, phone numbers, IP addresses, locations, usernames, organization/repository/package names, paths, URLs, query strings, request/response bodies, headers, cookies, tokens, source, lockfiles, prompts, conversation text, terminal output, raw error messages/stacks, dependency fingerprints and hashes of identities. Unknown nested fields are not serialized. Arbitrary enum labels and error codes become fixed `unknown` values. Getters, coercion methods, inherited properties and `toJSON` cannot inject project content into records.

Opaque identifiers are generated internally, not accepted from request headers or JSON-RPC IDs. Server and helper run identifiers are independent. The service does not automatically link a local trace to a person or repository.

These are minimized operational diagnostics, not a claim of mathematically anonymous data, guaranteed absence of inference, or legal exemption. Ordinary API processing, account data and infrastructure access logs are separate from this diagnostic schema.

## Server storage and expiry

Server-observed API, native MCP and legacy skill requests use `server/offense-traces.js`. Every stored event passes the same constructor-owned serializer first. The service stores records in the existing SQLite database's `offense_trace_events` table, separate from account and vulnerability records.

Defaults are capped at 10,000 rows, four megabytes of serialized event data, 1,024 bytes per event and 32 events per request. Oldest records are removed to maintain the caps. Records expire seven days after their minute-rounded event timestamp and expired records are not returned by the internal reader. Pruning runs on startup, writes, reads and the existing Worker maintenance alarm; the local Node server also invokes pruning every minute. Physical removal follows successful maintenance rather than a promise about backup media or exact deletion scheduling.

No public trace-ingestion, trace-read or transcript-upload endpoint is introduced. The internal store reader validates records again before returning them; it is intended for trusted operator tooling. The ephemeral table is not added to the application's customer-data import allowlist. Trace persistence or cleanup failures stay quiet, never copy raw error data into logs, and do not change scan results. `OFFENSE_TRACE_ENABLED=false` disables new server trace collection; existing records still expire and are pruned.

## Local report and sharing

The helper writes `trace.json` beside an audit's existing reports. It records only actions the helper observes. Server events are server-observed; locally reviewed verification artifacts remain separately labeled. A skill being loaded, an offline action or an agent acting outside the helper does not establish a complete trace. Missing actions stay unknown.

The local trace is not uploaded automatically. Use `--no-trace` to disable creation; existing trace files are left unchanged, and the helper does not return an older trace as a new result. Share only the returned `trace.json` when `traceStatus` says it was saved. A trace-export failure does not invalidate a completed scan or imply that a safe file was written.

`audit.json`, `remediation.md`, terminal errors and local verification artifacts have a different purpose. They can contain dependency names, paths and other private project information and are not covered by the safe-to-share trace format. Do not bundle the whole report directory or a transcript and describe it as a scrubbed trace.

Local traces have no automatic deletion service; the user controls their files. Users can inspect a local trace before choosing to share it. Vulnerability discovery counts are not derived from trace events: metadata matches and reviewed local artifacts do not become confirmed discoveries through telemetry.

## Verification

The schema, helper and store tests seed fake names/emails/tokens, private package names, paths, source/prompt markers, raw provider responses and forged request identifiers. They check that those markers never enter trace JSON or SQL bindings, including rejection, network/provider failure, incomplete planning and disabled/export-failure cases. They also exercise expiry, hard bounds, storage failure and maintenance hooks.

The existing updater is still checked before normal installed helper commands. An installation update requires a new coding-agent session; diagnostics do not bypass that gate. Released 0.4 file hashes are retained so unchanged installations can update without losing customizations.

Design references: [OWASP logging guidance](https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html#data-to-exclude), [Cloudflare Durable Object alarms](https://developers.cloudflare.com/durable-objects/api/alarms/).
