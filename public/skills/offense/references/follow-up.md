# Continue from the user's choice

An assessment-only request ends after findings, coverage and choices. Ask which
issue the user wants explained, investigated or fixed. Do not require another
confirmation for a continuation already explicitly authorized in the request.

**Explain:** use saved receipts and context. No scan, spending, upload, dependency
installation or application edit is needed merely to explain an existing finding.
State evidence age and uncertainty instead of refreshing silently.

**Investigate:** identify the specific missing fact and use existing authorized
local inspection first. New uploads, active testing, credential verification or
paid checks require the same scope and budget contracts as an initial assessment.
Do not turn uncertainty into a claim of exploitability or non-applicability.

**Fix selected findings:** first check that the current revision, affected input
and dependency/artifact identity still match the evidence. If they changed,
reassess applicability within authorized scope before editing. Honor a request
to fix one finding, not the entire inventory. Use an isolated environment when
executing project code or installing dependencies. Establish baseline tests,
make compatible changes, run the same checks and rescan the final changed inputs.
Follow [verification](verification.md) and the entry skill's remediation guidance.
Security regression evidence should fail for the actual issue before the fix
and pass after; setup failures and compatibility tests alone do not prove that.

Record every selected finding's outcome, exact commands/results, revised input
identity and remaining coverage gaps. Keep original evidence. A stale receipt
or partial rescan cannot establish a verified fix. Preserve unselected findings
as unresolved inventory. Publication, merge and deployment require their own
applicable user authorization; a fix request does not imply them.
