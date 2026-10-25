# ADAudit developer handoff

Prepared 25 October 2026. Current runner version: **v9.2.1**.

Finish the audit's progress visibility, bounded remote collection and performance improvements, then validate the customer reports and package a reproducible release. The reports serve both AD specialists planning remediation and customers reviewing their position over repeated engagements.

This is an implementation handoff. The tasks below are pending unless explicitly listed as completed. In particular, the requested public parameter **`-IsolateHost` is not yet implemented**; the current source still uses `-IsolatedClone`.

## Starting point and constraints

Repository: `C:\Users\Niclas Skarnes\Github\adaudit`.

The working directory contains substantial uncommitted changes and an untracked tests directory. Capture the complete working directory in a reviewed Git checkpoint before starting; checking out the existing committed revision alone will omit recent work. Preserve unrelated local files, including `.claude/`.

- Target PowerShell 7 on Windows. Retain supported module compatibility paths.
- The standard audit retains its existing DSInternals password-quality and duplicate-password checks. The standalone Password Audit remains a separate paid service and must not be added to `-all`.
- Reports must stand alone. Do not introduce a requirement to load an older audit or automatically label findings resolved. Preserve the existing optional lateral-movement baseline feature.
- Collection must not change AD objects, target services, firewall rules or management configuration to obtain access.
- Missing evidence must remain visibly unassessed. Disabled accounts, unknown account state and unavailable password material must remain distinct from enabled-account exposure and confirmed empty-password evidence.
- Do not write hashes, passwords, HIBP query material or replicated credential objects into progress messages or diagnostic logs.
- Keep collected evidence separate from derived report downloads. A report rebuild must not modify the original evidence files.

## Implemented work to preserve

- Run folders use readable local timestamps, such as `2026-10-25_11-28-24`, with collision suffixes. Metadata retains run identity and time information.
- Standard and standalone reports have dark/light theme support.
- Isolated-copy mode excludes remote operational probes and identifies snapshot limitations.
- Remote collection recognizes local short names/FQDNs and uses local collection or CIM/DCOM where supported, with optional WSMan fallback.
- Overall selected/skipped counts, phase progress and progress cleanup are implemented. The parent progress bar now repeats the current operation and target.
- Domain Audit service collection uses one filtered query per DC for the selected services, rather than five separate queries. Target-start progress is forced through throttling before the blocking call.
- ACL SID translations are cached. Standard password replication results are already cached for reuse within a run.
- Collected CSVs remain in `Raw Data/Source`; generated download tables use `Raw Data/ReportDownloads`.
- Account-state, computer-activity and several evidence-interpretation corrections have regression coverage.

The most recent supplied run used **Connected** mode despite running against an isolated copy. Domain Audit took approximately 511 seconds. That observation identifies repeated remote waits as a priority for investigation; it is not a measured performance result for the new service-batching fix.

## Code map

| Location | Responsibility and starting points |
|---|---|
| [AdAudit-PS7.ps1](<C:/Users/Niclas Skarnes/Github/adaudit/AdAudit-PS7.ps1>) | Public parameters, check selection, initialization, isolated-copy defaults, run metadata and final report invocation |
| [ADAudit-GUI.ps1](<C:/Users/Niclas Skarnes/Github/adaudit/ADAudit-GUI.ps1>) | Isolation checkbox, snapshot date, command preview and process launch |
| [ADAudit.Common.ps1](<C:/Users/Niclas Skarnes/Github/adaudit/Library/ADAudit.Common.ps1>) | `Write-ADAuditProgress`, `Invoke-AuditCheck`, `Invoke-AuditStep`, `Get-ADAuditCimInstance`, `Invoke-ADAuditCimMethod`, local-host detection, remote-target guard, coverage records and replication cache |
| [Invoke-DomainAuditCheck.ps1](<C:/Users/Niclas Skarnes/Github/adaudit/Checks/Invoke-DomainAuditCheck.ps1>) | Check 2; start with `Get-CriticalServicesStatus`, `Get-LastWUDate`, `Get-TimeSource`, share and SMB collectors |
| [Invoke-HealthCheck.ps1](<C:/Users/Niclas Skarnes/Github/adaudit/Checks/Invoke-HealthCheck.ps1>) | Native diagnostics, events, services and other potentially blocking health operations |
| [Invoke-PortConnectivityCheck.ps1](<C:/Users/Niclas Skarnes/Github/adaudit/Checks/Invoke-PortConnectivityCheck.ps1>) | Candidate for bounded parallel target probes; remote-origin probes currently require remote execution |
| [ADAudit.Report.ps1](<C:/Users/Niclas Skarnes/Github/adaudit/Library/ADAudit.Report.ps1>) | Management reports, evidence previews, companion wrapping and final assembly |
| [Tests](<C:/Users/Niclas Skarnes/Github/adaudit/Tests>) | Offline fixtures and regression harnesses |

## Task 1 Rename the public isolation option

**Required public spelling:** `-IsolateHost`.

Update parameter declaration and references, validation messages, GUI command generation, help, examples and tests. Use an understandable GUI label such as “Isolated host”. Preserve the existing collection behavior; this rename does not expand the tool into a different type of host audit.

Recommended compatibility implementation:

```powershell
[Alias('IsolatedClone')]
[switch]$IsolateHost = $false
```

Use the new variable in runner decisions and map it to the existing internal isolation state. Retaining internal identifiers or saved `AssessmentMode` values is acceptable for compatibility; avoid a blind repository-wide replacement. If saved metadata changes, readers must accept both old and new values.

`-SnapshotDate` remains optional and must require the isolation switch. Its date annotates the source copy; it does not rewind the clock or make time-based observations current production evidence.

**Acceptance criteria**

- `-all -IsolateHost` works from CLI and GUI.
- The legacy alias, if retained, produces identical behavior.
- GUI preview and launched arguments agree, including quoting.
- Invalid or future snapshot dates are rejected before collection.
- Nonlocal excluded targets are recorded as unassessed before opening remote connections.
- Existing saved reports and metadata remain readable.

## Task 2 Add live waiting status and enforceable deadlines

Current progress is updated when PowerShell control returns to the script. During a synchronous remote call, the last message can remain unchanged. Existing CIM operation timeouts do not establish a complete wall-clock deadline covering discovery, connection setup, fallback and every other blocking collector.

Implement a coordinator-owned waiting loop around cancellable collection work. Suggested UI interval: about five seconds. Show check number, phase, target, elapsed time and whether a response is awaited. Show percentages only for measurable completed units; never advance a percentage simply because time passes.

Apply a configurable end-to-end deadline to the selected operation or target. Include fallback attempts within that deadline. On expiry, stop or isolate the work, dispose sessions/processes, preserve completed results, record the gap and continue. Merely stopping the wait while leaving workers running is insufficient. Use process isolation where a native call cannot be reliably cancelled in a runspace.

Keep separate outcomes for success, timeout, unreachable transport, access denied, unsupported operation and intentional exclusion. Success means collection succeeded, not that a security control passed.

**Acceptance criteria**

- A deliberately blocked fixture emits periodic waiting updates before completion.
- Deadline expiry returns control within a documented grace period, including during fallback.
- No worker, session or diagnostic process remains active after cancellation or run completion.
- Completed data survives a later timeout; unavailable data never becomes an empty successful result.
- Both progress records are cleared on success, failure and cancellation. Console logging is throttled.

## Task 3 Reduce repeated connection attempts

Introduce a run-scoped, expiring cache for transport reachability and reuse suitable sessions. Key results by normalized target and protocol, with identity/options included where they can vary. Reset the state between runs.

Cache genuine connection failures briefly. An access-denied error for one operation must not suppress unrelated queries, and a DCOM failure must not prohibit a supported WSMan attempt. Preserve a coverage record for every skipped operation, explaining that a recent connection failure prevented another attempt.

Do not remove the existing password-replication cache or duplicate sensitive replication work while introducing this layer.

**Acceptance criteria**

- Repeated checks against an unavailable target do not repeatedly incur the same connection delay within the cache lifetime.
- Expiry permits another attempt; a recovering target can be collected.
- One operation's permission failure does not mark the host unreachable.
- Target/protocol results cannot leak into another target or a subsequent run.

## Task 4 Introduce bounded parallel collection

Implement after deadlines and cancellation work. Begin with independent target probes within a check, not simultaneous execution of all top-level checks. Start conservatively with two workers; make concurrency configurable and benchmark before raising the limit.

The runner currently shares `$script:` state, failure lists, coverage lists, current-check context, evidence paths and report output. Existing top-level check functions must not simply be placed inside `ForEach-Object -Parallel`.

Workers should receive explicit inputs and return typed results containing target, operation, outcome, elapsed time, evidence and error details. A single coordinator merges results, updates coverage/progress and writes shared files. Keep final report assembly serial. Initialize required modules in workers and preserve useful types across worker boundaries. Serialize or reuse credential-replication collection rather than running duplicate replication jobs.

**Acceptance criteria**

- Serial and parallel fixtures yield equivalent findings and coverage after excluding ordering, timestamps and timing fields.
- Workers cannot overwrite each other's evidence or misattribute failures to another check.
- Concurrency never exceeds the configured limit, including fallback work.
- Timeout/cancellation tests leave no orphan workers.
- Pilot measurements show elapsed time, DC resource impact and result equivalence. Retain a serial mode for troubleshooting.

## Task 5 Validate report behavior and pilot the collectors

Run an authorized pilot against both a connected AD and an isolated host. Include an unreachable DC, denied access, WinRM unavailable with DCOM usable, optional modules unavailable, a selected-check subset and an old directory copy.

Review account-state findings, machine-activity candidates, missing password material and partial collection with an AD specialist. Confirm that operational observations from an isolated copy are not presented as current production conditions.

Inspect primary and companion HTML, including standalone Password Audit output, in light/dark mode, a narrow viewport and print preview. Verify filters, navigation, evidence links, CSV downloads, actionable remediation guidance and empty/partial states. Confirm the displayed coverage agrees with the manifest and check-status CSV.

Run report generation twice and verify collected source files remain byte-for-byte unchanged. Do not silently regenerate a clean assessment from malformed or missing evidence. Use synthetic/redacted fixtures for development; do not commit customer exports or credential data.

## Tests and release completion

The latest v9.2.1 progress/service changes passed **40 focused offline tests** across Core, DomainServices and RemoteCollection. That is not a claim that the final future implementation has passed the full suite or a live AD pilot.

Relevant existing suites:

- Core and ProgressChecks: progress, cleanup, run-folder handling and shared report context.
- DomainServices and RemoteCollection: batching, transport selection, local-host recognition and isolation guards.
- HealthCollector: health evidence and incomplete collection.
- AccountChecks, AccountSeverity, SecurityChecks and LateralSeverity: account state and evidence interpretation.
- Report and PasswordLookup: report generation, evidence integrity and password lookup behavior.

From the repository root, the existing harness is:

```powershell
$standalone = @(
    'Report.Tests.ps1',
    'PasswordLookup.Tests.ps1',
    'ProgressChecks.Tests.ps1',
    'LateralSeverity.Tests.ps1'
)
$testFiles = Get-ChildItem .\Tests\*.Tests.ps1 |
    Where-Object Name -notin $standalone
$result = Invoke-Pester -Script $testFiles.FullName -PassThru
if ($result.FailedCount -gt 0) { throw 'Pester regression failure' }
foreach ($testName in $standalone) {
    pwsh -NoProfile -File (Join-Path .\Tests $testName)
    if ($LASTEXITCODE -ne 0) { throw "Regression failure: $testName" }
}
```

Existing validation used Pester 3.4.0 under PowerShell 7. Verify the harness before changing Pester versions. Add tests for the rename, heartbeat, hard deadlines, cache expiry, cancellation and serial/parallel equivalence. Run parser checks and `git diff --check` as part of final validation.

Deliver the reviewed code checkpoint, full test results, pilot timings and coverage findings, updated CLI/GUI documentation, versioned release notes and the complete deployment folder. Clearly identify any remaining operational limitations. The final package must include the shared libraries, checks and standalone Password Audit dependencies; copying only the runner is insufficient.
