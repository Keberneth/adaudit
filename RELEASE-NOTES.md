# ADAudit release notes

## v9.4.0 (26 October 2026)

### Focused AD security evidence

- Domain Audit now includes DC SMB client signing, insecure guest access, anonymous SMB restrictions/exception lists, available dialect configuration, and aggregated session protection evidence. Existing SMB1/server-signing findings are preserved without duplicate scoring. Missing properties remain unknown.
- SYSVOL, NETLOGON and additional disk-share inventory includes effective encryption requirements and both share/NTFS root ACE evidence. Broad authenticated read is expected. Extra shares, encryption exceptions and broad write/control ACE candidates require review and are unscored; static ACL observations do not prove effective access. Child-file overrides and full access-token evaluation are outside scope.
- LDAP now distinguishes configured signing/channel binding from certificate-validated LDAPS/StartTLS and the observed anonymous domain-object read. The StartTLS probe sends no credentials. Alternate resolved addresses share bounded probe budgets; endpoint success does not claim rejection of unprotected binds or effective CBT enforcement. A precise AD bind-required diagnostic is classified as rejection of the tested read, while generic operations errors remain unknown. Remote DCs in isolated-host mode are consistently Excluded.
- Both main reports retain positive, review, unavailable and excluded DC security observations with full CSV downloads. Structured LDAP severity replaces the earlier blanket High text-file interpretation; older evidence keeps its legacy fallback when no structured file exists.

### Clone pilot corrections

- Domain SID-500 password age uses the supplied snapshot date on an isolated host. Without that date, age remains unknown and does not gain severity merely because the clone aged; independent account risks remain. Renaming is Low-priority defense in depth, decoy accounts are optional, and recent logon evidence no longer automatically means misuse. The separate DSRM recovery account is clearly distinguished.
- DC-inapplicable SAM enumeration policies no longer produce anonymous-access findings. Applicable anonymous-permission settings retain explicit evidence and coverage.
- DNS zone aging is queried only where applicable, null timestamps are handled safely, and unknown values are distinguished from disabled settings. Real DNS collection errors now mark the check Partial and appear in coverage instead of leaving a misleading Completed result.
- Dependency imports remain visible after the module helper returns. Every wrapped operation records measured timing, status and coverage counts in `audit_step_timings.csv`; both main reports show the slowest operations. These measurements enable investigation of the Accounts delay without guessing its cause.

### Report presentation

- Risk-Report.html: the Interpretation score matrix again shows the colored Low/Medium/High/Critical level pills with the 0-49/50-99/100-149/150+ ranges and the earlier level descriptions, replacing the neutral Band 1-4 labels introduced with scoring methodology v2.1. The Priority basis line and the methodology and limits text stay. `report_summary.json` keeps the `IndexBand` key, now holding the matrix level, and the TXT summary prints the `Score matrix:` line again.

### Scope and deployment

All additions are read-only and remain focused on AD/DC security. No server baseline comparison or general server audit has been imported. The separate server-audit script and customer evidence are unchanged. Deploy the entire package because Domain Audit loads the new `Checks\Invoke-DcShareSecurityCheck.ps1` helper. No new GUI option is needed: the additions run with Domain Audit and `-all`.

The previously supplied isolated-host run (v9.3.1) completed 26 checks in about 11m15s, with 16 Completed, 10 Partial and no worker timeouts or orphaned workers. This is evidence for the previous build, not a live validation of these additions. Repeat the clone pilot with v9.4.0; connected multi-DC and real permission-restriction validation still require an authorized connected environment.

### Validation performed

- 619 regression checks passed across 23 suites: 253 Pester cases and 366 standalone assertions. All 57 PowerShell source/test files parsed successfully. Tests cover snapshot-aware account age, DNS applicability and coverage, LDAP diagnostics/TLS framing and deadlines, SMB tri-state values, share/NTFS evidence boundaries, snapshot-timeout evidence preservation, module visibility and Swedish decimal timing values.
- Nine generated report pages passed 99 headless-browser checks, including expanded DC evidence, theme controls, CSV downloads, local links, 390-pixel layout and light/expanded print behavior. The new dark-mode evidence section was visually inspected. These reports use synthetic fixtures.
- No live AD query or credential replication was performed by this validation. Existing runtime fixtures use synthetic workers/processes, local host metadata and loopback sockets. Customer evidence and the separate server audit script were not modified.

## v9.3.1 (26 October 2026)

### Connection-cache corrections

- TCP transport preflight attempts every distinct resolved IPv4/IPv6 address concurrently within one shared connect budget. A failed or slow first address no longer hides a reachable alternate; every socket is closed on success, failure or timeout. DNS retains its separate bounded resolver budget.
- A CIM query/provider timeout discards its session and remains a `Timeout` coverage result, without marking that transport unavailable or suppressing unrelated queries. Timed-out queries and methods are not retried through a fresh session or another transport. Connection-stage timeouts and explicit connection failures retain their existing caching and fallback behavior.
- New regression harnesses cover multi-address reachability, IPv4/IPv6 loopback sockets, shared deadlines, session/query timeout classification, and serial/parallel service-collection scenarios.

### GUI and report review fixes

- The GUI exposes **Advanced Options > Isolated host (-IsolateHost)** and passes the switch through the displayed command to the runner. The snapshot-date field now clearly states that it is optional; the description explains that remote DC operational checks are skipped. Dynamic tests verify the actual GUI command generation and date validation without opening a window or starting an audit.
- Report navigation is reconciled after final assembly so selected-check runs do not link to missing reports, while early-generated reports gain links to later outputs.
- Narrow-screen report tables scroll within the page. Printing uses a light background, hides interactive controls and exposes evidence sections; after printing, the prior disclosure state is restored without changing the selected theme.

### Pilot scope

The available customer pilot is one isolated DC clone, to be run by its owner. The clone commands and acceptance checks are in README.md under *Single-server clone pilot*. Offline validation and synthetic report review do not establish current live AD behavior. Connected multi-DC collection, actual remote permission restrictions and production performance still require a connected test environment. Earlier v9.3.0 measurements below are historical evidence, not measurements of this patch.

### Validation performed on 26 October

- 488 checks passed across 18 suites: 171 Pester cases plus 317 standalone assertions. All 51 PowerShell source/test files parsed successfully.
- The actual service collector and worker coordinator were exercised with synthetic directory/CIM responses for successful collection, unreachable DCs, denied access, provider timeouts, empty responses and isolated-host exclusions. Serial and parallel runs produced equivalent substantive results and coverage; worker cleanup passed.
- TCP tests include real IPv4/IPv6 loopback sockets plus deterministic pending/refused-address fixtures. No live AD queries or credential replication were performed. The worker runner fixture reads local host information only.
- Fresh Connected-complete, Connected-partial and IsolatedHost report fixtures passed 54 assertions (included in the total above): coverage/outcome labels, isolation banners, full CSV downloads, correct navigation after final assembly and unchanged source hashes/finding totals after rerendering.
- Headless Chrome passed 93 browser checks across nine generated pages (Audit Results, Risk Report and wrapped GPO report in each fixture mode): no broken local links, JavaScript errors or document overflow at 390 px; theme controls and CSV downloads work; print is light and expanded, and restores prior state afterward. Generated A4 PDFs were also inspected. This is synthetic report validation, not a review of new live clone output.

## v9.3.0 (25 October 2026)

Scope: progress visibility, bounded remote collection and performance (developer handoff Tasks 1 to 4), plus the regression coverage for them. Task 5 (authorized pilot and report review) is pending; see *Pilot checklist* below.

### Changes

**Isolation option renamed (Task 1)**
- Public parameter is `-IsolateHost`; `-IsolatedClone` remains as an alias with identical behaviour.
- `-SnapshotDate` requires `-IsolateHost`, must be a valid calendar date and cannot be in the future. Validation runs before any output folder or remote connection exists.
- GUI: checkbox *Isolated host (-IsolateHost)*, snapshot date and the new remote-collection fields are validated before launch; the launched command is exactly the preview text.
- Run metadata writes `AssessmentMode = IsolatedHost`; reports and companion wrappers accept both `IsolatedHost` and the earlier `IsolatedClone`.
- Report notice and exclusion messages now say *isolated host*; internal state names are unchanged.

**Live waiting status and enforceable deadlines (Task 2)**
- Every remote operation runs as a cancellable worker with an end-to-end deadline (`-TargetTimeoutSec`, default 60 s) covering name resolution, connection setup, the operation and transport fallback.
- While a call blocks, both progress records repeat check number, phase, target, elapsed/deadline seconds and "waiting for response" about every 5 s; console lines are throttled to every 30 s. Percentages are measured completed units only.
- On expiry the worker is stopped, its runspace disposed, the target recorded as *not assessed (Timeout)*, completed results kept, and the audit continues. Native tools (`dcdiag`, `repadmin`, `w32tm`) and operations that cannot be cancelled in a runspace (SYSVOL UNC access, replication partner metadata, DnsServer zone enumeration) run in child processes that are killed on expiry.
- Coverage records carry a collection outcome: `Timeout`, `Unreachable`, `AccessDenied`, `Unsupported`, `Excluded`, `Unavailable`. The report's coverage section shows the breakdown and the collection settings.
- A worker that ignores cancellation within the 5 s grace period is recorded as orphaned (console warning, `audit_run.json` → `Collection.Workers`), never reused, and its target stays not assessed.

**Fewer repeated connection attempts (Task 3)**
- Run-scoped, expiring cache of connection failures keyed by target, protocol and identity (`-ConnectionCacheSec`, default 300 s). Only *Unreachable* and *Timeout* are cached; access denied and unsupported operations are not. A DCOM failure never blocks a permitted WinRM attempt. Every skipped operation records the earlier failure and the time of the next allowed attempt.
- A name that does not resolve is recorded once for all transports without opening a connection. Before the first attempt on a transport a 3 s TCP probe of its port (135 DCOM/RPC/event log, 5985 WinRM, 445 SMB, 9389 ADWS) records a host that is down as unreachable without paying the protocol timeout. Short DC names and their domain FQDNs share one cache entry.
- CIM sessions are pooled per target and protocol, reused across checks, retried once with a fresh session on a reused-session failure, and disposed at the end of the run. The DSInternals replication cache is unchanged.
- Windows Update hotfix dates are now read over the same transport (`Win32_QuickFixEngineering`) instead of `Get-HotFix -ComputerName`; `w32tm` failures mark the target's RPC transport so the AD Health time-source query does not wait again.
- AD Health queries the eight core services with one batched request per DC.

**Bounded parallel collection (Task 4)**
- `Invoke-ADAuditParallelTargets`: one worker per target, bounded concurrency (`-MaxConcurrency`, default 2, `1` = serial), per-target deadlines, results merged in target order by a single coordinator that owns progress, coverage and evidence files. Workers receive explicit inputs and return typed results (target, operation, outcome, elapsed, result, error).
- Used by Domain Audit service, share, Print Spooler and Windows Update collectors and by the DC port probes. Final report assembly stays serial. Isolated-host exclusions are recorded before any worker starts.

### Pilot measurements (clone FP-SVC-DC-01, second DC down, Connected mode)

| Run | Domain Audit | Whole audit | Notes |
|---|---|---|---|
| v9.2 (25 Oct 11:22) | 511 s | about 12 min | every per-DC operation waited for DCOM and WinRM again |
| v9.3.0 first build (25 Oct 13:11) | 132 s | about 7 min | first contact paid once per name form; 2 worker runspaces, 1 child process, 0 orphaned workers; 61 coverage records with outcomes Timeout 22, Unreachable 13, Unavailable 26 |
| v9.3.0 with TCP preflight (25 Oct 14:25) | 26 s | about 6.5 min | every DC-02 transport recorded by the 3 s probe; 0 worker timeouts; AD Health 75 s, port check 19 s, AD CS 20 s and LDAP 10 s were spent re-resolving the dead name in each collector while the resolver was slow |

The 13:11 run still paid the first-contact wait twice (short name and FQDN were separate cache keys) and 42 s for `w32tm` against the dead DC; the TCP preflight and the shared cache key removed both. The 14:25 run showed the remaining cost was name resolution itself: the dead DC's name sometimes answered "no such host" at once and sometimes not within 5 s, and dcdiag (ten runs), the thirteen port probes, the two AD CS web requests and the LDAP endpoint tests each resolved it again. The run-scoped resolution cache and the LDAP/HTTP/RPC gates above make each of those one bounded wait per target. Findings were unchanged apart from coverage wording.

### Tests

Offline suites (Pester 3.4.0, PowerShell 7): Core, ProgressChecks, DomainServices, RemoteCollection, HealthCollector, AccountChecks, AccountSeverity, SecurityChecks, LateralSeverity, Report, PasswordLookup, plus new **BoundedCollection** (outcomes, cache, coordinator), **IsolateHost** (rename, GUI command generation, docs) and **WorkerRuntime** (real worker runspaces and child processes: heartbeats, deadlines, cancellation cleanup, concurrency limit, serial/parallel equivalence, native command kill, runner pre-collection validation and the legacy alias end to end). Run them as documented in README.md.

### Known limits

- `-dnszone` (DNS zone posture report) still relies on the DnsServer module's own timeouts.
- Deadlines are not enforced in the offline in-process test seam (documented).
- Session reuse is per run; a worker runspace abandoned at a deadline takes its sessions with it, which the retry-with-fresh-session path covers.
- Parallel workers default to two; raise `-MaxConcurrency` only after measuring DC impact in the pilot.

### Pilot checklist (Task 5, pending)

1. Connected AD with all DCs reachable: compare Domain Audit, AD Health and port check timings and coverage with the v9.2.1 run; confirm equal findings.
2. Connected AD with one unreachable DC: confirm one wait per transport, skipped operations recorded with reasons, no orphaned workers in `audit_run.json`.
3. Denied access (non-admin account on one DC): outcome `AccessDenied`, other DCs unaffected, no caching of the denial.
4. WinRM unavailable but DCOM usable: collection succeeds over DCOM; port check records WinRM as informational.
5. Optional modules unavailable (DSInternals, GroupPolicy, DnsServer): checks degrade to not assessed, never to empty passes.
6. Selected-check subset (`-select domainaudit,adhealth`) and `-MaxConcurrency 1`: equivalent findings and coverage to the default.
7. Isolated host (`-IsolateHost -SnapshotDate <date>`): excluded targets recorded before any connection, banner and reports identify the snapshot, old-copy time signals reviewed with an AD specialist.
8. Reports: primary and companion HTML in light/dark, narrow viewport and print preview; filters, navigation, evidence links, CSV downloads; coverage section agrees with `audit_check_status.csv` and `not_assessed.csv`; generate twice and verify `Raw Data\Source` is byte-for-byte unchanged.

### Package

The deployment folder is the runner, the GUI, `Library\`, `Checks\`, `Password Audit\`, README and these notes; copying only the runner is insufficient. Pushing the tag `v9.3.0` runs `.github/workflows/release.yml`, which verifies the tag against `$versionnum`, checks that every script parses, stages exactly that set, writes `MANIFEST.txt` with SHA-256 hashes and publishes the GitHub Release with `ADAudit-v9.3.0.zip` attached. The offline test suites are excluded from the synced repository.
