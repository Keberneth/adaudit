# ADAudit release notes

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

The deployment folder is the runner, the GUI, `Library\`, `Checks\`, `Password Audit\`, README and these notes; copying only the runner is insufficient. In the development working copy `Build-ADAuditRelease.ps1` stages exactly that set into `dist\ADAudit-v9.3.0\`, verifies every script parses, writes `MANIFEST.txt` with SHA-256 hashes and produces a zip. The test suites, the packaging script and `dist\` are excluded from the synced repository.
