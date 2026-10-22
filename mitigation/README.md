# Optional eMudhra blocking: IT review and rollout

English | [简体中文](README-zh.md)

**This tool changes system trust configuration. It is not a read-only audit, and successful report generation is not permission or a reason to run it.** This directory preserves the upstream script unchanged. It has been statically reviewed and hash-checked, but has not been executed locally or on any server. The audits' 61/61 results do not validate this blocker.

[Blocker](Block-EmudhraCompromisedCA.ps1) · [Upstream provenance](UPSTREAM.md) · [Expected certificate hashes](expected-certificates.json)

## Scope and necessity

The workaround targets Windows programs using the **OS certificate stores and chain validation**, including the relevant Schannel TLS and Authenticode paths. It adds 16 known compromised intermediate/cross-signed certificates to `LocalMachine\Disallowed` (Untrusted Certificates). It does not remove trusted roots, replace IIS/memoQ leaf certificates or update software.

The upstream advisory states that Windows has distributed blocks through CTL updates. **Machines with effective updates do not need this workaround.** No pending Windows Update/WSUS updates, or a cache being present, does not establish a current CTL. Enterprise rollout should be managed by IT; upstream also advises against individuals applying this mitigation to managed devices.

This script alone does not resolve:

- Applications using Java keystores, independent OpenSSL/application CA bundles or other validators: use their own updates or blocking mechanism.
- Software that ignores certificate errors or lacks effective validation: it may not honor system Disallowed entries.
- Legitimate business chains needing migration: arrange replacement and endpoint configuration with the provider and administrator.
- Suspected prior compromise: importing certificates does not revoke leaked credentials or recover exposed data; incident response is still needed.
- **Fully offline machines: this version downloads its manifest at runtime and cannot run offline as written.** Use an approved central/offline distribution process; do not remove hash checks or network restrictions to force execution.

Blocking only on the TMS host does not protect users' Windows devices. For S2S, check how the initiating child TMS validates the parent. Parent-side validation of the registered child certificate and permissions is a separate layer.

## Execution risks and limitations

| Behavior/limit | Operational implication |
| --- | --- |
| Administrator privileges, PowerShell 5.1+ and Windows PKI required | This runbook uses 64-bit Windows PowerShell 5.1; upstream's version declaration is not proof of tested PS5.1/PS7 compatibility |
| Downloads a manifest and checks a fixed SHA-256 | Depends on the site, DNS, proxy and TLS. Stop on download/hash failure; do not bypass TLS or remove checks |
| Persistent machine-level Disallowed imports | Closing PowerShell does not undo them. Other applications on the machine using this validation path may be affected |
| Legitimate services may still use an affected chain | memoQ, Web, S2S, API/plugin connections or software-signature checks may fail; prepare migration and a maintenance window |
| No confirmation prompt or implemented preview switch | **`-WhatIf` / `-Confirm` are not implemented. Do not append them as a supposedly safe dry run.** Inspect source, then test only on an approved machine |
| Sequential, non-transactional imports | Failure may leave partial changes. Nonzero exit does not mean zero changes or justify blind retries |
| No automatic rollback or structured audit report | Retain baseline/post-change reports, console output, exit code and a change record. No visible error is not complete acceptance |
| Imports 16 exact known certificates | This is not a generic SPKI blacklist or a guarantee about all wrappers, applications or future changes |

## Six-step workflow

### 1. Run the read-only audit and save the baseline

From the repository root, use the corresponding runtime and an existing local output parent. For 64-bit Windows PowerShell 5.1:

```powershell
.\Test-EmudhraCA-PS51.ps1 -OutputDirectory $env:TEMP
```

Keep that output folder as the **before-change** record. Read TXT and JSON coverage issues; investigate incomplete Root/CA/Disallowed reads. Record machine, identity, time, application versions, actual TLS backends and existing Disallowed entries. Do not export private keys. Account separately for relevant service identities.

Record legitimate business behavior using test projects/accounts: memoQ login, required synchronization/delivery, Web, enabled S2S queries/delivery and plugin calls. Check the functions actually used.

### 2. IT decides whether additional blocking is needed

- Effective CTL/software updates are present and the actual validator rejects the affected chain: record evidence and verify coverage; **do not run this workaround just to repeat protection**.
- Effective update status is unknown: investigate distribution, policy and validation behavior first. Unknown does not automatically mean import now.
- Effective blocking is missing and the application uses Windows validation: assess the blocker, target machines, pilot, maintenance window, failure owner and recovery plan.
- Independent or ineffective validators: use the relevant vendor's remediation. This script is not evidence that those applications are fixed.

Zero local matches, related roots or non-Disallowed matches cannot individually replace this decision. The audit does not perform handshakes or validate CTLs.

### 3. Inspect the files and prepare an approved test machine

Download the repository to an existing local working directory. Inspect the script line by line and check [provenance](UPSTREAM.md) and the root `SHA256SUMS.txt`. These commands only read local files/module information; run from the repository root:

```powershell
$blockFile = '.\mitigation\Block-EmudhraCompromisedCA.ps1'
$expectedHash = '0C758183E511C535CDCD58EE97B4712A76BCA3963E72634DCB29AF2A0B8424B3'
if ((Get-FileHash -LiteralPath $blockFile -Algorithm SHA256).Hash -ne $expectedHash) {
    throw 'Blocker file differs from the reviewed snapshot. Stop and review.'
}
Get-Module -ListAvailable PKI
```

If PKI is absent, the file differs or execution policy blocks it, stop for IT review. Do not install an unknown same-name module or use `ExecutionPolicy Bypass`, `Set-ExecutionPolicy` or automatic unblocking to bypass organizational controls. A hash identifies this snapshot; it does not replace trusted distribution and source review. If the organization signs/repackages it, document that change and verify the pre-signing content.

**Complete steps 4–6 on an approved test/pilot machine before production rollout. Do not make production the first trial.**

### 4. Apply only after approval; record output and exit code

Use an approved, elevated **64-bit Windows PowerShell 5.1** session at the repository root. This step performs network access and persistent machine-level certificate imports. File verification in step 3 is not execution authorization.

```powershell
$blockLog = Join-Path $env:TEMP ('EmudhraBlock-' + [Guid]::NewGuid().ToString('N') + '.txt')
powershell.exe -NoProfile -File .\mitigation\Block-EmudhraCompromisedCA.ps1 *> $blockLog
$blockExitCode = $LASTEXITCODE
Write-Output ('ExitCode=' + $blockExitCode + '; Log=' + $blockLog)
```

Keep the log and exit code. No execution-policy override is included. If organizational policy blocks it, stop and use the signing/approval process. If it fails, inspect the error and inventory any partial imports before IT decides the next step. There is no automatic rollback.

### 5. Re-run the audit and verify each expected import

Re-run step 1 with the same runtime, identity and output parent. Treat the new folder as the **after-change** record. Confirm readable TXT/JSON and a successful machine-level Disallowed read, then compare all 16 DER SHA-256 hashes.

This **local, read-only comparison** reads JSON only. It does not run the blocker, connect to the network, read private keys or modify stores. Replace the first line with the newly generated report path and run from the repository root:

```powershell
$reportPath = 'C:\Temp\REPLACE-WITH-POST-CHANGE-REPORT-FOLDER\report.json'
$after = Get-Content -LiteralPath $reportPath -Raw -Encoding UTF8 -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop
$expected = Get-Content -LiteralPath '.\mitigation\expected-certificates.json' -Raw -Encoding UTF8 -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop
$store = @($after.Stores | Where-Object { $_.Location -eq 'LocalMachine' -and $_.Store -eq 'Disallowed' })
if ($store.Count -ne 1 -or $store[0].Status -ne 'Read') {
    throw 'LocalMachine Disallowed coverage is incomplete; cannot verify imports.'
}
$wanted = @($expected.Certificates.CertificateSHA256 | Sort-Object -Unique)
if ($wanted.Count -ne 16) { throw 'Expected certificate list is incomplete; stop and review.' }
$present = @($after.Certificates | Where-Object {
    $_.Location -eq 'LocalMachine' -and $_.Store -eq 'Disallowed' -and $_.InDisallowed -eq $true
} | Select-Object -ExpandProperty CertificateSHA256 -Unique)
$missing = @($wanted | Where-Object { $_ -notin $present })
[pscustomobject]@{ Expected = 16; Present = 16 - $missing.Count; Missing = $missing.Count }
if ($missing.Count -gt 0) {
    $missing
    throw 'Some expected certificates are absent. Import verification is incomplete.'
}
Write-Output 'All 16 known certificate hashes are present. Application blocking is NOT assessed.'
```

Use this machine's fresh post-change report, not an old report or another machine's result. The comparison list is derived from the pinned manifest and contains public names, issuers and fingerprints only. It is not an import manifest; the blocker does not read it.

Interpretation:

- `Expected=16, Present=16, Missing=0` establishes that the report contains these 16 certificates, not that they were newly added or that all applications reject them. Compare with the baseline for actual changes.
- `CompromisedEntries` may increase because known compromised certificates in Disallowed still match. Do not remove blocks to clear findings.
- `CompromisedEntriesOutsideDisallowed` may remain nonzero: existing CA-store copies are not removed. Interpret them with blocking entries and application tests, not the count alone.
- `SafetyConclusion` always remains `NOT_ASSESSED`. Unresolved critical coverage gaps prevent completion of import verification.
- 16/16 is the explicit import target **when using this blocker**. A device that never ran it is not necessarily unsafe because it has fewer entries: CTLs or application-specific protection may already be effective.

### 6. Verify real applications: legitimate service and certificate rejection

| Path | Evidence to retain |
| --- | --- |
| Actual Windows memoQ desktop client → TMS | Legitimate login and required sync/delivery work; approved isolated tests demonstrate that this client rejects wrong-name, untrusted and relevant compromised chains |
| Actual browser → memoQ Web | Legitimate functions work and affected chains are rejected; this proves only that browser's behavior |
| S2S child TMS → parent TMS | Validate parent TLS using the actual version and service identity; legitimate queries/delivery work; registered child certificate, Server connection and permission checks still behave correctly |
| MT/AI, API and other outbound connections | Test each actual host, identity, runtime and CA store; retain application certificate errors and legitimate baselines |

Perform legitimate business regression in production. Put abnormal-certificate rejection tests in an IT-approved isolated environment using test identities/data, not real credentials, projects or translation text sent to a public test site. Record untested paths.

Use fresh TLS connections. Pre-change long-lived connections, session resumption or a still-logged-in screen do not demonstrate fresh certificate validation. Any application/service restart must follow vendor requirements and maintenance procedures; this script does not restart services.

Explicit certificate-validation rejection is useful evidence. Timeouts, DNS failure, HTTP 403 and ordinary application errors are not proof of blocking. Browser, curl or generic .NET tests do not automatically prove actual memoQ/S2S behavior. If the application cannot be tested, record **“imports verified; application enforcement not verified”**, not “fully remediated.”

This project does not supply a malicious-certificate handshake tester for memoQ and has not completed these tests against real memoQ/S2S connections.

## Failure and recovery

Retain the error, before/after reports and execution log. IT should distinguish download/hash problems, permissions/policy, partial imports and affected legitimate chains. There is no automatic rollback. Do not bulk-clear Disallowed, remove related roots, ignore certificate errors or restore trust in compromised chains to recover service.

Prioritize migration to a supported chain for affected legitimate services. Use existing production change/incident procedures. Recovery planning must distinguish pre-existing entries from those added by this change so existing protection is not removed. Reports/logs contain operational information: redact before sharing and never commit them publicly.

References: [upstream Windows guidance](https://emudhra.we-have-a-problem.com/) · [Microsoft CTL guidance](https://learn.microsoft.com/en-us/windows-server/identity/ad-cs/configure-trusted-roots-disallowed-certificates).
