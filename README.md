# memoQ security

English | [简体中文](README-zh.md)

Windows security audit tools and response guidance for memoQ TMS administrators, covering the October 2026 eMudhra / emSign intermediate CA key compromise. **This independent project is not an official memoQ tool or patch and does not certify that a device is safe.**

[Incident background](https://emudhra.we-have-a-problem.com/) · [IT notice to share](NOTICE-en.md) · [Chinese repository on CNB](https://cnb.cool/datalsp/memoq-security)

| Purpose | Files | System impact | Validation |
| --- | --- | --- | --- |
| Read-only audit | [PowerShell 5.1](Test-EmudhraCA-PS51.ps1) / [PowerShell 7](Test-EmudhraCA-PS7.ps1) | No network requests or certificate/configuration changes; writes TXT/JSON reports | 61/61 checks passed for each variant on one Windows server; [details](VALIDATION.md) |
| Optional mitigation managed by IT | [mitigation/Block-EmudhraCompromisedCA.ps1](mitigation/Block-EmudhraCompromisedCA.ps1) | Downloads a manifest and imports 16 certificates into `LocalMachine\Disallowed` | Unmodified upstream snapshot; source and hashes reviewed, **not executed or runtime-tested** |

The audits do not call the blocker. Read-only and network-free guarantees apply only to `Test-EmudhraCA-*.ps1`.

## Should I run the blocker immediately after a successful audit?

**No. A successful audit means reports were written, not that blocking is necessary or that the device is safe. Zero matches are not a safety verdict.**

1. **Audit and retain a baseline.** Check Windows servers and relevant Windows clients, save TXT/JSON, and investigate critical coverage gaps.
2. **Have IT determine whether additional blocking is needed.** Check effective Windows CTL/vendor updates and the application's actual validator. Devices with effective protection do not need this workaround. Independent CA bundles need their own updates. Enterprise changes belong to the IT rollout process.
3. **Test and approve any required mitigation.** Record the current state, legitimate business certificate chains, maintenance window and failure/recovery plan. Use an approved test or pilot machine first. The upstream script has no dry-run mode; adding `-WhatIf` is not a safe preview.
4. **Apply only after approval.** Follow the [mitigation runbook](mitigation/README.md), verify the file and retain output and the exit code. Do not bypass execution policy. A failure may leave some certificates already imported.
5. **Verify imports, then applications.** Re-run the audit and compare all 16 DER SHA-256 hashes against machine-level Disallowed entries. Separately verify legitimate memoQ, Web, S2S and plugin operations and certificate rejection. **Successful imports are not application-security acceptance.**

| Audit or operational result | Next step |
| --- | --- |
| Missing reports, errors or incomplete critical store reads | Resolve coverage first; do not automatically block based on an incomplete inventory |
| Compromised entries outside Disallowed | Prioritize investigation of actual trust and use; IT decides the response |
| Matches only in Disallowed, or effective system/application protection already confirmed | Keep blocks and verify coverage; do not delete entries to clear counts |
| Zero matches, related roots or name-only clues | Check updates and real applications; these alone justify neither a safety claim nor automatic import |

## Choose and run a read-only audit

| Runtime | Script | Executable |
| --- | --- | --- |
| 64-bit Windows PowerShell 5.1 | [Test-EmudhraCA-PS51.ps1](Test-EmudhraCA-PS51.ps1) | `powershell.exe` |
| 64-bit PowerShell 7 on Windows | [Test-EmudhraCA-PS7.ps1](Test-EmudhraCA-PS7.ps1) | `pwsh.exe` |

Both files are standalone, with the same indicators and audit logic and no third-party modules. Each accepts only its corresponding runtime. **PS7 is Windows-only**, not for macOS/Linux. Check `$PSVersionTable`; neither script installs PowerShell.

Download and inspect the script, then enter its directory in the appropriate PowerShell window. The output parent must already exist locally: no network shares, mapped network drives, junctions or symbolic-link paths.

Windows PowerShell 5.1:

```powershell
.\Test-EmudhraCA-PS51.ps1 -OutputDirectory $env:TEMP
```

PowerShell 7:

```powershell
.\Test-EmudhraCA-PS7.ps1 -OutputDirectory $env:TEMP
```

Alternatively use `-OutputDirectory C:\Temp` if it already exists. Standard users can attempt the audit; an approved administrator session usually improves coverage. If execution policy blocks it, use organizational review/signing. Do not disable or bypass policy. The script does not unblock downloaded files.

Each run creates a new `EmudhraAudit-<time>-<random-id>` folder containing UTF-8-with-BOM `report.txt` and `report.json`, without overwriting older reports. Read TXT first. JSON contains full metadata and raw HTTP.sys output. Add `-SkipHttpSys` to omit HTTP.sys.

## Scope and read-only boundaries

The audit checks:

- Current execution identity's CurrentUser and LocalMachine: Root, CA, Disallowed, My, WebHosting, TrustedPeople and TrustedPublisher (14 logical stores).
- DER SHA-256 for 16 disclosed compromised certificates and SPKI SHA-256 for 8 compromised public keys, including cross-signs and other same-key wrappers.
- Four related parent/root certificates and subject/issuer name clues, separately from compromised matches.
- Relevant automatic root/untrusted CTL configuration, cache presence and synchronization-value presence. It does not decode CTLs or verify freshness.
- Related services and software clues from uninstall registry entries. No Win32_Product or launching of Python, Java, Node, Git or discovered tools.
- By default, system `netsh.exe http show sslcert`, preserving original-language output and raw bytes instead of parsing English labels.

Only the new report directory and TXT/JSON are written. The audit makes **no network requests, downloads, certificate-chain builds, CRL/OCSP queries, private-key reads, certificate imports/deletions, registry/trust/execution-policy changes, service restarts or report uploads**.

Reports can contain internal names, certificate subjects, IPs/ports, account names and software versions. Redact before sharing; never commit raw reports to a public repository. HTTP.sys Base64 fields represent command-output bytes, not private keys.

## Read the results: TXT first, JSON for detail

Check `Scan status`, `SUMMARY`, `MATCHED ENTRIES` and `COVERAGE ISSUES`. Start with `CompromisedEntriesOutsideDisallowed`, `CompromisedEntries` and `CoverageIssueCount`; do not rely on the exit code alone.

| TXT section/field | JSON field | Interpretation |
| --- | --- | --- |
| `SUMMARY` | `Summary.*` | Counts of matched store entries and coverage issues |
| `MATCHED ENTRIES` | `Certificates[].Matches` and metadata | Use `Location`, `Store`, `InDisallowed`, `CertificateSHA256` and `SpkiSHA256` to identify entries |
| `STORE COVERAGE` | `Stores[].Status` / `Problem` | Missing, inaccessible or partially read stores |
| `TRUST UPDATE CONFIGURATION...` | `TrustUpdateRegistry[].Values[]` | Configuration and presence clues, not effective-update proof |
| `HTTP.sys: Read / Failed / Skipped` | `HttpSys.Status` / `Problem` / `Stdout` | Read succeeded, failed or was omitted; `Read` does not mean TLS is safe |
| `COVERAGE ISSUES` | `CoverageIssues[].Scope` / `Problem` | Checks requiring follow-up |

| Classification/field | Meaning |
| --- | --- |
| `ExactCompromisedCertificate` | Exact DER match to a disclosed compromised certificate |
| `CompromisedPublicKey` | SPKI matches a compromised key, including other wrappers |
| `KnownRelatedRootNotProofOfCompromise` | Related parent/root only; not evidence its key is compromised or an attack occurred |
| `NameOnlyNeedsChainReview` | Name association only; no established signature/trust relationship |
| `InDisallowed=true` | This entry is in that identity's/machine's untrusted store; not proof every same-key path is blocked |
| `CoverageIssues` | Missing stores, access failures, SPKI parsing failures or other gaps |
| `SafetyConclusion=NOT_ASSESSED` | Fixed value. **Zero matches do not prove safety.** |

Counts represent store entries, not unique certificates/keys. DER and SPKI matches overlap and must not be added. Logical stores may expose inherited entries. An unused missing WebHosting store may be normal but is still a coverage gap. Exit code 0 means report writing completed, not a gap-free or safe system.

## Results requiring urgent attention

These are **manual triage recommendations**, not severity scores generated by the script. Follow organizational incident/change procedures.

| Evidence/result | Priority and meaning | Response |
| --- | --- | --- |
| Confirmed malicious impersonation, data exfiltration or credentials sent to an attacker | **Immediate incident response.** This audit cannot establish these facts | Preserve evidence/logs, contain affected communication and revoke sessions/rotate credentials according to actual exposure. A local match alone does not establish leakage |
| Actual memoQ/S2S/plugin testing accepts a compromised chain | **Urgently remediate the validator**, without claiming an attack occurred | Restrict sensitive transfers as required; use A/F below. The audit does not perform this test |
| `CompromisedEntriesOutsideDisallowed > 0` | **High-priority investigation**, preferably the same day; not proof of trust or active use | Identify entries and applications; use A, and B if a legitimate chain depends on the affected hierarchy |
| `CompromisedEntries > 0`, outside Disallowed=0 | Known matches are in Disallowed; coverage still needs verification | Keep blocks; check cross-signs, identities and independent stores under A/F |
| `EnableDisallowedCertAutoUpdate=0` | Prioritize untrusted CTL distribution checks | Use C; effective central/offline distribution may be intentional but needs evidence |
| `DisableRootAutoUpdate=1` | Trusted-root updates disabled; does not establish that untrusted CTL updates are disabled | Use C; do not blindly change trusted-root policy |
| Coverage issues, `CompletedWithCoverageIssues`, `MissingOrInaccessible`, `Partial`, or HTTP.sys `Failed` | Incomplete audit, neither an attack finding nor a clean result | Use D; prioritize Root/CA/Disallowed gaps; document legitimately unused stores |
| Related-root or name-only matches | Clues, not confirmed compromised entries | Use E; no bulk root deletion or deletion by name |
| Zero compromised matches and zero coverage issues | No local inventory matches only | Use F; peers can supply intermediates not cached locally |

`HttpSys.Status=Skipped` means `-SkipHttpSys` was selected. Decide follow-up based on the machine's role. Service state, software versions and the presence of `EncodedCtl`, `DisallowedCertEncodedCtl` or synchronization values are not independent remediation evidence.

## Response guidance

### A. Compromised matches or acceptance of a compromised chain

Retain reports, time, store locations and DER/SPKI hashes. Identify the real validator: translator/PM workstation, browser, S2S child TMS, plugin host or API client. An administrator identity does not stand in for service accounts.

IT should verify effective Windows untrusted CTL distribution and vendor updates, and update independent CA bundles separately. If updates are unavailable, assess the [optional blocker](mitigation/README.md), test business impact and retain before/after evidence. Do not bulk-remove roots, delete IIS bindings or disable validation. Finish with F.

### B. Legitimate certificate migration or connection failures after updates

IT and the provider should inspect the actual handshake chain. If migration is necessary, deploy a supported replacement to the actual IIS, HTTP.sys, reverse-proxy or other TLS endpoint for that memoQ version/deployment. Verify every entry point; port 443 alone is not a complete inventory.

If replacing a leaf certificate used for S2S child identity, check the parent's registered certificate, Server connection association and the child's private-key availability. These are separate from the parent's HTTPS certificate. Retain configuration and a recovery plan. **Do not restore service by ignoring certificate errors or trusting a compromised chain again.**

### C. Disabled, unusual or unclear trust-update configuration

Check trusted-root and untrusted CTL policies separately, domain-policy overrides, central/offline distribution and content actually received. Absent settings usually leave defaults, not proof of successful updates. Use approved trusted distribution for offline devices.

Microsoft documents CTL management as independent of WSUS: no pending WSUS updates is not proof of a current CTL. See [Microsoft CTL documentation](https://learn.microsoft.com/en-us/windows-server/identity/ad-cs/configure-trusted-roots-disallowed-certificates).

### D. Coverage gaps or report failure

Use issue Scope/Problem. Check the Windows/PowerShell version, 64-bit process and existing local output directory. Use an approved administrator identity where needed and separately account for service identities. Do not grant broad directory/private-key permissions to remove warnings.

Document absent stores instead of creating empty ones. Investigate HTTP.sys errors and permissions. Failed SPKI parsing is not a completed negative check. Missing, truncated or unparseable reports mean an incomplete run.

### E. Related roots or name-only clues

A root's presence does not prove its key is compromised. Subject/issuer names can be forged and do not establish signatures. Review the actual full chain and application behavior in an approved validation process; keep an unresolved result where evidence is incomplete.

### F. Completion criteria

- Test the real application, identity, version and TLS implementation: legitimate connections work; wrong-name, untrusted and relevant compromised chains/cross-sign paths are rejected.
- Cover enabled memoQ desktop, Web, S2S, MT/AI and API paths. A browser or generic curl result does not prove another application's behavior; curl backends can differ.
- Retain explicit certificate errors and necessary logs. Timeouts, DNS failures, HTTP 403 and business errors are not proof of blocking. Use approved isolated tests and test data, never real credentials/documents against public test endpoints.
- Re-run the audit and resolve or explain gaps. Disallowed entries may keep matching; **zero matches are not an acceptance criterion**.
- Record application results, change evidence and limits. `SafetyConclusion` remains `NOT_ASSESSED`.

Active connections, updates, certificate replacement and blocking are separate IT activities, not audit-script behavior.

## Optional upstream blocker

The [upstream blocker](https://emudhra.we-have-a-problem.com/Block-EmudhraCompromisedCA.ps1) is preserved unchanged in [mitigation/](mitigation/README.md), with provenance, hashes, risks and a six-step runbook. It requires administrator privileges and Windows PKI, downloads a hash-pinned manifest and imports machine-level Disallowed entries. It has no implemented dry-run, transaction rollback or application-enforcement test. The incident site is not a Microsoft/memoQ patch channel.

The upstream example uses `-ExecutionPolicy Bypass`; this repository uses existing organizational approval/signing and distribution instead. The blocker is **not offline-capable as written** and **has not been executed by this project**. A pinned-hash failure requires review, not removal of the check.

## memoQ risks and limitations

**Without S2S:** if traffic is intercepted and a forged certificate accepted, a client/browser may trust an impostor TMS. MT/AI traffic may expose text or request credentials and accept altered responses. Check Windows Server and Windows endpoints; a legitimate IIS certificate alone is not proof of protection.

**With S2S:** distinguish the child's validation of the parent server from the parent's checks of the registered child certificate, Server connection and permissions. A compromised CA does not automatically confer a legitimate partner identity. Blocking can also interrupt legitimate connections using an affected chain.

- CurrentUser covers the executing identity only, not all users or service accounts.
- A leaf certificate normally has its own public key; its SPKI alone cannot identify a compromised issuer. No chain validation is performed.
- Independent CA bundles, Java keystores, containers, user profiles and centralized certificate-store directories are not scanned. Software inventory is an installation clue, not patch validation or exhaustive portable-tool discovery.
- HTTP.sys is not every TLS listener. Centralized certificate stores may need separate review. `ThumbprintSHA1` correlates Windows binding displays; detection primarily uses SHA-256.
- Browser protection does not cover every server/client application. Inbound certificate migration and outbound certificate-validation risks are separate questions.

Examples: DER=1 and SPKI=1 can describe one entry. Matches in Disallowed can remain after mitigation. Zero local matches cannot answer whether a remote chain will be accepted.

## Snapshot and sources

Snapshot: **2026-10-22**. OpenSSL calculations from public PEMs confirmed 16 compromised certificates, 8 compromised SPKIs and 4 related parent/root certificates match the audits. Indicators do not refresh online; later changes require review.

- [Mozilla incident record](https://bugzilla.mozilla.org/show_bug.cgi?id=2083449)
- [Google Chrome / Android advisory](https://blog.google/security/protecting-chrome-and-android-users-from-compromised-emudhra-intermediate-ca-certificates/)
- [Compromised manifest](https://emudhra.we-have-a-problem.com/impacted-intermediates.json) / [related roots](https://emudhra.we-have-a-problem.com/roots.json)
- [Microsoft CTL updates](https://learn.microsoft.com/en-us/windows-server/identity/ad-cs/configure-trusted-roots-disallowed-certificates)
- [HTTP.sys commands](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/netsh-http)
- [memoQ S2S](https://docs.memoq.com/current/en/Concepts/concepts-s2s.html) / [Server connection](https://docs.memoq.com/current/en/Workspace/server-connection-properties.html)

See [validation evidence and limits](VALIDATION.md) and [SHA256SUMS.txt](SHA256SUMS.txt). Raw operational reports and private keys are not published.
