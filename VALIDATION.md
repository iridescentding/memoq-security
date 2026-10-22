# Validation record

English | [简体中文](VALIDATION-zh.md)

**The 61/61 results apply only to the read-only `Test-EmudhraCA-*.ps1` scripts, not the blocker in `mitigation/`.** The blocker was checked against upstream bytes and its pinned manifest, including 16 DER and 8 SPKI hashes. It has not been executed locally or on any server. Imports, partial failure, application enforcement and business compatibility remain untested. See [provenance](mitigation/UPSTREAM.md).

Audit version: 1.1.0. Report schema: 1.2. Indicator snapshot: 2026-10-22. The English edition changes documentation only; all three PowerShell files retain their previously reviewed bytes.

## Live audit tests

On 2026-10-22 (Asia/Shanghai), both final audit variants ran as administrator on the same Windows NT 10.0.26100 server. The existing Windows PowerShell LocalMachine execution policy was RemoteSigned. Each runtime's policy list was unchanged before/after testing; no overrides were used.

| Check | PS 5.1 variant | PS 7 variant |
| --- | --- | --- |
| Actual runtime | 5.1.26100.32370 / Desktop, 64-bit | 7.6.4 / Core, 64-bit |
| Validation completed | 2026-10-22 11:50:06 +08:00 | 2026-10-22 11:49:43 +08:00 |
| PowerShell parse errors | 0 | 0 |
| Automated checks | 61 / 61 passed | 61 / 61 passed |
| Default run | Exit 0, about 1074 ms | Exit 0, about 1386 ms |
| SkipHttpSys run | Exit 0, about 926 ms | Exit 0, about 1189 ms |
| TXT / JSON | Generated, nonempty, readable, consistent counts | Generated, nonempty, readable, consistent counts |
| HTTP.sys | Read successfully, Chinese readable, raw bytes round-trip | Read successfully, Chinese readable, raw bytes round-trip |
| Missing output parent / UNC | Rejected with failure exit and no reports | Rejected with failure exit and no reports |

Inventory summaries agreed. This supports inventory/report functionality on the tested server, **not equivalent application trust behavior or a safety conclusion**.

## Check coverage

- Four public-certificate-only synthetic fixtures: RSA, EC, X.509 v1 without an explicit version, and different wrappers sharing a key; DER/SPKI checked against independent OpenSSL calculations.
- Combined DER/SPKI matches, same-key matches, related parents, name-only clues, no match, Disallowed classification and four malformed-DER rejection cases.
- Default/SkipHttpSys, spaces in paths, repeat runs without overwriting, absent parent directories and UNC rejection before access.
- Parseable JSON, consistent TXT/JSON counts, all 14 store attempts recorded and correct runtime/source-hash metadata.
- HTTP.sys byte round-trip and readable Chinese; SkipHttpSys does not launch netsh.
- Certificate fingerprint inventories and reported trust configuration agreed between the two full inventories in each runtime. Execution policies were unchanged.
- Reports were read back by an external test controller and each file's SHA-256 verified. The audits themselves provide no remote-execution or upload feature.

Fixtures were loaded only in memory, not installed. No test private keys were transferred. Certificate/trust/HTTP.sys configuration was not changed.

## Implementation review

Stores use ReadOnly / OpenExistingOnly; registry keys open read-only. There are no chain/revocation APIs, private-key reads or Win32_Product queries. The sole child process is system netsh's read-only binding query. Writes are limited to TXT/JSON in a new report directory.

No packet capture was performed. Source inspection is not a measurement proving that the entire OS generated no network traffic; unrelated Windows/services background activity is outside the audits' control.

## Not validated

- Other Windows versions, non-administrator/service identities or other PowerShell 7 minor versions.
- Live fault injection for inaccessible stores, mapped network drives or reparse points. Code rejects/reports these cases, but the environment was not changed to exercise them.
- Actual memoQ desktop, S2S, MT/AI or API certificate-blocking behavior.
- Complete chains, revocation status, CTL freshness, independent application stores or whether an attack occurred.
- Any runtime execution or effectiveness of the mitigation script.

## Audit source SHA-256

```text
FDC2D6BF4512A5D3820D390072F2665AB7FEA8AECF3159FE785E73B84614266C  Test-EmudhraCA-PS51.ps1
ADDAE1B5B650E9C25E3B5762BD6E8B4531401DF9D2C4EA214EA6DD36683B1232  Test-EmudhraCA-PS7.ps1
```

The variants differ only in minimum runtime/version guards and related messages. PS7 actually ran under `pwsh.exe`, without bypassing checks or delegating to 5.1.

The sanitized [validation summary](validation-summary.json) is public. Raw server reports contain operational information and are not published.
