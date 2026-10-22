# Upstream provenance and static review

English | [简体中文](UPSTREAM-zh.md)

- Original script: [Block-EmudhraCompromisedCA.ps1](https://emudhra.we-have-a-problem.com/Block-EmudhraCompromisedCA.ps1)
- Advisory: [eMudhra Intermediate CA Compromise](https://emudhra.we-have-a-problem.com/)
- Pinned manifest: [impacted-intermediates.json](https://emudhra.we-have-a-problem.com/impacted-intermediates.json)
- Download/review date: 2026-10-22 (Asia/Shanghai).
- The local `.ps1` retains the upstream bytes without modifications or an automatic invocation mechanism. Authorship remains upstream. This repository does not identify it as an official Microsoft/memoQ patch or assign new license terms to upstream code.

```text
0C758183E511C535CDCD58EE97B4712A76BCA3963E72634DCB29AF2A0B8424B3  Block-EmudhraCompromisedCA.ps1
F67B3ABE9B4879F4E91874ED041BECCD71257F1DB41C588C724CCF12AA90C59E  original pinned manifest bytes
```

A fresh download matched the previously reviewed script byte for byte. The downloaded manifest's SHA-256 matched the pin. Independent public-PEM calculations confirmed 16 DER SHA-256 hashes and 8 unique SPKI SHA-256 hashes against the manifest and both audit variants.

`expected-certificates.json` extracts public names, issuers and hashes from that manifest for comparison with a post-change audit report. It contains no private keys, is not used for import, and does not replace verification of the complete upstream manifest's hash.

**The blocker has not been executed.** Review covered source, bytes and public fingerprints only, not actual imports, PowerShell runtime compatibility, partial-failure behavior or memoQ/S2S enforcement. Publishing these files does not deploy or run the blocker on any server.

Upstream may change. This snapshot does not auto-update. Re-review differences, manifests, risk and business impact before replacing it, then update hashes and documentation. Do not remove the pin check or substitute a new hash simply to force execution.
