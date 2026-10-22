# Notice for IT administrators

[简体中文](NOTICE-zh.md)

The eMudhra intermediate CA key compromise could enable service impersonation if traffic is intercepted and the application accepts a forged certificate. Potential harm includes exposed credentials or translation content and altered translations. Please run the read-only audit on Windows servers and relevant client devices first. IT should assess existing updates and decide whether additional blocking is needed. After any approved change, verify both normal memoQ/S2S operations and rejection of affected certificate chains. A successful audit or zero matches does not prove safety; do not run the blocker automatically.

[GitHub repository](https://github.com/iridescentding/memoq-security) · [Incident details](https://emudhra.we-have-a-problem.com/)
