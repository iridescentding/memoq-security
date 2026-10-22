# 上游来源与静态核验

[English](UPSTREAM.md) | 简体中文

- 原始脚本：[Block-EmudhraCompromisedCA.ps1](https://emudhra.we-have-a-problem.com/Block-EmudhraCompromisedCA.ps1)
- 事件站点：[eMudhra Intermediate CA Compromise](https://emudhra.we-have-a-problem.com/)
- 脚本固定清单：[impacted-intermediates.json](https://emudhra.we-have-a-problem.com/impacted-intermediates.json)
- 下载与复核日期：2026-10-22（北京时间）。
- 本目录的 `.ps1` 保持上游原始字节，未修改、未加入自动执行入口；原作归上游作者。本仓库不将其标为 Microsoft／memoQ 官方补丁，也不另行宣称上游代码的许可条款。

```text
0C758183E511C535CDCD58EE97B4712A76BCA3963E72634DCB29AF2A0B8424B3  Block-EmudhraCompromisedCA.ps1
F67B3ABE9B4879F4E91874ED041BECCD71257F1DB41C588C724CCF12AA90C59E  上游固定清单原始字节
```

复核确认：重新下载的脚本与此前审查副本逐字节一致；下载的清单 SHA-256 等于脚本固定值；从公开 PEM 独立计算的 16 个 DER SHA-256、8 个唯一 SPKI SHA-256 与清单及两版只读自查脚本一致。

`expected-certificates.json` 由本次固定清单提取公开名称、签发者和指纹，用于导入后的本地报告核对，不包含私钥、不用于导入，也不能代替整份上游清单的哈希校验。

仅做源码、字节和指纹核对：**没有执行阻断脚本，没有验证真实导入、PowerShell 运行兼容性、部分失败处理或 memoQ／S2S 阻断效果。** 本次发布不会向服务器分发或运行该脚本。

上游日后可能更新。该副本不会自动升级；更新前应重新审查差异、清单、风险和业务影响，并同步哈希与说明。固定清单不匹配时不要删除检查或随意替换哈希。
