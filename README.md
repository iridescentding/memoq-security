# memoQ security

面向 memoQ TMS 运维的 Windows 本地只读自查工具。首个工具针对 2026 年 10 月 eMudhra / emSign 中间 CA 密钥事件；**不判断机器是否安全，也不是 memoQ 官方工具或修复补丁。**

事件背景与公开指标：[eMudhra Intermediate CA Compromise](https://emudhra.we-have-a-problem.com/)。其中的在线测试、阻断／修复脚本与本仓库的只读清点脚本是不同工具；本仓库脚本不执行网站上的修复步骤。

## 选哪个脚本

| 运行环境 | 文件 | 启动程序 |
| --- | --- | --- |
| 64 位 Windows PowerShell 5.1 | [Test-EmudhraCA-PS51.ps1](Test-EmudhraCA-PS51.ps1) | `powershell.exe` |
| Windows 上的 64 位 PowerShell 7 | [Test-EmudhraCA-PS7.ps1](Test-EmudhraCA-PS7.ps1) | `pwsh.exe` |

两个文件均可单独运行，无第三方模块依赖；检查范围和指标相同，只接受对应运行时。PS7 版仍是 **Windows 专用**，不适用于 macOS / Linux。脚本不会安装 PowerShell。先用 `$PSVersionTable` 查看版本，再选择文件。

## 运行

先下载并检查脚本，在对应的 PowerShell 窗口进入脚本目录。输出父目录必须已经存在、位于本地，不能是网络盘或包含目录联接／符号链接的路径。

Windows PowerShell 5.1：

```powershell
.\Test-EmudhraCA-PS51.ps1 -OutputDirectory $env:TEMP
```

PowerShell 7：

```powershell
.\Test-EmudhraCA-PS7.ps1 -OutputDirectory $env:TEMP
```

也可指定 `-OutputDirectory C:\Temp`，但 `C:\Temp` 需事先存在。普通权限可以尝试运行，管理员通常能读取更完整的信息。执行策略阻止时遵循组织审批／签名流程；不要关闭或绕过策略。下载文件是否被阻止由 Windows／组织策略决定，脚本不会自动解除阻止。

每次新建一个 `EmudhraAudit-时间-随机编号` 目录，包含 UTF-8（带 BOM）的 `report.txt` 和 `report.json`，不会覆盖旧报告。先看 TXT，再查看 JSON 中的详细清单及 HTTP.sys 原始输出。加 `-SkipHttpSys` 可跳过 HTTP.sys 读取。

## 检查什么

- 当前执行身份的 CurrentUser 与 LocalMachine，各检查 Root、CA、Disallowed、My、WebHosting、TrustedPeople、TrustedPublisher，共 14 个逻辑存储区。
- 16 张公开受损证书的 DER SHA-256、8 个受损公钥的 SPKI SHA-256，兼顾交叉签名和同公钥其他包装。
- 4 张相关上级证书，以及主体／颁发者名称线索，与真正的受损证书／公钥匹配分开报告。
- 自动根／不受信任 CTL 更新的相关配置、缓存及同步时间值是否存在；不读取或解码 CTL 内容，不确认新鲜度。
- 相关服务、卸载注册表中的软件线索；不调用 Win32_Product，不启动 Python、Java、Node、Git 等工具。
- 默认调用系统 `netsh.exe http show sslcert`，只读 HTTP.sys 绑定，保留原语言文本及原始输出字节，不依赖英文标签解析。

## 只读边界

仅创建报告目录及 TXT／JSON。**不联网、不下载、不构建证书链、不查询 CRL／OCSP、不读取私钥、不增删证书、不改注册表／信任配置／执行策略、不重启服务、不上传报告。**

报告可能包含内部域名、证书主体、IP／端口、账号和软件版本；分享前脱敏，勿直接提交到公开仓库。JSON 中 HTTP.sys 的 Base64 字段是原始命令输出字节，不是私钥。

## 怎样看结果

| 字段 | 含义 |
| --- | --- |
| `ExactCompromisedCertificate` | 与公开受损证书 DER 完全匹配 |
| `CompromisedPublicKey` | 与受损 SPKI 匹配，包含其他证书包装 |
| `KnownRelatedRootNotProofOfCompromise` | 只有相关上级证书，不证明根私钥受损或已遭攻击 |
| `NameOnlyNeedsChainReview` | 只有名称关联，不能证明签名或信任关系 |
| `InDisallowed=true` | 此证书条目位于该身份／机器的不受信任存储区，不证明所有同公钥路径都已被阻断 |
| `CoverageIssues` | 缺失存储区、访问失败、SPKI 解析失败等覆盖缺口，必须查看 |
| `SafetyConclusion=NOT_ASSESSED` | 固定值；**零匹配不代表安全** |

计数是存储区条目数，不是唯一证书或公钥数；DER 与 SPKI 命中可以重叠，不能相加。未部署 WebHosting 等存储区可能正常，但仍会列出读取缺口。退出码 0 仅表示报告写入完成，不代表安全或无覆盖缺口。

远端可以在 TLS 握手时发送中间证书，因此本地没缓存受损中间 CA 并不排除风险。配置、缓存存在不等于已有效阻断；CurrentUser 不覆盖其他用户／服务身份；独立应用 CA 包、Java keystore、容器和实际 memoQ 请求路径不在本工具范围内。

## 对 memoQ 的风险

非 S2S：客户端／浏览器可能在连接被劫持且假证书被接受时误信假 TMS；MT／AI 外连也可能涉及文本、请求凭据泄露或响应篡改。检查 Windows Server 与用户 Windows 设备，不能只看 IIS 证书。

S2S：分别检查子 TMS 对父 TMS 的服务端身份验证，以及父 TMS 对已登记子证书、Server connection 和权限的核验。受损 CA 不会自动授予合法合作方身份。若合法业务证书依赖被阻断的链，还可能出现连接中断。

可直接转发的通知见 [NOTICE-zh.md](NOTICE-zh.md)。实测环境和限制见 [VALIDATION.md](VALIDATION.md)。

## 指标与来源

指标快照：2026-10-22。此前已在制作环境以 OpenSSL 从 20 张公开 PEM 独立重算，确认 16 张受损证书、8 个受损公钥及 4 张相关上级证书与脚本一致。脚本不在线刷新指标；后续变化需要重新核查。

- [Mozilla 原始事故记录](https://bugzilla.mozilla.org/show_bug.cgi?id=2083449)
- [Google Chrome / Android 通告](https://blog.google/security/protecting-chrome-and-android-users-from-compromised-emudhra-intermediate-ca-certificates/)
- [受损证书清单](https://emudhra.we-have-a-problem.com/impacted-intermediates.json) / [相关上级清单](https://emudhra.we-have-a-problem.com/roots.json)
- [Microsoft CTL 更新说明](https://learn.microsoft.com/en-us/windows-server/identity/ad-cs/configure-trusted-roots-disallowed-certificates)
- [HTTP.sys 命令说明](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/netsh-http)
- [memoQ S2S 工作流](https://docs.memoq.com/current/en/Concepts/concepts-s2s.html) / [Server connection 配置](https://docs.memoq.com/current/en/Workspace/server-connection-properties.html)

此工具不会执行网站上的主动网络测试或本地阻断操作；任何实际修复需按组织变更流程评估。
