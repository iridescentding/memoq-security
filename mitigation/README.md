# eMudhra 补充阻断：供 IT 审批与实施

**这是会修改系统的阻断工具，不是只读自查。自查正常生成报告，不意味着下一步就应运行它。** 本目录保存上游原样副本，已做静态审查与指纹核对，未在本机或服务器执行；不能引用只读脚本的 61/61 检查作为本脚本的实测结论。

文件：[Block-EmudhraCompromisedCA.ps1](Block-EmudhraCompromisedCA.ps1)；来源与固定版本：[UPSTREAM.md](UPSTREAM.md)；导入核对清单：[expected-certificates.json](expected-certificates.json)。

## 适用范围与必要性

适用于 **Windows 上使用系统证书存储区及链验证的程序**，例如相应的 Schannel TLS 和 Authenticode 路径。它向 `LocalMachine\Disallowed`（不受信任的证书）加入 16 张已知受损中间 CA／交叉签名证书；不删除受信根，不更换 IIS／memoQ 的叶证书，不更新软件。

上游说明 Windows 已通过 CTL 更新发布阻断，**已实际取得有效更新的设备不需要这项补救**。不能只看“Windows Update／WSUS 没有待装补丁”或缓存存在就认定 CTL 已更新。企业管理设备优先由 IT 统一分发与验收，上游也不建议个人直接对企业设备应用此缓解。

以下情况不能靠运行此脚本解决：

- 软件使用 Java keystore、独立 OpenSSL／应用 CA 包或其他验证实现：需要该软件自己的更新或阻断措施。
- 软件忽略证书错误或没有有效验证：导入系统 Disallowed 不能保证它会遵守。
- 业务的合法证书链需要迁移：另由证书提供方与业务管理员替换、配置并验收。
- 怀疑已发生攻击或泄露：还需安全事件响应，导入证书不会撤销已泄露的凭据或追回数据。
- **完全离线的机器：这版脚本运行时仍需下载清单，不能直接离线运行。** 离线设备由 IT 使用批准的集中／离线分发方案；不要移除哈希校验或临时取消联网限制来强行运行。

只在 TMS 服务器上导入，不能代替用户 Windows 设备上的防护。S2S 要检查发起连接的子 TMS 如何验证父 TMS；父端对已登记子证书和账号权限的验证是另一层，不能由此次导入替代。

## 执行前必须知道的风险

| 行为或限制 | 运维含义 |
| --- | --- |
| 需要管理员权限、PowerShell 5.1+ 及 Windows PKI 模块 | 本文使用 64 位 Windows PowerShell 5.1；上游最低版本声明不代表本仓库已实测阻断脚本的 PS5.1／PS7 兼容性 |
| 运行时联网下载并校验固定 SHA-256 | 依赖站点、DNS、代理和 TLS；下载失败或哈希不同应停止查因，不能绕过 TLS 或删除校验 |
| 导入持久写入机器级 Disallowed | 关闭 PowerShell 窗口不会撤销；同机依赖此验证路径的其他应用也可能受影响 |
| 合法业务仍依赖受损层级时也可能被拒绝 | 可能导致 memoQ、Web、S2S、API／插件连接或软件签名验证失败；执行前安排证书迁移与业务窗口 |
| 没有确认提示、没有预演开关 | **未实现 `-WhatIf`／`-Confirm`。不要追加这些参数当作安全试跑，应只读审查源码，并在获准的测试机实际验证** |
| 逐张导入，非事务操作 | 中途失败时可能已导入一部分；非零退出不代表零修改，也不能直接盲目重跑 |
| 没有自动回滚和结构化审计报告 | 需自行保存前后报告、执行输出、退出码和变更记录；不能把终端没有报错当作完整验收 |
| 导入已知 16 张证书 | 不是通用 SPKI 黑名单，不能承诺其他包装、全部应用和未来变化都被覆盖 |

## 操作流程：每一步完成后再继续

### 第 1 步：只读自查，保存变更前基线

在仓库根目录运行对应版本，输出父目录须已存在且为本地目录。例如在 64 位 Windows PowerShell 5.1 中：

```powershell
.\Test-EmudhraCA-PS51.ps1 -OutputDirectory $env:TEMP
```

保存这次输出文件夹作为“变更前”。先看 TXT，再看 JSON 的覆盖缺口；关键 Root／CA／Disallowed 读不到时补查。记录当前机器、执行身份、时间、应用版本、实际 TLS 后端和已有 Disallowed 条目，不导出私钥。按需另查真实服务账号。

同时确认合法业务基线：memoQ 登录、项目同步／交付、Web、已启用的 S2S 查询／交付和插件调用是否正常。只测实际使用的功能，用测试项目和测试账号。

### 第 2 步：IT 判断是否需要补充阻断

- 已有有效 CTL／软件更新，且真实验证路径已拒绝受损链：记录证据，继续验收覆盖，**无需重复运行此补救脚本**。
- 系统更新是否生效未知：先核实分发、策略、验证行为；未知不等于需要立即导入。
- 未获得有效阻断，且目标应用使用 Windows 验证：IT 评估本脚本作为补充措施，确定机器范围、试点、业务窗口、失败负责人和恢复计划。
- 独立验证器或不校验证书：走其厂商的修复方案；不能拿本脚本作为已完成修复的依据。

本地零匹配、只有相关根、出现非 Disallowed 命中，都不能单独代替这一步的判断。自查脚本不进行实际握手或 CTL 验证。

### 第 3 步：审查并在批准的测试机准备变更

下载仓库文件到已有本地工作目录。逐行检查脚本，核对 [上游记录](UPSTREAM.md) 和根目录 `SHA256SUMS.txt`。以下检查只读取本地文件与模块信息，在仓库根目录执行：

```powershell
$blockFile = '.\mitigation\Block-EmudhraCompromisedCA.ps1'
$expectedHash = '0C758183E511C535CDCD58EE97B4712A76BCA3963E72634DCB29AF2A0B8424B3'
if ((Get-FileHash -LiteralPath $blockFile -Algorithm SHA256).Hash -ne $expectedHash) {
    throw 'Blocker file differs from the reviewed snapshot. Stop and review.'
}
Get-Module -ListAvailable PKI
```

PKI 模块不存在、文件不同或执行策略阻止时，交由 IT 处理；不要安装不明同名模块，不使用 `ExecutionPolicy Bypass`、`Set-ExecutionPolicy` 或自动解除阻止来绕过组织流程。哈希用于识别本次审查版本，不替代可信分发与源码审查。组织若签名／重新封装，应记录变更并核对签名前内容，不能把变动忽略掉。

**先在获准的测试机完成第 4～6 步，再批准生产分发；不要在生产机做首次试跑。**

### 第 4 步：批准后执行阻断，记录输出与退出码

仅在组织已经批准的管理员 **64 位 Windows PowerShell 5.1** 窗口，从仓库根目录执行下面代码。这一步会联网并修改机器级证书存储区；前面的文件校验不是执行授权。

```powershell
$blockLog = Join-Path $env:TEMP ('EmudhraBlock-' + [Guid]::NewGuid().ToString('N') + '.txt')
powershell.exe -NoProfile -File .\mitigation\Block-EmudhraCompromisedCA.ps1 *> $blockLog
$blockExitCode = $LASTEXITCODE
Write-Output ('ExitCode=' + $blockExitCode + '; Log=' + $blockLog)
```

保存该日志和退出码。命令不带执行策略覆盖参数；如果被组织策略阻止，停止并走审批／签名流程。若失败，先查看错误、重新清点实际已导入状态，再由 IT 决定下一步；本脚本没有自动回滚。

### 第 5 步：重跑只读自查，逐张核对导入结果

用第 1 步同样的运行时、身份与输出父目录重跑自查，新文件夹作为“变更后”。先确认 TXT／JSON 完整可读、机器级 Disallowed 读取成功，再比对 16 个完整 DER SHA-256。

可用下面的**本地只读核对代码**，将第一行改为刚生成的“变更后” JSON 路径。它只读 JSON，不运行阻断、不联网、不读取证书私钥、不修改存储区：

```powershell
$reportPath = 'C:\Temp\请替换为变更后报告目录\report.json'
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

同一次变更必须使用本机新报告，不能拿旧报告或其他机器的结果验收。核对清单来源于脚本固定清单，仅含公开证书名称、签发者及指纹；它不是导入文件，阻断脚本也不会读取它。

预期含义：

- `Expected=16, Present=16, Missing=0` 只说明新报告中已读到这 16 张证书；不证明是本次新增，也不证明全部应用已拒绝它们。对比变更前报告记录实际差异。
- `CompromisedEntries` 可能增加：Disallowed 里的已知受损证书仍会被自查识别，这是正常现象。不要删除阻断条目来“消除告警”。
- `CompromisedEntriesOutsideDisallowed` 不一定归零：原本在 CA 等存储区的副本不会被本脚本删除。需结合相应阻断条目和真实应用验证判断，不能仅据该计数认定成功或失败。
- `SafetyConclusion` 始终为 `NOT_ASSESSED`；关键覆盖缺口未解决时不得宣告导入验收完成。
- 16/16 是**采用本脚本后的显式导入目标**。没运行过本脚本的机器不能因为不足 16 就认定不安全，Windows CTL 或应用自身可能已有效阻断。

### 第 6 步：验收实际应用，确认业务正常与拒绝有效

| 检查路径 | 至少保留的证据 |
| --- | --- |
| Windows 上实际 memoQ 桌面客户端 → TMS | 合法服务器登录与必要同步／交付正常；在获准隔离测试中错误名称、不受信链和相关受损链被该客户端拒绝 |
| 实际浏览器 → memoQ Web | 合法页面与功能正常，受损链被该浏览器拒绝；浏览器结果只代表该浏览器 |
| 子 TMS → 父 TMS 的 S2S | 按实际版本与服务身份验证父端 TLS 链，合法连接及所用查询／交付正常；父端登记子证书、Server connection 和权限仍按预期工作 |
| MT／AI、API 或其他外连 | 按调用发生的机器、账号、运行时和实际 CA 库分别验证，保留应用证书错误和正常基线 |

生产做合法业务回归；异常证书的拒绝测试放在 IT 批准的隔离环境，使用测试账号和测试数据，不把真实凭据、项目或翻译文本发往公开测试站。只验证实际启用的路径，并记录没测到的部分。

验收应建立新的 TLS 连接，不能用变更前已建立的长连接、会话复用或仍保持登录的界面作为证书重新验证的证据。是否需要重启应用／服务，应按厂商要求和维护窗口安排；本脚本不会自动重启。

证书验证明确拒绝才是相关测试的有效证据；超时、DNS 失败、HTTP 403 或普通业务错误不是阻断证明。`curl`、浏览器、通用 .NET 测试的成功拒绝，不能自动代替真实 memoQ／S2S 应用的结果。若无法在实际应用中验证，应记录“导入已核对，应用阻断效果未验证”，不能写“已全部修复”。

本仓库没有提供可直接在 memoQ 中运行的恶意证书握手测试器，也没有对真实 memoQ／S2S 连接完成此项验收。

## 失败与恢复处理

记录错误、前后报告和日志，由 IT 判断是下载／哈希、权限／策略、部分导入，还是业务证书链被阻断。没有自动回滚；不要批量清空 Disallowed、删除相关根、忽略证书错误或恢复对受损链的信任来恢复连接。

合法业务被阻断时优先迁移到受支持证书链；需要改动生产环境时按既有变更和应急流程处理。恢复计划应区分变更前已有条目与本次新增条目，避免移除既有保护。日志和报告包含运维信息，分享前脱敏，不提交到公开仓库。

参考：[事件站 Windows 缓解说明](https://emudhra.we-have-a-problem.com/)、[Microsoft CTL 更新说明](https://learn.microsoft.com/en-us/windows-server/identity/ad-cs/configure-trusted-roots-disallowed-certificates)。
