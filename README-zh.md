# memoQ security

[English](README.md) | 简体中文

面向 memoQ TMS 运维的 Windows 安全自查与处置资料，针对 2026 年 10 月 eMudhra / emSign 中间 CA 密钥事件。**本仓库不是 memoQ 官方工具，也不提供“机器已安全”的自动判定。**

事件背景与公开指标：[eMudhra Intermediate CA Compromise](https://emudhra.we-have-a-problem.com/)。根目录的 `Test-*.ps1` 是只读自查；`mitigation/` 单独保存**会联网、会修改不受信任证书存储区**的上游阻断脚本。自查不会自动调用阻断脚本。

| 用途 | 文件位置 | 对系统的影响 | 验证状态 |
| --- | --- | --- | --- |
| 本地只读自查 | 根目录 `Test-EmudhraCA-PS51.ps1` / `Test-EmudhraCA-PS7.ps1` | 不联网、不改证书或配置，仅生成 TXT／JSON | 两版各 61/61 项检查通过，见 [验证记录](VALIDATION-zh.md) |
| IT 审批后补充阻断 | [mitigation/Block-EmudhraCompromisedCA.ps1](mitigation/Block-EmudhraCompromisedCA.ps1) | 联网下载清单，向 `LocalMachine\Disallowed` 导入 16 张证书 | 上游原样副本；仅静态审查和哈希核对，**未执行、未做阻断实测** |

## 自查之后能不能直接运行阻断脚本？

**不能把“自查运行成功”理解成“可以直接阻断”，也不能把“零匹配”理解成“已经安全”。** 自查回答的是本地有什么、哪些地方没读到；阻断是否必要以及是否有效，要结合系统更新和实际应用判断。

按下面流程执行；每一步达成条件后再进入下一步，不能把两个脚本串成一键命令：

1. **先自查并保存基线。** 在 Windows Server 和相关 Windows 客户端分别运行合适版本，保存 TXT／JSON。先处理读取失败、关键覆盖缺口；报告完整只代表清点完成。
2. **由 IT 判断是否需要补充阻断。** 核对 Windows CTL／厂商更新是否已生效，以及目标软件是否使用 Windows 系统证书验证。已有有效阻断时，无需重复运行此补救脚本；使用独立 CA 包的软件应走其自身更新流程。企业设备由 IT 统一安排，不由普通用户临时执行。
3. **确有需要时，先测试和审批。** 保存变更前状态、确认合法业务证书链、准备故障处置方案；在获准的测试机／试点机验证。这个上游脚本没有预演模式，不能加 `-WhatIf` 当作无修改试跑。
4. **批准后才实施。** 按 [阻断操作流程](mitigation/README-zh.md) 校验文件，在管理员 Windows PowerShell 中执行并记录输出和退出码；不要绕过执行策略。中途报错要核对是否部分导入，不可当作“什么都没改”。
5. **先核对导入，再验收应用。** 重跑自查，用完整 DER SHA-256 逐一核对 16 张证书的机器级 Disallowed 条目；然后验证实际 memoQ 客户端、Web、S2S 和插件的正常业务与证书拒绝行为。**证书导入成功不等于防护验收完成。**

| 自查或现场情况 | 下一步 |
| --- | --- |
| 报告报错、缺文件，或关键存储区未读全 | 先补查；不能据不完整报告自动决定阻断 |
| 受损条目在非 Disallowed 存储区 | 优先调查实际信任与使用情况，按上面第 2 步决定处置；不是“发现即运行” |
| 只在 Disallowed 命中，或已确认系统／应用更新有效 | 保留已有阻断，验收覆盖；不为清零计数重复操作或删除条目 |
| 零匹配，或只有相关根／名称线索 | 继续核实更新和实际应用；既不是安全证明，也不是直接阻断的理由 |

完整适用范围、执行风险、执行命令及导入后核对示例见 [mitigation/README.md](mitigation/README-zh.md)。

## 只读自查：选哪个脚本

| 运行环境 | 文件 | 启动程序 |
| --- | --- | --- |
| 64 位 Windows PowerShell 5.1 | [Test-EmudhraCA-PS51.ps1](Test-EmudhraCA-PS51.ps1) | `powershell.exe` |
| Windows 上的 64 位 PowerShell 7 | [Test-EmudhraCA-PS7.ps1](Test-EmudhraCA-PS7.ps1) | `pwsh.exe` |

两个文件均可单独运行，无第三方模块依赖；检查范围和指标相同，只接受对应运行时。PS7 版仍是 **Windows 专用**，不适用于 macOS / Linux。脚本不会安装 PowerShell。先用 `$PSVersionTable` 查看版本，再选择文件。

## 运行只读自查

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

## 只读自查的边界

仅创建报告目录及 TXT／JSON。**不联网、不下载、不构建证书链、不查询 CRL／OCSP、不读取私钥、不增删证书、不改注册表／信任配置／执行策略、不重启服务、不上传报告。**

报告可能包含内部域名、证书主体、IP／端口、账号和软件版本；分享前脱敏，勿直接提交到公开仓库。JSON 中 HTTP.sys 的 Base64 字段是原始命令输出字节，不是私钥。

## 怎样看结果：先读 TXT，再查 JSON

1. 打开 `report.txt`，先看 `Scan status`、`SUMMARY`、`MATCHED ENTRIES` 和 `COVERAGE ISSUES`。
2. `SUMMARY` 中最先看 `CompromisedEntriesOutsideDisallowed`、`CompromisedEntries` 和 `CoverageIssueCount`。不能只看第一行或退出码。
3. 用 JSON 定位具体条目：`Summary` 是计数，`Certificates[]` 的 `Matches` 是分类，`Location` / `Store` / `InDisallowed` 是所在存储区，`CertificateSHA256` / `SpkiSHA256` 是检测依据。
4. `TrustUpdateRegistry[]` 记录配置和缓存存在情况，`HttpSys` 记录绑定读取状态及原始输出，`CoverageIssues[]` 记录未完成的检查。

| TXT 位置／字段 | JSON 对应位置 | 怎么用 |
| --- | --- | --- |
| `SUMMARY` 的各项计数 | `Summary.*` | 先判断是否有受损命中、是否存在非 Disallowed 条目 |
| `MATCHED ENTRIES` | `Certificates[].Matches` 及条目元数据 | 定位实际证书，不按名称猜测 |
| `STORE COVERAGE` | `Stores[].Status` / `Problem` | 确认哪些存储区缺失、不可读或只读到一部分 |
| `TRUST UPDATE CONFIGURATION...` | `TrustUpdateRegistry[].Values[]` | 看策略值，不能据缓存存在判断已修复 |
| `HTTP.sys: Read / Failed / Skipped` | `HttpSys.Status` / `Problem` / `Stdout` | 区分读取成功、读取失败、主动跳过；`Read` 不代表 TLS 安全 |
| `COVERAGE ISSUES` | `CoverageIssues[].Scope` / `Problem` | 按错误对象补查，不能把失败当零风险 |

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

## 哪些结果需要紧急处理

下面是**人工处置优先级建议**，不是脚本自动生成的漏洞等级；组织既有应急和变更流程优先。

| 结果／现场证据 | 优先级与判断 | 对应处理 |
| --- | --- | --- |
| 现场已确认恶意冒充、异常数据外发，或凭据发送给了攻击端点 | **立即启动安全事件响应**。自查脚本本身不能发现或确认这些事实 | 联系安全团队，保留证书、时间、连接与应用日志；控制受影响通信路径；按实际暴露范围撤销会话、轮换凭据并调查数据影响。不要因单纯本地命中就断言凭据已泄露 |
| 实际 memoQ／S2S／插件测试确认仍接受真实受损链 | **紧急修复验证器**，但尚不能据此证明发生过攻击；本工具不执行此测试 | 在修复与验证完成前，按组织应急流程限制相关敏感数据传输；执行下面方案 A，并按方案 F 验收 |
| `Summary.CompromisedEntriesOutsideDisallowed > 0` | **高优先级核查，建议尽快当日处理**：受损证书或公钥出现在至少一个非 Disallowed 存储区；不等于已被信任、正在使用或已遭攻击 | 查看具体条目和受影响应用，执行方案 A；若业务叶证书链确实依赖受影响层级，另执行方案 B。不要先删证书 |
| `CompromisedEntries > 0`，且 `CompromisedEntriesOutsideDisallowed = 0` | **仍需验证阻断覆盖**：本次命中的条目都在 Disallowed，但不能确认其他包装、账号和应用已阻断 | 保留阻断条目；按方案 A/F 检查交叉签名、服务账号、独立证书库与真实客户端。不要为了让命中数归零而删除 Disallowed 条目 |
| `EnableDisallowedCertAutoUpdate=0` | **优先核查更新路径**：自动不受信任 CTL 更新被关闭 | 执行方案 C；若组织有有效的集中／离线分发，不一定是故障，但必须有实际分发与阻断证据 |
| `DisableRootAutoUpdate=1` | **核查策略意图**：关闭自动受信任根更新；不等于自动不受信任 CTL 更新也关闭 | 执行方案 C，分别核实两类策略。不要为了此次事件盲目修改受信根策略 |
| `CoverageIssueCount > 0`、`CompletedWithCoverageIssues`、`MissingOrInaccessible`、`Partial`，或 HTTP.sys `Failed` | **检查不完整，需补查**；不是“发现攻击”，也不是“没发现风险” | 执行方案 D；关键 Root／CA／Disallowed 无法读取应优先补查。明确未部署的 WebHosting 缺失可记录为适用范围限制 |
| 只有 `KnownRelatedRootNotProofOfCompromise` / `NameOnlyNeedsChainReview` | **关联线索，不能直接报受损** | 执行方案 E，核对真实链；不要批量删除 AAA / emSign 根或按名称删除证书 |
| 受损计数为 0，覆盖问题也为 0 | **仅本地清点未命中**，没有“安全通过”结论 | 继续按方案 F 验证实际应用；业务连接可能收到本地未缓存的中间证书 |

`HttpSys.Status=Skipped` 表示指定了 `-SkipHttpSys`，不是读取失败；是否补查取决于该机器是否承载相关服务。相关软件的版本、服务 `Running`、`EncodedCtl` / `DisallowedCertEncodedCtl` / 同步时间值存在，都不是单独的修复验收证据。

## 对应处理方案

### 方案 A：受损证书／公钥命中，或应用仍接受受损链

1. 保存本轮 TXT／JSON，记录命中条目的存储区、DER／SPKI 和时间。以哈希命中为依据，不依据证书名称或 SHA-1 单独判断事故范围。
2. 识别实际验证者：译员／PM 的 memoQ 客户端、浏览器、发起 S2S 的子 TMS、运行 MT／AI 插件的机器、调用 API 的外部程序。管理员账号的结果不能代替服务账号。
3. IT 统一核对 Windows 不受信任 CTL 分发和相关厂商更新，确认策略允许、更新源可达且实际生效；独立 CA 包／运行时按其厂商方案更新。Windows 更新不能自动代表所有独立应用完成修复。
4. 对暂时无法获得更新的机器，由 IT 评估是否采用下文的精确证书阻断方案，先测试业务影响，记录变更前后状态，再按组织流程分发。不要批量移除根、删除 IIS 绑定或关闭证书验证。
5. 按方案 F 验证目标应用确实拒绝相关链；本地扫描数值不能代替这一步。

### 方案 B：合法业务证书需要迁移，或更新后无法连接

由 IT／证书供应商核对实际握手链，确认是否依赖受影响层级。确需迁移时，取得受支持的替代证书链，按 memoQ 版本和实际部署更新 IIS、HTTP.sys、反向代理或其他 TLS 终止点；各入口分别验收，不只看 443，也不凭端口号猜测服务。

若更换了被用于 S2S 子端身份的叶证书，还需检查父端登记证书、Server connection 关联及子端私钥可用性；这与父端 HTTPS 证书是两种角色。变更前留存配置与回退计划，防止只改一处导致客户端／S2S 断连。**不要用忽略证书错误、重新信任已受损链来恢复业务。**

### 方案 C：信任更新配置异常、禁用或不明确

分别确认自动受信根与不受信任 CTL 的策略、域策略覆盖、集中／离线分发方式，以及客户端实际获得的内容。字段未配置通常意味着默认行为，仍不能证明更新成功。离线环境使用 IT 管理的可信分发流程，不要临时从不明来源导入根证书。

Microsoft 文档说明 CTL 管理与 WSUS 是独立概念，因此“WSUS 没有待装补丁”不能单独作为 CTL 已更新的证据。具体部署方式参考 [Microsoft CTL 官方说明](https://learn.microsoft.com/en-us/windows-server/identity/ad-cs/configure-trusted-roots-disallowed-certificates)。

### 方案 D：覆盖缺口或报告生成失败

按 `CoverageIssues` 的 Scope 和 Problem 处理：确认选择了正确的 Windows PowerShell／PowerShell 版本、64 位进程和已有本地输出目录。权限不足时在获准的管理员上下文重跑；仍需另查实际服务身份，不要给整个目录或私钥增加宽泛权限来消除报错。

存储区确未部署时注明原因，不为消除警告创建空存储区。HTTP.sys 失败时核对其错误和系统 netsh 读取权限；SPKI 解析失败时该条目不能视为“已检查且无风险”，应交由 IT 使用可信工具复核。若文件不存在、截断或 JSON 无法解析，本轮视为未完成，不能用于安全判断。

### 方案 E：仅相关根或名称线索

相关根本身存在不代表根私钥泄露。证书主体／颁发者名称可伪造，也不能证明真实签名链。记录关联条目，在获准的验证流程中核对实际服务使用的完整链与应用信任行为。没有完整证据时保留“需核查”，不执行批量根删除。

### 方案 F：怎样才算处理完成

- 在实际客户端／服务账号、准确版本与实际 TLS 实现下验收：合法基线连接正常，错误名称和不受信链被拒绝，受损链／相关交叉路径被拒绝。
- 分别验证 memoQ 桌面、Web、S2S、MT／AI、API 等实际启用路径。浏览器或普通 curl 的结果不能代替另一个应用；curl 的 TLS 后端也可能不同。
- 保留证书验证错误及必要日志。超时、DNS 失败、HTTP 403 或业务错误不能当成“证书阻断成功”。测试使用研究者／厂商控制的端点或隔离环境，不向测试端点发送业务数据和真实凭据。
- 重跑自查，确认报告完整、覆盖缺口已有解释或已补齐、变更与预期一致。**受损证书保留在 Disallowed 时继续命中是可能的，不要求所有匹配计数归零。**
- 将应用结果、变更记录和限制写入验收记录。`SafetyConclusion` 仍会固定为 `NOT_ASSESSED`；本工具不会变成“安全通过”。

上述主动连接、更新、证书替换或阻断均属于 IT 另行实施的验证／变更，**不是自查脚本的行为**。

## 上游 Block-EmudhraCompromisedCA.ps1 能否复用

可以作为 **IT 审批后的修复工具**评估复用，不能当作本仓库的只读自查脚本。[上游脚本](https://emudhra.we-have-a-problem.com/Block-EmudhraCompromisedCA.ps1)来自事件汇总站；该站不等同于 Microsoft 或 memoQ 官方发布渠道。本仓库在 [mitigation/](mitigation/README-zh.md) 保存这版原样副本、来源记录和验证清单，与只读脚本分开。

2026-10-22 下载的源码已做静态审查，未在服务器执行。确认其行为：

| 行为 | 审查结果 |
| --- | --- |
| 权限／依赖 | `#Requires -Version 5.1`、管理员权限、内置 PKI 模块。声明 5.1+ 不等于我们实测过该阻断脚本的所有 PS7 环境 |
| 是否联网 | **会**：运行时下载 `impacted-intermediates.json` |
| 完整性检查 | 在任何导入前校验固定 SHA-256；与我们独立核验的清单一致，共 16 张证书、8 个公钥 |
| 写入对象 | 逐张 `Import-Certificate` 到 `Cert:\LocalMachine\Disallowed`，最后删除临时文件 |
| 是否删除受信根 | 这版源码没有删除 Root 中的证书，也没有重启服务 |
| 失败处理 | 非事务操作；若中间某张导入失败，之前导入的证书可能已经保留。必须检查实际结果，不得把非零退出当成“全部没改” |
| 报告／回滚／验收 | 没有本仓库这种 TXT／JSON 清点报告，没有预先导出基线、自动回滚或真实应用阻断测试 |

**企业管理设备不建议由个人逐台临时执行。** 按上游提示，由 IT 负责统一评估和分发；先确认是否已收到 Windows 阻断更新。对确需补充阻断的设备，可在组织批准后复用上游精确证书清单与导入逻辑，但仍需变更记录、失败核对和方案 F 的实际应用验收。

上游网页示例使用 `-ExecutionPolicy Bypass`；本仓库不推荐照抄该参数。企业应采用既有审批／签名及软件分发流程，不以绕过策略作为解决运行错误的方法。

此阻断主要面向使用 Windows 系统证书存储区和链验证的客户端（如相关 Schannel／Authenticode 路径）。独立 CA 包仍需单独更新。导入的是 16 张已知证书，不是部署一个通用的 SPKI 黑名单；不能由此承诺未来其他同公钥包装、全部用户和应用均已覆盖。网页上“证书已导入”不等于 memoQ／S2S 已完成验收。

若固定清单哈希校验失败，应停止、核查上游变更，不能删除检查或随意替换哈希来强行运行。供审计比对的本次源码与清单哈希如下；上游以后可能更新，下载后应重新审查。

```text
0C758183E511C535CDCD58EE97B4712A76BCA3963E72634DCB29AF2A0B8424B3  上游阻断脚本源码
F67B3ABE9B4879F4E91874ED041BECCD71257F1DB41C588C724CCF12AA90C59E  其固定的 impacted-intermediates.json 清单
```

## 三个最容易误判的示例

下面仅为字段示例，不是任何客户机器的实际扫描结果。

| TXT / JSON 摘要 | 正确理解 | 应做什么 |
| --- | --- | --- |
| DER=1、SPKI=1、`CompromisedEntries=1`、`CompromisedEntriesOutsideDisallowed=1` | 同一条目可以同时命中 DER 和 SPKI；不是两张证书。至少一个受损条目不在 Disallowed | 高优先级执行方案 A，确认实际链和验证器；不直接判断已被攻击 |
| DER=1、SPKI=1、`CompromisedEntries=1`、`CompromisedEntriesOutsideDisallowed=0` | 已知受损条目在 Disallowed，继续命中不一定是修复失败 | 不删除阻断条目；核对应用与交叉路径，按方案 F 验收 |
| DER=0、SPKI=0、`CoverageIssueCount=0`，可能只有相关根 | 本地已读范围未命中；不能回答远端链会不会被接受 | 不因相关根存在而删除它；继续验证实际应用 |

## 对 memoQ 的风险

非 S2S：客户端／浏览器可能在连接被劫持且假证书被接受时误信假 TMS；MT／AI 外连也可能涉及文本、请求凭据泄露或响应篡改。检查 Windows Server 与用户 Windows 设备，不能只看 IIS 证书。

S2S：分别检查子 TMS 对父 TMS 的服务端身份验证，以及父 TMS 对已登记子证书、Server connection 和权限的核验。受损 CA 不会自动授予合法合作方身份。若合法业务证书依赖被阻断的链，还可能出现连接中断。

可直接转发的通知见 [NOTICE-zh.md](NOTICE-zh.md)。实测环境和限制见 [VALIDATION.md](VALIDATION-zh.md)。

## 指标与来源

指标快照：2026-10-22。此前已在制作环境以 OpenSSL 从 20 张公开 PEM 独立重算，确认 16 张受损证书、8 个受损公钥及 4 张相关上级证书与脚本一致。脚本不在线刷新指标；后续变化需要重新核查。

- [Mozilla 原始事故记录](https://bugzilla.mozilla.org/show_bug.cgi?id=2083449)
- [Google Chrome / Android 通告](https://blog.google/security/protecting-chrome-and-android-users-from-compromised-emudhra-intermediate-ca-certificates/)
- [受损证书清单](https://emudhra.we-have-a-problem.com/impacted-intermediates.json) / [相关上级清单](https://emudhra.we-have-a-problem.com/roots.json)
- [Microsoft CTL 更新说明](https://learn.microsoft.com/en-us/windows-server/identity/ad-cs/configure-trusted-roots-disallowed-certificates)
- [HTTP.sys 命令说明](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/netsh-http)
- [memoQ S2S 工作流](https://docs.memoq.com/current/en/Concepts/concepts-s2s.html) / [Server connection 配置](https://docs.memoq.com/current/en/Workspace/server-connection-properties.html)

根目录的只读自查脚本不会执行网站上的主动网络测试或本地阻断操作；`mitigation/` 阻断脚本会修改系统，必须单独按组织变更流程评估和实施。
