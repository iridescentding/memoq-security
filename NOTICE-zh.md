# 可转发给 IT 运维的说明

[English](NOTICE-en.md) | 简体中文

## 非 S2S 用户

IT运维老师您好：印度CA机构eMudhra的部分中间CA私钥受损，可能被用于伪造服务器证书。若连接被劫持且软件仍接受这些证书，攻击者可能冒充memoQ TMS或MT/AI服务，窃取登录信息、API密钥和翻译文本，或篡改返回译文。请关注Windows Server与用户Windows设备；IIS证书正常、浏览器已更新，不代表全部连接安全。

## S2S 用户

IT运维老师您好：eMudhra事件对S2S的主要风险，是子TMS在连接被劫持、假证书未被阻断时误信假父TMS，泄露查询或交付内容，或接收伪造的记忆库、术语结果，影响客户保密与交付质量。但不等于攻击者自动取得已登记合作方权限。若合法业务证书链受阻断影响，双方Windows Server之间的S2S连接也可能中断。

## 两版通知共用的链接与附件说明

事件详情：https://emudhra.we-have-a-problem.com/

Windows 本地只读自查：[PowerShell 5.1 版](Test-EmudhraCA-PS51.ps1) / [PowerShell 7 版](Test-EmudhraCA-PS7.ps1)，使用步骤见 [README](README-zh.md)。两版均不联网、不改证书或配置，仅生成本地 TXT／JSON。请按运行时选择，输出父目录需已存在；勿绕过组织安全策略。

**自查零匹配不代表安全，不能替代实际 memoQ／S2S 证书验证验收。报告分享前请脱敏。**

仓库另附 [IT 阻断处置流程与上游脚本](mitigation/README-zh.md)。该脚本会联网并修改系统证书存储区，不能因自查运行成功就直接执行；企业设备由 IT 评估、测试后统一部署。阻断脚本尚未实机执行验证。
