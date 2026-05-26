# OnionBird

**语言:** [English](README.md) · [Deutsch](README.de.md) · [Français](README.fr.md) · [Português](README.pt.md) · [Español](README.es.md) · [Polski](README.pl.md) · [Українська](README.uk.md) · [Русский](README.ru.md) · [Беларуская](README.be.md) · [Türkçe](README.tr.md) · [فارسی](README.fa.md) · [العربية](README.ar.md) · [עברית](README.he.md) · [Kurdî](README.ku.md) · [اردو](README.ur.md) · [پښتو](README.ps.md) · [ئۇيغۇرچە](README.ug.md) · [हिन्दी](README.hi.md) · [বাংলা](README.bn.md) · **简体中文** · [བོད་ཡིག](README.bo.md) · [Tiếng Việt](README.vi.md) · [ภาษาไทย](README.th.md) · [မြန်မာ](README.my.md) · [Bahasa Indonesia](README.id.md) · [Afrikaans](README.af.md) · [Kiswahili](README.sw.md) · [አማርኛ](README.am.md) · [ትግርኛ](README.ti.md) · [ქართული](README.ka.md)

> **ALPHA — 后期 alpha,在感知 Tor-DNS 的操作系统上无泄漏。安装前请阅读[前置条件](#安装前)。**

> 在用于匿名性关键的场景之前,请阅读[威胁模型](docs/threat-model.md)与 [follow-up 清单](docs/follow-up.md)。

OnionBird 是一个 Thunderbird 扩展,通过本地 Tor 代理路由 IMAP/SMTP,并剥离或归一化历史上被用来对发件人去匿名的邮件头。目标:Thunderbird 140 ESR。定位为不再维护的 TorBirdy 扩展(末版 v0.2.6,2018 年;在 TB 78 移除 Legacy XUL 后失效)的现代继任者。

当前版本:**0.1.4**。

---

## 100% 隐私与安全策略

项目的授权是二元的:**任何可观察的代码路径,如果泄露用户身份、真实 IP、hostname、locale、时区,或者用户正在加固邮件这一事实本身,都视为 P0 缺陷并阻断发布。** "够好了"、"通常能用"、"几乎没漏"都不是可接受的结果。

具体地:

- **默认 fail-closed。** `network.proxy.failover_direct = false` 强制 — 如果配置的 Tor 代理不可达,发送应当失败。扩展从不静默回落到 clearnet。
- **DNS 仅经 Tor。** `socks_remote_dns = true`、`network.trr.mode = 5`(无并行 DoH)、`network.dns.disablePrefetch = true`。经验证:真实 Tor 发送期间到达本地 resolver 的 DNS 查询为零。
- **OCSP 关闭。** 否则吊销检查会在每次 TLS 握手时向 CA 发起 clearnet HTTP 请求。
- **无更新 phone-home。** app + 扩展 + GMP-manager 的 URL 已清空。
- **无遥测、无 Safebrowsing、无 captive-portal 探测、无远程内容渲染。**
- **无 WebRTC、无 geolocation、无 DNS prefetch、无 predictor。**
- **会话中保护。** 每次 TB 启动以及加固期间,prefs 都会重新断言。
- **加固可逆。** 首次启用前会快照,通过选项页 Disable 按钮或 `disable-hardening` 消息恢复。
- **Self-test canary** 在启动和加固活动期间运行:把 SOCKS5-RESOLVE(3 条流隔离的 Tor circuit)与系统 resolver 完整应答集合做比对。
- **隐私安全的诊断。** 日志汇总计数、掩码 IP 与错误类别 — 不含原始 IP 与账号标识符。
- **experiment API 中的 pref 写入 allowlist。**

**固有边界 — OnionBird 不能修复:**

1. **`Authentication-Results: ... smtp.auth=<你的邮箱>@<服务商>`** 由服务商 MTA 添加 — 让每个收件人看到你认证的邮箱。*绕过:*敏感往来用一次性 / 化名邮箱。
2. **Tor 出口 IP 会出现在收件人的 `Received:` 链中。** MTA 做 reverse-DNS,生成像 `tor-exit-107.digitalcourage.de` 这样的名字。收件人知道"此用户经 Tor 发送"。
3. **OS 层泄漏** — 其他应用泄漏 hostname、NTP、swap、文件系统时间戳。请使用 Tails 或 Whonix。
4. **网络相关性** — 同时观察 Tor circuit 两端的对手。头部卫生无法击败它。

不属于这四类的一切都属于策略**范围**。发现反例请提 P0 bug。

---

## mail-Tor 全景

完整对比见 [README.md (EN)](README.md#onionbird-vs-torbirdy--feature-by-feature)。简言之:OnionBird 是**普通的 Thunderbird 扩展**(不是像 Tails/Whonix 那样的独立操作系统),具备**经验证的 DNS-via-Tor 覆盖**、**持续的 canary**,以及**可配置的 Message-ID FQDN**(替代 TorBirdy 那种 supercluster `localhost.localdomain`)。

---


> ⚠️ **与为 Tor 加固的操作系统堆叠** — OnionBird → Thunderbird; [Tails](https://tails.net/) / [Whonix](https://www.whonix.org/) → OS-level isolation.

## 安装前

扩展加固在 Thunderbird **内部**运行的部分。要 100% Tor 覆盖,**操作系统的 resolver** 也必须走 Tor:

- **Tails / Whonix workstation** — 系统 DNS 已经走 Tor。安装 `.xpi` 即可。
- **带系统 Tor 的标准 Linux** — 在 `/etc/tor/torrc` 中加上 `DNSPort 5353`,并确保 `/etc/resolv.conf` 指向它。
- **仅 Tor Browser bundle** — Tor 监听 `9150` 而非 `9050`;扩展会在写入代理 prefs 之前探测现有 pref 和两个常用本地端口。
- **远端 Tor/Whonix SOCKS** — 使用 IP 字面量(`10.152.152.10:9050`),不要用 hostname。
- **没把 OS DNS 经 Tor 的普通桌面** — 自负风险。canary 会在选项页和控制台标出该配置。

---

## 现在能做什么

- 通过本地 SOCKS5 代理(默认 `127.0.0.1:9050`,可配)路由 IMAP/SMTP,使用 `socks_remote_dns=true` 与 `failover_direct=false`。
- 归一化身份头:`User-Agent` / `X-Mailer` 抑制,`Message-ID` 的 FQDN 可配(默认你的 From-domain),SMTP `HELO`/`EHLO` 改写为 `[127.0.0.1]`,`Date` UTC,无 `format=flowed`。
- Defense-in-depth:TRR=5,OCSP off,无 WebRTC,无 DNS prefetch,无 predictor,无 phone-home,无遥测,无 Safebrowsing,无 captive-portal,无远程内容。
- **SOCKS5-RESOLVE vs 系统 DNS canary** 启动与周期运行。
- 选项页有 **Tor test mode**。
- 选项页支持系统/浅色/深色主题、多语言 UI 以及内置帮助(TL;DR + Nerd 模式)。
- 首次安装自动启用。**Disable 按钮**恢复 snapshot。
- 默认只加固 **onion + loopback** 的 SMTP 服务器(B-003) — 你已有的 clearnet 账号保持正常工作。

---

## 架构

OnionBird 是混合架构:一个 MailExtension 后台脚本提供公共 API 面,另一个 Experiments API 模块运行在 parent 进程中,暴露 `Services.prefs`、`MailServices.outgoingServer`、`MailServices.accounts`、原始 SOCKS5 RESOLVE / RESOLVE_PTR 及 `nsIDNSService.clearCache` 操作。两半通过自定义命名空间 `browser.onionbird.*` 通信。见 [docs/architecture.md](docs/architecture.md)。

---

## 路线图 / 已知限制

见 [docs/follow-up.md](docs/follow-up.md)。延迟到后续版本:mixed-mode UI 开关、网络链路/resolver 变化 hook、多 circuit PTR 重试、扩展创建的 login 标记、首次运行向导、面向被审查 ISP 的 bridges / pluggable-transports、Tor control-port 集成(每次发送 NEWNYM)、打包的跨平台安装器。

---

## 许可证

MPL-2.0。完整文本见 [LICENSE](LICENSE)。

软件按"原样"提供,不附任何明示或暗示的担保。作者不对因使用本软件而产生的去匿名或其他损害承担责任。完整免责声明见 LICENSE。
