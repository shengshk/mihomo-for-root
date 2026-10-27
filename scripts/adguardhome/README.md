# AGH 锁修复

基于 [AdGuard Home v0.107.79](https://github.com/AdguardTeam/AdGuardHome/tree/05ba17b282da1c4393d6a4ba4db0cf519194a362)，版本标识 `v0.107.79-mfr.1`，沿用 GPL-3.0。相关上游报告：[AdguardTeam/AdGuardHome#8658](https://github.com/AdguardTeam/AdGuardHome/issues/8658)。

DNS 查询记账持有 `serverLock.RLock` 时，客户端查找可能经 `IsBlockedClient` 再次取得同一读锁。此时若配置重载已排队等待写锁，内层读锁无法取得，外层也无法退出，导致 DNS/API 卡住。

`access-lock.patch` 为访问控制对象增加独立锁，覆盖对象替换、客户端与域名检查；保留保护日志/统计对象的外层锁。需要两个锁时固定先 server、后 access。没有关闭日志、统计或客户端检查。

运行 `sh scripts/build-adguardhome.sh`，使用固定提交、上游 npm 锁文件和完整 Web UI 构建 ARM64 二进制；先运行 `accounting_lock_test.go` 的针对性回归。需要 Go 1.26.6、Node.js 22+、npm、Git、patch。可通过 `MFR_GO_BIN` 选择 Go，`MFR_AGH_SOURCE` 指向该提交的本地 Git 源码；导出的是固定提交，不包含本地改动。

安装包携带原许可证和相同补丁；`assets/VERSIONS.json` 记录固定提交、补丁和二进制摘要。缓存匹配时可离线复用。

模块另有故障兜底：一次切换最多尝试两次、中间仅重启 AGH 一次；仍失败就保存停用状态、撤销接管并恢复原 DNS 劫持设置，保留规则和历史。普通查询超时、核心 DNS 未就绪、锁占用不触发停用。恢复运行配置失败时保留待恢复标记；不会无限重试同一个 AGH API，也不自动重新启用 AGH。
