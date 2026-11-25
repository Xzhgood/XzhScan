# Changelog

All notable changes to XzhScan will be documented in this file.

## [4.1.0] - 2025-11-26

### Added

- **复制 sqlmap 命令**：漏洞结果页仅 CONFIRMED 行提供，自动生成自包含
  `-u/--data/-H` 命令（含 Cookie/Authorization/Content-Type 等认证头），
  不落地临时 request 文件，可复制到其他机器直接执行。
- **排队状态**：发送二阶段立即显示「排队中」→「扫描中/验证中...」→
  「存在注入/不存在注入」，类型列同步收尾。
- **一阶段混合型引号探针**：新增 `1'1` / `1"1`（DetSQL 对标）。
- **49 条细粒度报错正则**：新增 `SQL扩展` 族（含中文、西班牙语、达梦等）。
- **一阶段防卡死**：单请求总预算（默认 180s，可设置）、基线采样失败快速终止、
  连续 3 次传输失败熔断、线程中断响应。
- **越权组合结论**：存在越权 OR 存在未授权 / 不存在越权 OR 存在未授权 / 存在越权；
  `鉴权正常` 不显示。
- **AuthScan 配置完整性指示**：设置页实时显示身份配置是否完整；启用前不完整会弹窗提醒。

### Changed

- **SQL 扫描默认停止**：插件加载/重启后不自启动，必须点击「开始扫描」；
  点击时一并应用并保存设置，原「应用设置」按钮已删除。
- **第二阶段开关**：勾选即时生效，控制右键「XzhScan SQL 验证」入口。
- **漏洞结果只入库 CONFIRMED**：SUSPECTED/RETAINED 仅记录日志。
- **SUSPECTED/RETAINED 不再阻断后续 payload/模块**：仅 CONFIRMED 短路。
- **差分候选取消绿色染色**：只保留红/黄两色。
- **移除页签**：删除「数据版」「FileScan」；Dictionary 删除「SQL库名注入」「sqlmap命令」。
- 关于页：新增 GitHub 地址，反馈改为 GitHub Issues。

### Fixed

- AuthScan 模块默认 `enabled=true` 与配置 `authEnabled=false` 不一致。
- 漏洞结果类型列扫描结束后停留在「验证中...」。
- `loadFinding` 证据解析阻塞 EDT；Dispatcher 持锁执行回调；多处空指针风险。
- AuthScan 线程池卸载改为优雅关闭（5s 超时后强杀）。

## [3.9.7] - 2024-11-24

### Fixed

- **右键菜单默认启用** - 修复 `watchManualMenu` 默认关闭导致右键菜单不显示的问题
- **UI 初始化失败** - 修复 `baselineSamples` 范围验证错误（2-6 → 2-20）
- **SQL 时间盲注误报率过高** - 实施 8 项核心修复，误报率从 20-30% 降至 <5%
- **中文响应乱码** - 自动从 Content-Type 读取 charset，支持 GBK/GB2312/Big5 等编码

### Changed

#### 时间盲注检测改进

- **基线采样增强** - 从 2-3 次增加到 5-7 次，提升统计可靠性
- **异常值检测** - 使用 IQR 方法自动过滤网络抖动和偶发延迟
- **多次采样** - 每个 sleep 级别测试 3 次取中位数，降低瞬时波动影响
- **标准差模型** - 实现 mean + 7σ 模型（对齐 sqlmap），自适应不同网络环境
- **阈值提高** - incrementOk 从 750ms 提高到 1000ms，更符合实际 sleep 行为
- **防止漏报** - 限制 absoluteFloor 上限，避免极慢服务器上的漏报

#### 编码支持

- **自动编码识别** - 从响应头 Content-Type 读取 charset
- **多编码支持** - UTF-8、GBK、GB2312、Big5、ISO-8859-1 等
- **智能回退** - 无 charset 声明时回退到 UTF-8

### Performance

- 检测时间增加约 20 秒（15%），换取 70% 的误报降低
- 每次验证请求数从 8-9 次增加到 23-25 次

### Technical Details

#### P0 核心修复（8 项）

1. 基线样本数：2-3 → 5-7 次
2. 时间测量：统一使用 Transport 精确测量（nanoTime）
3. 增量阈值：750ms → 1000ms
4. 多次采样：每级 1 次 → 3 次取中位数
5. 一致性检查：已移除（过于严格导致漏报）
6. 标准差公式：已修正为 n-1（Bessel's correction）
7. 异常值检测：IQR 方法过滤离群值
8. 标准差模型：mean + 7σ（限制上限防止极慢服务器漏报）

#### 三重判定逻辑

```
确认条件（必须同时满足）：
1. 相对差：sleep(S) - sleep(0) >= S×1000ms
2. 增量差：sleep(S+1) - sleep(S) >= 1000ms  
3. 绝对下限：sleep(S) >= max(minValidDelayMs, min(mean+7σ, S×1500ms))
```

---

## [3.9.6 及更早版本]

请参考项目的 Git 提交历史。
