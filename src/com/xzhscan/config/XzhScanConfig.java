package com.xzhscan.config;

/**
 * XzhScan 运行配置。UI 可改、可序列化为 JSON 持久化（Burp saveExtensionSetting）。
 * 所有差分评分权重在此集中定义并给出默认值；默认值由 tests/calibration 用例校准。
 */
public final class XzhScanConfig {

    /**
     * v4.0：配置变更监听器（不参与序列化/拷贝）。
     * 单一真相源约定：任何字段被修改后调用 {@link #notifyChanged()}，
     * 监听器负责立即持久化——杜绝"改内存≠落盘"导致的配置回滚。
     */
    private final transient java.util.List<Runnable> listeners = new java.util.ArrayList<>();

    /** 注册变更监听（扩展装配时接 saveConfig）。 */
    public void addListener(Runnable r) {
        if (r != null) {
            listeners.add(r);
        }
    }

    /** 通知配置已变更（UI 控件改动后调用；监听器异常不得影响调用方）。 */
    public void notifyChanged() {
        for (Runnable r : listeners) {
            try {
                r.run();
            } catch (Throwable ignored) {
                // 持久化失败不应中断 UI 操作
            }
        }
    }

    // ---------------- 总开关 ----------------
    /** 第一阶段（XiaSQL 被动初筛）总开关。 */
    public boolean phase1Enabled = true;
    /** 第二阶段（SQL 复检引擎）总开关。 */
    public boolean phase2Enabled = true;
    // v3.1：autoVerify（自动二阶段）已整体移除——被动只列候选，二阶段一律人工触发
    // （右键「XzhScan SQL 验证」/差分页右键）。旧持久化键读取时安全忽略。

    // ---------------- 流量来源 ----------------
    public boolean watchProxy = true;
    public boolean watchRepeater = true;
    public boolean watchScanner = false;
    // v3.9：Intruder 流量监听（默认关）。开启后仅状态码严格 200 的完整响应
    // 进入差分扫描准入（201/302/404/500 等一律跳过）；200 只是准入条件，
    // 注入判定仍由后端安全闸/差分门/二阶段引擎按原标准执行。
    public boolean watchIntruder = false;
    public boolean watchManualMenu = true;

    // ---------------- 第一阶段探针 ----------------
    // v3.5：被动时间探针（probeTimePayloads/timeProbePassRatio/allowStackedProbes/
    // probeOracleTime）整体移除——被动= XiaSQL 纯差分，时间盲注一律走右键人工触发的
    // Phase2 全模块序列（QUICK/XRAY 模板覆盖 MySQL/PG/MSSQL/Oracle/SQLite，且有三
    // 级 sleep 阶梯定罪，强于被动路径）。旧持久化键读取时安全忽略。
    public boolean probeSingleQuote = true;    // 值 + '
    public boolean probeQuotePair = true;      // 值 + ''（合法转义对，XiaSQL 遗产）
    public boolean probeNumericArith = true;   // JSON 数字值保持类型做 -1 算术变异
    public int maxParamsPerRequest = 30;
    /** 同一 (url+method+参数集) 的去重窗口（分钟），0=不去重。 */
    public int dedupWindowMinutes = 240;

    // ---------------- 基线与差分 ----------------
    /** 基线采样次数（>=2 才能评估稳定性）。 */
    public int baselineSamples = 3;
    /** INCONCLUSIVE 候选的最大重测次数。 */
    public int maxStabilityRetests = 2;
    /** 微弱长度差集（绝对值），默认 {1,2}。 */
    public int weakDeltaThreshold = 2;
    /** 差分通过门的最小综合分。 */
    public double minDifferenceScore = 0.55;
    /** JSON 严格校验：变异失败禁止发送。 */
    public boolean jsonStrictValidation = true;

    // 差分评分权重（DifferenceScore = 加权和，上限 1.0）
    public double weightStructure = 0.20;   // 结构变化
    public double weightDissimilarity = 0.20; // 1-相似度
    public double weightStatusChange = 0.20;  // 状态码变化
    public double weightDbError = 0.30;       // 数据库错误特征
    public double weightContentDiff = 0.10;   // 长度差比例

    // ---------------- 第二阶段 ----------------
    /** 二次验证时是否允许时间盲注探针（sleep 类）。 */
    public boolean allowTimeBasedProbe = true;
    /**
     * 时间盲注延迟秒数（v3.9.7，默认 5）。原版按基线速度浮动 2/3 秒，
     * 实测 2-3 秒在负载抖动/系统卡顿时会被误判为命中；5 秒把信号抬到
     * 抖动带之外，三级阶梯相对差分的判定下限同步放大到 S×750ms。
     * 取值 2-10；调低会明显增加误报，调高会显著变慢。
     */
    public int timeDelaySeconds = 5;
    /**
     * v4.1.1：时间探针分级。1=仅每 DBMS 首条核心探针（默认，快）；2=全量家族与变体。
     * 慢站耗时主要由探针数量 × 单条响应时间决定，默认 1 可把最坏耗时压到 1/5。
     */
    public int timeProbeLevel = 1;
    /**
     * v4.1.1：单请求进入时间模块的参数上限（默认 5）。右键"全部参数"时，
     * 超出配额的参数仍跑报错/布尔模块，仅跳过时间模块（最慢的一段）。
     */
    public int maxTimeParamsPerRequest = 5;
    /** 每个候选验证的最长耗时（ms）。S=5 时快探全量约 130s + 三级阶梯 11s，默认放到 300s。 */
    public long verifyTimeoutMs = 300_000;
    public boolean reportWafBlocked = true;

    // ---------------- 安全策略 ----------------
    /**
     * v4.1（用户评审 P0）：自动发包默认受 Burp Target Scope 约束。
     * Proxy/Repeater/Scanner/Intruder 流量必须在 Target Scope 内才进入扫描；
     * 右键手动验证属于用户显式授权，不受此限制。
     */
    public boolean requireInScope = true;
    public String domainWhitelist = "";   // 逗号分隔；空=全部允许
    public String urlBlacklist = "";      // 逗号分隔；命中即拒
    /** 默认拒绝写语义接口（方法+路径综合判定，见 ScanPolicyEngine）。 */
    public boolean denyWriteLookingEndpoints = true;
    public int requestIntervalMs = 200;
    public int maxConcurrentScans = 2;
    public int requestTimeoutMs = 20_000;

    // ---------------- AuthScan（原 PermAccess）持久化 ----------------
    /** v3.9.3：默认关闭——未在 AuthScan 页勾选启用时完全不干活、零日志输出。 */
    public boolean authEnabled = false;
    public boolean authFilterEnabled = true;
    /** 低权限认证头（多行，每行 "Name: value"）。 */
    public String authLowAuthHeaders = "";
    /** 待移除鉴权头名（多行）。 */
    public String authNoAuthHeaders = "";
    /** 授权域名白名单（多行，支持 *）。 */
    public String authWhitelistDomains = "";
    /** 追加静态扩展名（逗号分隔）。 */
    public String authExtraExtensions = "";

    // ---------------- UI ----------------
    public boolean uiGroupDedup = true;

    /** 深拷贝（供测试与设置回滚）。 */
    public XzhScanConfig copy() {
        XzhScanConfig c = new XzhScanConfig();
        c.phase1Enabled = phase1Enabled;
        c.phase2Enabled = phase2Enabled;
        c.watchProxy = watchProxy;
        c.watchRepeater = watchRepeater;
        c.watchScanner = watchScanner;
        c.watchIntruder = watchIntruder;
        c.watchManualMenu = watchManualMenu;
        c.probeSingleQuote = probeSingleQuote;
        c.probeQuotePair = probeQuotePair;
        c.probeNumericArith = probeNumericArith;
        c.maxParamsPerRequest = maxParamsPerRequest;
        c.dedupWindowMinutes = dedupWindowMinutes;
        c.baselineSamples = baselineSamples;
        c.maxStabilityRetests = maxStabilityRetests;
        c.weakDeltaThreshold = weakDeltaThreshold;
        c.minDifferenceScore = minDifferenceScore;
        c.jsonStrictValidation = jsonStrictValidation;
        c.weightStructure = weightStructure;
        c.weightDissimilarity = weightDissimilarity;
        c.weightStatusChange = weightStatusChange;
        c.weightDbError = weightDbError;
        c.weightContentDiff = weightContentDiff;
        c.allowTimeBasedProbe = allowTimeBasedProbe;
        c.timeDelaySeconds = timeDelaySeconds;
        c.timeProbeLevel = timeProbeLevel;
        c.maxTimeParamsPerRequest = maxTimeParamsPerRequest;
        c.verifyTimeoutMs = verifyTimeoutMs;
        c.reportWafBlocked = reportWafBlocked;
        c.requireInScope = requireInScope;
        c.domainWhitelist = domainWhitelist;
        c.urlBlacklist = urlBlacklist;
        c.denyWriteLookingEndpoints = denyWriteLookingEndpoints;
        c.requestIntervalMs = requestIntervalMs;
        c.maxConcurrentScans = maxConcurrentScans;
        c.requestTimeoutMs = requestTimeoutMs;
        c.authEnabled = authEnabled;
        c.authFilterEnabled = authFilterEnabled;
        c.authLowAuthHeaders = authLowAuthHeaders;
        c.authNoAuthHeaders = authNoAuthHeaders;
        c.authWhitelistDomains = authWhitelistDomains;
        c.authExtraExtensions = authExtraExtensions;
        return c;
    }
}
