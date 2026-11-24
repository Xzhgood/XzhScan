package com.xzhscan.model;

import java.util.ArrayList;
import java.util.List;

/**
 * 核心数据模型：参数标识、差分证据、差分候选、验证结果、流量记录。
 * 全部为纯数据类（可变字段仅供引擎内部更新状态），不依赖 Burp API。
 */
public final class Models {

    private Models() {
    }

    /** 参数所在位置。 */
    public enum Location {
        QUERY, FORM, JSON
    }

    /**
     * 无效请求分类：严格区分「请求构造错误」「JSON 语法错误」与其他变异失败
     * （任务书 3.4 / 一.9 —— 不得混为一谈，也不得吞掉原因）。
     */
    public enum InvalidRequestType {
        /** 无失败。 */
        NONE,
        /** JSON AST 变异后重序列化校验失败（本地判定非法 JSON，未发送）。 */
        JSON_MUTATION_INVALID,
        /** 基线请求体本身不是合法 JSON（不做基于 JSON 的自动变异）。 */
        BASELINE_JSON_INVALID,
        /** 目标参数在请求中找不到（构造失败，非 JSON 问题）。 */
        PARAM_NOT_FOUND,
        /** 其他构造失败（如数字字段拒绝隐式字符串化、不支持类型）。 */
        MUTATION_UNSUPPORTED
    }

    /** 参数原始标量类型。 */
    public enum ParamType {
        STRING, NUMBER, BOOLEAN, NULL, OBJECT, ARRAY
    }

    /**
     * 候选分型：决定第二阶段走哪个验证模块（任务书 §8）。
     * 第一阶段按最强证据信号分型；INVALID_REQUEST/WAF_BLOCKED/NETWORK_TIMEOUT
     * 形态的观察不会成为候选（分别被 Gate 拒绝或不产生差分证据）。
     */
    public enum CandidateType {
        /** 数据库错误指纹（→ 错误型复核：heuristic/md5 回显/裸表达式）。 */
        ERROR_CANDIDATE,
        /** 内容/结构/状态差分（→ 布尔差分复核：castBool/boolPair/orderBoolError）。 */
        BOOLEAN_CANDIDATE,
        /** 时间探针命中（→ 定向时间复核：仅命中规则的三级 sleep 阶梯）。 */
        TIME_CANDIDATE
    }

    /** 时间确认结果四态（任务书 §11；一次变慢不直接确认注入）。 */
    public enum TimingVerdict {
        /** 时间异常保留（未达确认标准，交人工/后续复核）。 */
        TIMING_ANOMALY,
        /** 无法判定（WAF 拦截/变异失败/证据矛盾）。 */
        TIMING_INCONCLUSIVE,
        /** 客户端/传输超时（status<=0 或超预算），不可作为延迟证据。 */
        TIMING_TIMEOUT,
        /** 三级 sleep 阶梯单调递增确认。 */
        TIMING_CONFIRMED
    }

    /** 一个可测试参数的唯一标识。 */
    public static final class ParameterIdentity {
        public final Location location;
        /** 展示名：QUERY/FORM 用参数名，JSON 用末段键名。 */
        public final String name;
        /** 统一路径：QUERY/FORM 为 "name"，JSON 为 "$.user.profile.name"。 */
        public final String path;
        /** 原始值（解码后展示值；QUERY/FORM 的原始报文片段由 Mutator 直接保留）。 */
        public final String originalValue;
        public final ParamType type;
        /** 同名参数序号（第 N 个同名参数，0 起；JSON 路径唯一则恒 0）。 */
        public final int occurrence;

        public ParameterIdentity(Location location, String name, String path, String originalValue, ParamType type) {
            this(location, name, path, originalValue, type, 0);
        }

        public ParameterIdentity(Location location, String name, String path, String originalValue,
                                 ParamType type, int occurrence) {
            this.location = location;
            this.name = name;
            this.path = path;
            this.originalValue = originalValue;
            this.type = type;
            this.occurrence = occurrence;
        }

        public boolean mutable() {
            return type == ParamType.STRING || type == ParamType.NUMBER;
        }

        @Override
        public String toString() {
            return location + ":" + path + (occurrence > 0 ? "[" + occurrence + "]" : "");
        }
    }

    /** 一次变异观察到的全部差分证据。 */
    public static final class DiffEvidence {
        public String requestId;
        public String parameterPath;
        public String mutationKind;
        public String originalValue;
        public String mutatedValue;
        public String originalType;
        public boolean typeChanged;
        /** 变异请求本地 JSON 校验是否通过（非 JSON 请求恒 true）。 */
        public boolean jsonValid = true;
        /** 无效请求分类（NONE=正常发送）。 */
        public InvalidRequestType invalidRequestType = InvalidRequestType.NONE;
        /** 构造失败的具体原因（未吞掉的 failureReason）。 */
        public String invalidRequestReason;
        // 基线（多次采样聚合）
        public int baselineStatus;
        public int baselineMinLen;
        public int baselineMaxLen;
        /** 基线长度中位数（评分归一用，比 min/max 均值更抗单次抖动）。 */
        public int baselineMedianLen;
        public int baselineLenVariance;
        public boolean baselineStable;
        // 变异响应
        public int mutatedStatus;
        public int mutatedLen;
        public int lenDelta;
        public double similarity;          // 归一化后 token Jaccard，1=完全一致
        public boolean structureChanged;   // JSON 结构（键集合/嵌套形态）变化
        public boolean dbErrorHit;
        public String dbErrorFamily;
        public boolean jsonParseErrorLike; // 响应呈现 JSON 解析错误特征
        public boolean redirectChanged;
        /** 综合差分分（0..1，DifferenceAnalyzer 计算）。 */
        public double differenceScore;
        // ---- 证据分型（任务书 §14：七类证据分开记录，弱证据不互相覆盖） ----
        /** 命中的证据类别：STATUS_DIFF/BODY_DIFF/LENGTH_DIFF/JSON_STRUCTURE_DIFF/
         *  SQL_ERROR/TIMING_ANOMALY/TIMING_TIMEOUT/WAF_BLOCKED（phase2 侧）。 */
        public final List<String> evidenceKinds = new ArrayList<>();
        /** 时间探针命中的 Payload Registry 规则 ID（时间证据复用链路）。 */
        public String payloadRuleId;
        // ---- TimingEvidence（独立保留；正文无差不等于无异常） ----
        /** 基线耗时均值 ms（多次采样）。 */
        public double baselineMeanMs;
        /** 基线耗时标准差 ms（网络抖动估计）。 */
        public double baselineStdMs;
        /** 基线最小耗时 ms。 */
        public long baselineMinMs;
        /** 变异响应耗时 ms（-1 = 未测量/未发送）。 */
        public long mutatedElapsedMs;
        /** 耗时差 = mutated - baselineMean。 */
        public long timingDeltaMs;
        /** 耗时偏差倍数（相对基线 σ）。 */
        public double timingSigma;
        /** 时间异常：|delta| >= max(800ms, 3σ) 且基线抖动可控。独立记录，不单凭它复检。 */
        public boolean timingAnomaly;
        /** 时间异常保留说明（弱差过滤时不删除时间证据）。 */
        public String timingNote;
        // v3.8.3：timeProbe/timeProbeHit/timingExpectedMs 三字段随被动时间探针子系统删除
        // （零读写死字段）；时间型结论由 Phase2 的 timingVerdict 承载。
        // 证据引用（原始+变异的请求响应由 EvidenceStore 保管）
        public String baselineEvidenceId;
        public String mutatedEvidenceId;

        public double contentDiffRatio() {
            return 1.0 - similarity;
        }
    }

    /** 差分过滤器决策。 */
    public enum FilterDecision {
        PASS, REJECT, INCONCLUSIVE
    }

    /**
     * DifferentialGate 的唯一输出模型：两阶段之间唯一允许的数据交接入口。
     */
    public static final class DifferentialCandidate {
        public String requestId;
        public String targetUrl;
        public String method;
        public String contentType;
        public String parameterName;
        public String parameterPath;
        public Location parameterLocation;
        public String originalValue;
        public String originalType;
        /** 候选分型（决定第二阶段验证模块，任务书 §8）。 */
        public CandidateType candidateType;
        /** 时间候选携带的 Payload 规则 ID（第二阶段定向复验，不重新枚举）。 */
        public String payloadRuleId;
        /** 同名参数序号（第二阶段重定位用，与第一阶段一致）。 */
        public int occurrence;
        public DiffEvidence baselineEvidence;   // 基线聚合证据
        public DiffEvidence mutatedEvidence;    // 触发差分的变异证据
        public boolean jsonValid;
        public boolean baselineStable;
        public double differenceScore;
        public List<String> differenceReasons = new ArrayList<>();
        public FilterDecision filterDecision;
        public String filterReason;
        public List<String> evidenceIds = new ArrayList<>();
        /** 原始请求快照，第二阶段需要它重建上下文。 */
        public RawHttp.RawRequest originalRequest;
        /** 通过门后是否已完成第二阶段。 */
        public boolean verified;

        public String summary() {
            return method + " " + targetUrl + " " + parameterPath
                    + " score=" + String.format("%.2f", differenceScore)
                    + " decision=" + filterDecision;
        }
    }

    /** 第二阶段验证状态。 */
    public enum VerifyState {
        PENDING, RUNNING, DONE, SKIPPED, FAILED
    }

    /** 验证结论。 */
    public enum VerifyVerdict {
        /** 注入迹象可稳定复现（md5 回显 / 布尔对 / 时间三级）。 */
        CONFIRMED,
        /** 出现疑似迹象但不可复现或证据不足。 */
        SUSPECTED,
        /** 引擎判定排除。 */
        REJECTED,
        /** 测试本身无效（如目标不可达、参数不可再变异）。 */
        INVALID
    }

    /** 一条注入验证的结论与证据。 */
    public static final class InjectionFinding {
        public String requestId;
        public String parameterName;
        public String parameterPath;
        public VerifyVerdict verdict;
        public String injectionType;   // Error/Boolean/Time/WAF-Blocked/None
        public String dbFamily;
        public String payload;
        public String evidenceText;
        public String falsePositiveNote;
        /** 时间型结论的细分状态（非时间型为 null）。 */
        public TimingVerdict timingVerdict;
        /** Payload Registry 规则 ID（时间/错误型复核溯源）。 */
        public String payloadRuleId;
        /** 证据分型（任务书 §14；WAF_BLOCKED/TIMING_ANOMALY 等）。 */
        public final List<String> evidenceKinds = new ArrayList<>();
        public List<String> evidenceIds = new ArrayList<>();
    }

    /** 面向 UI 的第二阶段验证结果行。 */
    public static final class VerificationResult {
        public String requestId;
        public String url;
        public String parameterName;
        public String parameterPath;
        public String verifyType;
        public VerifyState state = VerifyState.PENDING;
        public VerifyVerdict verdict;
        /** 时间型结论细分（任务书 §11）。 */
        public TimingVerdict timingVerdict;
        public String evidenceText = "";
        public String note = "";
        public long startedAt;
        public long elapsedMs;
        /** 本次验证实际发出的 HTTP 请求次数（§15 统计）。 */
        public int probeCount;
        public List<InjectionFinding> findings = new ArrayList<>();
        /** 本次验证产生的全部证据引用（原始+每个探针）。 */
        public List<String> evidenceIds = new ArrayList<>();
    }

    /** 流量记录（后台审计行；§15 每参数请求统计）。 */
    public static final class TrafficRecord {
        public int id;
        public String requestId;
        public String source;
        public String url;
        public String method;
        public int parameterCount;
        public String phase1Status = "-";
        public String phase2Status = "-";
        public long startedAtMs;
        public long elapsedMs;
        public int passedCandidates;
        public int rejectedCandidates;
        // ---- §15 请求预算统计（每请求聚合） ----
        /** 注册表为该请求参数生成的规则总数。 */
        public int rulesTotal;
        /** 实际执行（发出请求）的规则数。 */
        public int rulesExecuted;
        /** 跳过的规则数（上下文/开关/状态不符）。 */
        public int rulesSkipped;
        /** 同族/同模板重复跳过的规则数。 */
        public int rulesDuplicate;
        /** 第一阶段发出的 HTTP 请求总数（基线+探针）。 */
        public int httpRequests;
        /** 其中时间探针请求数。 */
        public int timeRequests;
        /** 第二阶段验证请求数。 */
        public int verifyRequests;
        /** 跳过原因抽样（上限 8 条，审计用）。 */
        public final List<String> skipReasons = new ArrayList<>();
    }

    /** 差分候选面板的一行（含被排除项与独立保留的计时证据，便于调试误报）。 */
    public static final class GateProbeView {
        public final String requestId;
        public final String url;
        public final String parameterName;
        public final String parameterPath;
        public final String parameterLocation;
        public final int baselineLen;
        public final int mutatedLen;
        public final int lenDelta;
        public final double similarity;
        public final double score;
        public final String decision;
        public final String reason;
        public final long timingDeltaMs;
        public final boolean timingAnomaly;
        public final String timingNote;
        // ---- v3.3 XiaSQL 原始观察字段（差分页主从表直显，不筛选） ----
        /** 探针 payload 渲染文本（null=无（兜底行））。 */
        public final String payload;
        /** 变异响应状态码（-1=未发送）。 */
        public final int status;
        /** 变异响应耗时 ms（-1=未测量）。 */
        public final long elapsedMs;
        /** 变异证据 id（差分页选中行查看报文/发 Repeater）。 */
        public final String mutatedEvidenceId;
        /** 基线证据 id（差分页主表选中时查看原始报文）。 */
        public final String baselineEvidenceId;

        public GateProbeView(String requestId, String url, String parameterName, String parameterPath,
                             String parameterLocation, int baselineLen, int mutatedLen, int lenDelta,
                             double similarity, double score, String decision, String reason,
                             long timingDeltaMs, boolean timingAnomaly, String timingNote) {
            this(requestId, url, parameterName, parameterPath, parameterLocation, baselineLen,
                    mutatedLen, lenDelta, similarity, score, decision, reason, timingDeltaMs,
                    timingAnomaly, timingNote, null, -1, -1, null, null);
        }

        public GateProbeView(String requestId, String url, String parameterName, String parameterPath,
                             String parameterLocation, int baselineLen, int mutatedLen, int lenDelta,
                             double similarity, double score, String decision, String reason,
                             long timingDeltaMs, boolean timingAnomaly, String timingNote,
                             String payload, int status, long elapsedMs, String mutatedEvidenceId) {
            this(requestId, url, parameterName, parameterPath, parameterLocation, baselineLen,
                    mutatedLen, lenDelta, similarity, score, decision, reason, timingDeltaMs,
                    timingAnomaly, timingNote, payload, status, elapsedMs, mutatedEvidenceId, null);
        }

        public GateProbeView(String requestId, String url, String parameterName, String parameterPath,
                             String parameterLocation, int baselineLen, int mutatedLen, int lenDelta,
                             double similarity, double score, String decision, String reason,
                             long timingDeltaMs, boolean timingAnomaly, String timingNote,
                             String payload, int status, long elapsedMs, String mutatedEvidenceId,
                             String baselineEvidenceId) {
            this.requestId = requestId;
            this.url = url;
            this.parameterName = parameterName;
            this.parameterPath = parameterPath;
            this.parameterLocation = parameterLocation;
            this.baselineLen = baselineLen;
            this.mutatedLen = mutatedLen;
            this.lenDelta = lenDelta;
            this.similarity = similarity;
            this.score = score;
            this.decision = decision;
            this.reason = reason;
            this.timingDeltaMs = timingDeltaMs;
            this.timingAnomaly = timingAnomaly;
            this.timingNote = timingNote;
            this.payload = payload;
            this.status = status;
            this.elapsedMs = elapsedMs;
            this.mutatedEvidenceId = mutatedEvidenceId;
            this.baselineEvidenceId = baselineEvidenceId;
        }
    }
}
