package com.xzhscan.engine;

import com.xzhscan.config.XzhScanConfig;
import com.xzhscan.differential.BaselineCollector;
import com.xzhscan.differential.DifferenceAnalyzer;
import com.xzhscan.model.EvidenceStore;
import com.xzhscan.model.Models.CandidateType;
import com.xzhscan.model.Models.DiffEvidence;
import com.xzhscan.model.Models.DifferentialCandidate;
import com.xzhscan.model.Models.FilterDecision;
import com.xzhscan.model.Models.GateProbeView;
import com.xzhscan.model.Models.ParameterIdentity;
import com.xzhscan.model.Models.TrafficRecord;
import com.xzhscan.model.RawHttp.RawRequest;
import com.xzhscan.model.RawHttp.RawResponse;
import com.xzhscan.model.RawHttp.Transport;
import com.xzhscan.payload.PayloadRegistry.PayloadRule;
import com.xzhscan.parameter.ParameterExtractor;
import com.xzhscan.parameter.ParameterMutators;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

/**
 * 第一阶段引擎（受控差分初筛，v2.2 Registry 化）：
 *
 *  保留：监听 Proxy/Repeater 流量、参数级探针（'、''、JSON 数字 -1）、
 *        引号开合与合法转义对的三相对比思想、多次基线采样 + 稳定性评估、
 *        归一化差分、差分过 DifferentialGate、参数级候选输出。
 *  v2.2 变更：
 *    - 时间探针不再全量遍历 7 条固定 payload；改为 PayloadRegistry 默认集
 *      （注释变体/高资源规则/SQLite/OOB 默认排除）；
 *    - v2.3 上下文适配：按参数 SQL 上下文选集（数字形态参数 → NUMERIC 家族
 *      代表 + 自给自足 XOR；字符串参数 → STRING 引号闭合型；同族只取一条代表），
 *      修复数字参数（如 id=111 无引号拼接）只发引号闭合型必语法错误、
 *      时间探针永不命中、进不了第二阶段的漏报；
 *    - 每条探针携带 Payload 规则 ID，命中候选携带 ID 供第二阶段定向复验
 *      （两阶段不再重复执行相同规则序列）；
 *    - 候选分型 ERROR_CANDIDATE / BOOLEAN_CANDIDATE / TIME_CANDIDATE；
 *    - 每请求输出 §15 请求预算统计（规则总数/执行/跳过/HTTP 请求数）。
 */
public final class PassiveDetectionEngine {

    /** 探针描述。 */
    public record Probe(String kind, ParameterMutators.Mode mode, String payload, boolean forNumeric,
                        boolean typeChangedByDesign, String ruleId, String dbms, long expectedMs) {

        /** 非时间探针（引号/算术）便捷构造。 */
        public static Probe classic(String kind, ParameterMutators.Mode mode, String payload,
                                    boolean forNumeric, boolean typeChangedByDesign) {
            return new Probe(kind, mode, payload, forNumeric, typeChangedByDesign, null, null, 0);
        }
    }

    private final XzhScanConfig config;
    private final Transport transport;
    private final EvidenceStore evidence;
    private final DifferentialGate gate;
    /** 当前请求的基线证据 id（process 局部传递；v2.1 的实例字段串线缺陷已修复）。 */
    private final ThreadLocal<String> currentBaselineEvidenceId = new ThreadLocal<>();

    public PassiveDetectionEngine(XzhScanConfig config, Transport transport, EvidenceStore evidence) {
        this.config = config;
        this.transport = transport;
        this.evidence = evidence;
        this.gate = new DifferentialGate(config);
    }

    /** 引擎回调：候选/被排除项/UI 状态。 */
    public interface Callback {
        void onTrafficUpdate(TrafficRecord record);

        void onCandidate(DifferentialCandidate candidate);

        void onRejected(String requestId, ParameterIdentity param, String probeKind, String reason, double score);

        void onGateView(GateProbeView view);
    }

    /** 对一个已观测的请求响应执行第一阶段。observedResponse 可为 null（手动发起）。 */
    public List<DifferentialCandidate> process(RawRequest originalRequest,
                                               RawResponse observedResponse,
                                               TrafficRecord record,
                                               Callback cb) {
        List<DifferentialCandidate> passed = new ArrayList<>();
        record.phase1Status = "extracting";

        ParameterExtractor.ExtractResult extraction = ParameterExtractor.extract(originalRequest);
        List<ParameterIdentity> params = extraction.parameters;
        record.parameterCount = params.size();

        if (extraction.baselineAnomaly != null && extraction.jsonBody == null) {
            record.phase1Status = "baseline-anomaly";
            // 输入本身异常（如非法 JSON）：不做自动变异，只记录（INVALID_REQUEST 不进入第二阶段）
            if (cb != null) {
                cb.onTrafficUpdate(record);
            }
            return passed;
        }
        if (params.isEmpty()) {
            record.phase1Status = "no-params";
            if (cb != null) {
                cb.onTrafficUpdate(record);
            }
            return passed;
        }

        // 截断参数数，避免大表单拖垮（超出部分显式计数，不静默）
        List<ParameterIdentity> testable = params.stream()
                .filter(ParameterIdentity::mutable)
                .limit(config.maxParamsPerRequest)
                .toList();
        if (testable.isEmpty()) {
            record.phase1Status = "no-mutable-params";
            if (cb != null) {
                cb.onTrafficUpdate(record);
            }
            return passed;
        }
        if (params.size() > testable.size() && record.skipReasons.size() < 8) {
            record.skipReasons.add("truncated: " + (params.size() - testable.size())
                    + " non-mutable/over-limit params");
        }

        // ---- 基线采样 ----
        record.phase1Status = "baseline";
        if (cb != null) {
            cb.onTrafficUpdate(record);
        }
        BaselineCollector.Baseline baseline = BaselineCollector.collect(originalRequest, config.baselineSamples, transport);
        record.httpRequests += baseline.responses.size();
        if (baseline.responses.isEmpty()) {
            record.phase1Status = "baseline-unreachable";
            if (cb != null) {
                cb.onTrafficUpdate(record);
            }
            return passed;
        }
        if (observedResponse != null) {
            evidence.put("baseline-observed", originalRequest, observedResponse);
        }
        // 请求级基线证据只存最后一次采样；采样间差异由 baseline.stable/dynamicFields 表达
        String baselineEvidenceId = evidence.put("baseline", originalRequest, baseline.last());
        this.currentBaselineEvidenceId.set(baselineEvidenceId);
        try {
            return processParams(originalRequest, observedResponse, record, cb, testable, baseline);
        } finally {
            this.currentBaselineEvidenceId.remove();
        }
    }

    private List<DifferentialCandidate> processParams(RawRequest originalRequest, RawResponse observedResponse,
                                                      TrafficRecord record, Callback cb,
                                                      List<ParameterIdentity> testable,
                                                      BaselineCollector.Baseline baseline) {
        List<DifferentialCandidate> passed = new ArrayList<>();
        String contentType = orDefault(originalRequest.headerValue("Content-Type"), "");
        boolean jsonRequest = contentType.toLowerCase(Locale.ROOT).contains("json")
                || (!originalRequest.bodyAsString().isEmpty()
                && ParameterExtractor.extract(originalRequest).jsonBody != null);

        // ---- 跨来源同模板合并统计（v2.3 Registry 审计口径） ----
        record.rulesDuplicate += com.xzhscan.payload.PayloadRegistry.duplicateSourceCount()
                .values().stream().mapToInt(Integer::intValue).sum()
                - com.xzhscan.payload.PayloadRegistry.duplicateSourceCount().size();

        // ---- 逐参数 × 探针 ----
        for (ParameterIdentity param : testable) {
            // v4.2.2：原始值已是注入载荷（Intruder/fuzz 场景）→ 跳过差分变异。
            // 理由：基线请求本身携带 payload，其响应是"出错/命中"后的页面，再对它做
            // 变异得到的差异没有注入语义，只会产生噪声候选（实测：同一 fuzz 请求变体
            // 响应字节级相同，却可能因基线异常被判候选）。显式记录原因，不静默丢弃。
            if (com.xzhscan.engine.SqlVerificationEngine.looksLikeStrongInjection(param.originalValue)) {
                if (cb != null) {
                    cb.onGateView(new GateProbeView(record.requestId, originalRequest.url, param.name, param.path,
                            param.location.name(), baseline.minLen, -1, 0, 1.0, 0,
                            "REJECT", "original value already looks like injection payload (fuzz baseline)",
                            -1, false, "timing not measured", null, -1, -1, null, baselineEvidenceIdOf()));
                }
                if (record.skipReasons.size() < 8) {
                    record.skipReasons.add("skipped fuzz-baseline param: " + param.path);
                }
                continue;
            }
            // v3.5：被动 = XiaSQL 纯差分（引号对 + 数字算术/LIMIT 对）；时间盲注
            // 一律走右键人工触发的 Phase2 全模块序列（QUICK/XRAY 五类 DBMS 模板 +
            // 三级 sleep 阶梯定罪）。被动时间探针子系统已整体移除。
            // 每参数预算口径：引号 2 + 数字检测对（-1/-0，命中数字值时） + LIMIT 对
            int numericExtra = config.probeNumericArith
                    ? (param.type == com.xzhscan.model.Models.ParamType.NUMBER ? 2
                        : (param.location != com.xzhscan.model.Models.Location.JSON
                            && looksNumeric(param.originalValue)) ? 4 : 0)
                    : 0;
            record.rulesTotal += 2 + numericExtra;
            List<Probe> probes = buildProbes(param);
            DiffEvidence best = null;
            final String[] bestProbeRef = {null};
            // v3.3 XiaSQL 形态：每条探针的原始观察都上报（不筛选），供差分页主从表直显
            List<GateProbeView> observations = new ArrayList<>();
            for (Probe probe : probes) {
                DiffEvidence ev = runProbe(originalRequest, param, probe, baseline, jsonRequest, record);
                if (ev == null) {
                    continue;
                }
                observations.add(new GateProbeView(record.requestId, originalRequest.url, param.name, param.path,
                        param.location.name(), baseline.minLen, ev.mutatedLen, ev.lenDelta,
                        ev.similarity, ev.differenceScore, "观察", describeEvidence(ev),
                        ev.timingDeltaMs, ev.timingAnomaly, ev.timingNote,
                        probe.payload(), ev.mutatedStatus, ev.mutatedElapsedMs, ev.mutatedEvidenceId,
                        baselineEvidenceIdOf()));
                if (best == null || evidenceStronger(ev, best)) {
                    best = ev;
                    bestProbeRef[0] = probe.kind();
                }
                // 微弱差分/无差分探针立即上报为排除（含原因），供 UI 调试
                if (ev.differenceScore < config.minDifferenceScore && cb != null) {
                    cb.onRejected(record.requestId, param, probe.kind(),
                            "score " + String.format("%.2f", ev.differenceScore) + " < threshold", ev.differenceScore);
                }
                // 强信号提前退出：DB 错误指纹已足以过门，跳过其余探针
                // （v3.8.3：timeProbeHit 分支随被动时间探针子系统删除，恒 false）
                if (best.dbErrorHit) {
                    int remaining = probes.size() - probes.indexOf(probe) - 1;
                    if (remaining > 0 && record.skipReasons.size() < 8) {
                        record.skipReasons.add("early-exit after " + bestProbeRef[0] + ": " + remaining + " probes skipped");
                    }
                    break;
                }
            }
            // v3.3：先上全部探针观察行（best 那条留作判定行，避免重复展示）
            String bestPayload = null;
            if (cb != null) {
                for (GateProbeView v : observations) {
                    if (best != null && best.mutatedEvidenceId != null
                            && best.mutatedEvidenceId.equals(v.mutatedEvidenceId)) {
                        bestPayload = v.payload;
                        continue;
                    }
                    cb.onGateView(v);
                }
            }
            if (best == null) {
                if (cb != null) {
                    cb.onRejected(record.requestId, param, "-", "all probes failed (transport/mutation)", 0);
                    cb.onGateView(new GateProbeView(record.requestId, originalRequest.url, param.name, param.path,
                            param.location.name(), baseline.minLen, -1, 0, 1.0, 0,
                            "REJECT", "no usable evidence (all probes failed)", -1, false, "timing not measured",
                            null, -1, -1, null, baselineEvidenceIdOf()));
                }
                continue;
            }

            DifferentialGate.GateResult result = gate.evaluate(best, jsonRequest);
            // INCONCLUSIVE：有限次数稳定性重测
            int retest = 0;
            while (result.decision == FilterDecision.INCONCLUSIVE && retest < config.maxStabilityRetests) {
                retest++;
                String bp = bestProbeRef[0];
                DiffEvidence re = runProbe(originalRequest, param,
                        probes.stream().filter(p -> p.kind().equals(bp)).findFirst().orElse(null),
                        baseline, jsonRequest, record);
                if (re == null) {
                    break;
                }
                best = re.differenceScore > best.differenceScore ? re : best;
                result = gate.evaluate(best, jsonRequest);
            }
            // v3.8.6：重测耗尽后不再强制转 REJECT——规则 B 弱差分与规则 C 动态页
            // 均保持待定（INCONCLUSIVE），由差分页黄色高亮提示人工复核。

            record.passedCandidates += result.decision == FilterDecision.PASS ? 1 : 0;
            record.rejectedCandidates += result.decision == FilterDecision.PASS ? 0 : 1;

            if (result.decision == FilterDecision.PASS) {
                DifferentialCandidate candidate = gate.buildCandidate(
                        best, record.requestId, originalRequest.url, originalRequest.method, contentType,
                        param.name, param.path, param.location, param.originalValue, best.originalType,
                        best.jsonValid, baseline.stable, originalRequest);
                candidate.filterDecision = FilterDecision.PASS;
                candidate.filterReason = result.reason;
                candidate.occurrence = param.occurrence;
                candidate.evidenceIds.add(best.baselineEvidenceId == null ? "" : best.baselineEvidenceId);
                candidate.evidenceIds.add(best.mutatedEvidenceId == null ? "" : best.mutatedEvidenceId);
                candidate.differenceReasons.add("probe=" + bestProbeRef[0]);
                candidate.differenceReasons.addAll(best.evidenceKinds);
                // ---- 候选分型（任务书 §8）----
                // v3.8.3：TIME_CANDIDATE 分支随被动时间探针子系统删除（恒 false）；
                // 被动仅产出 ERROR/BOOLEAN 两型，Phase2 的 TIME_CANDIDATE case 保留
                // 作为差分候选入口（当前生产不可达，测试构造可达）。
                if (best.dbErrorHit) {
                    candidate.candidateType = CandidateType.ERROR_CANDIDATE;
                } else {
                    candidate.candidateType = CandidateType.BOOLEAN_CANDIDATE;
                }
                passed.add(candidate);
                if (cb != null) {
                    cb.onCandidate(candidate);
                }
            } else if (result.decision == FilterDecision.INCONCLUSIVE && cb != null) {
                // v3.9.2 数据版：重测耗尽仍待定 -> 同款构造候选（filterDecision=INCONCLUSIVE）
                // 回流，供「数据版」页签聚合黄色参数并一键送二阶段；
                // 差分门判定标准与 record 统计口径零改动（rejectedCandidates 照旧 +1）。
                DifferentialCandidate candidate = gate.buildCandidate(
                        best, record.requestId, originalRequest.url, originalRequest.method, contentType,
                        param.name, param.path, param.location, param.originalValue, best.originalType,
                        best.jsonValid, baseline.stable, originalRequest);
                candidate.filterDecision = FilterDecision.INCONCLUSIVE;
                candidate.filterReason = result.reason;
                candidate.occurrence = param.occurrence;
                candidate.evidenceIds.add(best.baselineEvidenceId == null ? "" : best.baselineEvidenceId);
                candidate.evidenceIds.add(best.mutatedEvidenceId == null ? "" : best.mutatedEvidenceId);
                candidate.differenceReasons.add("probe=" + bestProbeRef[0]);
                candidate.differenceReasons.addAll(best.evidenceKinds);
                candidate.candidateType = best.dbErrorHit
                        ? CandidateType.ERROR_CANDIDATE : CandidateType.BOOLEAN_CANDIDATE;
                cb.onCandidate(candidate);
            } else if (cb != null) {
                cb.onRejected(record.requestId, param, bestProbeRef[0], result.reason, best.differenceScore);
            }
            if (cb != null) {
                cb.onGateView(new GateProbeView(record.requestId, originalRequest.url, param.name, param.path,
                        param.location.name(), best.baselineMinLen, best.mutatedLen, best.lenDelta,
                        best.similarity, best.differenceScore, result.decision.name(), result.reason,
                        best.timingDeltaMs, best.timingAnomaly, best.timingNote,
                        bestPayload, best.mutatedStatus, best.mutatedElapsedMs, best.mutatedEvidenceId,
                        baselineEvidenceIdOf()));
            }
        }

        record.phase1Status = "done";
        if (cb != null) {
            cb.onTrafficUpdate(record);
        }
        return passed;
    }

    private DiffEvidence runProbe(RawRequest original, ParameterIdentity param, Probe probe,
                                  BaselineCollector.Baseline baseline, boolean jsonRequest, TrafficRecord record) {
        if (probe == null) {
            return null;
        }
        ParameterMutators.MutationResult mutation =
                ParameterMutators.mutate(original, param, probe.mode(), probe.payload());
        if (!mutation.success) {
            // 本地变异失败：按分类记录（请求构造错误 / JSON 语法错误 / 参数缺失 / 不支持），
            // 不吞原因、不发请求。jsonValid 只在 JSON 语法类失败时为 false。
            DiffEvidence ev = new DiffEvidence();
            ev.requestId = null;
            ev.parameterPath = param.path;
            ev.mutationKind = probe.kind();
            ev.originalValue = param.originalValue;
            ev.originalType = param.type.name().toLowerCase(Locale.ROOT);
            ev.invalidRequestType = mutation.failureType;
            ev.invalidRequestReason = mutation.failureReason;
            ev.jsonValid = mutation.failureType == com.xzhscan.model.Models.InvalidRequestType.JSON_MUTATION_INVALID
                    || mutation.failureType == com.xzhscan.model.Models.InvalidRequestType.BASELINE_JSON_INVALID;
            ev.similarity = 1.0;
            ev.baselineStable = baseline.stable;
            ev.mutatedElapsedMs = -1;
            ev.timingNote = "not sent: " + mutation.failureType;
            return ev;
        }

        RawResponse mutatedResponse;
        try {
            mutatedResponse = transport.send(mutation.request);
        } catch (Exception e) {
            return null; // 网络失败：不产生差分证据
        }
        if (mutatedResponse == null) {
            return null;
        }
        record.httpRequests++;
        record.rulesExecuted++;
        String mutatedEvidenceId = evidence.put("mutated", mutation.request, mutatedResponse);

        DiffEvidence ev = DifferenceAnalyzer.analyze(baseline, mutatedResponse,
                null, param.path, probe.kind(), param.originalValue, mutation.mutatedValue,
                mutation.originalType, mutation.typeChanged, mutation.jsonValid, config);
        ev.baselineEvidenceId = baselineEvidenceIdOf();
        ev.mutatedEvidenceId = mutatedEvidenceId;
        return ev;
    }

    /** 证据排序：DB 错误 > 时间命中 > 综合分。 */
    private static boolean evidenceStronger(DiffEvidence a, DiffEvidence b) {
        int ra = rank(a);
        int rb = rank(b);
        return ra != rb ? ra > rb : a.differenceScore > b.differenceScore;
    }

    private static int rank(DiffEvidence e) {
        // v3.8.3：timeProbeHit 档位随被动时间探针子系统删除（恒 false）
        if (e.dbErrorHit) return 3;
        return 1;
    }

    private String baselineEvidenceIdOf() {
        return currentBaselineEvidenceId.get();
    }

    /**
     * 按参数类型构造探针集（v2.2：时间探针来自 PayloadRegistry 默认集）。
     * v3.4：数字值参数在 ' / '' 之外补 XiaSQL 数字检测对 -1 / -0
     * （query/form 为值后追加减式；JSON 数字为保持类型的算术变异），
     * 用于识别"数值参与 SQL 拼接"的接口（原值-0 应≈原响应，原值-1 应产生差异）。
     */
    private List<Probe> buildProbes(ParameterIdentity param) {
        List<Probe> probes = new ArrayList<>();
        boolean numeric = param.type == com.xzhscan.model.Models.ParamType.NUMBER;
        boolean jsonNumber = numeric && param.location == com.xzhscan.model.Models.Location.JSON;
        boolean valueNumeric = looksNumeric(param.originalValue);
        if (!numeric) {
            if (config.probeSingleQuote) {
                probes.add(Probe.classic("single-quote", ParameterMutators.Mode.APPEND, "'", false, false));
            }
            if (config.probeQuotePair) {
                probes.add(Probe.classic("quote-pair", ParameterMutators.Mode.APPEND, "''", false, false));
            }
            if (config.probeNumericArith && valueNumeric) {
                // XiaSQL 语义：value-1（期望产生差异）/ value-0（期望≈原响应，对照）
                probes.add(Probe.classic("numeric-minus1", ParameterMutators.Mode.APPEND, "-1", false, false));
                probes.add(Probe.classic("numeric-minus0", ParameterMutators.Mode.APPEND, "-0", false, false));
                // v3.4.1 补充：LIMIT 位逗号对 value,0 / value,1（分页参数注入常见形态：
                // LIMIT {value},1 返回行 vs LIMIT {value},0 返回空 → 长度/内容差分）
                probes.add(Probe.classic("numeric-comma0", ParameterMutators.Mode.APPEND, ",0", false, false));
                probes.add(Probe.classic("numeric-comma1", ParameterMutators.Mode.APPEND, ",1", false, false));
            }
        } else if (jsonNumber) {
            if (config.probeNumericArith) {
                probes.add(Probe.classic("numeric-arith-minus1", ParameterMutators.Mode.NUMBER_ARITH, "1", false, false));
                probes.add(Probe.classic("numeric-arith-minus0", ParameterMutators.Mode.NUMBER_ARITH, "0", false, false));
            }
            if (config.probeSingleQuote) {
                // 数字字段字符串化追加引号：显式弱证据（typeChanged）
                probes.add(Probe.classic("numeric-stringify-quote", ParameterMutators.Mode.NUMBER_TO_STRING_APPEND, "'", false, true));
            }
        } else {
            // 非 JSON 数字形态（当前提取器对 QUERY/FORM 恒判 STRING，此分支兜底）
            if (config.probeSingleQuote) {
                probes.add(Probe.classic("single-quote", ParameterMutators.Mode.APPEND, "'", false, false));
            }
        }
        // v3.5：被动时间探针循环已随子系统移除——时间盲注由 Phase2 verifyTimeBased
        // 全模块枚举负责（payload 编码语义同前：query/form 追加编码、JSON AST 原样）。
        return probes;
    }

    /** 观察行的简明证据描述（分型标签 + 关键数值，供差分页"变化"列）。 */
    private static String describeEvidence(DiffEvidence ev) {
        if (ev.invalidRequestType != null
                && ev.invalidRequestType != com.xzhscan.model.Models.InvalidRequestType.NONE) {
            return "未发送: " + ev.invalidRequestType;
        }
        StringBuilder sb = new StringBuilder();
        if (ev.dbErrorHit) {
            sb.append("DB错误指纹(").append(ev.dbErrorFamily).append(") ");
        }
        if (ev.timingAnomaly) {
            sb.append("计时异常 Δ=").append(ev.timingDeltaMs).append("ms ");
        }
        if (!ev.evidenceKinds.isEmpty()) {
            sb.append(String.join("/", ev.evidenceKinds));
        }
        if (sb.length() == 0) {
            sb.append("无明显变化");
        }
        return sb.toString().trim();
    }

    private static String orDefault(String s, String dft) {
        return s == null ? dft : s;
    }

    /** query/form 值数字形态（无类型标注；纯数字 → SQL 拼接大概率无引号）。 */
    static boolean looksNumeric(String v) {
        return v != null && v.matches("-?\\d+(\\.\\d+)?");
    }
}
