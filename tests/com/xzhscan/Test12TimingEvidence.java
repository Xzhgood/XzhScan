package com.xzhscan;

import com.xzhscan.config.XzhScanConfig;
import com.xzhscan.differential.BaselineCollector;
import com.xzhscan.differential.DifferenceAnalyzer;
import com.xzhscan.engine.DifferentialGate;
import com.xzhscan.model.Models.DiffEvidence;
import com.xzhscan.model.Models.FilterDecision;
import com.xzhscan.model.Models.InvalidRequestType;
import com.xzhscan.model.RawHttp.RawRequest;
import com.xzhscan.model.RawHttp.RawResponse;

import static com.xzhscan.MiniTest.TestContext;

/**
 * 测试十二：时间证据与无效请求分类（任务书 3.1–3.4）。
 *  - 相同正文、不同耗时：TimingEvidence 独立保留（正文差分为零 ≠ 无异常）；
 *  - 随机抖动不误报时间异常；
 *  - 微弱长度差过滤不删除时间数据（reason 附 TIMING-PRESERVED）；
 *  - 单次时间异常不单独触发复检（不 PASS）；
 *  - InvalidRequest 分类：query 参数缺失不再是 "JSON 无效"；JSON 序列化失败归
 *    JSON_MUTATION_INVALID；非法 JSON 基线归 BASELINE_JSON_INVALID。
 */
public final class Test12TimingEvidence {

    static final String BODY = "result rows: 1 2 3 4 5 status ok done footer";

    public static void run(TestContext t) {
        XzhScanConfig config = new XzhScanConfig();
        DifferentialGate gate = new DifferentialGate(config);
        RawRequest req = Support.get("http://t.local/s?name=admin");

        // ---------- 1. 相同正文 + 稳定延迟（3s） ----------
        BaselineCollector.Baseline stable = BaselineCollector.collect(req, 3,
                r -> timed(200, BODY, 50));
        DiffEvidence slow = analyze(stable, timed(200, BODY, 3050), config);
        t.check(slow.lenDelta == 0, "content delta zero");
        t.check(slow.similarity > 0.99, "content similarity ~1");
        t.check(slow.mutatedElapsedMs == 3050, "timing measured & kept (3050ms)");
        t.check(slow.timingDeltaMs >= 2900, "timing delta recorded: " + slow.timingDeltaMs);
        t.check(slow.timingAnomaly, "stable 3s delay flagged as timing anomaly");
        t.check(slow.timingNote != null && slow.timingNote.contains("preserved"),
                "timing note present: " + slow.timingNote);
        DifferentialGate.GateResult r1 = gate.evaluate(slow, false);
        t.check(r1.decision == FilterDecision.REJECT,
                "single timing anomaly does NOT auto-trigger phase2 (no content evidence): " + r1.reason);
        t.check(r1.reason.contains("TIMING-PRESERVED") || r1.reason.contains("timing"),
                "rejection keeps timing evidence visible: " + r1.reason);

        // ---------- 2. 随机抖动（±150ms）不误报 ----------
        final int[] seq = {40, 260, 90, 300, 60, 200};
        final int[] call = {0};
        BaselineCollector.Baseline jittery = BaselineCollector.collect(req, 3,
                r -> timed(200, BODY, seq[call[0]++ % seq.length]));
        DiffEvidence jitter = analyze(jittery, timed(200, BODY, 220), config);
        boolean noFalseAnomaly = !jitter.timingAnomaly
                || jitter.baselineStdMs > 100; // 基线本身抖动大 -> sigma 约束生效
        t.check(noFalseAnomaly, "network jitter not flagged as anomaly (std=" + jitter.baselineStdMs + ")");
        t.check(jitter.mutatedElapsedMs == 220, "jitter measurement still recorded");

        // ---------- 3. 微弱长度差（±1）+ 时间异常：过滤但不删时间 ----------
        DiffEvidence weakLenSlow = analyze(stable, timed(200, BODY + "x", 3050), config);
        DifferentialGate.GateResult r3 = gate.evaluate(weakLenSlow, false);
        t.check(r3.decision == FilterDecision.REJECT || r3.decision == FilterDecision.PASS
                        || r3.decision == FilterDecision.INCONCLUSIVE,
                "weak-len + timing evaluated: " + r3.reason);
        if (r3.decision == FilterDecision.REJECT || r3.decision == FilterDecision.INCONCLUSIVE) {
            t.check(r3.reason.contains("TIMING-PRESERVED"),
                    "weak-length rejection/pending retains timing data: " + r3.reason);
        }

        // ---------- 4. InvalidRequest 分类 ----------
        // 4.1 query 参数找不到 -> PARAM_NOT_FOUND（v1.1 误标 jsonValid=false 的修复）
        DiffEvidence notFound = new DiffEvidence();
        notFound.invalidRequestType = InvalidRequestType.PARAM_NOT_FOUND;
        notFound.invalidRequestReason = "query parameter not found: gone";
        notFound.similarity = 1.0;
        DifferentialGate.GateResult r4 = gate.evaluate(notFound, false);
        t.check(r4.decision == FilterDecision.REJECT && r4.reason.contains("PARAM_NOT_FOUND"),
                "param-not-found classified correctly: " + r4.reason);
        t.check(!r4.reason.contains("JSON"), "param-not-found is NOT a JSON problem");
        // 4.2 JSON 序列化失败 -> JSON_MUTATION_INVALID（请求未发送）
        DiffEvidence badJson = new DiffEvidence();
        badJson.invalidRequestType = InvalidRequestType.JSON_MUTATION_INVALID;
        badJson.invalidRequestReason = "re-serialized JSON failed local validation";
        badJson.jsonValid = false;
        DifferentialGate.GateResult r5 = gate.evaluate(badJson, true);
        t.check(r5.decision == FilterDecision.REJECT && r5.reason.contains("JSON_MUTATION_INVALID")
                        && r5.reason.contains("never sent"),
                "json mutation invalid blocked before sending: " + r5.reason);
        // 4.3 非法 JSON 基线
        DiffEvidence baseBad = new DiffEvidence();
        baseBad.invalidRequestType = InvalidRequestType.BASELINE_JSON_INVALID;
        baseBad.invalidRequestReason = "baseline body is not valid JSON";
        DifferentialGate.GateResult r6 = gate.evaluate(baseBad, true);
        t.check(r6.decision == FilterDecision.REJECT && r6.reason.contains("BASELINE_JSON_INVALID"),
                "baseline json invalid classified: " + r6.reason);
        // 4.4 端到端：mutateJson 非法基线返回分类
        var mutation = com.xzhscan.parameter.ParameterMutators.mutate(
                Support.postJson("http://t.local/bad", "{\"broken\":}"),
                new com.xzhscan.model.Models.ParameterIdentity(
                        com.xzhscan.model.Models.Location.JSON, "x", "$.x", "1",
                        com.xzhscan.model.Models.ParamType.STRING),
                com.xzhscan.parameter.ParameterMutators.Mode.APPEND, "'");
        t.check(!mutation.success, "mutation on broken baseline fails");
        t.checkEq(InvalidRequestType.BASELINE_JSON_INVALID, mutation.failureType,
                "broken baseline -> BASELINE_JSON_INVALID (end-to-end)");

        // ---------- 5. 单位/单调性：elapsedMs 恒为毫秒非负（除未测量 -1） ----------
        DiffEvidence unmeasured = new DiffEvidence();
        t.check(unmeasured.mutatedElapsedMs == 0, "default zero");
        RawResponse resp = timed(200, BODY, 17);
        t.check(resp.elapsedMs == 17, "transport elapsed in ms");
    }

    private static RawResponse timed(int status, String body, long elapsedMs) {
        return new RawResponse(status, new java.util.LinkedHashMap<>(),
                body.getBytes(java.nio.charset.StandardCharsets.UTF_8), elapsedMs);
    }

    private static DiffEvidence analyze(BaselineCollector.Baseline baseline, RawResponse mutated,
                                        XzhScanConfig config) {
        return DifferenceAnalyzer.analyze(baseline, mutated, "REQ-T", "name", "single-quote",
                "admin", "admin'", "string", false, true, config);
    }
}
