package com.xzhscan.engine;

import com.xzhscan.config.XzhScanConfig;
import com.xzhscan.model.Models.DiffEvidence;
import com.xzhscan.model.Models.DifferentialCandidate;
import com.xzhscan.model.Models.FilterDecision;

import java.util.ArrayList;
import java.util.List;

/**
 * DifferentialGate —— 两阶段之间唯一允许的数据交接入口。
 *
 * 规则 A：无效 JSON 差分必须拦截
 *  - 变异请求本地 JSON 校验失败（jsonValid=false）→ 直接 REJECT(local_json_invalid)，
 *    此类请求根本不应被发送；
 *  - 响应呈现 JSON 解析错误特征（parse error / unexpected token / ...）：
 *      · 若差分的其余维度全为弱证据 → REJECT(server_json_parse_error)；
 *      · 若同时存在 DB 错误特征或状态码显著变化 → 进入证据评估（不凭 400 一刀切）。
 *
 * 规则 B：微弱长度差默认过滤
 *  - |lenDelta| <= weakDeltaThreshold 且无 DB 错误、无状态码变化、无结构变化、
 *    相似度仍高 → REJECT(weak_length_delta)；
 *  - 带 DB 错误/状态码变化等强证据时进入单独证据评估逻辑（不计入弱过滤）。
 *
 * 规则 C：动态页面噪声
 *  - 基线窗口不稳定（baselineStable=false）→ INCONCLUSIVE，等待有限次数稳定性重测；
 *  - 重测后仍无法与基线区分 → REJECT(unstable_baseline)。
 *
 * 规则 D：只输出高质量候选
 *  - score >= minDifferenceScore 且原因列表非空 → PASS；
 *  - 每一条 REJECT 必须携带具体原因（UI 可见，便于调试误报）。
 */
public final class DifferentialGate {

    private final XzhScanConfig config;

    public DifferentialGate(XzhScanConfig config) {
        this.config = config;
    }

    /** 单次观察的过滤判定。 */
    public static final class GateResult {
        public final FilterDecision decision;
        public final String reason;
        /** 进入“单独证据评估”时的说明（规则 A/B 强证据旁路）。 */
        public final String strongEvidenceNote;

        GateResult(FilterDecision decision, String reason, String note) {
            this.decision = decision;
            this.reason = reason;
            this.strongEvidenceNote = note;
        }

        public static GateResult of(FilterDecision d, String r) {
            return new GateResult(d, r, null);
        }

        public static GateResult pass(String note) {
            return new GateResult(FilterDecision.PASS, note == null ? "meaningful difference" : note, note);
        }
    }

    /** 规则 A/B/C/D 主入口：对一条差分证据做决策。 */
    public GateResult evaluate(DiffEvidence ev, boolean jsonRequest) {
        // ---- 规则 A（前半）：本地构造失败（含 JSON 语法失败），未发送即拦截 ----
        if (ev.invalidRequestType == com.xzhscan.model.Models.InvalidRequestType.JSON_MUTATION_INVALID) {
            return GateResult.of(FilterDecision.REJECT,
                    "InvalidRequest/JSON_MUTATION_INVALID (never sent): " + ev.invalidRequestReason);
        }
        if (ev.invalidRequestType == com.xzhscan.model.Models.InvalidRequestType.BASELINE_JSON_INVALID) {
            return GateResult.of(FilterDecision.REJECT,
                    "InvalidRequest/BASELINE_JSON_INVALID: " + ev.invalidRequestReason);
        }
        if (ev.invalidRequestType == com.xzhscan.model.Models.InvalidRequestType.PARAM_NOT_FOUND
                || ev.invalidRequestType == com.xzhscan.model.Models.InvalidRequestType.MUTATION_UNSUPPORTED) {
            return GateResult.of(FilterDecision.REJECT,
                    "InvalidRequest/" + ev.invalidRequestType + ": " + ev.invalidRequestReason);
        }

        boolean strongEvidence = ev.dbErrorHit || ev.mutatedStatus != ev.baselineStatus || ev.structureChanged;

        // v3.5：被动时间探针命中分支已移除（被动 = XiaSQL 纯差分；时间盲注由
        // Phase2 verifyTimeBased 全模块枚举 + 三级 sleep 阶梯定罪）。
        // TimingEvidence 模型与 timing 展示链路仍独立保留。

        // ---- 规则 A（后半）：服务器返回 JSON 解析错误特征 ----
        if (jsonRequest && ev.jsonParseErrorLike) {
            if (strongEvidence) {
                // 合法 JSON 请求 + 解析错误响应 + 强证据：走证据评估（规则 D 计分）
                if (ev.dbErrorHit) {
                    return GateResult.pass("server JSON-error-like response WITH db error fingerprint: evidence evaluation");
                }
                // 400 + parse error 但无 DB 指纹：保守起见不进入第二阶段
                return GateResult.of(FilterDecision.REJECT,
                        "server JSON parse error response without db fingerprint (likely request-shape rejection)");
            }
            return GateResult.of(FilterDecision.REJECT, "server JSON parse error response (invalid-JSON differential)");
        }

        // ---- 规则 B：微弱长度差（v3.8.6：REJECT → INCONCLUSIVE，转人工复核） ----
        // 弱差分可能是真注入的低信号形态，直接拒绝会漏报；改判待定由差分页黄色高亮提示人工复核。
        if (Math.abs(ev.lenDelta) > 0 && Math.abs(ev.lenDelta) <= config.weakDeltaThreshold) {
            if (!strongEvidence && ev.similarity >= 0.9) {
                return GateResult.of(FilterDecision.INCONCLUSIVE,
                        "weak length delta (" + ev.lenDelta + " bytes) without strong evidence" + appendTiming(ev));
            }
            if (!strongEvidence) {
                return GateResult.of(FilterDecision.INCONCLUSIVE,
                        "weak length delta (" + ev.lenDelta + " bytes) only, similarity="
                                + String.format("%.2f", ev.similarity) + appendTiming(ev));
            }
            // 强证据 + 微弱长度差：进入单独证据评估（不打弱过滤标记，理由注明）
            return GateResult.pass("weak length delta (" + ev.lenDelta + ") but strong evidence present: "
                    + strongEvidenceSummary(ev));
        }

        // ---- 规则 C：基线不稳定 ----
        if (!ev.baselineStable) {
            return GateResult.of(FilterDecision.INCONCLUSIVE, "baseline unstable (dynamic page): stability retest required");
        }

        // ---- 规则 D：阈值 ----
        if (ev.differenceScore >= config.minDifferenceScore) {
            return GateResult.pass("score " + String.format("%.2f", ev.differenceScore) + " >= "
                    + config.minDifferenceScore + ": " + strongEvidenceSummary(ev));
        }
        if (ev.differenceScore < config.minDifferenceScore) {
            return GateResult.of(FilterDecision.REJECT, "score " + String.format("%.2f", ev.differenceScore)
                    + " below threshold " + config.minDifferenceScore + appendTiming(ev));
        }
        return GateResult.of(FilterDecision.REJECT, "score below threshold " + config.minDifferenceScore);
    }

    /** 拒绝理由附独立保留的计时证据说明（时间数据不因内容差分被过滤而丢弃，任务书 3.3）。 */
    private static String appendTiming(DiffEvidence ev) {
        if (ev.timingAnomaly) {
            return " | TIMING-PRESERVED: " + ev.timingNote;
        }
        if (ev.mutatedElapsedMs >= 0) {
            return " | timing Δ=" + ev.timingDeltaMs + "ms (no anomaly)";
        }
        return "";
    }

    private static String strongEvidenceSummary(DiffEvidence ev) {
        List<String> parts = new ArrayList<>();
        if (ev.dbErrorHit) {
            parts.add("db-error:" + ev.dbErrorFamily);
        }
        if (ev.mutatedStatus != ev.baselineStatus) {
            parts.add("status " + ev.baselineStatus + "->" + ev.mutatedStatus);
        }
        if (ev.structureChanged) {
            parts.add("structure-changed");
        }
        parts.add("sim=" + String.format("%.2f", ev.similarity));
        parts.add("lenDelta=" + ev.lenDelta);
        return String.join(", ", parts);
    }

    /** 组装候选（供 orchestrator 在 PASS 后调用）。 */
    public DifferentialCandidate buildCandidate(DiffEvidence evidence,
                                                String requestId,
                                                String url,
                                                String method,
                                                String contentType,
                                                String parameterName,
                                                String parameterPath,
                                                com.xzhscan.model.Models.Location location,
                                                String originalValue,
                                                String originalType,
                                                boolean jsonValid,
                                                boolean baselineStable,
                                                com.xzhscan.model.RawHttp.RawRequest originalRequest) {
        DifferentialCandidate c = new DifferentialCandidate();
        c.requestId = requestId;
        c.targetUrl = url;
        c.method = method;
        c.contentType = contentType;
        c.parameterName = parameterName;
        c.parameterPath = parameterPath;
        c.parameterLocation = location;
        c.originalValue = originalValue;
        c.originalType = originalType;
        c.mutatedEvidence = evidence;
        c.jsonValid = jsonValid;
        c.baselineStable = baselineStable;
        c.differenceScore = evidence.differenceScore;
        c.differenceReasons.add("dbError=" + evidence.dbErrorHit + (evidence.dbErrorFamily != null ? "(" + evidence.dbErrorFamily + ")" : ""));
        c.differenceReasons.add("statusChange=" + (evidence.mutatedStatus != evidence.baselineStatus));
        c.differenceReasons.add("structureChange=" + evidence.structureChanged);
        c.differenceReasons.add("similarity=" + String.format("%.3f", evidence.similarity));
        c.differenceReasons.add("lenDelta=" + evidence.lenDelta);
        c.originalRequest = originalRequest;
        return c;
    }
}
