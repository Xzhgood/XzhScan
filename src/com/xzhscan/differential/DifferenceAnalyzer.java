package com.xzhscan.differential;

import com.xzhscan.config.XzhScanConfig;
import com.xzhscan.model.Models.DiffEvidence;
import com.xzhscan.model.RawHttp.RawResponse;
import com.xzhscan.vendor.sql.SqlPayloadLibrary;

import java.util.HashSet;
import java.util.Set;

/**
 * 差分分析器：把“变异响应 vs 基线窗口”的观察折叠为 DiffEvidence + 综合分。
 *
 * DifferenceScore = w1*结构变化 + w2*(1-相似度) + w3*状态码变化 + w4*DB错误 + w5*内容差比例
 * 全部权重来自 XzhScanConfig（UI 可调，tests/calibration 校准默认值）。
 */
public final class DifferenceAnalyzer {

    private DifferenceAnalyzer() {
    }

    public static DiffEvidence analyze(BaselineCollector.Baseline baseline,
                                       RawResponse mutated,
                                       String requestId,
                                       String parameterPath,
                                       String mutationKind,
                                       String originalValue,
                                       String mutatedValue,
                                       String originalType,
                                       boolean typeChanged,
                                       boolean jsonValid,
                                       XzhScanConfig config) {
        DiffEvidence ev = new DiffEvidence();
        ev.requestId = requestId;
        ev.parameterPath = parameterPath;
        ev.mutationKind = mutationKind;
        ev.originalValue = originalValue;
        ev.mutatedValue = mutatedValue;
        ev.originalType = originalType;
        ev.typeChanged = typeChanged;
        ev.jsonValid = jsonValid;

        ev.baselineStatus = baseline.statusCode;
        ev.baselineMinLen = baseline.minLen;
        ev.baselineMaxLen = baseline.maxLen;
        ev.baselineMedianLen = baseline.medianLen;
        ev.baselineLenVariance = baseline.maxLen - baseline.minLen;
        ev.baselineStable = baseline.stable;

        ev.mutatedStatus = mutated.statusCode;
        ev.mutatedLen = mutated.length();
        ev.lenDelta = mutated.length() - baseline.medianLen;

        ResponseNormalizer.Normalized mn = ResponseNormalizer.normalize(mutated);
        // 相似度：取与每个基线归一化文本相似度的最大值（与最像的那个比，最保守）
        double bestSim = 0;
        for (ResponseNormalizer.Normalized bn : baseline.normalized) {
            double sim = ResponseNormalizer.similarity(bn.normalizedText, mn.normalizedText);
            if (sim > bestSim) {
                bestSim = sim;
            }
        }
        ev.similarity = bestSim;

        // JSON 结构变化：排除动态字段后的叶子路径集合差
        if (mn.json && !baseline.normalized.isEmpty() && baseline.normalized.get(0).json) {
            Set<String> base = new HashSet<>(baseline.normalized.get(0).structureFingerprint);
            Set<String> mut = new HashSet<>(mn.structureFingerprint);
            Set<String> diff = new HashSet<>();
            for (String p : mut) {
                if (!base.contains(p)) {
                    diff.add(p);
                }
            }
            for (String p : base) {
                if (!mut.contains(p)) {
                    diff.add(p);
                }
            }
            diff.removeAll(baseline.dynamicFields);
            ev.structureChanged = !diff.isEmpty();
        }

        // 数据库错误特征
        String dbFamily = SqlPayloadLibrary.detectError(mutated.bodyAsString());
        ev.dbErrorHit = dbFamily != null;
        ev.dbErrorFamily = dbFamily;

        // 响应呈现 JSON 解析错误特征（规则 A 证据之一）
        ev.jsonParseErrorLike = ResponseNormalizer.looksLikeJsonParseError(mutated.bodyAsString());

        // 重定向变化
        String baseLoc = baseline.last() == null ? null : baseline.last().header("location");
        String mutLoc = mutated.header("location");
        ev.redirectChanged = baseLoc != null ? !baseLoc.equals(mutLoc) : mutLoc != null;

        // ---- TimingEvidence：正文无差不等于无异常；独立记录，不折叠进内容分 ----
        ev.baselineMeanMs = baseline.meanElapsed;
        ev.baselineStdMs = baseline.stdElapsed;
        ev.baselineMinMs = baseline.minElapsedMs;
        ev.mutatedElapsedMs = mutated.elapsedMs;
        ev.timingDeltaMs = mutated.elapsedMs - (long) baseline.meanElapsed;
        double sigma = Math.max(baseline.stdElapsed, 25.0); // 下限 25ms：避免零抖动时小差也算多σ
        ev.timingSigma = ev.timingDeltaMs / sigma;
        // 异常判据：偏差同时满足幅度（>=800ms）与稳定性（>=系数σ，v3.10.0: 可配置，默认 5σ）。
        // 单次时间异常只作为证据保留，不据此判定漏洞或单独触发复检（任务书 3.2-6）。
        boolean amplitude = Math.abs(ev.timingDeltaMs) >= 800;
        boolean stable = Math.abs(ev.timingSigma) >= config.timingStdCoeff;  // v3.10.0: 使用配置值
        ev.timingAnomaly = amplitude && stable;
        if (ev.timingAnomaly) {
            ev.timingNote = "timing anomaly preserved: Δ=" + ev.timingDeltaMs + "ms ("
                    + String.format("%.1f", ev.timingSigma) + "σ vs baseline)";
        } else if (mutated.elapsedMs < 0) {
            ev.timingNote = "timing not measured";
        }

        ev.differenceScore = score(ev, config);
        classify(ev);
        // 校准规则：数据库错误指纹（xray 同款特征正则，误报率低）为确定性证据，
        // 评分下限 0.70 —— 允许进入第二阶段复检（复检由 md5-echo/布尔对/时间三级
        // 等可复现手段定罪，gate 的 PASS 不是漏洞结论）。依据 tests/calibration 用例。
        if (ev.dbErrorHit) {
            ev.differenceScore = Math.max(ev.differenceScore, 0.70);
        }
        return ev;
    }

    /** 证据分型（任务书 §14）：七类证据独立标记，弱证据（LENGTH_DIFF）不冒充强证据。 */
    public static void classify(DiffEvidence ev) {
        if (ev.mutatedStatus != ev.baselineStatus) {
            ev.evidenceKinds.add("STATUS_DIFF");
        }
        if (ev.similarity < 1.0) {
            ev.evidenceKinds.add("BODY_DIFF");
        }
        if (ev.lenDelta != 0) {
            ev.evidenceKinds.add("LENGTH_DIFF");
        }
        if (ev.structureChanged) {
            ev.evidenceKinds.add("JSON_STRUCTURE_DIFF");
        }
        if (ev.dbErrorHit) {
            ev.evidenceKinds.add("SQL_ERROR");
        }
        if (ev.timingAnomaly) {
            // 正文无差但计时异常：独立保留，绝不因正文相似度规则删除
            // （v3.8.3：timeProbeHit 死分支合并——被动时间探针子系统已删除）
            ev.evidenceKinds.add("TIMING_ANOMALY");
        }
    }

    /** 综合评分（0..1）。弱证据（typeChanged 的隐式字符串化）在结构/内容维度上打折扣。 */
    public static double score(DiffEvidence ev, XzhScanConfig config) {
        double s = 0;
        s += config.weightStructure * (ev.structureChanged ? 1 : 0);
        s += config.weightDissimilarity * clamp01(1 - ev.similarity);
        s += config.weightStatusChange * (ev.mutatedStatus != ev.baselineStatus ? 1 : 0);
        s += config.weightDbError * (ev.dbErrorHit ? 1 : 0);
        // 内容差比例：长度差相对基线中位数的比例，封顶 1
        double ratio = ev.baselineMedianLen <= 0
                ? (ev.mutatedLen > 0 ? 1 : 0)
                : Math.abs((double) ev.lenDelta) / Math.max(64, ev.baselineMedianLen);
        s += config.weightContentDiff * clamp01(ratio);
        return clamp01(s);
    }

    private static double clamp01(double v) {
        return Math.max(0, Math.min(1, v));
    }
}
