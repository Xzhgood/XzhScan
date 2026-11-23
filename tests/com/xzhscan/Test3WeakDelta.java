package com.xzhscan;

import com.xzhscan.config.XzhScanConfig;
import com.xzhscan.differential.BaselineCollector;
import com.xzhscan.differential.DifferenceAnalyzer;
import com.xzhscan.engine.DifferentialGate;
import com.xzhscan.model.Models.DiffEvidence;
import com.xzhscan.model.Models.FilterDecision;
import com.xzhscan.model.RawHttp.RawRequest;
import com.xzhscan.model.RawHttp.RawResponse;

import static com.xzhscan.MiniTest.TestContext;

/**
 * 测试三：微弱差分。
 * -1/-2/+1/+2 字节的纯长度差必须过滤；带 DB 错误/状态码等强证据时
 * 进入单独证据评估逻辑，不做一刀切。
 */
public final class Test3WeakDelta {

    static final String BASE = "aaaa bbbb cccc dddd eeee ffff gggg";

    public static void run(TestContext t) {
        XzhScanConfig config = new XzhScanConfig();
        DifferentialGate gate = new DifferentialGate(config);
        RawRequest req = Support.get("http://t.local/search?name=admin");

        BaselineCollector.Baseline baseline = BaselineCollector.collect(req, 2,
                r -> Support.text(200, BASE));

        // 1) 四个方向的微弱长度差：无其他证据 -> 全部 INCONCLUSIVE（v3.8.6：弱差分转待定人工复核）
        for (int delta : new int[]{-1, -2, 1, 2}) {
            String body = delta > 0 ? BASE + "x".repeat(delta) : BASE.substring(0, BASE.length() + delta);
            DiffEvidence ev = analyze(baseline, Support.text(200, body), config);
            DifferentialGate.GateResult r = gate.evaluate(ev, false);
            t.check(r.decision == FilterDecision.INCONCLUSIVE,
                    "pure lenDelta=" + delta + " pending manual review: " + r.reason);
        }

        // 2) 规则 B 旁路：lenDelta=+1 但存在 DB 错误指纹（直接构造证据，精确测旁路逻辑）
        DiffEvidence evDb = analyze(baseline, Support.text(200,
                "You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version for the right syntax to use near 'x' at line 1"), config);
        t.check(evDb.dbErrorHit, "analyzer detects MySQL error fingerprint");
        DiffEvidence bypass = new DiffEvidence();
        bypass.lenDelta = 1;
        bypass.similarity = 0.98;
        bypass.baselineStable = true;
        bypass.mutatedStatus = bypass.baselineStatus = 200;
        bypass.dbErrorHit = true;
        bypass.dbErrorFamily = "MySQL";
        bypass.differenceScore = 0.4; // 低于全局阈值，但强证据旁路优先
        DifferentialGate.GateResult rBypass = gate.evaluate(bypass, false);
        t.check(rBypass.decision == FilterDecision.PASS,
                "weak delta + db fingerprint -> separate evidence evaluation: " + rBypass.reason);

        // 3) lenDelta=-2 且状态码 200->500（强证据）-> 证据评估
        DiffEvidence evStatus = analyze(baseline, Support.text(500, BASE.substring(2)), config);
        DifferentialGate.GateResult rStatus = gate.evaluate(evStatus, false);
        t.check(rStatus.decision != FilterDecision.REJECT || !rStatus.reason.contains("weak length"),
                "status-code change with small delta not silently filtered");

        // 4) 大长度差 + 低相似度但无任何强证据（无 DB 指纹/状态码变化）：
        //    按规则 D 评分制保守拒绝（这与 XiaSQL 只看长度相比是刻意的收紧）
        DiffEvidence evBig = analyze(baseline, Support.text(200,
                "totally different content stack trace java exception 500 something"), config);
        DifferentialGate.GateResult rBig = gate.evaluate(evBig, false);
        t.check(rBig.decision == FilterDecision.REJECT,
                "content-only diff without strong evidence stays below threshold: " + rBig.reason);

        // 5) 校准断言：默认权重下，纯 1 字节差得分应远低于阈值
        DiffEvidence ev1 = analyze(baseline, Support.text(200, BASE + "x"), config);
        t.check(ev1.differenceScore < config.minDifferenceScore,
                String.format("1-byte-only score %.3f below threshold %.2f", ev1.differenceScore, config.minDifferenceScore));
    }

    private static DiffEvidence analyze(BaselineCollector.Baseline baseline, RawResponse mutated,
                                        XzhScanConfig config) {
        return DifferenceAnalyzer.analyze(baseline, mutated, "REQ-X", "name", "single-quote",
                "admin", "admin'", "string", false, true, config);
    }
}
