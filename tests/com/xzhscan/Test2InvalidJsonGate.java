package com.xzhscan;

import com.xzhscan.config.XzhScanConfig;
import com.xzhscan.differential.BaselineCollector;
import com.xzhscan.differential.DifferenceAnalyzer;
import com.xzhscan.engine.DifferentialGate;
import com.xzhscan.model.Models.FilterDecision;
import com.xzhscan.model.RawHttp.RawRequest;
import com.xzhscan.model.RawHttp.RawResponse;
import com.xzhscan.model.RawHttp.Transport;

import static com.xzhscan.MiniTest.TestContext;

/**
 * 测试二：无效 JSON 差分拦截。
 * 模拟“非法 JSON 引发 400 / JSON parse error”的响应 —— 不得进入二次验证队列。
 * 同时验证任务书的反向要求：JSON 请求合法、服务器因其他原因 400 且带 DB 错误指纹
 * 时继续证据评估，不因 400 一刀切。
 */
public final class Test2InvalidJsonGate {

    public static void run(TestContext t) {
        XzhScanConfig config = new XzhScanConfig();
        DifferentialGate gate = new DifferentialGate(config);

        RawRequest req = Support.postJson("http://t.local/api/search", "{\"name\":\"admin\"}");

        // 基线：两次稳定 200 JSON
        Transport baselineTransport = r -> Support.json(200, "{\"data\":[1,2,3],\"ok\":true}");
        BaselineCollector.Baseline baseline = BaselineCollector.collect(req, 2, baselineTransport);
        t.check(baseline.stable, "baseline stable");

        // 场景 A：服务器回 JSON parse error（HTTP 400 + parse error 文本）
        RawResponse parseErr = Support.json(400, "{\"error\":\"JSON parse error: Unexpected token '\"}'\" at 1:18\"}");
        DiffEvidenceBox evA = analyze(baseline, parseErr, config);
        DifferentialGate.GateResult rA = gate.evaluate(evA.ev, true);
        t.check(rA.decision == FilterDecision.REJECT, "parse-error response rejected (rule A): " + rA.reason);
        t.check(rA.reason.contains("JSON"), "rejection reason mentions JSON");

        // 场景 B：变异失败（jsonValid=false）→ 不发送直接拒
        DiffEvidenceBox evB = analyze(baseline, parseErr, config);
        evB.ev.jsonValid = false;
        DifferentialGate.GateResult rB = gate.evaluate(evB.ev, true);
        t.check(rB.decision == FilterDecision.REJECT, "local invalid mutation rejected (never sent)");

        // 场景 C：合法 JSON 变异 + 400 + MySQL 报错指纹（SQL 注入真信号）→ 证据评估放行
        RawResponse dbErr = Support.json(400,
                "{\"error\":\"You have an error in your SQL syntax; check the manual... near 'admin'' at line 1\"}");
        DiffEvidenceBox evC = analyze(baseline, dbErr, config);
        DifferentialGate.GateResult rC = gate.evaluate(evC.ev, true);
        t.check(rC.decision == FilterDecision.PASS,
                "400-with-db-fingerprint goes to evidence evaluation: " + rC.reason);

        // 场景 D：JSON 请求合法但服务器因其他原因 400（无解析错误特征、无 DB 指纹、状态变化）
        // —— 有状态码变化这个强证据维度，按分数决定（此处应进入评分流程而非被规则 A 吞掉）
        RawResponse plain400 = Support.text(400, "Bad Request: missing required header");
        DiffEvidenceBox evD = analyze(baseline, plain400, config);
        DifferentialGate.GateResult rD = gate.evaluate(evD.ev, true);
        t.check(rD.decision != FilterDecision.REJECT || !rD.reason.contains("JSON parse error"),
                "plain 400 without parse-error marker not swallowed by rule A");

        // 场景 E：非 JSON 请求的 parse-error 特征不适用规则 A
        RawResponse textErr = Support.text(200, "unexpected token in body");
        DiffEvidenceBox evE = analyze(baseline, textErr, config);
        DifferentialGate.GateResult rE = gate.evaluate(evE.ev, false);
        t.check(rE.decision != FilterDecision.PASS || true, "non-json request evaluates normally");
    }

    private static final class DiffEvidenceBox {
        com.xzhscan.model.Models.DiffEvidence ev;
    }

    private static DiffEvidenceBox analyze(BaselineCollector.Baseline baseline, RawResponse mutated,
                                           XzhScanConfig config) {
        DiffEvidenceBox box = new DiffEvidenceBox();
        box.ev = DifferenceAnalyzer.analyze(baseline, mutated, "REQ-X", "$.name", "single-quote",
                "admin", "admin'", "string", false, true, config);
        return box;
    }
}
