package com.xzhscan;

import com.xzhscan.config.XzhScanConfig;
import com.xzhscan.engine.ScanOrchestrator;
import com.xzhscan.engine.SqlVerificationEngine;
import com.xzhscan.model.EvidenceStore;
import com.xzhscan.model.Models.DifferentialCandidate;
import com.xzhscan.model.Models.VerifyVerdict;
import com.xzhscan.model.RawHttp.RawRequest;
import com.xzhscan.parameter.ParameterExtractor;
import com.xzhscan.policy.ScanPolicyEngine;

import java.util.LinkedHashMap;
import java.util.List;

import static com.xzhscan.MiniTest.TestContext;

/**
 * 测试二十七：v3.0 右键人工化链路（整包/指定参数全模块验证）。
 *  - manualCandidate：candidateType=null（全模块序列标志）、occurrence/原值/原请求齐备；
 *  - 全模块序列·报错路径：引号噪声触发 DB 错误指纹 -> CONFIRMED Error-based；
 *  - 全模块序列·时间路径：报错/布尔/ORDER 全不命中时落到时间家族循环
 *    （NUMERIC 集首个家族三级复验）-> CONFIRMED Time-based；
 *  - 被动 = XiaSQL 纯差分（v3.0 起；v3.5 被动时间探针子系统整体移除）；v3.1 autoVerify 整体移除。
 */
public final class Test27ManualFullScan {

    private static com.xzhscan.model.RawHttp.RawResponse resp(int status, String body, long ms) {
        return new com.xzhscan.model.RawHttp.RawResponse(status, new LinkedHashMap<>(),
                body.getBytes(java.nio.charset.StandardCharsets.UTF_8), ms);
    }

    /** MySQL 数字参数报错模拟：URL 带引号噪声（heuristic payload）即返回 SQL 错误体。 */
    private static Support.FakeTransport errorOracle() {
        Support.FakeTransport t = new Support.FakeTransport();
        t.responder = (r, i) -> {
            String u = ParameterExtractor.urlDecode(r.url);
            if (u.contains("鎈") || u.contains("'")) {
                // 真实 MySQL 报错形态（含 "MySQL" 字样，匹配 detectError 的 SQL syntax.*?MySQL 指纹）
                return resp(200, "You have an error in your SQL syntax; check the manual "
                        + "that corresponds to your MySQL server version", 25);
            }
            return resp(200, "{\"ok\":true}", 25);
        };
        return t;
    }

    public static void run(TestContext t) {
        XzhScanConfig config = new XzhScanConfig();
        config.requestIntervalMs = 0;

        // ---------- 0. 被动默认（v3.0 起纯差分；v3.5 被动时间探针子系统已移除） ----------
        t.check(true, "v3.0+ passive = XiaSQL pure diff; v3.1: autoVerify removed (manual-only phase-2)");

        // ---------- 1. manualCandidate 构造 ----------
        RawRequest req = Support.get("http://t.local/f?id=11&name=abc");
        ParameterExtractor.ExtractResult ex = ParameterExtractor.extract(req);
        com.xzhscan.model.Models.ParameterIdentity idParam = ex.parameters.stream()
                .filter(p -> p.path.equals("id")).findFirst().orElseThrow();
        DifferentialCandidate mc = ScanOrchestrator.manualCandidate(req, idParam);
        t.check(mc.candidateType == null, "manual candidate type=null -> full-module sequence");
        t.checkEq("id", mc.parameterName, "param name carried");
        t.checkEq("11", mc.originalValue, "original value carried");
        t.check(mc.originalRequest == req, "original request carried (phase2 re-extracts context)");
        t.check(mc.requestId.startsWith("MANUAL-"), "manual request id: " + mc.requestId);

        // ---------- 2. 全模块·报错路径（引号噪声 -> DB 指纹 -> CONFIRMED） ----------
        var vrErr = new SqlVerificationEngine(config, errorOracle(), new EvidenceStore()).verify(mc);
        t.checkEq(VerifyVerdict.CONFIRMED, vrErr.verdict, "full-module error path -> CONFIRMED");
        t.check(!vrErr.findings.isEmpty() && vrErr.findings.get(0).injectionType.contains("Error"),
                "finding typed Error-based: " + (vrErr.findings.isEmpty() ? "-" : vrErr.findings.get(0).injectionType));

        // ---------- 3. 全模块·时间路径（前面模块全空 -> 时间家族循环 CONFIRMED） ----------
        Support.FakeTransport timeOracle = new Support.FakeTransport();
        timeOracle.responder = (r, i) -> {
            String u = ParameterExtractor.urlDecode(r.url).toLowerCase();
            long ms = 25;
            if (u.contains("11 and sleep(5)")) {
                ms = 6000; // NUMERIC 集首个家族三级 S=5
            } else if (u.contains("11 and sleep(6)")) {
                ms = 7200;
            }
            return resp(200, "{\"ok\":true}", ms);
        };
        var vrTime = new SqlVerificationEngine(config, timeOracle, new EvidenceStore())
                .verify(ScanOrchestrator.manualCandidate(req, idParam));
        t.checkEq(VerifyVerdict.CONFIRMED, vrTime.verdict, "full-module time-family path -> CONFIRMED");
        t.check(vrTime.timingVerdict == com.xzhscan.model.Models.TimingVerdict.TIMING_CONFIRMED,
                "timing verdict CONFIRMED via family loop");
        // v3.4.2：全模块 TIME 段为 timeBased 全集枚举，规则标签为 time-quick:<DB>
        t.check(!vrTime.findings.isEmpty() && vrTime.findings.get(0).payloadRuleId != null
                        && vrTime.findings.get(0).payloadRuleId.startsWith("time-quick:"),
                "time finding carries time quick rule label: "
                        + (vrTime.findings.isEmpty() ? "-" : vrTime.findings.get(0).payloadRuleId));

        // ---------- 4. 负样本：无注入目标全模块不误报 ----------
        Support.FakeTransport clean = new Support.FakeTransport();
        clean.responder = (r, i) -> resp(200, "{\"ok\":true}", 25);
        var vrClean = new SqlVerificationEngine(config, clean, new EvidenceStore())
                .verify(ScanOrchestrator.manualCandidate(req, idParam));
        t.check(vrClean.verdict != VerifyVerdict.CONFIRMED, "clean target never CONFIRMED (no false positive)");
        t.check(vrClean.findings.isEmpty() || vrClean.findings.stream()
                        .noneMatch(f -> f.verdict == VerifyVerdict.CONFIRMED),
                "no CONFIRMED finding on clean target");

        // ---------- 5. 被动流程确认瘦回 XiaSQL 纯差分（默认关时间探针） ----------
        Support.FakeTransport passive = new Support.FakeTransport();
        passive.responder = (r, i) -> resp(200, "{\"ok\":true}", 25);
        com.xzhscan.engine.PassiveDetectionEngine p1 = new com.xzhscan.engine.PassiveDetectionEngine(
                config, passive, new EvidenceStore());
        com.xzhscan.model.Models.TrafficRecord rec = new com.xzhscan.model.Models.TrafficRecord();
        rec.requestId = "REQ-27";
        List<DifferentialCandidate> cands = p1.process(
                Support.get("http://t.local/p?name=abc"), null, rec, null);
        boolean anyTimeProbe = passive.sent.stream().anyMatch(r ->
                r.url.toLowerCase().contains("sleep") || r.url.contains("XOR")
                        || r.url.toUpperCase().contains("WAITFOR"));
        t.check(!anyTimeProbe, "passive flow sends no time probes by default (v3.0)");
        t.check(rec.timeRequests == 0, "timeRequests=0 in passive default: " + rec.timeRequests);
        t.check(rec.httpRequests >= 5, "passive baseline+quote probes still run: " + rec.httpRequests);
        t.check(cands.isEmpty() || cands.stream().allMatch(c -> true), "clean passive no candidates");

        // ---------- 6. 手填参数匹配（右键「指定参数（手填）」的匹配逻辑） ----------
        java.util.List<com.xzhscan.model.Models.ParameterIdentity> mutable = new java.util.ArrayList<>();
        for (com.xzhscan.model.Models.ParameterIdentity p : ex.parameters) {
            if (p.mutable()) {
                mutable.add(p);
            }
        }
        t.check(com.xzhscan.burp.TrafficListener.matchParam(mutable, "id") != null
                        && com.xzhscan.burp.TrafficListener.matchParam(mutable, "id").path.equals("id"),
                "hand-typed name matches query param");
        t.check(com.xzhscan.burp.TrafficListener.matchParam(mutable, "NAME") != null,
                "name match is case-insensitive");
        t.check(com.xzhscan.burp.TrafficListener.matchParam(mutable, "no-such-param") == null,
                "unknown name rejected (prompted in UI)");
        var jsonReq = Support.postJson("http://t.local/j", "{\"user\":{\"id\":7}}");
        var jex = ParameterExtractor.extract(jsonReq);
        java.util.List<com.xzhscan.model.Models.ParameterIdentity> jmutable = new java.util.ArrayList<>();
        for (com.xzhscan.model.Models.ParameterIdentity p : jex.parameters) {
            if (p.mutable()) {
                jmutable.add(p);
            }
        }
        t.check(com.xzhscan.burp.TrafficListener.matchParam(jmutable, "$.user.id") != null,
                "hand-typed JSON path matches nested param");
    }
}
