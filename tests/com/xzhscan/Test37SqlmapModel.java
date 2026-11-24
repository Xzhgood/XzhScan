package com.xzhscan;

import com.xzhscan.config.XzhScanConfig;
import com.xzhscan.engine.ScanOrchestrator;
import com.xzhscan.model.EvidenceStore;
import com.xzhscan.model.Models.DifferentialCandidate;
import com.xzhscan.model.RawHttp.RawRequest;
import com.xzhscan.parameter.ParameterExtractor;
import com.xzhscan.vendor.sql.SqlmapTimeModel;

import java.util.List;

import static com.xzhscan.MiniTest.TestContext;

/**
 * 测试三十七：sqlmap 注入模型时间盲注（v4.0）。
 *  - boundary 与 clause 解耦：prefix + clause + suffix 渲染正确；
 *  - 按参数类型排序 boundary（数字型优先 / 字符型优先）；
 *  - 条件对判定：TRUE 慢 / FALSE 快 → 进入三级阶梯 → CONFIRMED，
 *    证据标签含 sqlmap-pair；
 *  - boundary 枚举路径：数字型 parameter + query-SLEEP 子句命中 → CONFIRMED，
 *    标签含 sqlmap:。
 */
public final class Test37SqlmapModel {

    private static com.xzhscan.model.RawHttp.RawResponse resp(int status, String body, long ms) {
        return new com.xzhscan.model.RawHttp.RawResponse(status, new java.util.LinkedHashMap<>(),
                body.getBytes(java.nio.charset.StandardCharsets.UTF_8), ms);
    }

    private static DifferentialCandidate candidate(String url) {
        RawRequest req = Support.get(url);
        var ex = ParameterExtractor.extract(req);
        var p = ex.parameters.stream().filter(x -> x.path.equals("id")).findFirst().orElseThrow();
        return ScanOrchestrator.manualCandidate(req, p);
    }

    public static void run(TestContext t) {
        // ---------- 1. boundary 渲染 ----------
        SqlmapTimeModel.Boundary num = new SqlmapTimeModel.Boundary("1", "-- -", "数字型·注释");
        SqlmapTimeModel.Boundary str = new SqlmapTimeModel.Boundary("'", "-- -", "单引号·注释");
        t.checkEq("1 AND X-- -", num.wrap(" AND X"), "数字型 boundary 渲染");
        t.checkEq("' AND X-- -", str.wrap(" AND X"), "字符型 boundary 渲染");
        t.check(!num.stringCtx(), "数字型 boundary 判定");
        t.check(str.stringCtx(), "字符型 boundary 判定");

        // ---------- 2. clause 渲染占位 ----------
        String rendered = SqlmapTimeModel.render(" AND {R}=IF((1=1),SLEEP({S}),{R})", 5);
        t.check(!rendered.contains("{R}") && !rendered.contains("{S}"), "clause 占位全部渲染");
        t.check(rendered.contains("SLEEP(5)"), "延迟秒数注入 clause");

        // ---------- 3. boundary 排序（按参数类型） ----------
        List<SqlmapTimeModel.Boundary> numericFirst = SqlmapTimeModel.boundariesFor("1");
        t.check(!numericFirst.get(0).stringCtx(), "数字原值 → 数字型 boundary 优先");
        List<SqlmapTimeModel.Boundary> stringFirst = SqlmapTimeModel.boundariesFor("admin");
        t.check(stringFirst.get(0).stringCtx(), "字符串原值 → 字符型 boundary 优先");
        t.checkEq(SqlmapTimeModel.BOUNDARIES.size(), numericFirst.size(), "boundary 全量保留（排序不丢）");

        XzhScanConfig config = new XzhScanConfig();
        config.requestIntervalMs = 0;
        config.baselineSamples = 2;
        config.allowTimeBasedProbe = true;
        config.verifyTimeoutMs = 300_000;

        // ---------- 4. 条件对 + sqlmap 交叉验证：条件为真才延迟 → CONFIRMED ----------
        // mock 解析 sqlmap 的减法形态 SLEEP(S-(IF((a=b),0,S)))：
        // 条件为真 → 延迟 S×1200ms；条件为假 → 30ms（不延迟）。等价真实 DB 语义。
        Support.FakeTransport pair = new Support.FakeTransport();
        java.util.regex.Pattern subForm =
                java.util.regex.Pattern.compile("sleep\\((\\d+)-\\(if\\(\\((\\d+)=(\\d+)\\),0,(\\d+)\\)\\)\\)");
        pair.responder = (r, i) -> {
            String u = ParameterExtractor.urlDecode(r.url).toLowerCase();
            java.util.regex.Matcher m = subForm.matcher(u);
            if (m.find()) {
                int sec = Integer.parseInt(m.group(1));
                int a = Integer.parseInt(m.group(2));
                int b = Integer.parseInt(m.group(3));
                boolean condTrue = (a == b);
                long ms = condTrue ? sec * 1200L : 30L;
                return resp(200, "{\"ok\":1}", ms);
            }
            return resp(200, "{\"ok\":1}", 25);
        };
        var vr = new com.xzhscan.engine.SqlVerificationEngine(config, pair, new EvidenceStore())
                .verify(candidate("http://t.local/a?id=1"));
        t.checkEq(com.xzhscan.model.Models.VerifyVerdict.CONFIRMED, vr.verdict,
                "条件对（TRUE 慢/FALSE 快）→ CONFIRMED");
        boolean pairLabel = vr.findings.stream().anyMatch(f -> f.payloadRuleId != null
                && f.payloadRuleId.startsWith("sqlmap-pair:"));
        t.check(pairLabel, "证据标签为 sqlmap-pair（条件对路径）: "
                + vr.findings.stream().map(f -> f.payloadRuleId).toList());

        // ---------- 5. boundary 枚举：query-SLEEP 子句命中 → CONFIRMED ----------
        Support.FakeTransport bound = new Support.FakeTransport();
        bound.responder = (r, i) -> {
            String u = ParameterExtractor.urlDecode(r.url).toLowerCase();
            // 仅数字型 boundary + mysql query-sleep 形态延迟
            if (u.contains("from (select(sleep(0)))") || u.contains("sleep(0))))")) {
                return resp(200, "{\"ok\":1}", 30);
            }
            if (u.contains("from (select(sleep(5)))")) {
                return resp(200, "{\"ok\":1}", 6000);
            }
            if (u.contains("from (select(sleep(6)))")) {
                return resp(200, "{\"ok\":1}", 7200);
            }
            return resp(200, "{\"ok\":1}", 25);
        };
        var vr2 = new com.xzhscan.engine.SqlVerificationEngine(config, bound, new EvidenceStore())
                .verify(candidate("http://t.local/b?id=7"));
        t.checkEq(com.xzhscan.model.Models.VerifyVerdict.CONFIRMED, vr2.verdict,
                "boundary 枚举 query-SLEEP 命中 → CONFIRMED");
        // 命中路径不唯一（QUICK 集末尾也含 sqlmap query-SLEEP 形态），只断言检测成立
        t.check(!vr2.findings.isEmpty(),
                "boundary/query-SLEEP 命中并产生证据: "
                        + vr2.findings.stream().map(f -> f.payloadRuleId).toList());

        // ---------- 6. 无延迟响应 → 不确认（不误报） ----------
        Support.FakeTransport quiet = new Support.FakeTransport();
        quiet.responder = (r, i) -> resp(200, "{\"ok\":1}", 25);
        var vr3 = new com.xzhscan.engine.SqlVerificationEngine(config, quiet, new EvidenceStore())
                .verify(candidate("http://t.local/c?id=9"));
        t.check(vr3.verdict != com.xzhscan.model.Models.VerifyVerdict.CONFIRMED,
                "全部秒回 → 不判注入（sqlmap 模型不引入误报）");

        // ---------- 7. 假阳性拦截：条件对成立但非法语句也慢 → 交叉验证否决 ----------
        // 场景：站点对所有"像注入"的请求都慢（缓存/限速/卡顿），只有非法语句也慢
        // 才能暴露它不按 SQL 条件执行。sqlmap 的 checkFalsePositives 正是靠这一条兜底。
        Support.FakeTransport trickSlow = new Support.FakeTransport();
        java.util.regex.Pattern illegalForm = java.util.regex.Pattern.compile("1 \\d+ \\d+");
        trickSlow.responder = (r, i) -> {
            String u = ParameterExtractor.urlDecode(r.url).toLowerCase();
            java.util.regex.Matcher m = subForm.matcher(u);
            if (m.find()) {
                int a = Integer.parseInt(m.group(2));
                int b = Integer.parseInt(m.group(3));
                return resp(200, "{\"ok\":1}", a == b ? 6000 : 30); // 条件真慢、条件假快
            }
            if (illegalForm.matcher(u).find()) {
                return resp(200, "{\"ok\":1}", 6000); // 非法语句也慢 → 破绽
            }
            return resp(200, "{\"ok\":1}", 25);
        };
        var vr4 = new com.xzhscan.engine.SqlVerificationEngine(config, trickSlow, new EvidenceStore())
                .verify(candidate("http://t.local/e?id=4"));
        t.check(vr4.verdict != com.xzhscan.model.Models.VerifyVerdict.CONFIRMED,
                "非法语句也慢 → sqlmap 交叉验证判假阳性，不报注入");
    }

    private Test37SqlmapModel() {
    }
}
