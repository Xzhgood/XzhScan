package com.xzhscan;

import com.xzhscan.config.XzhScanConfig;
import com.xzhscan.engine.ScanOrchestrator;
import com.xzhscan.engine.SqlVerificationEngine;
import com.xzhscan.model.EvidenceStore;
import com.xzhscan.model.Models.DifferentialCandidate;
import com.xzhscan.model.RawHttp.RawRequest;
import com.xzhscan.parameter.ParameterExtractor;
import com.xzhscan.vendor.sql.SqlmapTimeModel;

import static com.xzhscan.MiniTest.TestContext;

/**
 * 测试三十九：二阶段耗时优化（v4.1.1）。
 *  - 探针分级：level 1 请求数显著少于 level 2（默认 level 1）；
 *  - query SLEEP 前置：首条探针是 MySQL 双层 SELECT 包裹形态；
 *  - 模板级去重：QUICK 与 sqlmap 集重叠的模板只发一次；
 *  - 参数配额：timeModuleSkipped 候选跳过时间模块；
 *  - 独立子句（MSSQL 堆叠 / ORDER BY）与 / ** /、反引号 boundary 存在。
 */
public final class Test39TimeBudget {

    private static com.xzhscan.model.RawHttp.RawResponse resp(long ms) {
        return new com.xzhscan.model.RawHttp.RawResponse(200, new java.util.LinkedHashMap<>(),
                "ok".getBytes(java.nio.charset.StandardCharsets.UTF_8), ms);
    }

    private static DifferentialCandidate candidate(String url) {
        RawRequest req = Support.get(url);
        var ex = ParameterExtractor.extract(req);
        var p = ex.parameters.stream().filter(x -> x.path.equals("id")).findFirst().orElseThrow();
        return ScanOrchestrator.manualCandidate(req, p);
    }

    public static void run(TestContext t) {
        // ---------- 1. 分级：level 1 请求数 < level 2 ----------
        XzhScanConfig l1 = new XzhScanConfig();
        l1.requestIntervalMs = 0;
        l1.baselineSamples = 2;
        l1.allowTimeBasedProbe = true;
        l1.timeProbeLevel = 1;

        XzhScanConfig l2 = new XzhScanConfig();
        l2.requestIntervalMs = 0;
        l2.baselineSamples = 2;
        l2.allowTimeBasedProbe = true;
        l2.timeProbeLevel = 2;

        Support.FakeTransport fast1 = new Support.FakeTransport();
        fast1.responder = (r, i) -> resp(25);
        var vr1 = new SqlVerificationEngine(l1, fast1, new EvidenceStore())
                .verify(candidate("http://t.local/a?id=1"));

        Support.FakeTransport fast2 = new Support.FakeTransport();
        fast2.responder = (r, i) -> resp(25);
        var vr2 = new SqlVerificationEngine(l2, fast2, new EvidenceStore())
                .verify(candidate("http://t.local/a?id=1"));

        t.check(vr1.probeCount > 0 && vr2.probeCount > 0, "两级都有探针发送");
        t.check(vr1.probeCount < vr2.probeCount,
                "level 1 请求数少于 level 2（" + vr1.probeCount + " < " + vr2.probeCount + "）");
        t.check(vr1.probeCount <= 45,
                "level 1 请求数在可控范围（实际 " + vr1.probeCount + "）");
        t.check(vr2.probeCount - vr1.probeCount >= 10,
                "level 2 明显多于 level 1（差 " + (vr2.probeCount - vr1.probeCount) + "）");
        t.checkEq(1, new XzhScanConfig().timeProbeLevel, "timeProbeLevel 默认 1");

        // ---------- 2. query SLEEP 前置 ----------
        var quick = com.xzhscan.vendor.sql.SqlPayloadLibrary.QUICK_TIME_PROBES;
        String first = quick.get(0).template().toLowerCase(java.util.Locale.ROOT);
        t.check(first.contains("from (select(sleep"), "首条 QUICK 探针为 query SLEEP 形态: " + first);

        // ---------- 3. 模板级去重：重叠模板只发一次 ----------
        // QUICK 首条模板（含 boundary 后）与 sqlmap mysql-query-sleep + ' boundary 等价
        // 只统计"纯 query SLEEP"（排除条件对的 IF 减法形态）
        long sameTemplateSent = fast1.sent.stream()
                .filter(r -> {
                    String u = ParameterExtractor.urlDecode(r.url).toLowerCase();
                    return u.contains("from (select(sleep(5)" ) && !u.contains("if(");
                })
                .count();
        t.check(sameTemplateSent >= 1, "query SLEEP 已发送");
        t.check(sameTemplateSent <= 3,
                "同模板未重复放大（实际 " + sameTemplateSent + " 次，去重生效）");

        // ---------- 4. 参数配额：timeModuleSkipped 跳过时间模块 ----------
        DifferentialCandidate skipped = candidate("http://t.local/b?id=2");
        skipped.timeModuleSkipped = true;
        Support.FakeTransport skipTransport = new Support.FakeTransport();
        skipTransport.responder = (r, i) -> resp(25);
        var vrSkip = new SqlVerificationEngine(l1, skipTransport, new EvidenceStore())
                .verify(skipped);
        t.check(vrSkip.probeCount < vr1.probeCount,
                "配额跳过后请求数更少（" + vrSkip.probeCount + " < " + vr1.probeCount + "）");
        t.check(vrSkip.timingVerdict == null, "配额跳过的候选不产生时间判定");

        // ---------- 5. 独立子句与绕过 boundary ----------
        t.checkEq(3, SqlmapTimeModel.STANDALONE_CLAUSES.size(), "独立子句 3 条（MSSQL/ORDER×2）");
        boolean hasBacktickCtx = SqlmapTimeModel.BOUNDARIES.stream()
                .anyMatch(b -> b.prefix().contains("`") && b.suffix().contains("#"));
        t.check(hasBacktickCtx, "boundary 含反引号+# 注释形态（WAF 绕过）");
        t.check(SqlmapTimeModel.BOUNDARIES.stream().noneMatch(b -> b.suffix().contains("/**/")),
                "boundary 不含错误形态 /**/ 后缀（只能替代空格，不能当注释）");
        t.checkEq(5, new XzhScanConfig().maxTimeParamsPerRequest, "时间模块参数配额默认 5");
    }

    private Test39TimeBudget() {
    }
}
