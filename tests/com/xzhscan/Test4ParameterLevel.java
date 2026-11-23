package com.xzhscan;

import com.xzhscan.config.XzhScanConfig;
import com.xzhscan.engine.SqlVerificationEngine;
import com.xzhscan.engine.PassiveDetectionEngine;
import com.xzhscan.model.EvidenceStore;
import com.xzhscan.model.Models.DifferentialCandidate;
import com.xzhscan.model.Models.ParameterIdentity;
import com.xzhscan.model.Models.TrafficRecord;
import com.xzhscan.model.RawHttp.RawRequest;
import com.xzhscan.model.RawHttp.RawResponse;
import com.xzhscan.Support.FakeTransport;

import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;

import static com.xzhscan.MiniTest.TestContext;

/**
 * 测试四：参数级验证。
 * GET /search?name=admin&page=1&sort=asc 三个参数中只有 name 产生可靠差分
 * （name 注入 -> MySQL 报错指纹），第二阶段只允许验证 name：
 * FakeTransport 记录的所有变异请求中 page 与 sort 必须保持原值。
 */
public final class Test4ParameterLevel {

    public static void run(TestContext t) {
        XzhScanConfig config = new XzhScanConfig();
        config.requestIntervalMs = 0;
        config.baselineSamples = 2;

        RawRequest original = Support.get("http://t.local/search?name=admin&page=1&sort=asc");

        FakeTransport transport = new FakeTransport();
        // 路由：name 含 ' -> SQL 报错；page/sort 变异 -> 与基线一致；基线 -> 正常
        transport.responder = (r, idx) -> {
            String url = r.url;
            boolean nameMutated = url.contains("name=admin'") || url.contains("name=admin%27")
                    || url.contains("name=") && url.contains("%27") || url.contains("name=admin''");
            if (url.contains("name=admin&") || url.endsWith("name=admin")) {
                return Support.json(200, "{\"rows\":[1,2,3],\"total\":3}");
            }
            if (nameMutated) {
                return Support.json(200,
                        "{\"error\":\"You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version for the right syntax to use near 'admin'' at line 1\"}");
            }
            // page/sort 变异：返回与基线相同内容
            return Support.json(200, "{\"rows\":[1,2,3],\"total\":3}");
        };

        EvidenceStore evidence = new EvidenceStore();
        PassiveDetectionEngine phase1 = new PassiveDetectionEngine(config, transport, evidence);
        TrafficRecord record = new TrafficRecord();
        record.requestId = "REQ-1";

        List<DifferentialCandidate> candidates = phase1.process(original, null, record, null);

        // 第一阶段应只有 name 过门
        boolean nameCandidate = candidates.stream().anyMatch(c -> c.parameterName.equals("name"));
        boolean pageCandidate = candidates.stream().anyMatch(c -> c.parameterName.equals("page"));
        boolean sortCandidate = candidates.stream().anyMatch(c -> c.parameterName.equals("sort"));
        t.check(nameCandidate, "name produced a PASS candidate");
        t.check(!pageCandidate, "page not passed (weak/no diff)");
        t.check(!sortCandidate, "sort not passed");

        if (candidates.isEmpty()) {
            return; // 后续无意义
        }
        DifferentialCandidate candidate = candidates.stream()
                .filter(c -> c.parameterName.equals("name")).findFirst().orElse(candidates.get(0));

        // ---- 第二阶段：只验证 name ----
        transport.sent.clear();
        SqlVerificationEngine phase2 = new SqlVerificationEngine(config, transport, evidence);
        var result = phase2.verify(candidate);
        t.check(result.state.name().equals("DONE"), "verification finished: " + result.state);

        // 核心：所有第二阶段变异请求中 page/sort 不得被改动
        AtomicInteger mutatedTotal = new AtomicInteger();
        for (RawRequest r : transport.sent) {
            mutatedTotal.incrementAndGet();
            boolean pageIntact = r.url.contains("page=1&") || r.url.contains("page=1");
            boolean sortIntact = r.url.contains("sort=asc");
            if (!pageIntact || !sortIntact) {
                t.check(false, "non-target parameter mutated: " + r.url);
            }
        }
        t.check(mutatedTotal.get() > 0, "phase2 actually sent probes (" + mutatedTotal.get() + ")");
        boolean allOtherIntact = transport.sent.stream()
                .allMatch(r -> r.url.contains("page=1") && r.url.contains("sort=asc"));
        t.check(allOtherIntact, "only 'name' parameter verified; page/sort untouched");
    }
}
