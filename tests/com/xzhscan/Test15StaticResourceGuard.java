package com.xzhscan;

import com.xzhscan.config.XzhScanConfig;
import com.xzhscan.engine.ScanOrchestrator;
import com.xzhscan.model.EvidenceStore;
import com.xzhscan.model.Models.TrafficRecord;
import com.xzhscan.policy.ScanPolicyEngine;

import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.TimeUnit;

import static com.xzhscan.MiniTest.TestContext;

/**
 * 测试十五：静态资源守卫（真实误报案例回归）。
 *
 * 案例：GET /assets/.../fontawesome-webfont.woff2?v=4.5.0'and(select 1)>0waitfor delay'0:0:2
 *  （原 payload 含内联注释写法，此处从简）—— v1.4 前 pathOf 未剥离 query，
 *    "v=4.5.0" 的点号劫持了扩展名提取，woff2 字体绕过后缀过滤被发时间探针。
 */
public final class Test15StaticResourceGuard {

    public static void run(TestContext t) throws Exception {
        XzhScanConfig config = new XzhScanConfig();
        config.requestIntervalMs = 0;
        ScanPolicyEngine policy = new ScanPolicyEngine(config);

        // 1. 误报案例 URL（含 payload 的 query）必须被拒
        String bugUrl = "http://127.0.0.1:8899/assets/font-awesome/4.5.0/fonts/fontawesome-webfont.woff2"
                + "?v=4.5.0'and(select/**/1)>0waitfor/**/delay'0:0:2";
        ScanPolicyEngine.Decision d1 = policy.check(Support.get(bugUrl));
        t.check(!d1.allowed && d1.reason.startsWith("static resource"),
                "woff2 with dotted query payload rejected: " + d1.reason);

        // 2. 常见静态资源带版本号 query 全部拒绝
        for (String u : List.of(
                "http://t.local/assets/fa/css/font-awesome.min.css?v=4.5.0",
                "http://t.local/static/app.js?_t=1.2.3",
                "http://t.local/img/logo.png?v=2.0'and/**/1=1",
                "http://t.local/fonts/x.woff?v=1",
                "http://t.local/fonts/x.woff2",
                "http://t.local/fonts/x.ttf?v=4.5.0'and(select/**/1)>0waitfor/**/delay'0:0:2",
                "http://t.local/map/app.js.map")) {
            ScanPolicyEngine.Decision d = policy.check(Support.get(u));
            t.check(!d.allowed && d.reason.startsWith("static resource"),
                    "static blocked: " + u.substring(u.lastIndexOf('/') + 1) + " -> " + d.reason);
        }

        // 3. 不误伤：带小数/带引号参数的动态 API 必须放行
        for (String u : List.of(
                "http://t.local/api/search?q=4.5.0",
                "http://t.local/api/item?price=1.5'&page=2",
                "http://t.local/api/file/download?id=1.2.3")) {
            ScanPolicyEngine.Decision d = policy.check(Support.get(u));
            t.check(d.allowed, "dynamic api allowed: " + u + " -> " + d.reason);
        }

        // 4. 端到端：orchestrator 收到静态资源 URL -> 零请求发出、状态 blocked-by-policy
        Support.FakeTransport transport = new Support.FakeTransport();
        transport.responder = (r, i) -> Support.text(200, "x");
        List<TrafficRecord> records = new CopyOnWriteArrayList<>();
        ScanOrchestrator orch = new ScanOrchestrator(config, transport, new EvidenceStore(), policy);
        orch.submit(Support.get(bugUrl), null, "PROXY", new ScanOrchestrator.HostCallback() {
            public void onTraffic(TrafficRecord r) {
                records.add(r);
            }

            public void onGateView(com.xzhscan.model.Models.GateProbeView v) {
            }

            public void onCandidate(com.xzhscan.model.Models.DifferentialCandidate c) {
            }

            public void onRejected(String id, com.xzhscan.model.Models.ParameterIdentity p, String pr, String rs, double s) {
            }

            public void onVerification(com.xzhscan.model.Models.VerificationResult r) {
            }

            public void onFinding(com.xzhscan.model.Models.DifferentialCandidate c,
                                  com.xzhscan.model.Models.VerificationResult vr,
                                  com.xzhscan.model.Models.InjectionFinding f) {
            }
        });
        long deadline = System.currentTimeMillis() + 3000;
        while (System.currentTimeMillis() < deadline && records.isEmpty()) {
            TimeUnit.MILLISECONDS.sleep(30);
        }
        t.check(!records.isEmpty() && "blocked-by-policy".equals(records.get(0).phase1Status),
                "end-to-end: static resource blocked before any probe");
        t.check(transport.sent.isEmpty(), "zero HTTP requests sent for static resource");
        orch.shutdown();
    }
}
