package com.xzhscan;

import com.xzhscan.config.XzhScanConfig;
import com.xzhscan.engine.PassiveDetectionEngine;
import com.xzhscan.model.EvidenceStore;
import com.xzhscan.model.Models.DifferentialCandidate;
import com.xzhscan.model.Models.TrafficRecord;
import com.xzhscan.model.RawHttp.RawRequest;
import com.xzhscan.Support.FakeTransport;

import java.util.List;
import java.util.concurrent.ThreadLocalRandom;
import java.util.concurrent.atomic.AtomicInteger;

import static com.xzhscan.MiniTest.TestContext;

/**
 * 测试六：动态响应。
 * 页面每次返回随机 token / 时间戳 / 请求 ID，第一阶段不得因此产生 PASS 候选。
 */
public final class Test6DynamicResponse {

    static final AtomicInteger seq = new AtomicInteger();

    static String page(String token, long ts, String reqId, String mutatedMarker) {
        return "<html><body>"
                + "<input name=\"csrf\" value=\"" + token + "\">"
                + "<span>generated at " + ts + "</span>"
                + "<span>request-id: " + reqId + "</span>"
                + (mutatedMarker == null ? "" : "<p>" + mutatedMarker + "</p>")
                + "<div>search results: item1 item2 item3</div>"
                + "</body></html>";
    }

    public static void run(TestContext t) {
        XzhScanConfig config = new XzhScanConfig();
        config.requestIntervalMs = 0;
        config.baselineSamples = 3;
        config.maxStabilityRetests = 2;

        RawRequest original = Support.get("http://t.local/list?kw=hello&page=2");

        FakeTransport transport = new FakeTransport();
        // 每次响应都带新的随机 token/时间戳/请求 ID（内容本身完全同构）
        transport.responder = (r, idx) -> Support.text(200, page(
                java.util.UUID.randomUUID().toString(),
                System.currentTimeMillis(),
                "req-" + seq.incrementAndGet(),
                null));

        PassiveDetectionEngine engine = new PassiveDetectionEngine(config, transport, new EvidenceStore());
        TrafficRecord record = new TrafficRecord();
        record.requestId = "REQ-6";
        List<DifferentialCandidate> candidates = engine.process(original, null, record, null);

        t.check(candidates.isEmpty(),
                "dynamic page yields no PASS candidates (got " + candidates.size() + ")");
        for (DifferentialCandidate c : candidates) {
            System.out.println("  unexpected candidate: " + c.summary() + " reason=" + c.filterReason);
        }

        // 对比组：确定性页面 + 注入点真差分（name -> SQL 报错）应有候选
        FakeTransport deterministic = new FakeTransport();
        deterministic.responder = (r, idx) -> {
            if (r.url.contains("kw=hello%27") || r.url.contains("kw=hello'")) {
                return Support.text(200, "You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version for the right syntax to use near 'hello'' at line 1");
            }
            return Support.text(200, page("fixed-token", 1700000000000L, "req-fixed", null));
        };
        PassiveDetectionEngine engine2 = new PassiveDetectionEngine(config, deterministic, new EvidenceStore());
        TrafficRecord record2 = new TrafficRecord();
        record2.requestId = "REQ-6B";
        List<DifferentialCandidate> candidates2 = engine2.process(original, null, record2, null);
        t.check(!candidates2.isEmpty(), "control: deterministic page with db error yields candidate");
    }
}
