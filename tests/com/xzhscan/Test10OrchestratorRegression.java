package com.xzhscan;

import com.xzhscan.config.ConfigCodec;
import com.xzhscan.config.XzhScanConfig;
import com.xzhscan.engine.ScanOrchestrator;
import com.xzhscan.model.EvidenceStore;
import com.xzhscan.model.Models.TrafficRecord;
import com.xzhscan.model.RawHttp.RawRequest;
import com.xzhscan.policy.ScanPolicyEngine;

import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

import static com.xzhscan.MiniTest.TestContext;

/**
 * 测试十：调度器回归（阶段二修复项的守护测试）。
 *  - 请求级去重：同 (method+URL+参数集) 在窗口内只跑一次第一阶段；
 *    手动（Manual）提交绕过去重；
 *  - EvidenceStore 容量上限 FIFO 淘汰；
 *  - ConfigCodec 往返（含新增 dedupWindowMinutes）与旧配置文本解析；
 *  - dedupKeyOf 与参数值无关、与参数集有关。
 */
public final class Test10OrchestratorRegression {

    public static void run(TestContext t) throws Exception {
        // ---------- 1. dedupKeyOf ----------
        RawRequest a = Support.get("http://t.local/search?name=admin&page=1&sort=asc");
        RawRequest b = Support.get("http://t.local/search?name=other&page=2&sort=desc"); // 值不同
        RawRequest c = Support.get("http://t.local/search?name=admin&page=1");          // 参数集不同
        t.check(ScanOrchestrator.dedupKeyOf(a).equals(ScanOrchestrator.dedupKeyOf(b)),
                "dedup key ignores parameter values");
        t.check(!ScanOrchestrator.dedupKeyOf(a).equals(ScanOrchestrator.dedupKeyOf(c)),
                "dedup key differs by parameter set");

        // ---------- 2. EvidenceStore 上限 ----------
        EvidenceStore store = new EvidenceStore();
        for (int i = 0; i < EvidenceStore.MAX_ENTRIES + 10; i++) {
            store.put("kind", Support.get("http://t.local/x?i=" + i), Support.text(200, "b" + i));
        }
        t.check(store.size() == EvidenceStore.MAX_ENTRIES,
                "evidence store capped at " + EvidenceStore.MAX_ENTRIES + " (actual " + store.size() + ")");
        t.check(store.get("EV-1") == null, "oldest evidence evicted");
        t.check(store.get("EV-" + (EvidenceStore.MAX_ENTRIES + 10)) != null, "newest evidence kept");

        // ---------- 3. 请求级去重（异步执行，回调聚合等待） ----------
        XzhScanConfig config = new XzhScanConfig();
        config.requestIntervalMs = 0;
        config.baselineSamples = 2;
        config.dedupWindowMinutes = 60;
        config.maxConcurrentScans = 1;

        Support.FakeTransport transport = new Support.FakeTransport();
        AtomicInteger completedScans = new AtomicInteger();
        List<TrafficRecord> records = new CopyOnWriteArrayList<>();
        ScanOrchestrator orch = new ScanOrchestrator(config, transport, new EvidenceStore(),
                new ScanPolicyEngine(config));
        ScanOrchestrator.HostCallback cb = new ScanOrchestrator.HostCallback() {
            public void onTraffic(TrafficRecord r) {
                records.add(r);
                if ("done".equals(r.phase1Status) || "no-params".equals(r.phase1Status)) {
                    completedScans.incrementAndGet();
                }
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
        };

        int requestsBefore = transport.sent.size();
        orch.submit(a, null, "PROXY", cb);
        boolean first = await(completedScans, 1, 10_000);
        t.check(first, "first submit completes");
        int sentFirst = transport.sent.size();
        t.check(sentFirst > requestsBefore, "first submit actually scanned (sent=" + sentFirst + ")");

        // 同参数集（值不同）再次提交：应 deduplicated，不再发请求
        completedScans.set(0);
        orch.submit(b, null, "PROXY", cb);
        long deadline = System.currentTimeMillis() + 1500;
        while (System.currentTimeMillis() < deadline
                && records.stream().noneMatch(r -> "deduplicated".equals(r.phase1Status))) {
            TimeUnit.MILLISECONDS.sleep(30);
        }
        boolean dedupSeen = records.stream().anyMatch(r -> "deduplicated".equals(r.phase1Status));
        t.check(dedupSeen, "second submit marked deduplicated");
        t.check(transport.sent.size() == sentFirst,
                "no additional requests for deduplicated submit (" + transport.sent.size() + " vs " + sentFirst + ")");

        // Manual 提交绕过去重
        completedScans.set(0);
        orch.submit(b, null, "Manual", cb);
        boolean manual = await(completedScans, 1, 10_000);
        t.check(manual, "manual submit executes");
        t.check(transport.sent.size() > sentFirst, "manual submit bypasses dedup window");

        orch.shutdown();
        // 关停后 submit 不抛异常（回执 queue-full/error 由 cb 承接）
        int before = records.size();
        orch.submit(c, null, "PROXY", cb);
        t.check(true, "submit after shutdown does not throw (records " + before + "->" + records.size() + ")");

        // ---------- 3b. v3.8.6：暂停=完全离岗（不发包也不入库） ----------
        Support.FakeTransport pausedTransport = new Support.FakeTransport();
        XzhScanConfig pCfg = new XzhScanConfig();
        pCfg.requestIntervalMs = 0;
        ScanPolicyEngine pPolicy = new ScanPolicyEngine(pCfg);
        pPolicy.pause();
        ScanOrchestrator pausedOrch = new ScanOrchestrator(pCfg, pausedTransport, new EvidenceStore(), pPolicy);
        pausedOrch.submit(Support.get("http://t.local/paused?name=abc"), null, "PROXY", cb);
        t.checkEq(0, pausedTransport.sent.size(), "paused submit sends nothing (traffic not ingested)");
        pPolicy.resume();
        final AtomicInteger resumedDone = new AtomicInteger();
        ScanOrchestrator.HostCallback resumedCb = new ScanOrchestrator.HostCallback() {
            public void onTraffic(TrafficRecord r) {
            }

            public void onGateView(com.xzhscan.model.Models.GateProbeView v) {
            }

            public void onCandidate(com.xzhscan.model.Models.DifferentialCandidate c) {
            }

            public void onRejected(String id, com.xzhscan.model.Models.ParameterIdentity p,
                                   String pr, String rs, double s) {
            }

            public void onVerification(com.xzhscan.model.Models.VerificationResult r) {
            }

            public void onFinding(com.xzhscan.model.Models.DifferentialCandidate c,
                                  com.xzhscan.model.Models.VerificationResult r,
                                  com.xzhscan.model.Models.InjectionFinding f) {
                resumedDone.incrementAndGet();
            }
        };
        pausedOrch.submit(Support.get("http://t.local/resumed?name=abc"), null, "PROXY", resumedCb);
        // 异步 phase1：轮询等待基线请求发出（5s 上限）
        long resumeDeadline = System.currentTimeMillis() + 5000;
        while (pausedTransport.sent.isEmpty() && System.currentTimeMillis() < resumeDeadline) {
            TimeUnit.MILLISECONDS.sleep(30);
        }
        pausedOrch.shutdown();
        t.check(pausedTransport.sent.size() > 0,
                "resume processes traffic again (" + pausedTransport.sent.size() + " requests sent)");

        // ---------- 4. 配置往返 + 迁移 ----------
        XzhScanConfig out = new XzhScanConfig();
        out.dedupWindowMinutes = 120;
        out.minDifferenceScore = 0.62;
        out.domainWhitelist = "a.com,b.com";
        String props = ConfigCodec.toProperties(out);
        XzhScanConfig in = new XzhScanConfig();
        ConfigCodec.fromProperties(props, in);
        t.check(in.dedupWindowMinutes == 120, "dedupWindowMinutes round-trip");
        t.check(Math.abs(in.minDifferenceScore - 0.62) < 1e-9, "score round-trip");
        t.checkEq("a.com,b.com", in.domainWhitelist, "whitelist round-trip");
        // 旧格式记录（无 dedup 键）解析不炸、缺省保留
        String legacy = "phase1Enabled=false\nbaselineSamples=4\n";
        XzhScanConfig old = new XzhScanConfig();
        ConfigCodec.fromProperties(legacy, old);
        t.check(!old.phase1Enabled && old.baselineSamples == 4 && old.dedupWindowMinutes == new XzhScanConfig().dedupWindowMinutes,
                "legacy config parses, missing keys keep defaults");
    }

    private static boolean await(AtomicInteger counter, int target, long timeoutMs) throws InterruptedException {
        long deadline = System.currentTimeMillis() + timeoutMs;
        while (System.currentTimeMillis() < deadline) {
            if (counter.get() >= target) {
                return true;
            }
            TimeUnit.MILLISECONDS.sleep(30);
        }
        return counter.get() >= target;
    }
}
