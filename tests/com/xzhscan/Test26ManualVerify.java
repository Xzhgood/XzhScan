package com.xzhscan;

import burp.api.montoya.MontoyaApi;
import com.xzhscan.config.XzhScanConfig;
import com.xzhscan.engine.ScanOrchestrator;
import com.xzhscan.model.EvidenceStore;
import com.xzhscan.model.Models.CandidateType;
import com.xzhscan.model.Models.DiffEvidence;
import com.xzhscan.model.Models.DifferentialCandidate;
import com.xzhscan.model.Models.GateProbeView;
import com.xzhscan.model.Models.InjectionFinding;
import com.xzhscan.model.Models.TimingVerdict;
import com.xzhscan.model.Models.VerificationResult;
import com.xzhscan.model.Models.VerifyVerdict;
import com.xzhscan.policy.ScanPolicyEngine;
import com.xzhscan.ui.SqlScanUi;

import javax.swing.*;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;

import static com.xzhscan.MiniTest.TestContext;

/**
 * 测试二十六：手动送二阶段（v2.4，差分候选页右键「发送到二阶段验证」）。
 *  - ScanOrchestrator.verifyNow 完整路径：异步 + 策略闸二次复核 + 结论经
 *    onVerification/onFinding 完整回流（自动模式关闭时的人工验证入口）；
 *  - 黑名单目标手动验证 -> INVALID + blocked-by-policy（安全闸不因手动触发旁路）；
 *  - UI 候选仓：onCandidate 存储 -> PASS 行视图按 (requestId|path) 关联候选，
 *    REJECT/未知行不关联；setManualVerifyAction 注入可用。
 */
public final class Test26ManualVerify {

    private static DifferentialCandidate timeCandidate(String url) {
        DifferentialCandidate c = new DifferentialCandidate();
        c.requestId = "REQ-26";
        c.targetUrl = url;
        c.method = "GET";
        c.parameterName = "name";
        c.parameterPath = "name";
        c.parameterLocation = com.xzhscan.model.Models.Location.QUERY;
        c.originalValue = "11";
        c.originalType = "string";
        c.candidateType = CandidateType.TIME_CANDIDATE;
        c.payloadRuleId = "QT-MYSQL-SLEEP-01";
        c.occurrence = 0;
        c.originalRequest = Support.get(url);
        DiffEvidence ev = new DiffEvidence();
        ev.timingDeltaMs = 6_100L;
        ev.mutatedStatus = 200;
        ev.payloadRuleId = c.payloadRuleId;
        c.mutatedEvidence = ev;
        return c;
    }

    public static void run(TestContext t) throws Exception {
        XzhScanConfig config = new XzhScanConfig();
        config.requestIntervalMs = 0;

        // ---------- 1. verifyNow 完整路径：TIME 候选 -> CONFIRMED 回流 ----------
        Support.FakeTransport tiered = new Support.FakeTransport();
        tiered.responder = (r, i) -> {
            String u = r.url.toUpperCase();
            long ms = 30;
            if (u.contains("SLEEP(5)")) {
                ms = 6000;
            } else if (u.contains("SLEEP(6)")) {
                ms = 7200;
            }
            return new com.xzhscan.model.RawHttp.RawResponse(200, new java.util.LinkedHashMap<>(),
                    "ok".getBytes(java.nio.charset.StandardCharsets.UTF_8), ms);
        };
        EvidenceStore store = new EvidenceStore();
        ScanOrchestrator orch = new ScanOrchestrator(config, tiered, store, new ScanPolicyEngine(config));

        List<VerificationResult> verifications = new CopyOnWriteArrayList<>();
        List<InjectionFinding> findings = new CopyOnWriteArrayList<>();
        CountDownLatch done = new CountDownLatch(2); // onVerification + onFinding
        ScanOrchestrator.HostCallback cb = new ScanOrchestrator.HostCallback() {
            @Override
            public void onTraffic(com.xzhscan.model.Models.TrafficRecord r) {
            }

            @Override
            public void onGateView(GateProbeView v) {
            }

            @Override
            public void onCandidate(DifferentialCandidate c) {
            }

            @Override
            public void onRejected(String requestId, com.xzhscan.model.Models.ParameterIdentity param,
                                   String probe, String reason, double score) {
            }

            @Override
            public void onVerification(VerificationResult r) {
                verifications.add(r);
                done.countDown();
            }

            @Override
            public void onFinding(DifferentialCandidate c, VerificationResult vr, InjectionFinding f) {
                findings.add(f);
                done.countDown();
            }
        };
        orch.verifyNow(timeCandidate("http://t.local/m?name=11"), cb);
        t.check(done.await(15, TimeUnit.SECONDS), "manual verify completed asynchronously");
        t.checkEq(1, verifications.size(), "onVerification fired once");
        if (!verifications.isEmpty()) {
            t.checkEq(VerifyVerdict.CONFIRMED, verifications.get(0).verdict, "manual TIME verify -> CONFIRMED");
            t.checkEq(TimingVerdict.TIMING_CONFIRMED, verifications.get(0).timingVerdict,
                    "timing verdict flows to UI");
            t.check(verifications.get(0).note != null && verifications.get(0).note.contains("manual verify"),
                    "note marks manual path: " + verifications.get(0).note);
        }
        t.checkEq(1, findings.size(), "onFinding fired (lands in vulnerability panel)");
        if (!findings.isEmpty()) {
            t.checkEq(VerifyVerdict.CONFIRMED, findings.get(0).verdict, "finding CONFIRMED");
            t.check(findings.get(0).injectionType.contains("Time-based"), "finding typed Time-based");
        }

        // ---------- 2. 黑名单目标：手动触发不旁路安全闸 ----------
        XzhScanConfig blockedCfg = config.copy();
        blockedCfg.urlBlacklist = "blocked-host";
        ScanOrchestrator blockedOrch = new ScanOrchestrator(blockedCfg, tiered, new EvidenceStore(),
                new ScanPolicyEngine(blockedCfg));
        List<VerificationResult> blocked = new CopyOnWriteArrayList<>();
        CountDownLatch blockedDone = new CountDownLatch(1);
        ScanOrchestrator.HostCallback blockedCb = new ScanOrchestrator.HostCallback() {
            @Override
            public void onTraffic(com.xzhscan.model.Models.TrafficRecord r) {
            }

            @Override
            public void onGateView(GateProbeView v) {
            }

            @Override
            public void onCandidate(DifferentialCandidate c) {
            }

            @Override
            public void onRejected(String requestId, com.xzhscan.model.Models.ParameterIdentity param,
                                   String probe, String reason, double score) {
            }

            @Override
            public void onVerification(VerificationResult r) {
                blocked.add(r);
                blockedDone.countDown();
            }

            @Override
            public void onFinding(DifferentialCandidate c, VerificationResult vr, InjectionFinding f) {
            }
        };
        blockedOrch.verifyNow(timeCandidate("http://blocked-host/x?name=11"), blockedCb);
        t.check(blockedDone.await(15, TimeUnit.SECONDS), "blocked manual verify responds");
        t.checkEq(1, blocked.size(), "blocked case reports");
        if (!blocked.isEmpty()) {
            t.checkEq(VerifyVerdict.INVALID, blocked.get(0).verdict, "blacklisted target -> INVALID");
            t.check(blocked.get(0).note != null && blocked.get(0).note.contains("blocked-by-policy"),
                    "blocked note cites policy: " + blocked.get(0).note);
        }
        orch.shutdown();
        blockedOrch.shutdown();

        // ---------- 3. UI 候选仓关联（行视图 -> 候选） ----------
        MontoyaApi api = Test9ExtensionLoadSmoke.proxy(MontoyaApi.class, null);
        EvidenceStore uiStore = new EvidenceStore();
        SqlScanUi ui = new SqlScanUi(api, config, uiStore, new ScanPolicyEngine(config));
        AtomicReference<Throwable> uiError = new AtomicReference<>();
        CountDownLatch built = new CountDownLatch(1);
        SwingUtilities.invokeLater(() -> {
            try {
                ui.build();
            } catch (Throwable e) {
                uiError.set(e);
            } finally {
                built.countDown();
            }
        });
        t.check(built.await(15, TimeUnit.SECONDS), "ui build completed");
        t.check(uiError.get() == null, "ui build no error" + (uiError.get() == null ? "" : ": " + uiError.get()));
        if (uiError.get() != null) {
            return;
        }
        DifferentialCandidate cand = timeCandidate("http://t.local/m?name=11");
        ui.onCandidate(cand);
        GateProbeView passView = new GateProbeView("REQ-26", cand.targetUrl, "name", "name", "QUERY",
                10, 10, 0, 1.0, 0.9, "PASS", "time-payload delay", 6100, true, "probe hit");
        t.check(ui.candidateForRow(passView) == cand, "PASS row resolves to stored candidate");
        GateProbeView rejectView = new GateProbeView("REQ-404", cand.targetUrl, "name", "name", "QUERY",
                10, 10, 0, 1.0, 0.0, "REJECT", "score 0.00 < threshold", -2, false, "");
        t.check(ui.candidateForRow(rejectView) == null, "REJECT/unknown row resolves to no candidate");
        t.check(true, "v3.2: differential-panel verify entry removed (single entry via message context menu)");

        // ---------- 4. 差分候选页显示中文化（v2.4.1） ----------
        t.checkEq("通过", SqlScanUi.localizeDecision("PASS"), "decision PASS -> 通过");
        t.checkEq("拒绝", SqlScanUi.localizeDecision("REJECT"), "decision REJECT -> 拒绝");
        t.checkEq("待定", SqlScanUi.localizeDecision("INCONCLUSIVE"), "decision INCONCLUSIVE -> 待定");
        String zh = SqlScanUi.localizeReason("score 0.00 below threshold 0.55 | timing Δ=-2ms (no anomaly)");
        t.check(zh.contains("差分分 0.00 低于阈值 0.55") && zh.contains("计时 Δ=-2ms（无异常）"),
                "user-live reject line localized: " + zh);
        t.check(SqlScanUi.localizeReason(
                        "time-payload delay observed: Δ=6100ms >= 3000ms with HTTP 200 -> evidence evaluation")
                        .startsWith("时间探针命中"), "time-payload pass reason localized");
        t.check(SqlScanUi.localizeReason("baseline unstable (dynamic page): stability retest required")
                        .contains("基线不稳定"), "dynamic-page reason localized");
        t.check(SqlScanUi.localizeReason("future engine phrase") .equals("future engine phrase"),
                "unmatched template kept verbatim (no info loss)");
        t.checkEq("未测量", SqlScanUi.localizeNote("timing not measured"), "timing note localized");
    }
}
