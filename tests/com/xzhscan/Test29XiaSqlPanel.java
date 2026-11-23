package com.xzhscan;

import com.xzhscan.config.XzhScanConfig;
import com.xzhscan.engine.PassiveDetectionEngine;
import com.xzhscan.model.EvidenceStore;
import com.xzhscan.model.Models.GateProbeView;
import com.xzhscan.model.Models.TrafficRecord;
import com.xzhscan.ui.SqlScanUi;

import javax.swing.*;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;

import static com.xzhscan.MiniTest.TestContext;

/**
 * 测试二十九：差分页 XiaSQL 主从表形态（v3.3）。
 *  - 引擎上报**全部探针**的原始观察行（不再只报 best），行上携带
 *    payload/返回包长度/状态码/用时/变异证据 id/基线证据 id；
 *  - 每条判定行（PASS/REJECT）携带命中 payload 与证据；
 *  - UI 主表按请求归组（一次请求一行，含基线长度/状态）；
 *  - 从表默认显示全部观察，主表选中后过滤到该请求；
 *  - 未开启时间探针时（v3.0 默认）每参数仅引号 2 条观察。
 */
public final class Test29XiaSqlPanel {

    public static void run(TestContext t) throws Exception {
        XzhScanConfig config = new XzhScanConfig();
        config.requestIntervalMs = 0;
        config.baselineSamples = 2; // v3.5：被动=纯差分（时间探针子系统已移除，无开关）

        Support.FakeTransport transport = new Support.FakeTransport();
        transport.responder = (r, i) -> r.url.contains("name=admin%27") || r.url.contains("name=admin'")
                ? Support.text(200, "{\"error\":\"You have an error in your SQL syntax; check the manual "
                + "that corresponds to your MySQL server version\"}")
                : Support.text(200, "{\"rows\":[1,2,3]}");

        List<GateProbeView> views = new CopyOnWriteArrayList<>();
        PassiveDetectionEngine engine = new PassiveDetectionEngine(config, transport, new EvidenceStore());
        TrafficRecord rec = new TrafficRecord();
        rec.requestId = "REQ-29";
        engine.process(Support.get("http://t.local/s?name=admin&page=1"), null, rec,
                new PassiveDetectionEngine.Callback() {
                    public void onTrafficUpdate(TrafficRecord r) {
                    }

                    public void onCandidate(com.xzhscan.model.Models.DifferentialCandidate c) {
                    }

                    public void onRejected(String id, com.xzhscan.model.Models.ParameterIdentity p,
                                           String probe, String reason, double score) {
                    }

                    public void onGateView(GateProbeView view) {
                        views.add(view);
                    }
                });

        // ---------- 1. 全部探针都上报（best 探针以"判定行"呈现，不重复；其余探针为"观察行"） ----------
        // name: 首探针命中 DB 错误 -> 早退，1 条判定行（best 观察行被判定行替代）
        // page=1 数字值：' / '' / -1 / -0 / ,0 / ,1 = 6 条探针 -> 5 观察行 + 1 判定行
        int observations = (int) views.stream().filter(v -> "观察".equals(v.decision)).count();
        int verdicts = (int) views.stream().filter(v -> "PASS".equals(v.decision)
                || "REJECT".equals(v.decision)).count();
        t.checkEq(5, observations, "non-best probes reported as observation rows (no filtering)");
        t.checkEq(2, verdicts, "one gate verdict row per parameter (best attempt, not duplicated)");
        t.checkEq(7, views.size(), "all probe attempts visible overall: " + views.size());

        // v3.8.6 三色档位：待定黄 > 拒绝绿 > 变化红 > 默认（优先级从高到低）
        GateProbeView pending = new GateProbeView("R", "u", "p", "p", "QUERY", 100, 101, 1,
                1.0, 0.0, "INCONCLUSIVE", "weak length delta (1 bytes) only", 10, false, null);
        GateProbeView rejected = new GateProbeView("R", "u", "p", "p", "QUERY", 100, 100, 0,
                1.0, 0.0, "REJECT", "score 0.00 below threshold", 10, false, null);
        GateProbeView changed = new GateProbeView("R", "u", "p", "p", "QUERY", 100, 90, -10,
                0.5, 0.7, "PASS", "db-error", 10, false, null);
        GateProbeView plain = new GateProbeView("R", "u", "p", "p", "QUERY", 100, 100, 0,
                1.0, 0.0, "观察", "无明显变化", 10, false, null);
        t.checkEq(SqlScanUi.TIER_PENDING, SqlScanUi.highlightTier(pending), "pending row = yellow tier");
        t.checkEq(SqlScanUi.TIER_REJECTED, SqlScanUi.highlightTier(rejected), "rejected row = green tier");
        t.checkEq(SqlScanUi.TIER_CHANGED, SqlScanUi.highlightTier(changed), "changed row = red tier");
        t.checkEq(SqlScanUi.TIER_DEFAULT, SqlScanUi.highlightTier(plain), "observation row = default");

        // v3.4：数字值参数 6 条探针集 ' / '' / -1 / -0 / ,0 / ,1
        boolean sentMinus1 = transport.sent.stream().anyMatch(r -> r.url.contains("page=1-1"));
        boolean sentMinus0 = transport.sent.stream().anyMatch(r -> r.url.contains("page=1-0"));
        boolean sentComma0 = transport.sent.stream().anyMatch(r -> r.url.contains("page=1,0"));
        boolean sentComma1 = transport.sent.stream().anyMatch(r -> r.url.contains("page=1,1"));
        t.check(sentMinus1, "numeric value gets -1 probe (value-1)");
        t.check(sentMinus0, "numeric value gets -0 control probe (value-0)");
        t.check(sentComma0, "numeric value gets ,0 probe (LIMIT offset control)");
        t.check(sentComma1, "numeric value gets ,1 probe (LIMIT offset difference)");
        boolean stringParamNoMinus = transport.sent.stream()
                .anyMatch(r -> r.url.contains("name=admin-1") || r.url.contains("name=admin,1"));
        t.check(!stringParamNoMinus, "non-numeric value gets no numeric probes");
        for (GateProbeView v : views) {
            t.check(v.payload != null || "REJECT".equals(v.decision),
                    "observation rows carry rendered payload: " + v.parameterPath);
            if ("观察".equals(v.decision)) {
                t.check(v.mutatedEvidenceId != null, "observation row carries mutated evidence id");
                t.check(v.baselineEvidenceId != null, "observation row carries baseline evidence id");
                t.check(v.status > 0, "observation row carries response status: " + v.status);
                t.check(v.elapsedMs >= 0, "observation row carries elapsed ms: " + v.elapsedMs);
            }
        }
        // 判定行（报错指纹命中 -> PASS）带 payload 与证据
        GateProbeView pass = views.stream().filter(v -> "PASS".equals(v.decision)).findFirst().orElse(null);
        t.check(pass != null, "error fingerprint promotes parameter (PASS verdict row)");
        if (pass != null) {
            t.check(pass.payload != null && !pass.payload.isEmpty(),
                    "verdict row carries hit payload text: " + pass.payload);
            t.check(pass.mutatedEvidenceId != null, "verdict row carries mutated evidence id");
            t.check(pass.status > 0 && pass.elapsedMs >= 0, "verdict row carries status/elapsed");
        }

        // ---------- 2. UI 主表归组 + 从表过滤 ----------
        burp.api.montoya.MontoyaApi api = Test9ExtensionLoadSmoke.proxy(burp.api.montoya.MontoyaApi.class, null);
        SqlScanUi ui = new SqlScanUi(api, config, new EvidenceStore(),
                new com.xzhscan.policy.ScanPolicyEngine(config));
        AtomicReference<Throwable> err = new AtomicReference<>();
        CountDownLatch built = new CountDownLatch(1);
        SwingUtilities.invokeLater(() -> {
            try {
                ui.build();
            } catch (Throwable e) {
                err.set(e);
            } finally {
                built.countDown();
            }
        });
        t.check(built.await(15, TimeUnit.SECONDS), "ui build completed");
        t.check(err.get() == null, "ui build no error" + (err.get() == null ? "" : ": " + err.get()));
        if (err.get() != null) {
            return;
        }
        CountDownLatch fed = new CountDownLatch(1);
        SwingUtilities.invokeLater(() -> {
            for (GateProbeView v : views) {
                ui.onGateView(v);
            }
            fed.countDown();
        });
        t.check(fed.await(10, TimeUnit.SECONDS), "views fed to UI");
        SwingUtilities.invokeAndWait(() -> {
        });
        t.checkEq(1, ui.gateRequestModel.data.size(), "main table groups by request (1 row)");
        if (!ui.gateRequestModel.data.isEmpty()) {
            SqlScanUi.RequestRow row = ui.gateRequestModel.data.get(0);
            t.checkEq("REQ-29", row.requestId, "main row request id");
            t.check(row.baselineLen > 0, "main row baseline length: " + row.baselineLen);
            t.check(row.baselineEvidenceId != null, "main row carries baseline evidence id");
        }
        t.checkEq(views.size(), ui.gateModel.data.size(), "detail table shows all observations (no request selected)");

        // v3.8.4 高亮：响应有变化（lenDelta≠0）的从表行 + 对应主表 URL 行亮红
        boolean changedInData = ui.gateModel.data.stream().anyMatch(SqlScanUi::isChangedProbe);
        t.check(changedInData == views.stream().anyMatch(v -> v.lenDelta != 0),
                "changed-probe detection matches data (lenDelta≠0)");
        t.check(ui.requestHasChange("REQ-29") == changedInData,
                "requestHasChange mirrors detail rows");
        t.check(!ui.requestHasChange("REQ-NO-SUCH"), "unknown request never highlighted");
        t.checkEq(255, SqlScanUi.CHANGED_RED.getRed(), "highlight red is bright (R=255)");
        t.check(SqlScanUi.CHANGED_RED.getGreen() < 120 && SqlScanUi.CHANGED_RED.getBlue() < 120,
                "highlight red is eye-catching (G/B low)");

        // v3.8.7 主表 URL 档位：红 > 黄 > 绿（红最优先，即使其他参数是绿）
        // 注意：待定行若本身带长度变化（弱差分）按"有变化"计→红；此处用 lenDelta=0 的
        // 待定行（规则 C 基线不稳场景）验证黄色档位。
        GateProbeView mixPending = new GateProbeView("REQ-MIX", "u", "p1", "p1", "QUERY", 100, 100, 0,
                1.0, 0.0, "INCONCLUSIVE", "baseline unstable", 10, false, null);
        GateProbeView mixRejected = new GateProbeView("REQ-MIX", "u", "p2", "p2", "QUERY", 100, 100, 0,
                1.0, 0.0, "REJECT", "below threshold", 10, false, null);
        SwingUtilities.invokeAndWait(() -> {
            ui.onGateView(mixPending);
            ui.onGateView(mixRejected);
        });
        t.checkEq(SqlScanUi.TIER_PENDING, ui.requestHighlightTier("REQ-MIX"),
                "pending + rejected (no change) -> url yellow");
        GateProbeView mixChanged = new GateProbeView("REQ-MIX", "u", "p3", "p3", "QUERY", 100, 90, -10,
                0.5, 0.7, "PASS", "db-error", 10, false, null);
        SwingUtilities.invokeAndWait(() -> ui.onGateView(mixChanged));
        t.checkEq(SqlScanUi.TIER_CHANGED, ui.requestHighlightTier("REQ-MIX"),
                "changed row wins -> url red even with yellow/green rows present");
        t.check(ui.requestHasChange("REQ-MIX"), "requestHasChange true when any changed row");

        // 主表选中 -> 从表过滤到该请求；再点其他请求 -> 清空该请求观察
        SwingUtilities.invokeAndWait(() -> {
            ui.gateModel.data.clear();
            ui.gateModel.fireTableDataChanged();
        });
        t.checkEq(0, ui.gateModel.data.size(), "detail cleared (sanity)");
        SwingUtilities.invokeAndWait(() -> ui.onGateView(views.get(0)));
        SwingUtilities.invokeAndWait(() -> {
        }); // 冲刷 onGateView 内部 edtl 的异步任务
        t.checkEq(1, ui.gateModel.data.size(), "new observation still arrives after clear");

        // ---------- 3. 静态资源不进列表（v3.4） ----------
        com.xzhscan.model.Models.TrafficRecord staticRec = new com.xzhscan.model.Models.TrafficRecord();
        staticRec.requestId = "REQ-STATIC";
        staticRec.url = "http://t.local/assets/js/ace.min.js";
        staticRec.phase1Status = "blocked-by-policy";
        com.xzhscan.model.Models.TrafficRecord cssRec = new com.xzhscan.model.Models.TrafficRecord();
        cssRec.requestId = "REQ-CSS";
        cssRec.url = "http://t.local/assets/css/bootstrap.min.css";
        cssRec.phase1Status = "blocked-by-policy";
        com.xzhscan.model.Models.TrafficRecord htmlRec = new com.xzhscan.model.Models.TrafficRecord();
        htmlRec.requestId = "REQ-HTML";
        htmlRec.url = "http://t.local/vul/sqli/sqli_id.php";
        htmlRec.phase1Status = "done";
        // v3.4.2：去重记录与无参数请求同样不进列表
        com.xzhscan.model.Models.TrafficRecord dupRec = new com.xzhscan.model.Models.TrafficRecord();
        dupRec.requestId = "REQ-DUP";
        dupRec.url = "http://t.local/check?id=11";
        dupRec.phase1Status = "deduplicated";
        com.xzhscan.model.Models.TrafficRecord noParamRec = new com.xzhscan.model.Models.TrafficRecord();
        noParamRec.requestId = "REQ-NOPARAM";
        noParamRec.url = "http://t.local/22366/";
        noParamRec.phase1Status = "no-params";
        com.xzhscan.model.Models.TrafficRecord noMutableRec = new com.xzhscan.model.Models.TrafficRecord();
        noMutableRec.requestId = "REQ-NOMUT";
        noMutableRec.url = "http://t.local/api/status";
        noMutableRec.phase1Status = "no-mutable-params";
        int before = ui.gateRequestModel.data.size();
        SwingUtilities.invokeAndWait(() -> {
            ui.onTraffic(staticRec, "PROXY");
            ui.onTraffic(cssRec, "PROXY");
            ui.onTraffic(htmlRec, "PROXY");
            ui.onTraffic(dupRec, "PROXY");
            ui.onTraffic(noParamRec, "PROXY");
            ui.onTraffic(noMutableRec, "PROXY");
        });
        SwingUtilities.invokeAndWait(() -> {
        }); // 冲刷 edtl 异步任务
        t.check(ui.gateRequestModel.find("REQ-STATIC") == null, "JS asset row excluded from differential list");
        t.check(ui.gateRequestModel.find("REQ-CSS") == null, "CSS asset row excluded from differential list");
        t.check(ui.gateRequestModel.find("REQ-DUP") == null, "deduplicated row excluded from differential list");
        t.check(ui.gateRequestModel.find("REQ-NOPARAM") == null, "no-params row excluded from differential list");
        t.check(ui.gateRequestModel.find("REQ-NOMUT") == null, "no-mutable-params row excluded from differential list");
        t.check(ui.gateRequestModel.find("REQ-HTML") != null, "dynamic endpoint row still listed");
        t.checkEq(before + 1, ui.gateRequestModel.data.size(), "only actionable request appended");
    }
}
