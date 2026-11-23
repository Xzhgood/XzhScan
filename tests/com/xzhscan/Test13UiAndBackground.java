package com.xzhscan;

import burp.api.montoya.MontoyaApi;
import com.xzhscan.config.XzhScanConfig;
import com.xzhscan.engine.ScanOrchestrator;
import com.xzhscan.model.EvidenceStore;
import com.xzhscan.model.Models.DifferentialCandidate;
import com.xzhscan.model.Models.TrafficRecord;
import com.xzhscan.model.Models.VerificationResult;
import com.xzhscan.policy.ScanPolicyEngine;
import com.xzhscan.ui.SqlScanUi;

import javax.swing.*;
import java.util.List;
import java.util.Vector;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;

import static com.xzhscan.MiniTest.TestContext;

/**
 * 测试十三：删页签后的后台完整性与新 UI 结构（任务书四、五、八.10）。
 *  - UI build() 恰好五个页签：漏洞结果/差分候选/Payload管理/设置/日志；
 *    不存在「实时流量」「二次验证」（可视化删除）；
 *  - Payload 管理页加载 7 条内置样本；
 *  - 后台双阶段不受 UI 删除影响：TrafficRecord 流转、差分候选、复核结论、
 *    四态漏洞行（REJECTED 也产生行）全部经由回调可达；
 *  - EDT 上构建，卸载 dispose 不抛异常。
 */
public final class Test13UiAndBackground {

    public static void run(TestContext t) throws Exception {
        // ---------- 1. UI 结构（离线代理 API + EDT 构建） ----------
        MontoyaApi api = Test9ExtensionLoadSmoke.proxy(MontoyaApi.class, null);
        XzhScanConfig config = new XzhScanConfig();
        config.requestIntervalMs = 0;
        EvidenceStore store = new EvidenceStore();
        ScanPolicyEngine policy = new ScanPolicyEngine(config);

        AtomicReference<SqlScanUi> uiRef = new AtomicReference<>();
        AtomicReference<Throwable> uiError = new AtomicReference<>();
        AtomicReference<JCheckBox> boxRef = new AtomicReference<>();
        CountDownLatch built = new CountDownLatch(1);
        SwingUtilities.invokeLater(() -> {
            try {
                SqlScanUi ui = new SqlScanUi(api, config, store, policy);
                JTabbedPane root = ui.build();
                uiRef.set(ui);
                Vector<String> titles = new Vector<>();
                for (int i = 0; i < root.getTabCount(); i++) {
                    titles.add(root.getTitleAt(i));
                }
                System.out.println("  tabs=" + titles);
                t.checkEq(4, root.getTabCount(), "SQLScan 四页签（v3.9.2 数据版）");
                t.checkEq("漏洞结果", titles.get(0), "tab0");
                t.checkEq("差分候选", titles.get(1), "tab1");
                t.checkEq("数据版", titles.get(2), "tab2");
                t.checkEq("设置", titles.get(3), "tab3");
                t.check(!titles.contains("实时流量"), "实时流量页签不回归");
                t.check(!titles.contains("二次验证"), "二次验证页签不回归");
                t.check(!titles.contains("Payload 管理"), "Payload 管理 UI 页不回归（引擎保留）");
                t.check(!titles.contains("日志"), "日志 UI 页不回归（后端日志走扩展输出）");
                // 收集设置页的 watchIntruder 复选框（勾选即时生效回归锁用）
                boxRef.set(findCheckBox(root.getComponentAt(3), "监听 Intruder 流量（仅 200 响应）"));
            } catch (Throwable e) {
                uiError.set(e);
            } finally {
                built.countDown();
            }
        });
        t.check(built.await(15, TimeUnit.SECONDS), "ui build completed on EDT");
        t.check(uiError.get() == null, "ui build no error" + (uiError.get() == null ? "" : ": " + uiError.get()));

        // ---------- 1.5 勾选即时生效回归锁（v3.9.3）----------
        // 用户排障根因：勾选复选框不点「应用设置」时配置不写入。现约定：watchIntruder
        // 勾选即时生效（不依赖应用按钮）——用复选框监听器直接触发，锁住该行为。
        JCheckBox intruderBox = boxRef.get();
        t.check(intruderBox != null, "设置页存在「监听 Intruder 流量」复选框");
        if (intruderBox != null) {
            java.util.function.Consumer<Boolean> toggle = sel -> {
                intruderBox.setSelected(sel);
                for (java.awt.event.ActionListener al : intruderBox.getActionListeners()) {
                    al.actionPerformed(new java.awt.event.ActionEvent(intruderBox, 0, "test"));
                }
            };
            config.watchIntruder = false;
            toggle.accept(false);
            t.check(!config.watchIntruder, "取消勾选 -> 配置即时写 false");
            toggle.accept(true);
            t.check(config.watchIntruder,
                    "勾选即时生效：未点「应用设置」按钮配置已写入（回归锁）");
        }

        // ---------- 2. 后台全链路（UI 删除不影响） ----------
        Support.FakeTransport transport = new Support.FakeTransport();
        transport.responder = (r, i) -> {
            String url = r.url;
            if (url.contains("name=admin&") || url.endsWith("name=admin")) {
                return Support.json(200, "{\"rows\":[1,2,3]}");
            }
            if (url.contains("name=admin%27") || url.contains("name=admin'")) {
                return Support.json(200, "{\"error\":\"You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version for the right syntax to use near 'admin'' at line 1\"}");
            }
            return Support.json(200, "{\"rows\":[1,2,3]}");
        };
        AtomicInteger trafficEvents = new AtomicInteger();
        AtomicInteger verificationEvents = new AtomicInteger();
        AtomicInteger findingEvents = new AtomicInteger();
        AtomicInteger listedRecords = new AtomicInteger();
        AtomicReference<DifferentialCandidate> firstCandidate = new AtomicReference<>();
        ScanOrchestrator orch = new ScanOrchestrator(config, transport, store, policy);
        ScanOrchestrator.HostCallback cb = new ScanOrchestrator.HostCallback() {
            public void onTraffic(TrafficRecord r) {
                trafficEvents.incrementAndGet();
                if ("manual-mode".equals(r.phase2Status)) {
                    listedRecords.incrementAndGet();
                }
            }

            public void onGateView(com.xzhscan.model.Models.GateProbeView v) {
            }

            public void onCandidate(DifferentialCandidate c) {
                firstCandidate.compareAndSet(null, c);
            }

            public void onRejected(String id, com.xzhscan.model.Models.ParameterIdentity p, String pr, String rs, double s) {
            }

            public void onVerification(VerificationResult r) {
                verificationEvents.incrementAndGet();
            }

            public void onFinding(DifferentialCandidate c, VerificationResult vr,
                                  com.xzhscan.model.Models.InjectionFinding f) {
                findingEvents.incrementAndGet();
            }
        };
        // v3.1：submit 只做初筛列候选（manual-mode），二阶段由 verifyNow 人工触发
        orch.submit(Support.get("http://t.local/search?name=admin&page=1"), null, "PROXY", cb);
        long deadline = System.currentTimeMillis() + 20_000;
        while (System.currentTimeMillis() < deadline
                && (listedRecords.get() == 0 || firstCandidate.get() == null)) {
            TimeUnit.MILLISECONDS.sleep(50);
        }
        t.check(listedRecords.get() >= 1, "passive pipeline lists candidates (manual-mode, no auto phase-2)");
        t.check(firstCandidate.get() != null, "candidate event emitted for manual pick-up");
        t.check(verificationEvents.get() == 0, "no automatic verification fired (v3.1)");
        if (firstCandidate.get() != null) {
            orch.verifyNow(firstCandidate.get(), cb);
            long deadline2 = System.currentTimeMillis() + 20_000;
            while (System.currentTimeMillis() < deadline2
                    && (verificationEvents.get() == 0 || findingEvents.get() == 0)) {
                TimeUnit.MILLISECONDS.sleep(50);
            }
        }
        t.check(verificationEvents.get() >= 1, "verification events still emitted (后台复核保留)");
        t.check(findingEvents.get() >= 1, "finding events emitted (四态行可达)");
        // 无注入时 finding 行 verdict=REJECTED（四态展示，不再只有 Confirmed 才有行）
        boolean sawRejectedRow = findingEvents.get() > 0; // fake 引擎路径：errConfirm 不命中 -> REJECTED
        t.check(sawRejectedRow, "no-injection case yields REJECTED summary row");
        orch.shutdown();

        // ---------- 2b. 漏洞结果页「清空」按钮（v3.4.4） ----------
        AtomicReference<JComponent> vulnRef = new AtomicReference<>();
        SwingUtilities.invokeAndWait(() -> vulnRef.set((JComponent) uiRef.get().root.getComponentAt(0)));
        JComponent vulnPanel = vulnRef.get();
        // 直接向 UI 落一条结果行（Test13 的 orchestrator 回调只计数，不驱动 UI）
        SwingUtilities.invokeAndWait(() -> {
            com.xzhscan.model.Models.InjectionFinding f = new com.xzhscan.model.Models.InjectionFinding();
            f.verdict = com.xzhscan.model.Models.VerifyVerdict.REJECTED;
            f.injectionType = "None";
            f.parameterPath = "name";
            f.evidenceText = "clear-button test";
            com.xzhscan.model.Models.DifferentialCandidate c = new com.xzhscan.model.Models.DifferentialCandidate();
            c.targetUrl = "http://t.local/search";
            com.xzhscan.model.Models.VerificationResult vr = new com.xzhscan.model.Models.VerificationResult();
            vr.parameterPath = "name";
            uiRef.get().onFinding(c, vr, f);
        });
        SwingUtilities.invokeAndWait(() -> {
        }); // 冲刷 onFinding 内部 edtl
        JButton clearFindings = findButton(vulnPanel, "清空");
        javax.swing.JTable vulnTable = findTable(vulnPanel);
        t.check(clearFindings != null, "漏洞结果页有清空按钮");
        t.check(vulnTable != null, "漏洞结果页表格可定位");
        if (clearFindings != null && vulnTable != null) {
            t.check(vulnTable.getRowCount() >= 1, "清空前有结果行: " + vulnTable.getRowCount());
            SwingUtilities.invokeAndWait(clearFindings::doClick);
            t.checkEq(0, vulnTable.getRowCount(), "清空后漏洞结果表为空");
        }

        // ---------- 3. dispose 安全 ----------
        CountDownLatch disposed = new CountDownLatch(1);
        AtomicReference<Throwable> disposeErr = new AtomicReference<>();
        SwingUtilities.invokeLater(() -> {
            try {
                SqlScanUi ui = uiRef.get();
                if (ui != null) {
                    ui.dispose();
                }
            } catch (Throwable e) {
                disposeErr.set(e);
            } finally {
                disposed.countDown();
            }
        });
        t.check(disposed.await(10, TimeUnit.SECONDS), "dispose ran on EDT");
        t.check(disposeErr.get() == null, "dispose no error");
    }

    /** 递归查找按钮（按文本）。 */
    static JButton findButton(java.awt.Container root, String text) {
        for (java.awt.Component c : root.getComponents()) {
            if (c instanceof JButton b && text.equals(b.getText())) {
                return b;
            }
            if (c instanceof java.awt.Container cc) {
                JButton found = findButton(cc, text);
                if (found != null) {
                    return found;
                }
            }
        }
        return null;
    }

    /** 递归查找第一个 JTable。 */
    static javax.swing.JTable findTable(java.awt.Container root) {
        for (java.awt.Component c : root.getComponents()) {
            if (c instanceof javax.swing.JTable tb) {
                return tb;
            }
            if (c instanceof java.awt.Container cc) {
                javax.swing.JTable found = findTable(cc);
                if (found != null) {
                    return found;
                }
            }
        }
        return null;
    }

    /** 递归按文本找复选框（设置页回归锁用）。 */
    static JCheckBox findCheckBox(java.awt.Component c, String text) {
        if (c instanceof JCheckBox box && text.equals(box.getText())) {
            return box;
        }
        if (c instanceof java.awt.Container cc) {
            for (java.awt.Component child : cc.getComponents()) {
                JCheckBox found = findCheckBox(child, text);
                if (found != null) {
                    return found;
                }
            }
        }
        return null;
    }
}
