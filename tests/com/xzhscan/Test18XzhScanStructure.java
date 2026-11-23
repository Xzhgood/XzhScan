package com.xzhscan;

import burp.api.montoya.MontoyaApi;
import com.xzhscan.config.XzhScanConfig;
import com.xzhscan.model.EvidenceStore;
import com.xzhscan.policy.ScanPolicyEngine;
import com.xzhscan.ui.XzhScanMainPanel;

import javax.swing.*;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;

import static com.xzhscan.MiniTest.TestContext;

/**
 * 测试十八：XzhScan 顶层结构（离线代理 API + EDT）。
 *  - 顶层 Tab "XzhScan" 三个子页：SQLScan / AuthScan / 关于（v2.2 DirScan 移除、v2.4.2 增关于）；
 *  - SQLScan 四页：漏洞结果/差分候选/数据版/设置（Payload/日志 UI 已移除，引擎保留）。
 */
public final class Test18XzhScanStructure {

    public static void run(TestContext t) throws Exception {
        MontoyaApi api = Test9ExtensionLoadSmoke.proxy(MontoyaApi.class, null);
        XzhScanConfig config = new XzhScanConfig();
        EvidenceStore store = new EvidenceStore();
        ScanPolicyEngine policy = new ScanPolicyEngine(config);

        AtomicReference<Throwable> err = new AtomicReference<>();
        CountDownLatch done = new CountDownLatch(1);
        final String[] titles = {null};
        final String[] sqlTitles = {null};
        SwingUtilities.invokeLater(() -> {
            try {
                XzhScanMainPanel mp = new XzhScanMainPanel(api, config, store, policy);
                JTabbedPane root = mp.build();
                StringBuilder sb = new StringBuilder();
                for (int i = 0; i < root.getTabCount(); i++) {
                    sb.append(root.getTitleAt(i)).append('|');
                }
                titles[0] = sb.toString();
                java.awt.Component sql = root.getComponentAt(0);
                if (sql instanceof JTabbedPane st) {
                    StringBuilder sb2 = new StringBuilder();
                    for (int i = 0; i < st.getTabCount(); i++) {
                        sb2.append(st.getTitleAt(i)).append('|');
                    }
                    sqlTitles[0] = sb2.toString();
                }
            } catch (Throwable e) {
                err.set(e);
            } finally {
                done.countDown();
            }
        });
        t.check(done.await(15, TimeUnit.SECONDS), "main panel built on EDT");
        t.check(err.get() == null, "no build error" + (err.get() == null ? "" : ": " + err.get()));
        t.checkEq("SQLScan|AuthScan|Dictionary|关于|", titles[0], "顶层四子页（v3.7 字典页更名 Dictionary）");
        t.checkEq("漏洞结果|差分候选|数据版|设置|", sqlTitles[0], "SQLScan 四页（v3.9.2 数据版）");
    }
}
