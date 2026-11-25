package com.xzhscan.ui;

import burp.api.montoya.MontoyaApi;
import com.xzhscan.config.XzhScanConfig;
import com.xzhscan.model.EvidenceStore;
import com.xzhscan.policy.ScanPolicyEngine;

import javax.swing.*;

/**
 * XzhScan 主面板：顶层 Tab "XzhScan"，内含平级功能页签。
 *
 *   XzhScan
 *   ├── SQLScan    （SqlScanUi：漏洞结果/差分候选/设置）
 *   ├── AuthScan   （越权检测：迁移自 gatherBurp Perm）
 *   ├── Dictionary （DictionaryUi：XSS/路径/信息生成/字典生成）
 *   └── 关于       （版本/开发者信息）
 *
 * 各模块结果/队列/启停状态完全隔离；主面板只做容器与主题适配。
 */
public final class XzhScanMainPanel {

    private final MontoyaApi api;
    private final XzhScanConfig config;
    private final EvidenceStore evidence;
    private final ScanPolicyEngine policy;
    private JTabbedPane root;
    private SqlScanUi sqlScanUi;

    public XzhScanMainPanel(MontoyaApi api, XzhScanConfig config, EvidenceStore evidence, ScanPolicyEngine policy) {
        this.api = api;
        this.config = config;
        this.evidence = evidence;
        this.policy = policy;
    }

    public JTabbedPane build() {
        root = new JTabbedPane();
        sqlScanUi = new SqlScanUi(api, config, evidence, policy);
        root.addTab("SQLScan", sqlScanUi.build());
        root.addTab("AuthScan", placeholder("AuthScan 模块初始化中…"));
        root.addTab("Dictionary", new DictionaryUi().build());
        root.addTab("关于", aboutPanel());
        applyTheme(root);
        return root;
    }

    /** 关于页（v2.4.2）：版本与开发者信息，只读。 */
    private static JComponent aboutPanel() {
        JTextArea text = new JTextArea(12, 40);
        text.setEditable(false);
        text.setText("""
                XzhScan v%s

                Burp Suite 扩展：SQL 注入两阶段检测（受控差分初筛 + 证据分型复核）与越权检测。

                GitHub：https://github.com/Xzhgood/XzhScan/

                开发者：Xzh
                QQ：1421946905

                问题反馈请附 github issues
                """.formatted(com.xzhscan.burp.XzhScanExtension.VERSION));
        JPanel p = new JPanel(new java.awt.BorderLayout());
        p.add(new JScrollPane(text), java.awt.BorderLayout.CENTER);
        return p;
    }

    /** 模块就绪后挂载/替换子页（EDT 上执行，重复注入安全）。 */
    public void attachModuleTab(String title, JComponent panel) {
        SwingUtilities.invokeLater(() -> {
            if (root == null) {
                return;
            }
            for (int i = 0; i < root.getTabCount(); i++) {
                if (title.equals(root.getTitleAt(i))) {
                    root.setComponentAt(i, panel);
                    root.revalidate();
                    root.repaint();
                    return;
                }
            }
            root.addTab(title, panel);
            root.revalidate();
            root.repaint();
        });
    }

    private static JComponent placeholder(String text) {
        JPanel p = new JPanel(new java.awt.GridBagLayout());
        p.add(new JLabel(text, JLabel.CENTER));
        return p;
    }

    private void applyTheme(java.awt.Component c) {
        try {
            api.userInterface().applyThemeToComponent(c);
        } catch (Throwable ignored) {
        }
    }

    public SqlScanUi sqlScanUi() {
        return sqlScanUi;
    }
}
