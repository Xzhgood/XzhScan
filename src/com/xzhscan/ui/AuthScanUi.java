package com.xzhscan.ui;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.ui.editor.EditorOptions;
import burp.api.montoya.ui.editor.HttpRequestEditor;
import burp.api.montoya.ui.editor.HttpResponseEditor;
import com.xzhscan.burp.BurpTransport;
import com.xzhscan.model.RawHttp.RawRequest;
import com.xzhscan.auth.AuthScanModule;
import com.xzhscan.auth.AuthScanRequestFilter.FilterRecord;
import com.xzhscan.auth.AuthScanEngine.IdentityConfig;
import com.xzhscan.auth.AuthScanEngine.PermResult;

import javax.swing.*;
import javax.swing.table.AbstractTableModel;
import java.awt.*;
import java.awt.datatransfer.StringSelection;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CopyOnWriteArrayList;

/**
 * AuthScan 子页（原 PermAccess，v2.1 更名）：越权结果（+原生 HTTP 编辑器四视图）/ 设置。
 * 请求过滤不再独立占页：后台过滤全量保留（含下载型/静态/方法判定），
 * 统计与开关移入设置页，逐条原因走 Burp Output [filter] 日志。
 * 模型更新一律 EDT；结果行点击同步加载证据，缺失显空状态。
 */
public final class AuthScanUi {

    private final MontoyaApi api;
    private final AuthScanModule module;
    private final List<PermResult> results = new CopyOnWriteArrayList<>();

    private ResultTableModel resultModel;
    private JLabel filterStatsLabel;
    private HttpRequestEditor origReqEditor;
    private HttpRequestEditor lowReqEditor;
    private HttpRequestEditor noAuthReqEditor;
    private HttpResponseEditor origRespEditor;
    private HttpResponseEditor lowRespEditor;
    private HttpResponseEditor noAuthRespEditor;
    private JTextArea lowAuthArea;
    private JTextArea noAuthArea;
    private JTextArea domainArea;
    private JTextField extraExtField;
    private JCheckBox enableBox;
    private JCheckBox filterEnableBox;

    public AuthScanUi(MontoyaApi api, AuthScanModule module) {
        this.api = api;
        this.module = module;
    }

    public JComponent build() {
        module.setCallback(new AuthScanModule.Callback() {
            public void onFilterRecord(FilterRecord r) {
                // 过滤诊断：计数进设置页（后台保留完整记录与原因，见模块日志）
                SwingUtilities.invokeLater(() -> refreshFilterStats());
                try {
                    api.logging().logToOutput("[XzhScan][AuthScan][filter] " + r.decision + " "
                            + r.method + " " + r.url + " -> " + r.filterReason);
                } catch (Throwable ignored) {
                }
            }

            public void onResult(PermResult r) {
                SwingUtilities.invokeLater(() -> addResult(r));
            }
        });
        JTabbedPane tabs = new JTabbedPane();
        tabs.addTab("越权结果", buildResults());
        tabs.addTab("设置", buildSettings());
        try {
            api.userInterface().applyThemeToComponent(tabs);
        } catch (Throwable ignored) {
        }
        return tabs;
    }

    // ================= 检测结果 =================

    public class ResultTableModel extends AbstractTableModel {
        private final String[] cols = {"URL", "Method", "结论", "状态码(原/低/无)", "体长(原/低/无)", "证据摘要", "时间"};

        @Override
        public int getRowCount() {
            return results.size();
        }

        @Override
        public int getColumnCount() {
            return cols.length;
        }

        @Override
        public String getColumnName(int c) {
            return cols[c];
        }

        @Override
        public Object getValueAt(int r, int c) {
            PermResult p = results.get(r);
            return switch (c) {
                case 0 -> p.url;
                case 1 -> p.method;
                case 2 -> p.verdict == null ? "-" : p.verdict.label;
                case 3 -> code(p.originalResponse) + "/" + code(p.lowResponse) + "/" + code(p.noAuthResponse);
                case 4 -> len(p.originalResponse) + "/" + len(p.lowResponse) + "/" + len(p.noAuthResponse);
                case 5 -> p.evidenceSummary == null ? "" : p.evidenceSummary;
                case 6 -> new java.text.SimpleDateFormat("HH:mm:ss").format(new java.util.Date());
                default -> "";
            };
        }

        private String code(com.xzhscan.model.RawHttp.RawResponse r) {
            return r == null ? "-" : String.valueOf(r.statusCode);
        }

        private String len(com.xzhscan.model.RawHttp.RawResponse r) {
            return r == null ? "-" : String.valueOf(r.body.length);
        }
    }

    private JComponent buildResults() {
        resultModel = new ResultTableModel();
        JTable table = new JTable(resultModel);
        table.setAutoCreateRowSorter(true);
        origReqEditor = safeReqEditor();
        lowReqEditor = safeReqEditor();
        noAuthReqEditor = safeReqEditor();
        origRespEditor = safeRespEditor();
        lowRespEditor = safeRespEditor();
        noAuthRespEditor = safeRespEditor();
        // v3.9.3：六附签 -> 三个身份数据版（原始/低权限/未授权），每页左右分栏（左=请求 右=响应）
        JTabbedPane editors = new JTabbedPane();
        editors.addTab("原始数据版", evidenceSplit(origReqEditor, origRespEditor,
                "（无原始请求证据）", "（无原始响应证据）"));
        editors.addTab("低权限数据版", evidenceSplit(lowReqEditor, lowRespEditor,
                "（无低权限对照请求）", "（无低权限对照响应）"));
        // v3.4.5：无鉴权重放（删除指定鉴权头后的请求）——对照判定看的就是这一组
        editors.addTab("未授权数据版", evidenceSplit(noAuthReqEditor, noAuthRespEditor,
                "（无无鉴权重放请求）", "（无无鉴权重放响应）"));
        table.getSelectionModel().addListSelectionListener(e -> {
            if (!e.getValueIsAdjusting() && table.getSelectedRow() >= 0) {
                loadResult(results.get(table.convertRowIndexToModel(table.getSelectedRow())));
            }
        });
        JPopupMenu menu = new JPopupMenu();
        JMenuItem rep = new JMenuItem("Send to Repeater（对照请求）");
        rep.addActionListener(e -> {
            int row = table.getSelectedRow();
            if (row < 0) {
                return;
            }
            PermResult p = results.get(table.convertRowIndexToModel(row));
            RawRequest target = p.lowRequest != null ? p.lowRequest : p.originalRequest;
            if (target != null) {
                api.repeater().sendToRepeater(BurpTransport.build(BurpTransport.serviceOf(target.url), target),
                        "XzhScan-Auth-" + p.verdict);
            }
        });
        JMenuItem curl = new JMenuItem("Copy URL");
        curl.addActionListener(e -> copySelected(table, p -> p.url));
        JMenuItem csum = new JMenuItem("复制结果摘要");
        csum.addActionListener(e -> copySelected(table, p -> p.verdict + " " + p.url + " " + p.evidenceSummary));
        menu.add(rep);
        menu.add(curl);
        menu.add(csum);
        table.setComponentPopupMenu(menu);

        // v3.4.4：越权结果页清空列表（结果 + 四个对照编辑器一起清）
        JButton clearResults = new JButton("清空");
        clearResults.setToolTipText("清空越权结果列表与证据视图（不影响过滤统计与统计计数）");
        clearResults.addActionListener(e -> {
            results.clear();
            resultModel.fireTableDataChanged();
            loadReq(origReqEditor, null);
            loadResp(origRespEditor, null);
            loadReq(lowReqEditor, null);
            loadResp(lowRespEditor, null);
            loadReq(noAuthReqEditor, null);
            loadResp(noAuthRespEditor, null);
        });
        JPanel top = new JPanel(new java.awt.FlowLayout(java.awt.FlowLayout.LEFT));
        top.add(clearResults);

        JSplitPane split = new JSplitPane(JSplitPane.VERTICAL_SPLIT, new JScrollPane(table), editors);
        split.setResizeWeight(0.5);
        split.setDividerLocation(0.45);
        JPanel p = new JPanel(new java.awt.BorderLayout());
        p.add(top, java.awt.BorderLayout.NORTH);
        p.add(split, java.awt.BorderLayout.CENTER);
        return p;
    }

    /** 身份数据版页签：左右分栏（左=该身份的请求，右=该身份的响应），比例可拖。 */
    private JComponent evidenceSplit(Object reqEditor, Object respEditor, String reqHint, String respHint) {
        javax.swing.JSplitPane sp = new javax.swing.JSplitPane(
                javax.swing.JSplitPane.HORIZONTAL_SPLIT,
                editorOrPlaceholder(reqEditor, reqHint), editorOrPlaceholder(respEditor, respHint));
        sp.setResizeWeight(0.5);
        sp.setDividerLocation(0.5);
        return sp;
    }

    private void loadResult(PermResult p) {
        loadReq(origReqEditor, p.originalRequest);
        loadResp(origRespEditor, p.originalResponse);
        loadReq(lowReqEditor, p.lowRequest);
        loadResp(lowRespEditor, p.lowResponse);
        loadReq(noAuthReqEditor, p.noAuthRequest);   // v3.4.5：删除鉴权头后的对照请求
        loadResp(noAuthRespEditor, p.noAuthResponse);
    }

    // ================= 设置 =================

    private JComponent buildSettings() {
        JPanel p = new JPanel(new GridBagLayout());
        GridBagConstraints g = new GridBagConstraints();
        g.insets = new Insets(3, 6, 3, 6);
        g.anchor = GridBagConstraints.WEST;
        g.fill = GridBagConstraints.HORIZONTAL;
        int row = 0;

        enableBox = new JCheckBox("启用 AuthScan 越权检测（监听流量自动复核）", module.isEnabled());
        // v3.9.3：用户勾选即持久化（扩展注册回调）
        enableBox.addActionListener(e -> module.setEnabledByUser(enableBox.isSelected()));
        addRow(p, g, row++, enableBox);

        filterEnableBox = new JCheckBox("静态资源过滤总开关（js/ico/图片/字体/音视频/压缩包/下载文件等）",
                module.filter().config().enabled);
        filterEnableBox.addActionListener(e -> {
            var c = module.filter().config();
            c.enabled = filterEnableBox.isSelected();
        });
        addRow(p, g, row++, filterEnableBox);

        lowAuthArea = new JTextArea(5, 40);
        lowAuthArea.setToolTipText("每行一条完整头，如 Cookie: session=low_user（同名替换，缺则追加）");
        noAuthArea = new JTextArea(3, 40);
        noAuthArea.setToolTipText("每行一个头名，如 Cookie / Authorization（重放时删除）");
        domainArea = new JTextArea(3, 40);
        domainArea.setToolTipText("每行一个域名，支持 * 通配（从右往左段匹配）；空=全部允许");
        extraExtField = new JTextField(24);
        extraExtField.setToolTipText("逗号分隔小写扩展名，追加到内置静态清单");

        // v3.4.5：设置页必须以模块当前身份为初值（此前为空 → 重启后点「应用」会把
        // 已持久化的低权限/移除头清空）。模块 identity 是唯一事实源，更新即实时生效。
        IdentityConfig current = module.identity();
        lowAuthArea.setText(String.join("\n", current.lowAuthHeaders));
        noAuthArea.setText(String.join("\n", current.noAuthHeaderNames));
        domainArea.setText(String.join("\n", current.whitelistDomains));
        extraExtField.setText(module.filter().config().extraExtensions == null
                ? "" : module.filter().config().extraExtensions);

        g.gridwidth = 2;
        g.gridx = 0;
        g.gridy = row++;
        p.add(new JLabel("低权限认证头（每行 \"Name: value\"）："), g);
        g.gridy = row++;
        p.add(new JScrollPane(lowAuthArea), g);
        g.gridy = row++;
        p.add(new JLabel("待移除的鉴权头名（无权限态）："), g);
        g.gridy = row++;
        p.add(new JScrollPane(noAuthArea), g);
        g.gridy = row++;
        p.add(new JLabel("授权域名白名单（支持 *，空=全部）："), g);
        g.gridy = row++;
        p.add(new JScrollPane(domainArea), g);
        // v3.4.3 修复：此行必须占用独立 gridy 并自增，否则标签/输入框与下方
        // 过滤统计行落在同一网格单元 → 文字互相覆盖（用户截图乱码）。
        g.gridwidth = 1;
        g.gridy = row++;
        p.add(new JLabel("追加静态扩展名："), g);
        g.gridx = 1;
        g.fill = GridBagConstraints.HORIZONTAL;
        p.add(extraExtField, g);
        g.gridx = 0;
        g.gridwidth = 2;

        filterStatsLabel = new JLabel("过滤统计：ALLOW 0 / REJECT 0 / UNKNOWN 0");
        g.gridy = row++;
        p.add(filterStatsLabel, g);

        JButton apply = new JButton("应用身份与过滤配置");
        apply.addActionListener(e -> {
            IdentityConfig cfg = new IdentityConfig();
            cfg.lowAuthHeaders = lines(lowAuthArea.getText());
            cfg.noAuthHeaderNames = lines(noAuthArea.getText());
            cfg.whitelistDomains = lines(domainArea.getText());
            module.updateIdentity(cfg);
            module.filter().config().extraExtensions = extraExtField.getText().trim();
            refreshFilterStats();
            String extra = module.filter().config().extraExtensions == null
                    || module.filter().config().extraExtensions.isBlank()
                    ? "无" : module.filter().config().extraExtensions;
            api.logging().logToOutput("[XzhScan][AuthScan] identity updated (low=" + cfg.lowAuthHeaders.size()
                    + " headers, remove=" + cfg.noAuthHeaderNames.size() + ", domains=" + cfg.whitelistDomains.size()
                    + ", extraExt=" + extra + ")");
            // v3.4.6：应用成功提示弹窗（含生效摘要；配置为热更新，下一条流量立即使用）
            try {
                JOptionPane.showMessageDialog(p,
                        "越权检测配置已应用（实时生效）\n\n"
                                + "低权限认证头：" + cfg.lowAuthHeaders.size() + " 条\n"
                                + "待移除的鉴权头：" + cfg.noAuthHeaderNames.size() + " 个"
                                + (cfg.noAuthHeaderNames.isEmpty() ? "" : "（" + String.join(", ", cfg.noAuthHeaderNames) + "）") + "\n"
                                + "授权域名白名单：" + (cfg.whitelistDomains.isEmpty() ? "空（全部允许）"
                                : cfg.whitelistDomains.size() + " 个") + "\n"
                                + "追加静态扩展名：" + extra + "\n\n"
                                + (cfg.lowAuthHeaders.isEmpty() || cfg.noAuthHeaderNames.isEmpty()
                                ? "注意：低权限头与待移除头需同时配置才会执行自动复核。"
                                : "下一条通过过滤的流量将按新配置执行三态重放。"),
                        "XzhScan AuthScan", JOptionPane.INFORMATION_MESSAGE);
            } catch (Throwable ignored) {
                // 无图形环境（测试/headless）时仅保留日志，不影响配置生效
            }
        });
        g.gridy = row++;
        p.add(apply, g);
        g.gridy = row;
        p.add(new JLabel("提示：低权限与待移除头均配置后才执行自动复核；POST/下载型默认仅记录不自动复核。"), g);
        return new JScrollPane(p);
    }

    // ================= 辅助 =================

    private void addResult(PermResult r) {
        results.add(0, r);
        if (results.size() > 2000) {
            results.remove(results.size() - 1);
        }
        resultModel.fireTableDataChanged();
    }

    private static List<String> lines(String text) {
        List<String> out = new ArrayList<>();
        if (text == null) {
            return out;
        }
        for (String l : text.split("\n")) {
            if (!l.isBlank()) {
                out.add(l.trim());
            }
        }
        return out;
    }

    private void copySelected(JTable table, java.util.function.Function<PermResult, String> f) {
        int row = table.getSelectedRow();
        if (row >= 0) {
            copy(f.apply(results.get(table.convertRowIndexToModel(row))));
        }
    }

    private void copy(String s) {
        Toolkit.getDefaultToolkit().getSystemClipboard().setContents(new StringSelection(s == null ? "" : s), null);
    }

    private HttpRequestEditor safeReqEditor() {
        try {
            return api.userInterface().createHttpRequestEditor(EditorOptions.READ_ONLY);
        } catch (Throwable t) {
            return null;
        }
    }

    private HttpResponseEditor safeRespEditor() {
        try {
            return api.userInterface().createHttpResponseEditor(EditorOptions.READ_ONLY);
        } catch (Throwable t) {
            return null;
        }
    }

    private JComponent editorOrPlaceholder(Object editor, String emptyText) {
        Component c = null;
        if (editor instanceof HttpRequestEditor e && e.uiComponent() != null) {
            c = e.uiComponent();
        } else if (editor instanceof HttpResponseEditor e && e.uiComponent() != null) {
            c = e.uiComponent();
        }
        if (c != null) {
            return new JScrollPane(c);
        }
        JPanel ph = new JPanel(new GridBagLayout());
        ph.add(new JLabel(emptyText, JLabel.CENTER));
        return ph;
    }

    private void loadReq(HttpRequestEditor editor, RawRequest r) {
        if (editor == null) {
            return;
        }
        if (r == null) {
            editor.setRequest(null);
            return;
        }
        try {
            editor.setRequest(BurpTransport.build(BurpTransport.serviceOf(r.url), r));
        } catch (Throwable t) {
            editor.setRequest(null);
        }
    }

    private void loadResp(HttpResponseEditor editor, com.xzhscan.model.RawHttp.RawResponse r) {
        if (editor == null) {
            return;
        }
        if (r == null) {
            editor.setResponse(null);
            return;
        }
        try {
            editor.setResponse(HttpResponse.httpResponse(rawRespText(r)));
        } catch (Throwable t) {
            editor.setResponse(null);
        }
    }

    static String rawRespText(com.xzhscan.model.RawHttp.RawResponse r) {
        StringBuilder sb = new StringBuilder(256 + r.body.length);
        sb.append("HTTP/1.1 ").append(r.statusCode).append("\r\n");
        r.headers.forEach((k, v) -> sb.append(k).append(": ").append(v).append("\r\n"));
        sb.append("\r\n").append(r.bodyAsString());
        return sb.toString();
    }

    private void refreshFilterStats() {
        if (filterStatsLabel != null) {
            long[] c = module.filterCounters();
            filterStatsLabel.setText("过滤统计：ALLOW " + c[0] + " / REJECT " + c[1] + " / UNKNOWN " + c[2]
                    + "（REJECT 原因见 Burp Output [filter] 行）");
        }
    }

    private void addRow(JPanel p, GridBagConstraints g, int row, JComponent c) {
        g.gridwidth = 2;
        g.gridx = 0;
        g.gridy = row;
        p.add(c, g);
    }
}
