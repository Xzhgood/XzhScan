package com.xzhscan.ui;

import com.xzhscan.burp.BurpTransport;
import com.xzhscan.config.ConfigCodec;
import com.xzhscan.config.XzhScanConfig;
import com.xzhscan.engine.ScanOrchestrator;
import com.xzhscan.model.EvidenceStore;
import com.xzhscan.model.Models.DifferentialCandidate;
import com.xzhscan.model.Models.GateProbeView;
import com.xzhscan.model.Models.InjectionFinding;
import com.xzhscan.model.Models.TrafficRecord;
import com.xzhscan.model.Models.VerificationResult;
import com.xzhscan.model.Models.VerifyVerdict;
import com.xzhscan.payload.PayloadLibrary;
import com.xzhscan.policy.ScanPolicyEngine;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.ui.editor.EditorOptions;
import burp.api.montoya.ui.editor.HttpRequestEditor;
import burp.api.montoya.ui.editor.HttpResponseEditor;
import com.xzhscan.model.EvidenceBundles;

import javax.swing.*;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;
import javax.swing.table.AbstractTableModel;
import javax.swing.table.TableRowSorter;
import java.awt.*;
import java.awt.datatransfer.StringSelection;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.regex.Pattern;

/**
 * XzhScan 独立 UI：一个 Tab 五个面板（实时流量 / 差分候选 / 二次验证 / 漏洞结果 / 设置）。
 * 全部 Swing；事件回调统一 post 到 EDT。
 */
public final class SqlScanUi {

    /** v3.8.4/v3.8.6 差分候选高亮：待定=黄 > 拒绝=绿 > 变化=红 > 默认（优先级从高到低）。 */
    public static final java.awt.Color CHANGED_RED = new java.awt.Color(255, 77, 77);
    public static final java.awt.Color CHANGED_RED_SELECTED = new java.awt.Color(204, 0, 0);
    public static final java.awt.Color PENDING_YELLOW = new java.awt.Color(255, 204, 0);
    public static final java.awt.Color PENDING_YELLOW_SELECTED = new java.awt.Color(204, 153, 0);
    public static final java.awt.Color REJECTED_GREEN = new java.awt.Color(0, 170, 85);
    public static final java.awt.Color REJECTED_GREEN_SELECTED = new java.awt.Color(0, 120, 60);

    /** 高亮档位（数值大者优先）：0=默认 1=变化红 2=拒绝绿 3=待定黄。 */
    public static final int TIER_DEFAULT = 0;
    public static final int TIER_CHANGED = 1;
    public static final int TIER_REJECTED = 2;
    public static final int TIER_PENDING = 3;

    /** 变化行判定：响应长度与基线不一致即视为"响应有变化"（从表参数行）。 */
    public static boolean isChangedProbe(com.xzhscan.model.Models.GateProbeView view) {
        return view != null && view.lenDelta != 0;
    }

    /** 待定行判定：差分门规则 B（弱差分）/规则 C（动态页）改判待定，需人工复核。 */
    public static boolean isPendingProbe(com.xzhscan.model.Models.GateProbeView view) {
        return view != null && ("INCONCLUSIVE".equals(view.decision) || "待定".equals(view.decision));
    }

    /** 拒绝行判定：差分门规则 A/阈值不足等（v3.8.6 起拒绝行整行标绿）。 */
    public static boolean isRejectedProbe(com.xzhscan.model.Models.GateProbeView view) {
        return view != null && ("REJECT".equals(view.decision) || "拒绝".equals(view.decision));
    }

    /** 单行高亮档位：待定 > 拒绝 > 变化 > 默认。 */
    public static int highlightTier(com.xzhscan.model.Models.GateProbeView view) {
        if (isPendingProbe(view)) {
            return TIER_PENDING;
        }
        if (isRejectedProbe(view)) {
            return TIER_REJECTED;
        }
        if (isChangedProbe(view)) {
            return TIER_CHANGED;
        }
        return TIER_DEFAULT;
    }

    /**
     * 主表 URL 行档位（v3.8.7 用户口径）：**红 > 黄 > 绿**。
     * 该请求任意观察行有响应变化（lenDelta≠0）→ 红（即使其他参数是绿）；
     * 无红但有待定 → 黄；否则有拒绝 → 绿；全默认 → 默认。
     * 注意与从表单行档位 {@link #highlightTier}（黄>绿>红）不同：
     * 主表红色最优先，因为"响应真的变了"是最需要立刻关注的信号。
     */
    public int requestHighlightTier(String requestId) {
        List<GateProbeView> rows = gateRowsByRequest.get(requestId);
        if (rows == null || rows.isEmpty()) {
            return TIER_DEFAULT;
        }
        if (rows.stream().anyMatch(SqlScanUi::isChangedProbe)) {
            return TIER_CHANGED;
        }
        if (rows.stream().anyMatch(SqlScanUi::isPendingProbe)) {
            return TIER_PENDING;
        }
        if (rows.stream().anyMatch(SqlScanUi::isRejectedProbe)) {
            return TIER_REJECTED;
        }
        return TIER_DEFAULT;
    }

    /** 兼容旧调用：该请求是否有响应变化行（v3.8.7 档位重排后不再用数值比较）。 */
    public boolean requestHasChange(String requestId) {
        List<GateProbeView> rows = gateRowsByRequest.get(requestId);
        return rows != null && rows.stream().anyMatch(SqlScanUi::isChangedProbe);
    }

    private final MontoyaApi api;
    private final XzhScanConfig config;
    private final EvidenceStore evidence;
    private final ScanPolicyEngine policy;
    private final List<Runnable> applyConfigListeners = new ArrayList<>();
    private JLabel pauseStateLabel;
    private JButton pauseBtn;

    public JTabbedPane root;
    /** 差分页主表（请求级，XiaSQL 流量表）。 */
    public GateRequestModel gateRequestModel;
    /** 差分页从表（payload 观察级）。 */
    public GateTableModel gateModel;
    public FindingTableModel findingModel;
    /** 数据版（v3.9.2）：红/黄参数聚合 + 一键送二阶段。 */
    public DataBoardModel dataBoardModel;
    // Burp 原生 HTTP 编辑器（任务书六）
    private HttpRequestEditor origReqEditor;
    private HttpRequestEditor probeReqEditor;
    private HttpResponseEditor origRespEditor;
    private HttpResponseEditor probeRespEditor;
    // 差分候选页证据查看编辑器（v2.4：候选行 -> 原始/变异请求响应，独立于漏洞页防串数据）
    // v3.9.3 差分页改版：四附签 -> 左右分栏（左=请求 右=响应，随选中行切换 原始/变异）
    private HttpRequestEditor gateReqEditor;
    private HttpResponseEditor gateRespEditor;
    // v3.2：差分页右键「发送到二阶段验证」已删除——与 Burp 消息右键
    // 「XzhScan SQL 验证」工作流重复。验证唯一入口=消息右键（全部/指定/手填参数）；
    // 差分页回归侦察职责（看行/看证据/发 Repeater 定位）。
    /**
     * PASS 候选对象仓（右键验证/查看证据按 行视图 -> 候选 关联；上限防内存）。
     * onCandidate 来自扫描线程：并发安全 + 超限淘汰。
     */
    private final java.util.concurrent.ConcurrentHashMap<String, DifferentialCandidate> candidateStore =
            new java.util.concurrent.ConcurrentHashMap<>();

    private void storeCandidate(DifferentialCandidate c) {
        candidateStore.put(c.requestId + "|" + c.parameterPath, c);
        if (candidateStore.size() > 4000) {
            // 超限淘汰最旧一半（迭代序即插入序近似；候选对象几 KB 级，4000 条仍在 MB 级）
            int toRemove = 2000;
            for (String k : candidateStore.keySet()) {
                if (toRemove-- <= 0) {
                    break;
                }
                candidateStore.remove(k);
            }
        }
    }
    private boolean closed;

    // v3.9.2 数据版：一键送二阶段所需引擎引用（EDT 装配段注入；未注入时按钮禁用）
    private ScanOrchestrator orchestrator;
    private ScanOrchestrator.HostCallback hostCb;

    /** 装配注入（XzhScanExtension EDT 任务调用一次）。 */
    public void setScanEngine(ScanOrchestrator o, ScanOrchestrator.HostCallback cb) {
        this.orchestrator = o;
        this.hostCb = cb;
    }

    public SqlScanUi(MontoyaApi api, XzhScanConfig config, EvidenceStore evidence, ScanPolicyEngine policy) {
        this.api = api;
        this.config = config;
        this.evidence = evidence;
        this.policy = policy;
    }

    public JTabbedPane build() {
        root = new JTabbedPane();
        root.addTab("漏洞结果", new VulnerabilityPanel().build());
        root.addTab("差分候选", new DifferentialPanel().build());
        root.addTab("数据版", new DataBoardPanel().build());
        root.addTab("设置", new SettingsPanel().build());
        applyTheme(root);
        return root;
    }

    /** 跟随 Burp 深浅主题（旧版 Burp 无此 API 时退化为默认外观）。 */
    private void applyTheme(Component c) {
        try {
            api.userInterface().applyThemeToComponent(c);
        } catch (Throwable ignored) {
        }
    }

    private void edtl(Runnable r) {
        Runnable action = () -> {
            if (!closed) {
                r.run();
            }
        };
        if (SwingUtilities.isEventDispatchThread()) {
            action.run();
        } else {
            SwingUtilities.invokeLater(action);
        }
    }

    public void dispose() {
        closed = true;
        applyConfigListeners.clear();
        // 卸载可能与 UI 构建并发（Burp 在非 EDT 线程触发 unload）：模型可能尚未创建
        if (root != null) {
            root.removeAll();
        }
        if (gateModel != null) {
            gateModel.data.clear();
        }
        if (findingModel != null) {
            findingModel.data.clear();
        }
        if (dataBoardModel != null) {
            dataBoardModel.clearAll();
        }
        dataBoardAgg.clear();
    }

    private JTable createTable(AbstractTableModel model) {
        JTable table = new JTable(model) {
            @Override
            public String getToolTipText(java.awt.event.MouseEvent event) {
                int row = rowAtPoint(event.getPoint());
                int column = columnAtPoint(event.getPoint());
                if (row < 0 || column < 0) {
                    return null;
                }
                Object value = getValueAt(row, column);
                return value == null ? null : value.toString();
            }
        };
        table.setAutoCreateRowSorter(true);
        table.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        table.setFillsViewportHeight(true);
        table.setRowHeight(Math.max(table.getRowHeight(), table.getFontMetrics(table.getFont()).getHeight() + 6));
        JPopupMenu menu = new JPopupMenu();
        JMenuItem copy = new JMenuItem("复制所选单元格");
        copy.addActionListener(e -> {
            int row = table.getSelectedRow();
            int col = table.getSelectedColumn();
            if (row >= 0 && col >= 0) {
                Object value = table.getValueAt(row, col);
                if (value != null) {
                    Toolkit.getDefaultToolkit().getSystemClipboard().setContents(new StringSelection(value.toString()), null);
                }
            }
        });
        menu.add(copy);
        table.setComponentPopupMenu(menu);
        table.addMouseListener(new java.awt.event.MouseAdapter() {
            @Override
            public void mousePressed(java.awt.event.MouseEvent event) {
                selectForPopup(event);
            }

            @Override
            public void mouseReleased(java.awt.event.MouseEvent event) {
                selectForPopup(event);
            }

            private void selectForPopup(java.awt.event.MouseEvent event) {
                if (event.isPopupTrigger()) {
                    int row = table.rowAtPoint(event.getPoint());
                    int column = table.columnAtPoint(event.getPoint());
                    if (row >= 0 && column >= 0) {
                        table.changeSelection(row, column, false, false);
                    } else {
                        table.clearSelection();
                    }
                }
            }
        });
        return table;
    }

    private JPanel tableToolbar(JTable table, int... searchColumns) {
        JPanel toolbar = new JPanel(new FlowLayout(FlowLayout.LEFT));
        JTextField search = new JTextField(24);
        JLabel label = new JLabel("搜索");
        label.setLabelFor(search);
        toolbar.add(label);
        toolbar.add(search);
        TableRowSorter<?> sorter = (TableRowSorter<?>) table.getRowSorter();
        Timer filterDelay = new Timer(180, e -> {
            String value = search.getText().strip();
            sorter.setRowFilter(value.isEmpty() ? null
                    : RowFilter.regexFilter("(?iu)" + Pattern.quote(value), searchColumns));
        });
        filterDelay.setRepeats(false);
        search.getDocument().addDocumentListener(new DocumentListener() {
            public void insertUpdate(DocumentEvent e) { filterDelay.restart(); }
            public void removeUpdate(DocumentEvent e) { filterDelay.restart(); }
            public void changedUpdate(DocumentEvent e) { filterDelay.restart(); }
        });
        search.addHierarchyListener(e -> {
            long flags = e.getChangeFlags();
            if ((flags & java.awt.event.HierarchyEvent.DISPLAYABILITY_CHANGED) != 0 && !search.isDisplayable()) {
                filterDelay.stop();
            }
        });
        return toolbar;
    }

    // ================= 1. 差分候选（v3.3 XiaSQL 主从表形态） =================

    /**
     * 主表：一次请求一行（对应 XiaSQL 流量表：#/来源/URL/返回包长度/状态）。
     * 选中某行 -> 下方从表只显示该请求的 payload 观察记录（XiaSQL changeSelection 语义）。
     */
    public static final class RequestRow {
        public final String requestId;
        public String source = "";
        public String url = "";
        public int baselineLen = -1;
        public String status = "-";
        /** 原始请求/响应证据 id（主表选中时查看）。 */
        public String baselineEvidenceId;

        RequestRow(String requestId, String url) {
            this.requestId = requestId;
            this.url = url;
        }
    }

    public class GateRequestModel extends AbstractTableModel {
        private final String[] cols = {"#", "来源", "URL", "返回包长度", "状态"};
        public final List<RequestRow> data = new ArrayList<>();

        @Override
        public int getRowCount() {
            return data.size();
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
            RequestRow row = data.get(r);
            return switch (c) {
                case 0 -> r + 1;
                case 1 -> row.source;
                case 2 -> row.url;
                case 3 -> row.baselineLen < 0 ? "-" : row.baselineLen;
                case 4 -> row.status;
                default -> "";
            };
        }

        public RequestRow find(String requestId) {
            for (RequestRow r : data) {
                if (r.requestId.equals(requestId)) {
                    return r;
                }
            }
            return null;
        }

        void upsert(String requestId, String url) {
            if (find(requestId) != null) {
                return;
            }
            data.add(new RequestRow(requestId, url));
            fireTableRowsInserted(data.size() - 1, data.size() - 1);
        }

        void touch(String requestId) {
            int idx = -1;
            for (int i = 0; i < data.size(); i++) {
                if (data.get(i).requestId.equals(requestId)) {
                    idx = i;
                    break;
                }
            }
            if (idx >= 0) {
                fireTableRowsUpdated(idx, idx);
            }
        }
    }

    /** 从表：每条 payload 探针一行（XiaSQL：参数/payload/返回包长度/变化/用时/响应码 + 判定）。 */
    public class GateTableModel extends AbstractTableModel {
        private final String[] cols = {"参数", "payload", "返回包长度", "变化", "用时", "响应码", "判定"};
        public final List<GateProbeView> data = new ArrayList<>();

        @Override
        public int getRowCount() {
            return data.size();
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
            GateProbeView g = data.get(r);
            return switch (c) {
                case 0 -> g.parameterPath == null ? g.parameterName : g.parameterPath;
                case 1 -> g.payload == null ? "-" : g.payload;
                case 2 -> g.mutatedLen < 0 ? "-" : g.mutatedLen;
                case 3 -> (g.lenDelta > 0 ? "+" : "") + g.lenDelta + " ｜ "
                        + (g.reason == null || g.reason.isEmpty() ? "-" : g.reason);
                case 4 -> g.elapsedMs < 0 ? "-" : g.elapsedMs + "ms";
                case 5 -> g.status < 0 ? "-" : g.status;
                case 6 -> localizeDecision(g.decision);
                default -> "";
            };
        }

        void add(GateProbeView v) {
            if (data.size() == 5000) {
                data.remove(0);
                fireTableRowsDeleted(0, 0);
            }
            data.add(v);
            fireTableRowsInserted(data.size() - 1, data.size() - 1);
        }
    }

    /** 差分页全部观察行（从表按主表选中请求过滤的数据源）。 */
    public final java.util.Map<String, List<GateProbeView>> gateRowsByRequest =
            new java.util.concurrent.ConcurrentHashMap<>();
    /** 主表当前过滤的 requestId（null=显示全部）。 */
    private volatile String gateFilterRequestId;

    // ---- 差分候选页显示中文化（v2.4.1）：引擎数据保持英文（测试断言/日志不受影响），
    //      仅 UI 层映射；未匹配模板原样显示，保证信息不丢。 ----

    public static String localizeDecision(String d) {
        if (d == null) {
            return "";
        }
        return switch (d) {
            case "PASS" -> "通过";
            case "REJECT" -> "拒绝";
            case "INCONCLUSIVE" -> "待定";
            default -> d;
        };
    }

    private static final java.util.regex.Pattern[] REASON_PATTERNS = {
            java.util.regex.Pattern.compile("^score ([\\d.]+) below threshold ([\\d.]+)(.*)$"),
            java.util.regex.Pattern.compile("^score below threshold (.+)$"),
            java.util.regex.Pattern.compile("^score ([\\d.]+) >= ([\\d.]+): (.*)$"),
            java.util.regex.Pattern.compile("^time-payload delay observed: Δ=(-?\\d+)ms >= (\\d+)ms with HTTP (\\d+) -> evidence evaluation$"),
            java.util.regex.Pattern.compile("^weak length delta \\((\\d+) bytes\\) without strong evidence(.*)$"),
            java.util.regex.Pattern.compile("^weak length delta \\((\\d+) bytes\\) only, similarity=([\\d.]+)(.*)$"),
            java.util.regex.Pattern.compile("^weak length delta \\((\\d+)\\) but strong evidence present: (.*)$"),
            java.util.regex.Pattern.compile("^baseline unstable \\(dynamic page\\): stability retest required$"),
            java.util.regex.Pattern.compile("^still inconclusive after (\\d+) stability retests \\(dynamic page\\)$"),
            java.util.regex.Pattern.compile("^server JSON parse error response without db fingerprint \\(likely request-shape rejection\\)$"),
            java.util.regex.Pattern.compile("^server JSON parse error response \\(invalid-JSON differential\\)$"),
            java.util.regex.Pattern.compile("^server JSON-error-like response WITH db error fingerprint: evidence evaluation$"),
            java.util.regex.Pattern.compile("^no usable evidence \\(all probes failed\\)$"),
    };

    public static String localizeReason(String reason) {
        if (reason == null || reason.isEmpty()) {
            return "";
        }
        java.util.regex.Matcher m;
        // 顺序即优先级：长模板在前，避免前缀误吞
        m = REASON_PATTERNS[3].matcher(reason);
        if (m.matches()) {
            return "时间探针命中：Δ=" + m.group(1) + "ms ≥ " + m.group(2) + "ms（HTTP " + m.group(3) + "）→ 进入证据评估";
        }
        m = REASON_PATTERNS[9].matcher(reason);
        if (m.matches()) {
            return "服务端返回 JSON 解析错误且无数据库指纹（疑似请求形态被拒）";
        }
        m = REASON_PATTERNS[10].matcher(reason);
        if (m.matches()) {
            return "服务端返回 JSON 解析错误（非法 JSON 差分）";
        }
        m = REASON_PATTERNS[11].matcher(reason);
        if (m.matches()) {
            return "JSON 解析错误响应且含数据库指纹 → 证据评估";
        }
        m = REASON_PATTERNS[12].matcher(reason);
        if (m.matches()) {
            return "无可用证据（探针全部失败）";
        }
        m = REASON_PATTERNS[7].matcher(reason);
        if (m.matches()) {
            return "基线不稳定（动态页）：需稳定性复测";
        }
        m = REASON_PATTERNS[8].matcher(reason);
        if (m.matches()) {
            return "动态页稳定性复测 " + m.group(1) + " 轮后仍无法判定";
        }
        m = REASON_PATTERNS[0].matcher(reason);
        if (m.matches()) {
            return "差分分 " + m.group(1) + " 低于阈值 " + m.group(2) + localizeTimingTail(m.group(3));
        }
        m = REASON_PATTERNS[1].matcher(reason);
        if (m.matches()) {
            return "差分分低于阈值 " + m.group(1);
        }
        m = REASON_PATTERNS[2].matcher(reason);
        if (m.matches()) {
            return "差分分 " + m.group(1) + " ≥ 阈值 " + m.group(2) + "：" + localizeEvidenceSummary(m.group(3));
        }
        m = REASON_PATTERNS[4].matcher(reason);
        if (m.matches()) {
            return "微弱长度差（" + m.group(1) + " 字节）且无强证据" + localizeTimingTail(m.group(2));
        }
        m = REASON_PATTERNS[5].matcher(reason);
        if (m.matches()) {
            return "仅微弱长度差（" + m.group(1) + " 字节），相似度=" + m.group(2) + localizeTimingTail(m.group(3));
        }
        m = REASON_PATTERNS[6].matcher(reason);
        if (m.matches()) {
            return "微弱长度差（" + m.group(1) + "）但存在强证据：" + localizeEvidenceSummary(m.group(2));
        }
        return reason; // 未匹配模板：原文显示（信息不丢）
    }

    /** 拒绝理由尾部的时间证据附注（appendTiming 产物）。 */
    private static String localizeTimingTail(String tail) {
        if (tail == null || tail.isEmpty()) {
            return "";
        }
        String t = tail.replace(" | TIMING-PRESERVED: ", " ｜ 时间证据保留：");
        java.util.regex.Matcher m = java.util.regex.Pattern
                .compile(" \\| timing Δ=(-?\\d+)ms \\(no anomaly\\)$").matcher(t);
        if (m.find()) {
            t = t.substring(0, m.start()) + " ｜ 计时 Δ=" + m.group(1) + "ms（无异常）";
        }
        return t;
    }

    /** 强证据摘要（strongEvidenceSummary 产物：db-error:家族 / status A->B / structure-changed / sim / lenDelta）。 */
    private static String localizeEvidenceSummary(String s) {
        if (s == null || s.isEmpty()) {
            return "";
        }
        String out = s.replace("db-error:", "数据库错误指纹:")
                .replace("structure-changed", "JSON结构变化");
        java.util.regex.Matcher m = java.util.regex.Pattern
                .compile("status (\\d+)->(\\d+)").matcher(out);
        if (m.find()) {
            out = out.replaceAll("status (\\d+)->(\\d+)", "状态码 $1→$2");
        }
        return out;
    }

    /** 时间异常列的 timingNote 映射。 */
    public static String localizeNote(String note) {
        if (note == null || note.isEmpty()) {
            return "";
        }
        if ("timing not measured".equals(note)) {
            return "未测量";
        }
        if (note.startsWith("not sent: ")) {
            return "未发送：" + note.substring("not sent: ".length());
        }
        if (note.startsWith("timing anomaly preserved: ")) {
            return "时间异常保留：" + note.substring("timing anomaly preserved: ".length());
        }
        return note;
    }

        private class DifferentialPanel {

        JComponent build() {
            // ---- 主表（XiaSQL 流量表）：一次请求一行 ----
            gateRequestModel = new GateRequestModel();
            JTable mainTable = createTable(gateRequestModel);
            // ---- 从表：该请求每条 payload 的原始观察（不筛选） ----
            gateModel = new GateTableModel();
            JTable detailTable = createTable(gateModel);
            // v3.8.4：响应有变化的行整行亮红——从表按 lenDelta≠0，主表按该请求存在变化观察行
            // v3.8.5 修复：渲染器组件被 Swing 复用，未命中行必须显式还原默认色
            // v3.8.6：三色档位——待定=黄 > 拒绝=绿 > 变化=红 > 默认（优先级从高到低）
            detailTable.setDefaultRenderer(Object.class, new javax.swing.table.DefaultTableCellRenderer() {
                @Override
                public java.awt.Component getTableCellRendererComponent(JTable table, Object value,
                                                                        boolean selected, boolean focused,
                                                                        int viewRow, int column) {
                    java.awt.Component c = super.getTableCellRendererComponent(
                            table, value, selected, focused, viewRow, column);
                    int modelRow = table.convertRowIndexToModel(viewRow);
                    if (modelRow >= 0 && modelRow < gateModel.data.size()) {
                        int tier = highlightTier(gateModel.data.get(modelRow));
                        if (tier == TIER_PENDING) {
                            c.setBackground(selected ? PENDING_YELLOW_SELECTED : PENDING_YELLOW);
                            c.setForeground(selected ? java.awt.Color.WHITE : java.awt.Color.BLACK);
                        } else if (tier == TIER_REJECTED) {
                            c.setBackground(selected ? REJECTED_GREEN_SELECTED : REJECTED_GREEN);
                            c.setForeground(selected ? java.awt.Color.WHITE : java.awt.Color.BLACK);
                        } else if (tier == TIER_CHANGED) {
                            c.setBackground(selected ? CHANGED_RED_SELECTED : CHANGED_RED);
                            c.setForeground(selected ? java.awt.Color.WHITE : java.awt.Color.BLACK);
                        } else {
                            c.setBackground(selected ? table.getSelectionBackground() : table.getBackground());
                            c.setForeground(selected ? table.getSelectionForeground() : table.getForeground());
                        }
                    } else {
                        c.setBackground(selected ? table.getSelectionBackground() : table.getBackground());
                        c.setForeground(selected ? table.getSelectionForeground() : table.getForeground());
                    }
                    return c;
                }
            });
            mainTable.setDefaultRenderer(Object.class, new javax.swing.table.DefaultTableCellRenderer() {
                @Override
                public java.awt.Component getTableCellRendererComponent(JTable table, Object value,
                                                                        boolean selected, boolean focused,
                                                                        int viewRow, int column) {
                    java.awt.Component c = super.getTableCellRendererComponent(
                            table, value, selected, focused, viewRow, column);
                    int modelRow = table.convertRowIndexToModel(viewRow);
                    if (modelRow >= 0 && modelRow < gateRequestModel.data.size()) {
                        int tier = requestHighlightTier(gateRequestModel.data.get(modelRow).requestId);
                        if (tier == TIER_PENDING) {
                            c.setBackground(selected ? PENDING_YELLOW_SELECTED : PENDING_YELLOW);
                            c.setForeground(selected ? java.awt.Color.WHITE : java.awt.Color.BLACK);
                        } else if (tier == TIER_REJECTED) {
                            c.setBackground(selected ? REJECTED_GREEN_SELECTED : REJECTED_GREEN);
                            c.setForeground(selected ? java.awt.Color.WHITE : java.awt.Color.BLACK);
                        } else if (tier == TIER_CHANGED) {
                            c.setBackground(selected ? CHANGED_RED_SELECTED : CHANGED_RED);
                            c.setForeground(selected ? java.awt.Color.WHITE : java.awt.Color.BLACK);
                        } else {
                            c.setBackground(selected ? table.getSelectionBackground() : table.getBackground());
                            c.setForeground(selected ? table.getSelectionForeground() : table.getForeground());
                        }
                    } else {
                        c.setBackground(selected ? table.getSelectionBackground() : table.getBackground());
                        c.setForeground(selected ? table.getSelectionForeground() : table.getForeground());
                    }
                    return c;
                }
            });

            // ---- Burp 原生编辑器 ×4（选中观察行查看 原始/变异 请求响应） ----
            // v3.9.3：四附签 -> 左右分栏（左=请求 右=响应；主表行显示原始对、从表行显示变异对）
            gateReqEditor = safeCreateRequestEditor();
            gateRespEditor = safeCreateResponseEditor();
            javax.swing.JSplitPane gateEvidenceSplit = new javax.swing.JSplitPane(
                    javax.swing.JSplitPane.HORIZONTAL_SPLIT,
                    editorOrPlaceholder(gateReqEditor, "（选中主表行看原始请求 / 从表行看变异请求）"),
                    editorOrPlaceholder(gateRespEditor, "（选中主表行看原始响应 / 从表行看变异响应）"));
            gateEvidenceSplit.setResizeWeight(0.5);
            gateEvidenceSplit.setDividerLocation(0.5);

            // 主表选中 -> 从表过滤到该请求（XiaSQL changeSelection 语义）
            mainTable.getSelectionModel().addListSelectionListener(e -> {
                if (!e.getValueIsAdjusting() && mainTable.getSelectedRow() >= 0) {
                    int idx = mainTable.convertRowIndexToModel(mainTable.getSelectedRow());
                    if (idx >= 0 && idx < gateRequestModel.data.size()) {
                        RequestRow row = gateRequestModel.data.get(idx);
                        gateFilterRequestId = row.requestId;
                        refreshGateDetail();
                        loadRequestRowEvidence(row);
                    }
                }
            });
            // 从表选中 -> 四编辑器加载
            detailTable.getSelectionModel().addListSelectionListener(e -> {
                if (!e.getValueIsAdjusting() && detailTable.getSelectedRow() >= 0) {
                    loadGateRowEvidence(detailTable);
                }
            });
            attachCandidateContextMenu(detailTable);

            JButton clear = new JButton("清空");
            clear.addActionListener(e -> {
                gateRowsByRequest.clear();
                gateModel.data.clear();
                gateModel.fireTableDataChanged();
                gateRequestModel.data.clear();
                gateRequestModel.fireTableDataChanged();
                gateFilterRequestId = null;
            });
            JPanel detailTop = tableToolbar(detailTable, 0, 1, 3);
            detailTop.add(clear);
            JPanel detailPanel = new JPanel(new BorderLayout());
            detailPanel.add(detailTop, BorderLayout.NORTH);
            detailPanel.add(new JScrollPane(detailTable), BorderLayout.CENTER);

            JSplitPane inner = new JSplitPane(JSplitPane.VERTICAL_SPLIT, detailPanel, gateEvidenceSplit);
            inner.setResizeWeight(0.45);
            inner.setDividerLocation(0.45);
            JSplitPane outer = new JSplitPane(JSplitPane.VERTICAL_SPLIT, new JScrollPane(mainTable), inner);
            outer.setResizeWeight(0.30);
            outer.setDividerLocation(0.30);

            JPanel p = new JPanel(new BorderLayout());
            p.add(outer, BorderLayout.CENTER);
            return p;
        }
    }

    /** 按主表选中请求刷新从表（null 过滤=全部）。 */
    private void refreshGateDetail() {
        gateModel.data.clear();
        String filter = gateFilterRequestId;
        for (Map.Entry<String, List<GateProbeView>> e : gateRowsByRequest.entrySet()) {
            if (filter == null || filter.equals(e.getKey())) {
                gateModel.data.addAll(e.getValue());
            }
        }
        gateModel.fireTableDataChanged();
    }

    /** 主表行选中 -> 原始请求/响应编辑器（基线证据）。 */
    private void loadRequestRowEvidence(RequestRow row) {
        com.xzhscan.model.RawHttp.RawRequest req = null;
        com.xzhscan.model.RawHttp.RawResponse resp = null;
        if (row.baselineEvidenceId != null) {
            EvidenceStore.Evidence ev = evidence.get(row.baselineEvidenceId);
            if (ev != null) {
                req = ev.request;
                resp = ev.response;
            }
        }
        loadRequestEditor(gateReqEditor, req);
        loadResponseEditor(gateRespEditor, resp);
    }

    /** 行视图 -> 候选对象（仅 PASS 行有对应候选；REJECT 行/已被淘汰返回 null）。测试可查。 */
    public DifferentialCandidate candidateForRow(GateProbeView g) {
        if (g == null) {
            return null;
        }
        return candidateStore.get(g.requestId + "|" + g.parameterPath);
    }

    /** 选中观察行 -> 四编辑器加载基线/变异证据（v3.3：直接取行上的证据 id，含全部观察行）。 */
    private void loadGateRowEvidence(JTable table) {
        int modelRow = table.convertRowIndexToModel(table.getSelectedRow());
        if (modelRow < 0 || modelRow >= gateModel.data.size()) {
            return;
        }
        GateProbeView v = gateModel.data.get(modelRow);
        DifferentialCandidate c = candidateForRow(v);
        com.xzhscan.model.RawHttp.RawRequest origReq = c == null ? null : c.originalRequest;
        com.xzhscan.model.RawHttp.RawResponse origResp = null;
        com.xzhscan.model.RawHttp.RawRequest mutReq = null;
        com.xzhscan.model.RawHttp.RawResponse mutResp = null;
        if (v.baselineEvidenceId != null) {
            EvidenceStore.Evidence ev = evidence.get(v.baselineEvidenceId);
            if (ev != null) {
                origReq = ev.request != null ? ev.request : origReq;
                origResp = ev.response;
            }
        }
        if (v.mutatedEvidenceId != null) {
            EvidenceStore.Evidence ev = evidence.get(v.mutatedEvidenceId);
            if (ev != null) {
                mutReq = ev.request;
                mutResp = ev.response;
            }
        }
        loadRequestEditor(gateReqEditor, mutReq != null ? mutReq : origReq);
        loadResponseEditor(gateRespEditor, mutResp != null ? mutResp : origResp);
    }

    /** 差分页从表右键：Repeater 定位（原始/变异，任意观察行可用）/ 复制。验证入口=消息右键。 */
    private void attachCandidateContextMenu(JTable table) {
        JPopupMenu menu = new JPopupMenu();
        JMenuItem repOrig = new JMenuItem("发送到 Repeater（原始请求）");
        repOrig.addActionListener(e -> withSelectedView(table, v -> {
            EvidenceStore.Evidence ev = v.baselineEvidenceId == null ? null : evidence.get(v.baselineEvidenceId);
            DifferentialCandidate c = candidateForRow(v);
            com.xzhscan.model.RawHttp.RawRequest req = ev != null && ev.request != null ? ev.request
                    : (c == null ? null : c.originalRequest);
            if (req != null) {
                api.repeater().sendToRepeater(
                        BurpTransport.build(BurpTransport.serviceOf(req.url), req),
                        "XzhScan-orig-" + v.parameterPath);
            } else {
                log("WARN", "该行无原始请求证据");
            }
        }));
        menu.add(repOrig);
        JMenuItem repMut = new JMenuItem("发送到 Repeater（变异请求）");
        repMut.setToolTipText("定位后可在消息上右键「XzhScan SQL 验证」指定该参数送二阶段");
        repMut.addActionListener(e -> withSelectedView(table, v -> {
            EvidenceStore.Evidence ev = v.mutatedEvidenceId == null ? null : evidence.get(v.mutatedEvidenceId);
            if (ev != null && ev.request != null) {
                api.repeater().sendToRepeater(
                        BurpTransport.build(BurpTransport.serviceOf(ev.request.url), ev.request),
                        "XzhScan-mut-" + v.parameterPath);
            } else {
                log("WARN", "该行无变异请求证据（可能已被证据仓淘汰）");
            }
        }));
        menu.add(repMut);
        menu.addSeparator();
        JMenuItem copyUrl = new JMenuItem("复制 URL");
        copyUrl.addActionListener(e -> withSelectedView(table, v -> copy(v.url)));
        menu.add(copyUrl);
        JMenuItem copyReq = new JMenuItem("复制变异请求");
        copyReq.addActionListener(e -> withSelectedView(table, v -> {
            EvidenceStore.Evidence ev = v.mutatedEvidenceId == null ? null : evidence.get(v.mutatedEvidenceId);
            copy(ev == null || ev.request == null ? "" : renderRequest(ev.request));
        }));
        menu.add(copyReq);
        table.setComponentPopupMenu(menu);
    }

    private void withSelectedView(JTable table, java.util.function.Consumer<GateProbeView> action) {
        int modelRow = table.convertRowIndexToModel(table.getSelectedRow());
        if (modelRow < 0 || modelRow >= gateModel.data.size()) {
            return;
        }
        action.accept(gateModel.data.get(modelRow));
    }

    // ================= 2. 漏洞结果 =================

    public static class FindingRow {
        public final InjectionFinding finding;
        public final DifferentialCandidate candidate;
        public final VerificationResult verification;

        FindingRow(InjectionFinding f, DifferentialCandidate c, VerificationResult v) {
            this.finding = f;
            this.candidate = c;
            this.verification = v;
        }
    }

    public class FindingTableModel extends AbstractTableModel {
        private final String[] cols = {"结论", "类型", "URL", "参数", "DB", "Payload"};
        public final List<FindingRow> data = new ArrayList<>();

        @Override
        public int getRowCount() {
            return data.size();
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
            FindingRow row = data.get(r);
            InjectionFinding f = row.finding;
            return switch (c) {
                case 0 -> f.verdict.name();
                case 1 -> f.injectionType;
                case 2 -> row.candidate.targetUrl;
                case 3 -> f.parameterPath;
                case 4 -> f.dbFamily == null ? "-" : f.dbFamily;
                case 5 -> f.payload == null ? "-" : (f.payload.length() > 60 ? f.payload.substring(0, 60) + "..." : f.payload);
                default -> "";
            };
        }
    }

    // ================= 3. 数据版（v3.9.2：红/黄参数聚合 + 一键送二阶段） =================

    /**
     * 参数级聚合档位（数据版口径）：红 > 黄 > 绿。
     * 与差分页从表单行档位（黄>绿>红）、主表 URL 档位语义均不同——
     * 数据版回答"这个参数值不值得送二阶段"：只要出现过变化就是红色；
     * 只有待定没有变化是黄色；全部被拒绝则排除（不进数据版）。
     */
    public static int dataBoardTier(int[] agg) {
        if (agg[0] > 0) {
            return TIER_CHANGED;
        }
        if (agg[1] > 0) {
            return TIER_PENDING;
        }
        if (agg[2] > 0) {
            return TIER_REJECTED;
        }
        return TIER_DEFAULT;
    }

    /** 数据版行（key = requestId|parameterPath）。 */
    public static final class DataBoardRow {
        public final String requestId;
        public final String url;
        public final String parameterPath;
        public final String parameterLocation;
        public int tier = TIER_DEFAULT;
        public double bestScore;
        public String verifyStatus = "未发送";
        public boolean sent;
        /** 发送二阶段时绑定的候选（点行加载证据用）。 */
        public DifferentialCandidate candidate;
        /** 二阶段结论（含 evidenceIds，点行加载测试请求/响应用）。 */
        public VerificationResult verification;
        /** v3.9.4：聚合时得分最高的观察行（无候选时点行也能看原始/变异请求响应证据）。 */
        public GateProbeView bestView;
        /** v3.9.6：候选是否由原始请求现场构造（差分门未过门 → 全模块直验）。 */
        public boolean rebuiltCandidate;

        DataBoardRow(String requestId, String url, String parameterPath, String parameterLocation) {
            this.requestId = requestId;
            this.url = url;
            this.parameterPath = parameterPath;
            this.parameterLocation = parameterLocation;
        }
    }

    public class DataBoardModel extends AbstractTableModel {
        private final String[] cols = {"URL", "参数", "档位", "最高差分分", "二阶段状态"};
        /** key = requestId|parameterPath，插入序即展示序。 */
        public final java.util.LinkedHashMap<String, DataBoardRow> rows = new java.util.LinkedHashMap<>();
        /** 与 rows 同序的行列表（表格随机访问用）。 */
        public final List<DataBoardRow> list = new ArrayList<>();

        @Override
        public int getRowCount() {
            return list.size();
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
            DataBoardRow d = list.get(r);
            return switch (c) {
                case 0 -> d.url;
                case 1 -> d.parameterPath;
                case 2 -> d.tier == TIER_CHANGED ? "红色·有变化" : "黄色·待定";
                case 3 -> String.format("%.2f", d.bestScore);
                case 4 -> d.verifyStatus;
                default -> "";
            };
        }

        void upsert(GateProbeView v, int tier) {
            String key = v.requestId + "|" + v.parameterPath;
            DataBoardRow row = rows.get(key);
            if (row == null) {
                row = new DataBoardRow(v.requestId, v.url, v.parameterPath, v.parameterLocation);
                rows.put(key, row);
                list.add(row);
                fireTableRowsInserted(list.size() - 1, list.size() - 1);
            }
            row.tier = tier;
            if (v.score > row.bestScore) {
                row.bestScore = v.score;
            }
            // v3.9.4：保存最强观察行——差分门 REJECT 的参数没有候选对象，
            // 点行时仍可用该行的证据 id 加载 原始/变异请求响应（否则编辑器全空）
            if (row.bestView == null || v.score >= row.bestView.score) {
                row.bestView = v;
            }
            int idx = list.indexOf(row);
            if (idx >= 0) {
                fireTableRowsUpdated(idx, idx);
            }
        }

        void remove(String key) {
            DataBoardRow row = rows.remove(key);
            if (row == null) {
                return;
            }
            int idx = list.indexOf(row);
            if (idx >= 0) {
                list.remove(idx);
                fireTableRowsDeleted(idx, idx);
            }
        }

        void clearAll() {
            int n = list.size();
            rows.clear();
            list.clear();
            if (n > 0) {
                fireTableRowsDeleted(0, n - 1);
            }
        }

        /** 二阶段结论回流：状态刷新 + 绑定结论对象（点行加载测试请求/响应用）。 */
        void attachVerification(VerificationResult v) {
            DataBoardRow row = rows.get(v.requestId + "|" + v.parameterPath);
            if (row != null) {
                row.verification = v;
                int idx = list.indexOf(row);
                if (idx >= 0) {
                    fireTableRowsUpdated(idx, idx);
                }
            }
        }

        void markVerify(String requestId, String parameterPath, String status) {
            DataBoardRow row = rows.get(requestId + "|" + parameterPath);
            if (row != null) {
                row.verifyStatus = status;
                int idx = list.indexOf(row);
                if (idx >= 0) {
                    fireTableRowsUpdated(idx, idx);
                }
            }
        }

        void refreshAll() {
            fireTableDataChanged();
        }
    }

    /** 数据版聚合计数（key = requestId|parameterPath；int[3] = {变化, 待定, 拒绝}）。 */
    private final java.util.concurrent.ConcurrentHashMap<String, int[]> dataBoardAgg =
            new java.util.concurrent.ConcurrentHashMap<>();

    /** onGateView 挂钩：参数级聚合红/黄/绿，红黄 upsert 进数据版、纯绿剔除。 */
    private void dataBoardUpdate(GateProbeView v) {
        if (v.parameterPath == null || dataBoardModel == null) {
            return;
        }
        String key = v.requestId + "|" + v.parameterPath;
        int[] agg = dataBoardAgg.computeIfAbsent(key, k -> new int[3]);
        int tier = highlightTier(v);
        if (tier == TIER_CHANGED) {
            agg[0]++;
        } else if (tier == TIER_PENDING) {
            agg[1]++;
        } else if (tier == TIER_REJECTED) {
            agg[2]++;
        }
        int board = dataBoardTier(agg);
        edtl(() -> {
            if (dataBoardModel == null) {
                return;
            }
            if (board == TIER_CHANGED || board == TIER_PENDING) {
                dataBoardModel.upsert(v, board);
            } else if (board == TIER_REJECTED) {
                dataBoardModel.remove(key);
            }
        });
    }

    private class DataBoardPanel {

        private JTable boardTable;
        private HttpRequestEditor boardReqEditor;
        private HttpResponseEditor boardRespEditor;

        JComponent build() {
            dataBoardModel = new DataBoardModel();
            boardTable = createTable(dataBoardModel);
            JTable table = boardTable;
            // 行染色：红=有变化、黄=待定；v3.8.5 教训——渲染器复用，未命中行必须显式还原默认色
            table.setDefaultRenderer(Object.class, new javax.swing.table.DefaultTableCellRenderer() {
                @Override
                public java.awt.Component getTableCellRendererComponent(JTable t, Object value,
                                                                        boolean selected, boolean focused,
                                                                        int viewRow, int column) {
                    java.awt.Component c = super.getTableCellRendererComponent(
                            t, value, selected, focused, viewRow, column);
                    int modelRow = t.convertRowIndexToModel(viewRow);
                    if (modelRow >= 0 && modelRow < dataBoardModel.list.size()) {
                        DataBoardRow d = dataBoardModel.list.get(modelRow);
                        if (d.tier == TIER_CHANGED) {
                            c.setBackground(selected ? CHANGED_RED_SELECTED : CHANGED_RED);
                            c.setForeground(selected ? java.awt.Color.WHITE : java.awt.Color.BLACK);
                        } else if (d.tier == TIER_PENDING) {
                            c.setBackground(selected ? PENDING_YELLOW_SELECTED : PENDING_YELLOW);
                            c.setForeground(selected ? java.awt.Color.WHITE : java.awt.Color.BLACK);
                        } else {
                            c.setBackground(selected ? t.getSelectionBackground() : t.getBackground());
                            c.setForeground(selected ? t.getSelectionForeground() : t.getForeground());
                        }
                    } else {
                        c.setBackground(selected ? t.getSelectionBackground() : t.getBackground());
                        c.setForeground(selected ? t.getSelectionForeground() : t.getForeground());
                    }
                    return c;
                }
            });

            JPanel btns = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 2));
            JButton sendRed = new JButton("红色参数发送二阶段");
            sendRed.setToolTipText("把数据版全部未发送的 红色（出现过变化） 参数逐个送二阶段（同右键安全闸与预算）");
            JButton sendYellow = new JButton("黄色参数发送二阶段");
            sendYellow.setToolTipText("把数据版全部未发送的 黄色（待定） 参数逐个送二阶段（同右键安全闸与预算）");
            JButton sendSel = new JButton("发送所选");
            JButton clearBtn = new JButton("清空");
            JLabel hint = new JLabel("红色=出现过变化　黄色=待定（纯绿已剔除）；发送前仍过安全闸，队列满自动拒绝");
            btns.add(sendRed);
            btns.add(sendYellow);
            btns.add(sendSel);
            btns.add(clearBtn);
            btns.add(hint);

            JPanel top = new JPanel(new BorderLayout());
            top.add(tableToolbar(table, 0, 1), BorderLayout.NORTH);
            top.add(btns, BorderLayout.SOUTH);
            // v3.9.3 数据版改版：点开参数行 -> 下方左=测试请求 右=测试响应（左右分栏）
            boardReqEditor = safeCreateRequestEditor();
            boardRespEditor = safeCreateResponseEditor();
            javax.swing.JSplitPane evidenceSplit = new javax.swing.JSplitPane(
                    javax.swing.JSplitPane.HORIZONTAL_SPLIT,
                    editorOrPlaceholder(boardReqEditor, "（点上方参数行：左看测试请求）"),
                    editorOrPlaceholder(boardRespEditor, "（点上方参数行：右看测试响应）"));
            evidenceSplit.setResizeWeight(0.5);
            evidenceSplit.setDividerLocation(0.5);
            javax.swing.JSplitPane boardSplit = new javax.swing.JSplitPane(
                    javax.swing.JSplitPane.VERTICAL_SPLIT,
                    new JScrollPane(table), evidenceSplit);
            boardSplit.setResizeWeight(0.45);
            boardSplit.setDividerLocation(0.45);
            JPanel panel = new JPanel(new BorderLayout());
            panel.add(top, BorderLayout.NORTH);
            panel.add(boardSplit, BorderLayout.CENTER);
            table.getSelectionModel().addListSelectionListener(e -> {
                if (!e.getValueIsAdjusting() && boardTable.getSelectedRow() >= 0) {
                    loadBoardEvidence();
                }
            });

            sendRed.addActionListener(e -> {
                int sent = sendByTier(TIER_CHANGED);
                dataBoardModel.refreshAll();
                log("INFO", "[数据版] 红色参数发送完成: 发送 " + sent + " 条");
            });
            sendYellow.addActionListener(e -> {
                int sent = sendByTier(TIER_PENDING);
                dataBoardModel.refreshAll();
                log("INFO", "[数据版] 黄色参数发送完成: 发送 " + sent + " 条");
            });
            sendSel.addActionListener(e -> {
                int idx = table.getSelectedRow();
                if (idx < 0) {
                    return;
                }
                int modelRow = table.convertRowIndexToModel(idx);
                if (modelRow < 0 || modelRow >= dataBoardModel.list.size()) {
                    return;
                }
                sendRow(dataBoardModel.list.get(modelRow), false);
                dataBoardModel.refreshAll();
            });
            clearBtn.addActionListener(e -> {
                dataBoardAgg.clear();
                dataBoardModel.clearAll();
                log("INFO", "[数据版] 已清空（新流量会重新聚合）");
            });
            attachDataBoardContextMenu(table);
            return panel;
        }

        /**
         * 按档位批量发送（v3.9.2）：红色=出现过变化 / 黄色=待定，各自独立按钮。
         * 只发未发送行；无候选行标记状态并跳过；发送链路与右键 verifyNow 完全同款
         * （安全闸复核 + 队列满拒绝 + 结论回流）。
         */
        private int sendByTier(int tier) {
            if (orchestrator == null || hostCb == null) {
                log("WARN", "[数据版] 引擎未装配（扩展尚未就绪），无法发送");
                return 0;
            }
            String colorWord = tier == TIER_CHANGED ? "红色" : "黄色";
            int sent = 0, none = 0;
            for (DataBoardRow d : dataBoardModel.list) {
                if (d.tier != tier || d.sent) {
                    continue;
                }
                DifferentialCandidate c = resolveBoardCandidate(d);
                if (c == null) {
                    none++;
                    d.verifyStatus = "无证据（原始请求快照不可用）";
                    continue;
                }
                d.candidate = c;
                d.sent = true;
                d.verifyStatus = "已发送";
                log("INFO", "[数据版][" + colorWord + "] 送二阶段: " + d.parameterPath + " @" + d.url
                        + (d.rebuiltCandidate ? "（差分未过门，全模块直验）" : ""));
                orchestrator.verifyNow(c, hostCb);
                sent++;
            }
            if (none > 0) {
                log("WARN", "[数据版][" + colorWord + "] " + none + " 条无可用原始请求快照，已跳过");
            }
            return sent;
        }

        /**
         * v3.9.6：取数据版行可送二阶段的候选。
         * 差分门 PASS/INCONCLUSIVE 的参数直接用候选仓对象；差分门 REJECT 的参数
         * （有变化但分数低于阈值，数据版照样标红）没有候选——用聚合观察行的
         * 原始请求证据现场构造候选（走右键「指定参数验证」同款 manualCandidate
         * 全模块直验链路，不依赖差分门）。原始请求快照不可用才返回 null。
         */
        private DifferentialCandidate resolveBoardCandidate(DataBoardRow d) {
            DifferentialCandidate c = candidateStore.get(d.requestId + "|" + d.parameterPath);
            if (c != null) {
                return c;
            }
            if (d.bestView == null || d.bestView.baselineEvidenceId == null) {
                return null;
            }
            EvidenceStore.Evidence base = evidence.get(d.bestView.baselineEvidenceId);
            if (base == null || base.request == null) {
                return null;
            }
            com.xzhscan.parameter.ParameterExtractor.ExtractResult ex =
                    com.xzhscan.parameter.ParameterExtractor.extract(base.request);
            com.xzhscan.model.Models.ParameterIdentity p = null;
            for (com.xzhscan.model.Models.ParameterIdentity cand : ex.parameters) {
                if (cand.path.equals(d.parameterPath)) {
                    p = cand;
                    break;
                }
            }
            if (p == null || !p.mutable()) {
                return null;
            }
            DifferentialCandidate rebuilt = ScanOrchestrator.manualCandidate(base.request, p);
            if (rebuilt == null) {
                return null;
            }
            d.rebuiltCandidate = true;
            return rebuilt;
        }

        /** 单行发送（sent 行跳过；右键强制重发走 force）。 */
        private void sendRow(DataBoardRow d, boolean force) {
            if (orchestrator == null || hostCb == null) {
                log("WARN", "[数据版] 引擎未装配（扩展尚未就绪），无法发送");
                return;
            }
            if (d.sent && !force) {
                return;
            }
            DifferentialCandidate c = resolveBoardCandidate(d);
            if (c == null) {
                d.verifyStatus = "无证据（原始请求快照不可用）";
                log("WARN", "[数据版] 发送跳过（无可用原始请求快照）: " + d.parameterPath + " @" + d.url);
                return;
            }
            d.candidate = c;
            d.sent = true;
            d.verifyStatus = "已发送";
            log("INFO", "[数据版] 送二阶段" + (force ? "（重发）" : "") + ": " + d.parameterPath + " @" + d.url
                    + (d.rebuiltCandidate ? "（差分未过门，全模块直验）" : ""));
            orchestrator.verifyNow(c, hostCb);
        }

        /** 点开参数行：优先二阶段测试证据；无候选/未验证时回退观察行证据（原始+变异对）。 */
        private void loadBoardEvidence() {
            int idx = boardTable.convertRowIndexToModel(boardTable.getSelectedRow());
            if (idx < 0 || idx >= dataBoardModel.list.size()) {
                return;
            }
            DataBoardRow d = dataBoardModel.list.get(idx);
            EvidenceBundles.Bundle b = EvidenceBundles.resolve(d.candidate, d.verification, null, evidence);
            com.xzhscan.model.RawHttp.RawRequest req = b.probeRequest != null ? b.probeRequest : b.originalRequest;
            com.xzhscan.model.RawHttp.RawResponse resp = b.probeResponse != null ? b.probeResponse : b.originalResponse;
            // v3.9.4 回退：无候选（差分门 REJECT 的参数在数据版里同样标红）时，
            // 用聚合时的观察行证据 id 加载原始请求/响应 + 变异请求/响应中的变异侧
            if (req == null && resp == null && d.bestView != null) {
                EvidenceStore.Evidence mut = d.bestView.mutatedEvidenceId == null
                        ? null : evidence.get(d.bestView.mutatedEvidenceId);
                if (mut != null) {
                    req = mut.request;
                    resp = mut.response;
                }
                if (req == null && d.bestView.baselineEvidenceId != null) {
                    EvidenceStore.Evidence base = evidence.get(d.bestView.baselineEvidenceId);
                    if (base != null) {
                        req = base.request;
                        resp = base.response;
                    }
                }
            }
            loadRequestEditor(boardReqEditor, req);
            loadResponseEditor(boardRespEditor, resp);
        }

        private void attachDataBoardContextMenu(JTable table) {
            JPopupMenu menu = new JPopupMenu();
            JMenuItem send = new JMenuItem("发送到二阶段（强制重发）");
            send.addActionListener(e -> {
                int idx = table.getSelectedRow();
                if (idx < 0) {
                    return;
                }
                int modelRow = table.convertRowIndexToModel(idx);
                if (modelRow < 0 || modelRow >= dataBoardModel.list.size()) {
                    return;
                }
                sendRow(dataBoardModel.list.get(modelRow), true);
                dataBoardModel.refreshAll();
            });
            menu.add(send);
            table.setComponentPopupMenu(menu);
        }
    }

    private class VulnerabilityPanel {
        JComponent build() {
            findingModel = new FindingTableModel();
            JTable table = new JTable(findingModel);
            table.setAutoCreateRowSorter(true);

            // ---- Burp 原生 HTTP 编辑器 ×4（复用语法高亮/Raw/原生右键复制等能力） ----
            origReqEditor = safeCreateRequestEditor();
            probeReqEditor = safeCreateRequestEditor();
            origRespEditor = safeCreateResponseEditor();
            probeRespEditor = safeCreateResponseEditor();

            JTabbedPane editors = new JTabbedPane();
            editors.addTab("原始请求", editorOrPlaceholder(origReqEditor, "（无原始请求证据）"));
            editors.addTab("测试请求", editorOrPlaceholder(probeReqEditor, "（无测试请求证据）"));
            editors.addTab("原始响应", editorOrPlaceholder(origRespEditor, "（无原始响应证据）"));
            editors.addTab("测试响应", editorOrPlaceholder(probeRespEditor, "（无测试响应证据）"));

            JPanel south = new JPanel(new BorderLayout());
            south.add(editors, BorderLayout.CENTER);

            ListSelectionModel sm = table.getSelectionModel();
            sm.addListSelectionListener(e -> {
                if (!e.getValueIsAdjusting() && table.getSelectedRow() >= 0) {
                    loadFinding(table, findingModel);
                }
            });

            attachVulnContextMenu(table);

            JButton repeaterBtn = new JButton("发送到 Repeater（测试请求）");
            repeaterBtn.setToolTipText("优先发送判定所用的测试请求；缺失时回退原始请求");
            repeaterBtn.addActionListener(e -> sendSelectedToRepeater(table));

            // v3.4.4：漏洞结果页清空列表（结果 + 四个证据编辑器一起清）
            JButton clearFindings = new JButton("清空");
            clearFindings.setToolTipText("清空漏洞结果列表与证据视图（不影响差分候选与证据仓）");
            clearFindings.addActionListener(e -> {
                findingModel.data.clear();
                findingModel.fireTableDataChanged();
                loadRequestEditor(origReqEditor, null);
                loadRequestEditor(probeReqEditor, null);
                loadResponseEditor(origRespEditor, null);
                loadResponseEditor(probeRespEditor, null);
            });

            JPanel top = new JPanel(new FlowLayout(FlowLayout.LEFT));
            top.add(repeaterBtn);
            top.add(clearFindings);
            JSplitPane split = new JSplitPane(JSplitPane.VERTICAL_SPLIT,
                    new JScrollPane(table), south);
            split.setResizeWeight(0.45);
            split.setDividerLocation(0.45);
            JPanel p = new JPanel(new BorderLayout());
            p.add(top, BorderLayout.NORTH);
            p.add(split, BorderLayout.CENTER);
            return p;
        }
    }

    /** Test9 离线代理环境 uiComponent() 可能为 null：统一安全创建。 */
    private HttpRequestEditor safeCreateRequestEditor() {
        try {
            return api.userInterface().createHttpRequestEditor(EditorOptions.READ_ONLY);
        } catch (Throwable t) {
            return null;
        }
    }

    private HttpResponseEditor safeCreateResponseEditor() {
        try {
            return api.userInterface().createHttpResponseEditor(EditorOptions.READ_ONLY);
        } catch (Throwable t) {
            return null;
        }
    }

    /**
     * 编辑器容器（v3.9.4 自适应修复）：Burp 原生编辑器组件自带滚动与尺寸管理，
     * 再套一层 JScrollPane 是双重包装——内层组件拿不到正确尺寸，表现为编辑器
     * 塌陷/空白且不随分割条拖动自适应。现在直接返回编辑器组件，仅设最小尺寸
     * 防止容器被压到 0；占位提示仍用居中面板。
     */
    private JComponent editorOrPlaceholder(Object editor, String emptyText) {
        Component c = null;
        if (editor instanceof HttpRequestEditor e && e.uiComponent() != null) {
            c = e.uiComponent();
        } else if (editor instanceof HttpResponseEditor e && e.uiComponent() != null) {
            c = e.uiComponent();
        }
        if (c != null) {
            if (c instanceof JComponent jc) {
                jc.setMinimumSize(new java.awt.Dimension(160, 100));
                return jc;
            }
            return new JScrollPane(c);
        }
        JPanel ph = new JPanel(new GridBagLayout());
        ph.add(new JLabel(emptyText, JLabel.CENTER));
        ph.setMinimumSize(new java.awt.Dimension(160, 100));
        return ph;
    }

    /** 选中行 -> 四编辑器同步加载；缺证据显示明确空状态（每次全量重载，防串数据）。 */
    private void loadFinding(JTable table, FindingTableModel model) {
        int modelRow = table.convertRowIndexToModel(table.getSelectedRow());
        if (modelRow < 0 || modelRow >= model.data.size()) {
            return;
        }
        FindingRow fr = model.data.get(modelRow);
        EvidenceBundles.Bundle b = EvidenceBundles.resolve(fr.candidate, fr.verification, fr.finding, evidence);
        loadRequestEditor(origReqEditor, b.originalRequest);
        loadRequestEditor(probeReqEditor, b.probeRequest);
        loadResponseEditor(origRespEditor, b.originalResponse);
        loadResponseEditor(probeRespEditor, b.probeResponse);
        if (b.anyMissing()) {
            log("INFO", "证据缺失 " + fr.finding.parameterPath + ": " + String.join("; ", b.missing));
        }
    }

    private void loadRequestEditor(HttpRequestEditor editor, com.xzhscan.model.RawHttp.RawRequest r) {
        if (editor == null) {
            return;
        }
        if (r == null) {
            editor.setRequest(null); // 明确清空：不用上一条数据
            return;
        }
        try {
            editor.setRequest(BurpTransport.build(BurpTransport.serviceOf(r.url), r));
        } catch (Throwable t) {
            editor.setRequest(null);
        }
    }

    private void loadResponseEditor(HttpResponseEditor editor, com.xzhscan.model.RawHttp.RawResponse resp) {
        if (editor == null) {
            return;
        }
        if (resp == null) {
            editor.setResponse(null);
            return;
        }
        try {
            editor.setResponse(HttpResponse.httpResponse(toRawResponseText(resp)));
        } catch (Throwable t) {
            editor.setResponse(null);
        }
    }

    /** RawResponse -> 原始响应报文文本（HTTP/1.1 状态行 + 头 + 正文）。 */
    static String toRawResponseText(com.xzhscan.model.RawHttp.RawResponse r) {
        StringBuilder sb = new StringBuilder(256 + r.body.length);
        sb.append("HTTP/1.1 ").append(r.statusCode).append(' ')
          .append(r.statusCode >= 200 && r.statusCode < 300 ? "OK" : "Status").append("\r\n");
        r.headers.forEach((k, v) -> sb.append(k).append(": ").append(v).append("\r\n"));
        sb.append("\r\n");
        sb.append(r.bodyAsString());
        return sb.toString();
    }

    private void sendSelectedToRepeater(JTable table) {
        int row = table.getSelectedRow();
        if (row < 0) {
            return;
        }
        FindingRow fr = findingModel.data.get(table.convertRowIndexToModel(row));
        EvidenceBundles.Bundle b = EvidenceBundles.resolve(fr.candidate, fr.verification, fr.finding, evidence);
        com.xzhscan.model.RawHttp.RawRequest target = b.probeRequest != null ? b.probeRequest : b.originalRequest;
        if (target != null) {
            api.repeater().sendToRepeater(
                    BurpTransport.build(BurpTransport.serviceOf(target.url), target),
                    "XzhScan-" + fr.finding.parameterPath);
        } else {
            log("WARN", "该记录无可用请求证据，无法发送 Repeater");
        }
    }

    private void attachVulnContextMenu(JTable table) {
        JPopupMenu menu = new JPopupMenu();
        JMenuItem repeater = new JMenuItem("Send to Repeater（测试请求）");
        repeater.addActionListener(e -> sendSelectedToRepeater(table));
        menu.add(repeater);
        menu.addSeparator();
        JMenuItem copyUrl = new JMenuItem("Copy URL");
        copyUrl.addActionListener(e -> withSelected(table, fr -> copy(fr.candidate.targetUrl)));
        menu.add(copyUrl);
        JMenuItem copyParam = new JMenuItem("Copy Parameter");
        copyParam.addActionListener(e -> withSelected(table, fr -> copy(fr.finding.parameterPath)));
        menu.add(copyParam);
        JMenuItem copyReq = new JMenuItem("Copy Request");
        copyReq.addActionListener(e -> withSelected(table, fr -> {
            EvidenceBundles.Bundle b = EvidenceBundles.resolve(fr.candidate, fr.verification, fr.finding, evidence);
            com.xzhscan.model.RawHttp.RawRequest r = b.probeRequest != null ? b.probeRequest : b.originalRequest;
            copy(r == null ? "" : renderRequest(r));
        }));
        menu.add(copyReq);
        JMenuItem copyResp = new JMenuItem("Copy Response");
        copyResp.addActionListener(e -> withSelected(table, fr -> {
            EvidenceBundles.Bundle b = EvidenceBundles.resolve(fr.candidate, fr.verification, fr.finding, evidence);
            com.xzhscan.model.RawHttp.RawResponse r = b.probeResponse != null ? b.probeResponse : b.originalResponse;
            copy(r == null ? "" : toRawResponseText(r));
        }));
        menu.add(copyResp);
        JMenuItem copyDiff = new JMenuItem("查看/复制差分原因");
        copyDiff.addActionListener(e -> withSelected(table, fr -> copy("差分原因: "
                + String.join("; ", fr.candidate.differenceReasons) + " | gate: " + fr.candidate.filterReason)));
        menu.add(copyDiff);
        JMenuItem copySummary = new JMenuItem("复制漏洞摘要");
        copySummary.addActionListener(e -> withSelected(table, fr -> copy(
                fr.finding.verdict + " " + fr.finding.injectionType + " "
                        + fr.candidate.targetUrl + " param=" + fr.finding.parameterPath
                        + (fr.finding.payload != null ? " payload=" + fr.finding.payload : ""))));
        menu.add(copySummary);
        table.setComponentPopupMenu(menu);
    }

    private void withSelected(JTable table, java.util.function.Consumer<FindingRow> action) {
        int row = table.getSelectedRow();
        if (row >= 0) {
            action.accept(findingModel.data.get(table.convertRowIndexToModel(row)));
        }
    }

    private static String renderRequest(com.xzhscan.model.RawHttp.RawRequest r) {
        if (r == null) {
            return "";
        }
        StringBuilder sb = new StringBuilder();
        sb.append(r.method).append(' ').append(r.url).append("\n");
        for (String h : r.headers) {
            sb.append(h).append('\n');
        }
        sb.append('\n').append(r.bodyAsString());
        return sb.toString();
    }


    private void copy(String text) {
        java.awt.datatransfer.StringSelection sel =
                new java.awt.datatransfer.StringSelection(text == null ? "" : text);
        Toolkit.getDefaultToolkit().getSystemClipboard().setContents(sel, null);
    }

    // ================= 4. 设置 =================

    private class SettingsPanel {
        JComponent build() {
            JPanel p = new JPanel(new GridBagLayout());
            GridBagConstraints g = new GridBagConstraints();
            g.insets = new Insets(3, 6, 3, 6);
            g.anchor = GridBagConstraints.WEST;
            g.fill = GridBagConstraints.HORIZONTAL;
            int row = 0;

            // 暂停/恢复（ScanPolicyEngine 能力的 UI 入口）
            pauseBtn = new JButton(policy.isPaused() ? "恢复扫描" : "暂停扫描");
            pauseStateLabel = new JLabel(policy.isPaused() ? "状态：已暂停" : "状态：运行中");
            pauseBtn.setToolTipText("暂停后不再发出新的主动变异请求；不影响流量记录与已有结果");
            pauseBtn.addActionListener(e -> {
                if (policy.isPaused()) {
                    policy.resume();
                } else {
                    policy.pause();
                }
                pauseBtn.setText(policy.isPaused() ? "恢复扫描" : "暂停扫描");
                pauseStateLabel.setText(policy.isPaused() ? "状态：已暂停" : "状态：运行中");
                log("INFO", policy.isPaused() ? "扫描已暂停" : "扫描已恢复");
            });
            JPanel pauseBar = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 2));
            pauseBar.add(pauseBtn);
            pauseBar.add(pauseStateLabel);
            addRow(p, g, row++, pauseBar);

            JCheckBox cPhase1 = new JCheckBox("启用第一阶段（XiaSQL 被动初筛）", config.phase1Enabled);
            JCheckBox cPhase2 = new JCheckBox("启用第二阶段（SQL 复检引擎，右键人工触发）", config.phase2Enabled);
            JCheckBox cProxy = new JCheckBox("监控 Proxy 流量", config.watchProxy);
            JCheckBox cRepeater = new JCheckBox("监控 Repeater 流量", config.watchRepeater);
            JCheckBox cScanner = new JCheckBox("监控 Scanner 流量", config.watchScanner);
            // v3.9：Intruder 流量监听（默认关）。仅状态码严格 200 的完整响应进入差分扫描，
            // 201/302/404/500 等一律跳过；200 只是准入条件，判定仍走原有安全闸/差分/二阶段。
            JCheckBox cIntruder = new JCheckBox("监听 Intruder 流量（仅 200 响应）", config.watchIntruder);
            // v4.0：全部开关统一"改即生效 + 立即落盘"——不再要求用户先勾选再点应用设置。
            // 单一真相源：控件监听器写字段 → config.notifyChanged() → 扩展监听器 saveConfig。
            bindToggle(cPhase1, v -> config.phase1Enabled = v);
            bindToggle(cPhase2, v -> config.phase2Enabled = v);
            bindToggle(cProxy, v -> config.watchProxy = v);
            bindToggle(cRepeater, v -> config.watchRepeater = v);
            bindToggle(cScanner, v -> config.watchScanner = v);
            bindToggle(cIntruder, v -> config.watchIntruder = v);
            JCheckBox cJsonStrict = new JCheckBox("JSON 严格校验（变异失败禁止发送）", config.jsonStrictValidation);
            JCheckBox cTimeProbe = new JCheckBox("允许时间盲注探针·第二阶段（sleep 复验）", config.allowTimeBasedProbe);
            // v3.9.7：时间盲注延迟秒数（默认 5；2-3 秒会被系统卡顿误判）
            SpinnerNumberModel spDelay = new SpinnerNumberModel(
                    Math.max(2, Math.min(10, config.timeDelaySeconds)), 2, 10, 1);
            // v3.5：第一阶段时间探针/stacked/Oracle 三开关已随被动时间子系统移除
            // （时间盲注走右键人工触发的 Phase2 全模块序列，见 cTimeProbe 一项）。
            JCheckBox cDenyWrite = new JCheckBox("写语义接口默认拒绝", config.denyWriteLookingEndpoints);
            bindToggle(cJsonStrict, v -> config.jsonStrictValidation = v);
            bindToggle(cTimeProbe, v -> config.allowTimeBasedProbe = v);
            bindToggle(cDenyWrite, v -> config.denyWriteLookingEndpoints = v);

            // v4.0：spinner 变更即时生效（change 事件 → 写字段 → 落盘）
            SpinnerNumberModel spBaseline = new SpinnerNumberModel(config.baselineSamples, 2, 6, 1);
            SpinnerNumberModel spThreads = new SpinnerNumberModel(config.maxConcurrentScans, 1, 8, 1);
            SpinnerNumberModel spWeak = new SpinnerNumberModel(config.weakDeltaThreshold, 0, 10, 1);
            SpinnerNumberModel spRate = new SpinnerNumberModel(config.requestIntervalMs, 0, 5000, 50);
            SpinnerNumberModel spTimeout = new SpinnerNumberModel(config.requestTimeoutMs, 2000, 120000, 1000);
            SpinnerNumberModel spScore = new SpinnerNumberModel(config.minDifferenceScore * 100, 5, 100, 1);
            SpinnerNumberModel spDedup = new SpinnerNumberModel(config.dedupWindowMinutes, 0, 1440, 10);

            JTextField tfWhite = new JTextField(config.domainWhitelist, 26);
            JTextField tfBlack = new JTextField(config.urlBlacklist, 26);

            addRow(p, g, row++, cPhase1);
            addRow(p, g, row++, cPhase2);
            addRow(p, g, row++, cProxy);
            addRow(p, g, row++, cRepeater);
            addRow(p, g, row++, cScanner);
            addRow(p, g, row++, cIntruder);
            addRow(p, g, row++, cJsonStrict);
            addRow(p, g, row++, cTimeProbe);
            addRow(p, g, row++, cDenyWrite);
            addPair(p, g, row++, "基线采样次数：", new JSpinner(spBaseline));
            addPair(p, g, row++, "扫描线程数：", new JSpinner(spThreads));
            addPair(p, g, row++, "微弱长度差阈值（字节）：", new JSpinner(spWeak));
            addPair(p, g, row++, "差分通过分数（%）：", new JSpinner(spScore));
            addPair(p, g, row++, "请求间隔（ms）：", new JSpinner(spRate));
            addPair(p, g, row++, "请求超时（ms）：", new JSpinner(spTimeout));
            addPair(p, g, row++, "时间盲注延迟（秒，默认5）：", new JSpinner(spDelay));
            bindSpinner(spThreads, v -> config.maxConcurrentScans = v);
            bindSpinner(spWeak, v -> config.weakDeltaThreshold = v);
            bindSpinner(spRate, v -> config.requestIntervalMs = v);
            bindSpinner(spTimeout, v -> config.requestTimeoutMs = v);
            bindSpinner(spDedup, v -> config.dedupWindowMinutes = v);
            bindSpinner(spDelay, v -> config.timeDelaySeconds = v);
            addPair(p, g, row++, "去重窗口（分钟，0=不去重）：", new JSpinner(spDedup));
            addPair(p, g, row++, "域名白名单（逗号分隔，空=全部）：", tfWhite);
            addPair(p, g, row++, "URL 黑名单（逗号分隔）：", tfBlack);

            JButton apply = new JButton("应用设置");
            apply.addActionListener(e -> {
                config.phase1Enabled = cPhase1.isSelected();
                config.phase2Enabled = cPhase2.isSelected();
                config.watchProxy = cProxy.isSelected();
                config.watchRepeater = cRepeater.isSelected();
                config.watchScanner = cScanner.isSelected();
                config.watchIntruder = cIntruder.isSelected();
                config.jsonStrictValidation = cJsonStrict.isSelected();
                config.allowTimeBasedProbe = cTimeProbe.isSelected();
                config.denyWriteLookingEndpoints = cDenyWrite.isSelected();
                config.baselineSamples = spBaseline.getNumber().intValue();
                config.maxConcurrentScans = spThreads.getNumber().intValue();
                config.weakDeltaThreshold = spWeak.getNumber().intValue();
                config.minDifferenceScore = spScore.getNumber().intValue() / 100.0;
                config.requestIntervalMs = spRate.getNumber().intValue();
                config.requestTimeoutMs = spTimeout.getNumber().intValue();
                config.timeDelaySeconds = spDelay.getNumber().intValue();
                config.dedupWindowMinutes = spDedup.getNumber().intValue();
                config.domainWhitelist = tfWhite.getText().trim();
                config.urlBlacklist = tfBlack.getText().trim();
                for (Runnable l : applyConfigListeners) {
                    l.run();
                }
                config.notifyChanged();
                // v3.9.3：应用成功弹窗（对齐 AuthScan 页先例；含关键开关摘要）
                try {
                    javax.swing.JOptionPane.showMessageDialog(apply,
                            "设置已应用并保存（重载插件不丢失）\n\n"
                                    + "第一阶段=" + config.phase1Enabled
                                    + "  第二阶段=" + config.phase2Enabled + "\n"
                                    + "Proxy=" + config.watchProxy
                                    + "  Repeater=" + config.watchRepeater
                                    + "  Scanner=" + config.watchScanner
                                    + "  Intruder=" + config.watchIntruder + "\n"
                                    + "线程=" + config.maxConcurrentScans
                                    + "  请求间隔=" + config.requestIntervalMs + "ms\n"
                                    + "时间盲注延迟=" + config.timeDelaySeconds + "s"
                                    + "  去重窗口=" + config.dedupWindowMinutes + " 分钟",
                            "XzhScan", javax.swing.JOptionPane.INFORMATION_MESSAGE);
                } catch (Throwable ignored) {
                    // 无头环境（自动化测试）弹窗失败不影响设置写入
                }
                api.logging().logToOutput("[XzhScan] settings applied (phase1=" + config.phase1Enabled
                        + ", watchProxy=" + config.watchProxy + ", watchRepeater=" + config.watchRepeater
                        + ", watchScanner=" + config.watchScanner + ", watchIntruder=" + config.watchIntruder + ")");
            });
            addRow(p, g, row++, apply);
            return new JScrollPane(p);
        }

        /** v4.0：复选框绑定——勾选/取消立即写配置并触发落盘。 */
        private void bindToggle(JCheckBox box, java.util.function.Consumer<Boolean> setter) {
            box.addActionListener(e -> {
                setter.accept(box.isSelected());
                config.notifyChanged();
            });
        }

        /** v4.0：数字框绑定——值变更立即写配置并触发落盘。 */
        private void bindSpinner(SpinnerNumberModel model, java.util.function.IntConsumer setter) {
            model.addChangeListener(e -> {
                setter.accept(model.getNumber().intValue());
                config.notifyChanged();
            });
        }

        private void addRow(JPanel p, GridBagConstraints g, int row, JComponent c) {
            g.gridx = 0;
            g.gridy = row;
            g.gridwidth = 2;
            p.add(c, g);
        }

        private void addPair(JPanel p, GridBagConstraints g, int row, String label, JComponent c) {
            g.gridwidth = 1;
            g.gridx = 0;
            g.gridy = row;
            p.add(new JLabel(label), g);
            g.gridx = 1;
            p.add(c, g);
        }
    }

    // ================= 对外事件入口（orchestrator 回调 -> EDT） =================

    /** 实时流量页签已移除（v1.2）：后台 TrafficRecord 流程保留，这里落一行审计日志（含 §15 统计）。 */
    public void onTraffic(TrafficRecord r, String source) {
        // 差分页主表（XiaSQL 流量表）：请求行状态实时更新。
        // v3.4/v3.4.2 列表过滤：静态资源（js/css/字体/图片）、去重记录、无参数请求
        // 一律不进列表（无可测面/重复项，避免刷屏）；仍在 Burp Output 审计日志可见。
        boolean skipRow = com.xzhscan.policy.ScanPolicyEngine.isStaticResource(r.url)
                || "deduplicated".equals(r.phase1Status)
                || "no-params".equals(r.phase1Status)
                || "no-mutable-params".equals(r.phase1Status);
        // v3.9：Intruder 来源状态日志（任务要求区分安全拦截/去重跳过/队列拒绝）。
        // 三个早退分支均只回调一次，逐条输出；正常受理路径的确认已在 TrafficListener 提交时输出。
        // v3.9.2 调试增强：no-params/no-mutable-params 也是单次回调——Intruder 排障关键
        //（载荷打在路径上、Cookie/Header 参数不参与变异都会落到这里），不输出就是盲区。
        if ("INTRUDER".equals(source)) {
            String st = r.phase1Status == null ? "" : r.phase1Status;
            switch (st) {
                case "blocked-by-policy" -> log("INFO", "[Intruder] 安全规则拦截: " + r.method + " " + r.url);
                case "deduplicated" -> log("INFO", "[Intruder] 去重跳过（240min 窗口）: " + r.method + " " + r.url);
                case "queue-full" -> log("WARN", "[Intruder] 队列拒绝（已满）: " + r.method + " " + r.url);
                case "no-params", "no-mutable-params" -> log("INFO",
                        "[Intruder] 请求无可测参数（query/form/json 无可变项；Cookie/Header 不参与变异）: "
                                + r.method + " " + r.url);
                default -> {
                }
            }
        }
        edtl(() -> {
            if (gateRequestModel != null && r.requestId != null && !skipRow) {
                gateRequestModel.upsert(r.requestId, r.url);
                RequestRow row = gateRequestModel.find(r.requestId);
                if (row != null) {
                    row.source = source == null ? "" : source;
                    row.status = r.phase1Status;
                    gateRequestModel.touch(r.requestId);
                }
            }
        });
        // v3.9.3：流量流水日志（done/baseline/blocked-by-policy...）已移除——每条流量
        // 一行长日志在浏览/Intruder 场景刷屏占内存；状态在差分页主表可见，关键事件
        // （候选/复核/FOUND/Intruder 分诊/数据版发送）仍单独输出。
    }

    /**
     * 差分页观察行（v3.3 XiaSQL 形态）：全部探针逐条记录，不筛选；
     * 按请求归组，主表选中某请求时从表只显示该请求的观察。
     */
    public void onGateView(GateProbeView v) {
        if (v != null && !com.xzhscan.policy.ScanPolicyEngine.isStaticResource(v.url)) {
            dataBoardUpdate(v); // v3.9.2 数据版聚合（内部自行 edtl）
        }
        edtl(() -> {
            if (v == null || com.xzhscan.policy.ScanPolicyEngine.isStaticResource(v.url)) {
                return; // 静态资源永不进差分列表（防御：引擎层正常不会产生）
            }
            List<GateProbeView> rows = gateRowsByRequest.computeIfAbsent(v.requestId,
                    k -> java.util.Collections.synchronizedList(new ArrayList<>()));
            if (rows.size() < 5000) {
                rows.add(v);
            }
            if (gateRequestModel != null) {
                gateRequestModel.upsert(v.requestId, v.url);
                RequestRow row = gateRequestModel.find(v.requestId);
                if (row != null) {
                    if (row.baselineLen < 0 && v.baselineLen >= 0) {
                        row.baselineLen = v.baselineLen;
                    }
                    if (row.baselineEvidenceId == null) {
                        row.baselineEvidenceId = v.baselineEvidenceId;
                    }
                    gateRequestModel.touch(v.requestId);
                }
            }
            if (gateFilterRequestId == null || gateFilterRequestId.equals(v.requestId)) {
                gateModel.add(v);
            }
        });
    }

    public void onCandidate(DifferentialCandidate c) {
        storeCandidate(c); // 差分页行 -> 候选关联（证据查看/候选仓/数据版发送源）
        if (c.filterDecision == com.xzhscan.model.Models.FilterDecision.INCONCLUSIVE) {
            // v3.9.2：待定候选（黄色）也回流——数据版聚合，可一键送二阶段
            log("INFO", "候选待定(黄色): " + c.parameterPath + " score="
                    + String.format("%.2f", c.differenceScore) + " " + c.targetUrl
                    + "（已进数据版，可一键发送二阶段）");
        } else {
            log("INFO", "候选通过差分门: " + c.parameterPath + " score="
                    + String.format("%.2f", c.differenceScore) + " " + c.targetUrl
                    + "（在消息上右键\"XzhScan SQL 验证\"指定该参数复核）");
        }
    }

    /** 二次验证页签已移除（v1.2）：后台复核保留，结论并入漏洞结果页与日志。 */
    public void onVerification(VerificationResult v) {
        log("INFO", "复核 " + v.parameterPath + " @ " + v.url + ": "
                + (v.verdict == null ? v.state : v.verdict) + " (" + v.elapsedMs + "ms)");
        // v3.9.2：结论回写数据版行状态（verdict 原样英文，与漏洞页口径一致）
        if (v.verdict != null) {
            edtl(() -> {
                if (dataBoardModel != null) {
                    dataBoardModel.markVerify(v.requestId, v.parameterPath, v.verdict.name());
                    dataBoardModel.attachVerification(v); // 点行加载测试请求/响应用
                }
            });
        }
    }

    public void onFinding(DifferentialCandidate c, VerificationResult vr, InjectionFinding f) {
        edtl(() -> {
            findingModel.data.add(new FindingRow(f, c, vr));
            findingModel.fireTableRowsInserted(findingModel.data.size() - 1, findingModel.data.size() - 1);
        });
        log(f.verdict == VerifyVerdict.CONFIRMED ? "FOUND" : "INFO",
                f.verdict + " " + f.injectionType + " " + c.targetUrl + " param=" + f.parameterPath
                        + (f.dbFamily != null ? " db=" + f.dbFamily : ""));
    }

    /** 后端日志（走 Burp 扩展输出；日志 UI 页已按 v2.1 需求移除，引擎日志能力保留）。 */
    public void log(String level, String message) {
        try {
            api.logging().logToOutput("[XzhScan][" + level + "] " + message);
        } catch (Throwable ignored) {
        }
    }

    public void onApplyConfig(Runnable r) {
        applyConfigListeners.add(r);
    }
}
