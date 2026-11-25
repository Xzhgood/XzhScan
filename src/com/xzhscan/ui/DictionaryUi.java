package com.xzhscan.ui;

import com.xzhscan.dictionary.DictEntry;
import com.xzhscan.dictionary.InfoGenerator;
import com.xzhscan.dictionary.PathDict;
import com.xzhscan.dictionary.WeakPasswordGenerator;
import com.xzhscan.dictionary.XssDict;

import javax.swing.BorderFactory;
import javax.swing.DefaultListModel;
import javax.swing.JButton;
import javax.swing.JComboBox;
import javax.swing.JComponent;
import javax.swing.JLabel;
import javax.swing.JList;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JSplitPane;
import javax.swing.JTabbedPane;
import javax.swing.JTextArea;
import javax.swing.JTextField;
import javax.swing.ListSelectionModel;
import java.awt.BorderLayout;
import java.awt.Dimension;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.Insets;
import java.awt.Toolkit;
import java.awt.datatransfer.StringSelection;
import java.awt.event.ActionListener;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

/**
 * Dictionary 页签：渗透字典与生成器速查（四子页）。
 *
 *  - XSS字典：实战 payload（分组 + 原始备注）；
 *  - 路径字典：文件读取/路径穿越 payload（原版扫描器全量 45 条，四类目标文件）；
 *  - 信息生成：随机姓名/手机号/身份证/信用代码/组织机构代码/银行卡；
 *  - 字典生成：十关键字段弱口令组合字典 + top100。
 *
 * 通用字典面板 = 分类过滤 + 搜索 + 条目列表 + 详情正文 + 一键复制。零 Burp 依赖。
 */
public final class DictionaryUi {

    /** 构建 Dictionary 主面板（EDT 调用）。 */
    public JTabbedPane build() {
        JTabbedPane tabs = new JTabbedPane();
        tabs.addTab("XSS字典", dictPanel(XssDict.all(), false));
        tabs.addTab("路径字典", dictPanel(pathEntries(), false));
        tabs.addTab("信息生成", buildInfoPanel());
        tabs.addTab("字典生成", buildWeakPwdPanel());
        return tabs;
    }

    /**
     * URL 空格编码：空格 → %20。
     * Burp GET 参数里裸空格会被截断/丢弃，SQL payload 需编码后直接粘贴；
     * POST/JSON 场景仍可复制详情区的原始形态。
     */
    public static String urlSpaceEncode(String s) {
        return s == null ? "" : s.replace(" ", "%20");
    }

    // ================= 通用字典面板 =================

    /** 文件读取/路径穿越 payload → 条目（原版文件读取扫描器四组，共 45 条）。 */
    private static List<DictEntry> pathEntries() {
        List<DictEntry> out = new ArrayList<>();
        for (String s : splitDict(PathDict.LINUX_PASSWD)) {
            out.add(new DictEntry("Linux·文件读取", s, s, "任意文件读取 /etc/passwd（含 ../、%2e%2e、%252f、%uXXXX 等绕过）"));
        }
        for (String s : splitDict(PathDict.WINDOWS_WINI)) {
            out.add(new DictEntry("Windows·文件读取", s, s, "任意文件读取 Windows/win.ini（含反斜杠、%5c、%u2216 等绕过）"));
        }
        for (String s : splitDict(PathDict.JAVA_WEB_XML)) {
            out.add(new DictEntry("Java Web·配置读取", s, s, "WEB-INF/web.xml 读取（Java 应用信息泄露）"));
        }
        for (String s : splitDict(PathDict.SPECIAL)) {
            out.add(new DictEntry("特殊·路径穿越", s, s, "http:/ 前缀特殊穿越形态"));
        }
        return out;
    }

    private static List<String> splitDict(String data) {
        List<String> out = new ArrayList<>();
        for (String s : data.split("#")) {
            if (!s.isEmpty()) {
                out.add(s);
            }
        }
        return out;
    }

    private JComponent dictPanel(List<DictEntry> entries, boolean appendUrlEncoded) {
        List<String> cats = new ArrayList<>();
        for (DictEntry e : entries) {
            if (!cats.contains(e.category())) {
                cats.add(e.category());
            }
        }

        JPanel root = new JPanel(new BorderLayout(6, 6));
        root.setBorder(BorderFactory.createEmptyBorder(6, 8, 8, 8));

        // ---- 顶部工具条：分类 + 搜索 ----
        JPanel top = new JPanel(new GridBagLayout());
        GridBagConstraints g = new GridBagConstraints();
        g.insets = new Insets(0, 4, 0, 4);
        g.gridy = 0;
        g.gridx = 0;
        JComboBox<String> catBox = new JComboBox<>();
        catBox.addItem("全部分类");
        for (String c : cats) {
            catBox.addItem(c);
        }
        top.add(new JLabel("分类:"), g);
        g.gridx = 1;
        top.add(catBox, g);
        g.gridx = 2;
        top.add(new JLabel("搜索:"), g);
        g.gridx = 3;
        g.weightx = 1.0;
        g.fill = GridBagConstraints.HORIZONTAL;
        JTextField search = new JTextField(20);
        top.add(search, g);
        g.gridx = 4;
        g.weightx = 0;
        g.fill = GridBagConstraints.NONE;
        JButton copyBtn = new JButton("复制正文");
        top.add(copyBtn, g);
        g.gridx = 5;
        JLabel countLabel = new JLabel("0 条");
        top.add(countLabel, g);
        root.add(top, BorderLayout.NORTH);

        // ---- 列表 + 详情 ----
        DefaultListModel<String> model = new DefaultListModel<>();
        JList<String> list = new JList<>(model);
        list.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        JTextArea detail = new JTextArea();
        detail.setEditable(false);
        detail.setLineWrap(true);
        detail.setWrapStyleWord(true);
        detail.setBorder(BorderFactory.createTitledBorder("正文（选中条目后复制）"));
        JScrollPane detailScroll = new JScrollPane(detail);
        detailScroll.setPreferredSize(new Dimension(200, 160));

        List<DictEntry> visible = new ArrayList<>();
        Runnable refilter = () -> {
            String cat = (String) catBox.getSelectedItem();
            String q = search.getText().trim().toLowerCase(Locale.ROOT);
            visible.clear();
            model.clear();
            for (DictEntry e : entries) {
                if (!"全部分类".equals(cat) && !cat.equals(e.category())) {
                    continue;
                }
                if (!q.isEmpty() && !e.label().toLowerCase(Locale.ROOT).contains(q)
                        && !e.body().toLowerCase(Locale.ROOT).contains(q)
                        && !e.category().toLowerCase(Locale.ROOT).contains(q)) {
                    continue;
                }
                visible.add(e);
            }
            for (DictEntry e : visible) {
                String shown = e.category().equals(e.label()) ? e.label() : "[" + e.category() + "] " + e.label();
                model.addElement(shown);
            }
            countLabel.setText(visible.size() + " 条");
            detail.setText("");
        };
        refilter.run();
        catBox.addActionListener(e -> refilter.run());
        search.getDocument().addDocumentListener(new javax.swing.event.DocumentListener() {
            @Override public void insertUpdate(javax.swing.event.DocumentEvent e) {
                refilter.run();
            }
            @Override public void removeUpdate(javax.swing.event.DocumentEvent e) {
                refilter.run();
            }
            @Override public void changedUpdate(javax.swing.event.DocumentEvent e) {
                refilter.run();
            }
        });

        list.addListSelectionListener(e -> {
            if (e.getValueIsAdjusting()) {
                return;
            }
            int idx = list.getSelectedIndex();
            if (idx < 0 || idx >= visible.size()) {
                return;
            }
            DictEntry d = visible.get(idx);
            StringBuilder sb = new StringBuilder(d.body());
            if (!d.note().isEmpty()) {
                sb.append("\n\n# 备注: ").append(d.note());
            }
            if (appendUrlEncoded && !d.label().startsWith("说明")) {
                sb.append("\n\n# URL 空格编码版（空格→%20，可直接粘贴 Burp GET 参数）:\n")
                        .append(urlSpaceEncode(d.body()));
            }
            detail.setText(sb.toString());
            detail.setCaretPosition(0);
        });

        copyBtn.addActionListener(e -> copyToClipboard(detail.getText()));

        JSplitPane split = new JSplitPane(JSplitPane.VERTICAL_SPLIT,
                new JScrollPane(list), detailScroll);
        split.setResizeWeight(0.62);
        root.add(split, BorderLayout.CENTER);
        return root;
    }

    // ================= 信息生成 =================

    /** 信息生成子页：左侧按钮列 + 右侧输出区。 */
    private JComponent buildInfoPanel() {
        JPanel root = new JPanel(new BorderLayout(6, 6));
        root.setBorder(BorderFactory.createEmptyBorder(6, 8, 8, 8));

        JPanel left = new JPanel(new GridBagLayout());
        GridBagConstraints g = new GridBagConstraints();
        g.gridx = 0;
        g.gridy = 0;
        g.fill = GridBagConstraints.HORIZONTAL;
        g.insets = new Insets(2, 2, 2, 6);

        JTextArea output = new JTextArea();
        output.setEditable(false);
        output.setLineWrap(true);
        output.setBorder(BorderFactory.createTitledBorder("生成结果（选中复制 / 按钮）"));

        Runnable[] gens = {
                () -> appendInfo(output, InfoGenerator.generateAll()),
                () -> appendInfo(output, List.of(new InfoGenerator.Info("姓名", InfoGenerator.randomName(), ""))),
                () -> appendInfo(output, List.of(InfoGenerator.randomPhone())),
                () -> appendInfo(output, List.of(InfoGenerator.randomIdCard())),
                () -> appendInfo(output, List.of(InfoGenerator.randomCreditCode())),
                () -> appendInfo(output, List.of(InfoGenerator.randomOrgCode())),
                () -> appendInfo(output, List.of(InfoGenerator.randomBankCard())),
        };
        String[] labels = {"生成全部（各一条）", "生成姓名", "生成手机号", "生成身份证",
                "生成信用代码", "生成组织机构", "生成银行卡"};
        for (int i = 0; i < gens.length; i++) {
            final int idx = i;
            JButton b = new JButton(labels[i]);
            b.addActionListener(e -> gens[idx].run());
            left.add(b, g);
            g.gridy++;
        }
        JButton batch = new JButton("批量生成 100 套");
        batch.addActionListener(e -> {
            StringBuilder sb = new StringBuilder();
            for (int i = 0; i < 100; i++) {
                sb.append("---- 第 ").append(i + 1).append(" 套 ----\n");
                appendPairs(sb, InfoGenerator.generateAll());
            }
            output.setText(sb.toString());
            output.setCaretPosition(0);
        });
        left.add(batch, g);
        g.gridy++;
        g.weighty = 1.0;
        g.fill = GridBagConstraints.VERTICAL;
        left.add(new JPanel(), g);

        JPanel btnRow = new JPanel(new java.awt.FlowLayout(java.awt.FlowLayout.RIGHT));
        btnRow.add(button("复制", e -> copyToClipboard(output.getText())));
        btnRow.add(button("清空", e -> output.setText("")));
        JPanel right = new JPanel(new BorderLayout(0, 4));
        right.add(new JScrollPane(output), BorderLayout.CENTER);
        right.add(btnRow, BorderLayout.SOUTH);

        JSplitPane split = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT, left, right);
        split.setResizeWeight(0.18);
        root.add(split, BorderLayout.CENTER);
        return root;
    }

    private static void appendInfo(JTextArea output, List<InfoGenerator.Info> infos) {
        StringBuilder sb = new StringBuilder(output.getText());
        if (sb.length() > 0 && !sb.toString().endsWith("\n")) {
            sb.append('\n');
        }
        appendPairs(sb, infos);
        output.setText(sb.toString());
        output.setCaretPosition(output.getDocument().getLength());
    }

    private static void appendPairs(StringBuilder sb, List<InfoGenerator.Info> infos) {
        for (InfoGenerator.Info info : infos) {
            sb.append(info.type()).append(": ").append(info.value());
            if (!info.note().isEmpty()) {
                sb.append("  (# ").append(info.note()).append(")");
            }
            sb.append('\n');
        }
    }

    // ================= 字典生成 =================

    /** 字典生成子页：十关键字段输入 + 组合展开 + top100。 */
    private JComponent buildWeakPwdPanel() {
        JPanel root = new JPanel(new BorderLayout(6, 6));
        root.setBorder(BorderFactory.createEmptyBorder(6, 8, 8, 8));

        JPanel form = new JPanel(new GridBagLayout());
        GridBagConstraints g = new GridBagConstraints();
        g.insets = new Insets(2, 4, 2, 4);
        Map<String, JTextField> inputs = new LinkedHashMap<>();
        for (int i = 0; i < WeakPasswordGenerator.INPUT_KEYS.length; i++) {
            g.gridx = i % 2 * 2;
            g.gridy = i / 2;
            g.weightx = i % 2 == 0 ? 0 : 1.0;
            g.fill = i % 2 == 0 ? GridBagConstraints.NONE : GridBagConstraints.HORIZONTAL;
            String key = WeakPasswordGenerator.INPUT_KEYS[i];
            form.add(new JLabel(key + ":"), g);
            JTextField tf = new JTextField(14);
            inputs.put(key, tf);
            g.gridx++;
            form.add(tf, g);
        }

        JLabel countLabel = new JLabel("未生成");
        JTextArea output = new JTextArea();
        output.setEditable(false);
        output.setLineWrap(true);
        output.setBorder(BorderFactory.createTitledBorder("字典结果（复制后导入爆破工具）"));

        JButton gen = new JButton("生成字典");
        gen.addActionListener(e -> {
            Map<String, String> vals = new LinkedHashMap<>();
            for (Map.Entry<String, JTextField> en : inputs.entrySet()) {
                vals.put(en.getKey(), en.getValue().getText().trim());
            }
            List<String> dict = WeakPasswordGenerator.generate(vals);
            output.setText(String.join("\n", dict));
            output.setCaretPosition(0);
            countLabel.setText("一共生成：" + dict.size() + " 条字典！");
        });

        JPanel top = new JPanel(new BorderLayout(8, 4));
        top.add(form, BorderLayout.CENTER);
        JPanel genRow = new JPanel(new java.awt.FlowLayout(java.awt.FlowLayout.RIGHT));
        genRow.add(countLabel);
        genRow.add(gen);
        genRow.add(button("复制", e -> copyToClipboard(output.getText())));
        genRow.add(button("清空", e -> {
            output.setText("");
            countLabel.setText("未生成");
        }));
        top.add(genRow, BorderLayout.SOUTH);

        JSplitPane split = new JSplitPane(JSplitPane.VERTICAL_SPLIT, top, new JScrollPane(output));
        split.setResizeWeight(0.35);
        root.add(split, BorderLayout.CENTER);
        return root;
    }

    // ================= 公共 =================

    private static JButton button(String text, ActionListener l) {
        JButton b = new JButton(text);
        b.addActionListener(l);
        return b;
    }

    private static void copyToClipboard(String text) {
        if (text != null && !text.isEmpty()) {
            Toolkit.getDefaultToolkit().getSystemClipboard()
                    .setContents(new StringSelection(text), null);
        }
    }
}
