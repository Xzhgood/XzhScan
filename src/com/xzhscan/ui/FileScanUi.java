package com.xzhscan.ui;

import burp.api.montoya.MontoyaApi;
import com.xzhscan.burp.BurpTransport;
import com.xzhscan.filescan.FileScanEngine;
import com.xzhscan.filescan.FileScanResult;

import javax.swing.*;
import javax.swing.table.AbstractTableModel;
import java.awt.*;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;

/**
 * FileScan UI - 文件读取扫描界面
 * 顶级页签，和 SQLScan 同等级
 */
public class FileScanUi {
    private final MontoyaApi api;
    private final FileScanEngine engine;
    private final ResultTableModel resultModel;

    public FileScanUi(MontoyaApi api, com.xzhscan.model.RawHttp.Transport transport) {  // 修复：使用 Transport
        this.api = api;
        this.engine = new FileScanEngine(transport);
        this.resultModel = new ResultTableModel();

        // 设置回调：引擎发现漏洞时通知 UI
        engine.setCallback(result -> {
            SwingUtilities.invokeLater(() -> {
                resultModel.addResult(result);
                log("FOUND", "文件读取: " + result.hitType + " " + result.url + " param=" + result.parameterName);
            });
        });
    }

    public JPanel build() {
        JPanel panel = new JPanel(new BorderLayout());

        // 顶部：控制按钮
        JPanel topPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        JCheckBox enableBox = new JCheckBox("启用被动扫描", engine.isEnabled());
        enableBox.addActionListener(e -> {
            engine.setEnabled(enableBox.isSelected());
            log("INFO", "FileScan 被动扫描：" + (enableBox.isSelected() ? "已启用" : "已禁用"));
        });
        topPanel.add(enableBox);

        JButton clearBtn = new JButton("清空结果");
        clearBtn.addActionListener(e -> {
            resultModel.clear();
            log("INFO", "已清空 FileScan 结果");
        });
        topPanel.add(clearBtn);

        JLabel countLabel = new JLabel("0 条");
        topPanel.add(new JLabel("   结果: "));
        topPanel.add(countLabel);

        // 中间：结果表格
        JTable table = new JTable(resultModel);
        table.setAutoCreateRowSorter(true);
        table.getColumnModel().getColumn(0).setPreferredWidth(300);  // URL
        table.getColumnModel().getColumn(1).setPreferredWidth(60);   // 方法
        table.getColumnModel().getColumn(2).setPreferredWidth(100);  // 参数
        table.getColumnModel().getColumn(3).setPreferredWidth(150);  // 文件类型
        table.getColumnModel().getColumn(4).setPreferredWidth(200);  // Payload
        table.getColumnModel().getColumn(5).setPreferredWidth(100);  // 时间

        JScrollPane scrollPane = new JScrollPane(table);

        // 更新计数
        resultModel.addTableModelListener(e -> {
            countLabel.setText(resultModel.getRowCount() + " 条");
        });

        panel.add(topPanel, BorderLayout.NORTH);
        panel.add(scrollPane, BorderLayout.CENTER);

        return panel;
    }

    public FileScanEngine getEngine() {
        return engine;
    }

    private void log(String level, String message) {
        try {
            api.logging().logToOutput("[XzhScan][FileScan][" + level + "] " + message);
        } catch (Throwable ignored) {
        }
    }

    /** 结果表格模型 */
    static class ResultTableModel extends AbstractTableModel {
        private final String[] columns = {"URL", "方法", "参数", "文件类型", "Payload", "时间"};
        private final List<FileScanResult> results = new CopyOnWriteArrayList<>();

        void addResult(FileScanResult result) {
            results.add(result);
            fireTableRowsInserted(results.size() - 1, results.size() - 1);
        }

        void clear() {
            results.clear();
            fireTableDataChanged();
        }

        @Override
        public int getRowCount() {
            return results.size();
        }

        @Override
        public int getColumnCount() {
            return columns.length;
        }

        @Override
        public String getColumnName(int column) {
            return columns[column];
        }

        @Override
        public Object getValueAt(int row, int column) {
            if (row >= results.size()) return "";
            FileScanResult r = results.get(row);
            return switch (column) {
                case 0 -> r.url;
                case 1 -> r.method;
                case 2 -> r.parameterName;
                case 3 -> r.hitType;
                case 4 -> r.payload.length() > 50 ? r.payload.substring(0, 50) + "..." : r.payload;
                case 5 -> new java.text.SimpleDateFormat("HH:mm:ss").format(new java.util.Date(r.timestamp));
                default -> "";
            };
        }
    }
}
