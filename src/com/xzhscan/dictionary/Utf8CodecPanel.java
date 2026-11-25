package com.xzhscan.dictionary;

import javax.swing.*;
import javax.swing.border.TitledBorder;
import java.awt.*;
import java.awt.datatransfer.StringSelection;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.net.URLEncoder;
import java.net.URLDecoder;

/**
 * UTF-8 编解码工具面板（移植自 DetSql CodeToolPanel）
 * <p>
 * 解决问题：Burp Suite 自带的 Decoder 在处理中文时会出现乱码。
 * 本工具基于 UTF-8 编码，可正确处理中文字符。
 * <p>
 * 功能：
 * 1. Base64 编解码（UTF-8）
 * 2. URL 编解码（UTF-8）
 * 3. Unicode 编解码（Unicode 转义格式）
 * 4. JSON 格式化
 */
public class Utf8CodecPanel extends JPanel {

    private final JTextArea inputArea;
    private final JTextArea outputArea;

    public Utf8CodecPanel() {
        setLayout(new BorderLayout(10, 10));
        setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));

        // 输入区域
        JPanel inputPanel = new JPanel(new BorderLayout());
        inputPanel.setBorder(new TitledBorder("输入"));
        inputArea = new JTextArea(10, 50);
        inputArea.setLineWrap(true);
        inputArea.setWrapStyleWord(true);
        inputArea.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 13));
        inputPanel.add(new JScrollPane(inputArea), BorderLayout.CENTER);

        // 输出区域
        JPanel outputPanel = new JPanel(new BorderLayout());
        outputPanel.setBorder(new TitledBorder("输出"));
        outputArea = new JTextArea(10, 50);
        outputArea.setLineWrap(true);
        outputArea.setWrapStyleWord(true);
        outputArea.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 13));
        outputPanel.add(new JScrollPane(outputArea), BorderLayout.CENTER);

        // 按钮区域
        JPanel buttonPanel = createButtonPanel();

        // 布局
        JSplitPane splitPane = new JSplitPane(JSplitPane.VERTICAL_SPLIT, inputPanel, outputPanel);
        splitPane.setDividerLocation(200);
        splitPane.setResizeWeight(0.5);

        add(splitPane, BorderLayout.CENTER);
        add(buttonPanel, BorderLayout.SOUTH);
    }

    private JPanel createButtonPanel() {
        JPanel panel = new JPanel(new FlowLayout(FlowLayout.LEFT, 5, 5));

        // Base64 编解码
        JButton base64EncodeBtn = new JButton("Base64 编码");
        base64EncodeBtn.addActionListener(e -> base64Encode());
        panel.add(base64EncodeBtn);

        JButton base64DecodeBtn = new JButton("Base64 解码");
        base64DecodeBtn.addActionListener(e -> base64Decode());
        panel.add(base64DecodeBtn);

        panel.add(new JSeparator(SwingConstants.VERTICAL));

        // URL 编解码
        JButton urlEncodeBtn = new JButton("URL 编码");
        urlEncodeBtn.addActionListener(e -> urlEncode());
        panel.add(urlEncodeBtn);

        JButton urlDecodeBtn = new JButton("URL 解码");
        urlDecodeBtn.addActionListener(e -> urlDecode());
        panel.add(urlDecodeBtn);

        panel.add(new JSeparator(SwingConstants.VERTICAL));

        // Unicode 编解码
        JButton unicodeEncodeBtn = new JButton("Unicode 编码");
        unicodeEncodeBtn.addActionListener(e -> unicodeEncode());
        panel.add(unicodeEncodeBtn);

        JButton unicodeDecodeBtn = new JButton("Unicode 解码");
        unicodeDecodeBtn.addActionListener(e -> unicodeDecode());
        panel.add(unicodeDecodeBtn);

        panel.add(new JSeparator(SwingConstants.VERTICAL));

        // JSON 格式化
        JButton jsonFormatBtn = new JButton("JSON 格式化");
        jsonFormatBtn.addActionListener(e -> jsonFormat());
        panel.add(jsonFormatBtn);

        panel.add(new JSeparator(SwingConstants.VERTICAL));

        // 工具按钮
        JButton clearBtn = new JButton("清空");
        clearBtn.addActionListener(e -> {
            inputArea.setText("");
            outputArea.setText("");
        });
        panel.add(clearBtn);

        JButton copyBtn = new JButton("复制输出");
        copyBtn.addActionListener(e -> {
            String output = outputArea.getText();
            if (!output.isEmpty()) {
                Toolkit.getDefaultToolkit().getSystemClipboard()
                        .setContents(new StringSelection(output), null);
                JOptionPane.showMessageDialog(this, "已复制到剪贴板", "提示", JOptionPane.INFORMATION_MESSAGE);
            }
        });
        panel.add(copyBtn);

        JButton swapBtn = new JButton("交换输入输出");
        swapBtn.addActionListener(e -> {
            String temp = inputArea.getText();
            inputArea.setText(outputArea.getText());
            outputArea.setText(temp);
        });
        panel.add(swapBtn);

        return panel;
    }

    // ==================== Base64 ====================

    private void base64Encode() {
        String input = inputArea.getText();
        if (input.isEmpty()) {
            outputArea.setText("");
            return;
        }
        try {
            byte[] bytes = input.getBytes(StandardCharsets.UTF_8);
            String encoded = Base64.getEncoder().encodeToString(bytes);
            outputArea.setText(encoded);
        } catch (Exception e) {
            outputArea.setText("编码失败: " + e.getMessage());
        }
    }

    private void base64Decode() {
        String input = inputArea.getText().trim();
        if (input.isEmpty()) {
            outputArea.setText("");
            return;
        }
        try {
            byte[] bytes = Base64.getDecoder().decode(input);
            String decoded = new String(bytes, StandardCharsets.UTF_8);
            outputArea.setText(decoded);
        } catch (Exception e) {
            outputArea.setText("解码失败: " + e.getMessage());
        }
    }

    // ==================== URL ====================

    private void urlEncode() {
        String input = inputArea.getText();
        if (input.isEmpty()) {
            outputArea.setText("");
            return;
        }
        try {
            String encoded = URLEncoder.encode(input, StandardCharsets.UTF_8);
            outputArea.setText(encoded);
        } catch (Exception e) {
            outputArea.setText("编码失败: " + e.getMessage());
        }
    }

    private void urlDecode() {
        String input = inputArea.getText().trim();
        if (input.isEmpty()) {
            outputArea.setText("");
            return;
        }
        try {
            String decoded = URLDecoder.decode(input, StandardCharsets.UTF_8);
            outputArea.setText(decoded);
        } catch (Exception e) {
            outputArea.setText("解码失败: " + e.getMessage());
        }
    }

    // ==================== Unicode ====================

    private void unicodeEncode() {
        String input = inputArea.getText();
        if (input.isEmpty()) {
            outputArea.setText("");
            return;
        }
        StringBuilder sb = new StringBuilder();
        for (char c : input.toCharArray()) {
            if (c < 128) {
                sb.append(c);
            } else {
                sb.append(String.format("\\u%04x", (int) c));
            }
        }
        outputArea.setText(sb.toString());
    }

    private void unicodeDecode() {
        String input = inputArea.getText().trim();
        if (input.isEmpty()) {
            outputArea.setText("");
            return;
        }
        try {
            StringBuilder sb = new StringBuilder();
            int i = 0;
            while (i < input.length()) {
                if (input.charAt(i) == '\\' && i + 1 < input.length() && input.charAt(i + 1) == 'u') {
                    // Unicode 转义格式
                    if (i + 5 < input.length()) {
                        String hex = input.substring(i + 2, i + 6);
                        int code = Integer.parseInt(hex, 16);
                        sb.append((char) code);
                        i += 6;
                    } else {
                        sb.append(input.charAt(i));
                        i++;
                    }
                } else {
                    sb.append(input.charAt(i));
                    i++;
                }
            }
            outputArea.setText(sb.toString());
        } catch (Exception e) {
            outputArea.setText("解码失败: " + e.getMessage());
        }
    }

    // ==================== JSON ====================

    private void jsonFormat() {
        String input = inputArea.getText().trim();
        if (input.isEmpty()) {
            outputArea.setText("");
            return;
        }
        try {
            // 简单的 JSON 格式化（使用 XzhScan 现有的 MiniJson）
            com.xzhscan.parameter.MiniJson.JsonValue json = com.xzhscan.parameter.MiniJson.parse(input);
            String formatted = formatJson(json, 0);
            outputArea.setText(formatted);
        } catch (Exception e) {
            outputArea.setText("格式化失败: " + e.getMessage());
        }
    }

    private String formatJson(com.xzhscan.parameter.MiniJson.JsonValue value, int indent) {
        String indentStr = "  ".repeat(indent);
        String indentStr2 = "  ".repeat(indent + 1);

        if (value instanceof com.xzhscan.parameter.MiniJson.JsonObject obj) {
            if (obj.members().isEmpty()) {
                return "{}";
            }
            StringBuilder sb = new StringBuilder("{\n");
            var entries = obj.members().entrySet().iterator();
            while (entries.hasNext()) {
                var entry = entries.next();
                sb.append(indentStr2).append("\"").append(entry.getKey()).append("\": ");
                sb.append(formatJson(entry.getValue(), indent + 1));
                if (entries.hasNext()) {
                    sb.append(",");
                }
                sb.append("\n");
            }
            sb.append(indentStr).append("}");
            return sb.toString();
        } else if (value instanceof com.xzhscan.parameter.MiniJson.JsonArray arr) {
            if (arr.items().isEmpty()) {
                return "[]";
            }
            StringBuilder sb = new StringBuilder("[\n");
            var items = arr.items().iterator();
            while (items.hasNext()) {
                sb.append(indentStr2).append(formatJson(items.next(), indent + 1));
                if (items.hasNext()) {
                    sb.append(",");
                }
                sb.append("\n");
            }
            sb.append(indentStr).append("]");
            return sb.toString();
        } else if (value instanceof com.xzhscan.parameter.MiniJson.JsonString str) {
            return "\"" + str.value() + "\"";
        } else if (value instanceof com.xzhscan.parameter.MiniJson.JsonNumber num) {
            return num.rawToken();
        } else if (value instanceof com.xzhscan.parameter.MiniJson.JsonBool bool) {
            return String.valueOf(bool.value());
        } else if (value instanceof com.xzhscan.parameter.MiniJson.JsonNull) {
            return "null";
        }
        return value.toString();
    }
}
