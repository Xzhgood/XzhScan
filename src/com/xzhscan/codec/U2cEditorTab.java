package com.xzhscan.codec;

import burp.api.montoya.ui.editor.extension.EditorCreationContext;
import burp.api.montoya.ui.editor.extension.ExtensionProvidedHttpRequestEditor;
import burp.api.montoya.ui.editor.extension.ExtensionProvidedHttpResponseEditor;
import burp.api.montoya.ui.editor.extension.HttpRequestEditorProvider;
import burp.api.montoya.ui.editor.extension.HttpResponseEditorProvider;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.ui.Selection;

import javax.swing.*;
import java.awt.*;
import java.nio.charset.StandardCharsets;
import java.util.List;

/**
 * Chinese 中文查看页签（迁移自 gatherBurp U2CTab/U2CTabFactory，Montoya 化）。
 *
 * 全局能力：注册到 Burp 消息编辑器（请求与响应各一个 provider），
 * 每个 Burp 原生编辑器出现 "Chinese" 附签——展示 Unicode 还原/JSON 美化/
 * 字符集轮换后的只读视图。不占 XzhScan 主界面页签。
 */
public final class U2cEditorTab {

    /** 共享 UI（请求/响应复用同套组件逻辑）。 */
    private static final class Panel {
        private final JTextArea area = new JTextArea(12, 80);
        private final JComboBox<String> charsetBox = new JComboBox<>();
        private final JLabel status = new JLabel(" ");
        private byte[] currentRaw;
        private boolean currentIsResponse;
        private String detectedCharset;

        JPanel build() {
            area.setEditable(false);
            area.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
            area.setLineWrap(true);
            charsetBox.addActionListener(e -> rerender((String) charsetBox.getSelectedItem()));
            JPanel top = new JPanel(new FlowLayout(FlowLayout.LEFT, 6, 2));
            top.add(new JLabel("编码:"));
            top.add(charsetBox);
            top.add(status);
            JPanel p = new JPanel(new BorderLayout(0, 4));
            p.add(top, BorderLayout.NORTH);
            p.add(new JScrollPane(area), BorderLayout.CENTER);
            return p;
        }

        void load(byte[] raw, boolean isResponse) {
            this.currentRaw = raw;
            this.currentIsResponse = isResponse;
            detectedCharset = UnicodeCodec.detectCharset(raw, UnicodeCodec.extractCharsetParam(
                    UnicodeCodec.headerBlock(new String(raw, StandardCharsets.ISO_8859_1)), isResponse));
            charsetBox.removeAllItems();
            for (String cs : UnicodeCodec.charsetCandidates(raw, null)) {
                charsetBox.addItem(cs);
            }
            charsetBox.setSelectedItem(detectedCharset);
            rerender(detectedCharset);
        }

        private void rerender(String charset) {
            if (currentRaw == null) {
                area.setText("");
                status.setText("（无内容）");
                return;
            }
            UnicodeCodec.DisplayResult r = UnicodeCodec.buildDisplayContent(currentRaw, currentIsResponse, charset);
            area.setText(r.content());
            area.setCaretPosition(0);
            status.setText(r.json() ? "JSON 美化" : (r.transformed() ? "Unicode 已还原" : "原文"));
        }
    }

    /** 请求侧页签。 */
    public static final class RequestTab implements ExtensionProvidedHttpRequestEditor {
        private final Panel panel = new Panel();
        private final JComponent ui = panel.build();
        private HttpRequest current;

        @Override
        public HttpRequest getRequest() {
            return current;
        }

        @Override
        public void setRequestResponse(HttpRequestResponse requestResponse) {
            current = requestResponse == null ? null : requestResponse.request();
            if (current != null) {
                panel.load(current.toByteArray().getBytes(), false);
            } else {
                panel.load(null, false);
            }
        }

        @Override
        public boolean isEnabledFor(HttpRequestResponse requestResponse) {
            return true;
        }

        @Override
        public String caption() {
            return "Chinese";
        }

        @Override
        public Component uiComponent() {
            return ui;
        }

        @Override
        public Selection selectedData() {
            return null; // 只读展示，交给原生编辑器处理选区
        }

        @Override
        public boolean isModified() {
            return false;
        }
    }

    /** 响应侧页签。 */
    public static final class ResponseTab implements ExtensionProvidedHttpResponseEditor {
        private final Panel panel = new Panel();
        private final JComponent ui = panel.build();
        private HttpResponse current;

        @Override
        public HttpResponse getResponse() {
            return current;
        }

        @Override
        public void setRequestResponse(HttpRequestResponse requestResponse) {
            current = requestResponse == null ? null : requestResponse.response();
            if (current != null) {
                panel.load(current.toByteArray().getBytes(), true);
            } else {
                panel.load(null, true);
            }
        }

        @Override
        public boolean isEnabledFor(HttpRequestResponse requestResponse) {
            return true;
        }

        @Override
        public String caption() {
            return "Chinese";
        }

        @Override
        public Component uiComponent() {
            return ui;
        }

        @Override
        public Selection selectedData() {
            return null;
        }

        @Override
        public boolean isModified() {
            return false;
        }
    }

    /** 请求侧工厂。 */
    public static final class RequestProvider implements HttpRequestEditorProvider {
        @Override
        public ExtensionProvidedHttpRequestEditor provideHttpRequestEditor(EditorCreationContext context) {
            return new RequestTab();
        }
    }

    /** 响应侧工厂。 */
    public static final class ResponseProvider implements HttpResponseEditorProvider {
        @Override
        public ExtensionProvidedHttpResponseEditor provideHttpResponseEditor(EditorCreationContext context) {
            return new ResponseTab();
        }
    }

    private U2cEditorTab() {
    }
}
