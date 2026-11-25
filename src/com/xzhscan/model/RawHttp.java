package com.xzhscan.model;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * 引擎层自有的最小 HTTP 抽象：engine/parameter/differential 各模块一律通过它收发请求，
 * 不直接依赖 Burp Montoya API。Burp 适配层负责 RawRequest/Response 与 Montoya 对象互转，
 * 单元测试注入 FakeTransport 即可离线运行全部检测逻辑。
 */
public final class RawHttp {

    private RawHttp() {
    }

    /** 与传输实现无关的请求描述。 */
    public static final class RawRequest {
        public final String method;
        /** 完整 URL，含查询串。 */
        public final String url;
        /** 有序列表，形如 "Name: value"；不含 Content-Length（发送时由传输层重算）。 */
        public final List<String> headers;
        public final byte[] body;

        public RawRequest(String method, String url, List<String> headers, byte[] body) {
            this.method = method == null || method.isEmpty() ? "GET" : method;
            this.url = url;
            this.headers = headers == null ? new ArrayList<>() : new ArrayList<>(headers);
            this.body = body == null ? new byte[0] : body;
        }

        public String bodyAsString() {
            return new String(body, StandardCharsets.UTF_8);
        }

        public RawRequest withBody(byte[] newBody) {
            return new RawRequest(method, url, headers, newBody);
        }

        public String headerValue(String name) {
            String ln = name.toLowerCase();
            for (String h : headers) {
                int c = h.indexOf(':');
                if (c > 0 && h.substring(0, c).trim().toLowerCase().equals(ln)) {
                    return h.substring(c + 1).trim();
                }
            }
            return null;
        }

        @Override
        public String toString() {
            return method + " " + url + " (" + body.length + "-byte body)";
        }
    }

    /** 传输层响应。 */
    public static final class RawResponse {
        public final int statusCode;
        public final Map<String, String> headers;
        public final byte[] body;
        /** 传输层记录的耗时 ms；不可用时为 -1。 */
        public final long elapsedMs;

        public RawResponse(int statusCode, Map<String, String> headers, byte[] body, long elapsedMs) {
            this.statusCode = statusCode;
            this.headers = headers == null ? new LinkedHashMap<>() : headers;
            this.body = body == null ? new byte[0] : body;
            this.elapsedMs = elapsedMs;
        }

        public int length() {
            return body.length;
        }

        public String bodyAsString() {
            // 修复中文乱码：从 Content-Type 读取 charset
            String contentType = header("Content-Type");
            if (contentType != null) {
                String charset = extractCharset(contentType);
                if (charset != null) {
                    try {
                        return new String(body, charset);
                    } catch (Exception e) {
                        // 如果编码不支持，回退到 UTF-8
                    }
                }
            }
            // 默认 UTF-8
            return new String(body, StandardCharsets.UTF_8);
        }

        private String extractCharset(String contentType) {
            String lower = contentType.toLowerCase();
            int idx = lower.indexOf("charset=");
            if (idx < 0) return null;
            // 从原始字符串提取（保持大小写），但索引来自小写版本
            String charset = contentType.substring(idx + 8).trim();
            int semicolon = charset.indexOf(';');
            if (semicolon > 0) {
                charset = charset.substring(0, semicolon);
            }
            int space = charset.indexOf(' ');
            if (space > 0) {
                charset = charset.substring(0, space);
            }
            charset = charset.replace("\"", "").replace("'", "").trim();
            return charset.isEmpty() ? null : charset;
        }

        public String header(String name) {
            return headers.get(name.toLowerCase());
        }
    }

    /** 发送接口：Burp 实现 + 测试 Fake 实现共用。实现必须自行保证速率限制与超时。 */
    public interface Transport {
        RawResponse send(RawRequest request) throws Exception;

        /**
         * 带单次超时的发送（v2.2.2：时间盲注探针的延迟可能被逐行放大——如
         * xor sleep(6) 在 7 行表上 = 42s——必须允许超过 requestTimeoutMs 的预算；
         * 默认实现忽略 timeoutMs（Fake/测试传输不受影响）。
         */
        default RawResponse send(RawRequest request, long timeoutMs) throws Exception {
            return send(request);
        }
    }
}
