package com.xzhscan.model;

import com.xzhscan.model.RawHttp.RawRequest;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

/**
 * 请求报文构造纯函数（不依赖 Burp API，可离线 + Mock HTTP 服务验证）。
 *
 * 规则：
 *  - 头顺序保留，仅 Content-Length 重算（与修改后正文严格一致）；
 *  - 缺 Host 时按 URL 补；
 *  - 请求行 = method + path(含 query) + HTTP/1.1；
 *  - 头用 ISO-8859-1 拼装（ASCII 安全），body 原字节拼接 —— 二进制安全。
 * BurpTransport.build 委托本类；单测用本地 HttpServer 直接收字节比对。
 */
public final class RawHttpRequests {

    private RawHttpRequests() {
    }

    /** 构造完整原始请求字节（含重算后的 Content-Length）。 */
    public static byte[] buildRaw(RawRequest request, String host, int port, boolean secure) {
        StringBuilder head = new StringBuilder(256);
        head.append(request.method).append(' ').append(pathOf(request.url)).append(" HTTP/1.1\r\n");
        boolean hasHost = false;
        for (String h : request.headers) {
            int c = h.indexOf(':');
            if (c <= 0) {
                continue;
            }
            String name = h.substring(0, c).trim();
            if (name.equalsIgnoreCase("Content-Length")) {
                continue; // 始终重算，杜绝与正文不一致
            }
            if (name.equalsIgnoreCase("Host")) {
                hasHost = true;
            }
            head.append(h.trim()).append("\r\n");
        }
        if (!hasHost) {
            boolean defaultPort = (secure && port == 443) || (!secure && port == 80);
            head.append("Host: ").append(host).append(defaultPort ? "" : ":" + port).append("\r\n");
        }
        head.append("Content-Length: ").append(request.body.length).append("\r\n");
        head.append("\r\n");
        byte[] headBytes = head.toString().getBytes(StandardCharsets.ISO_8859_1);
        byte[] raw = new byte[headBytes.length + request.body.length];
        System.arraycopy(headBytes, 0, raw, 0, headBytes.length);
        System.arraycopy(request.body, 0, raw, headBytes.length, request.body.length);
        return raw;
    }

    /** 从 URL 提取 path?query（无则 "/"）。 */
    public static String pathOf(String url) {
        int scheme = url.indexOf("://");
        int start = url.indexOf('/', scheme >= 0 ? scheme + 3 : 0);
        return start < 0 ? "/" : url.substring(start);
    }

    /** 提取 host（供 buildRaw 调用方解析 URL 用）。 */
    public static String hostOf(String url) {
        int scheme = url.indexOf("://");
        int start = scheme >= 0 ? scheme + 3 : 0;
        int slash = url.indexOf('/', start);
        String hostPort = slash >= 0 ? url.substring(0, slash) : url;
        int colon = hostPort.lastIndexOf(':');
        return colon > 0 ? hostPort.substring(0, colon) : hostPort;
    }

    /** 提取端口（默认 80/443）。 */
    public static int portOf(String url) {
        boolean secure = url.toLowerCase().startsWith("https://");
        int scheme = url.indexOf("://");
        int start = scheme >= 0 ? scheme + 3 : 0;
        int slash = url.indexOf('/', start);
        String hostPort = slash >= 0 ? url.substring(0, slash) : url;
        int colon = hostPort.lastIndexOf(':');
        if (colon > 0 && hostPort.indexOf(']') < colon) {
            try {
                return Integer.parseInt(hostPort.substring(colon + 1));
            } catch (NumberFormatException ignored) {
            }
        }
        return secure ? 443 : 80;
    }

    public static boolean isSecure(String url) {
        return url.toLowerCase().startsWith("https://");
    }

    /** 去除 Content-Length 的头列表（变异重建时使用）。 */
    public static List<String> stripContentLength(List<String> headers) {
        List<String> out = new ArrayList<>();
        for (String h : headers) {
            int c = h.indexOf(':');
            if (c > 0 && h.substring(0, c).trim().equalsIgnoreCase("Content-Length")) {
                continue;
            }
            out.add(h);
        }
        return out;
    }
}
