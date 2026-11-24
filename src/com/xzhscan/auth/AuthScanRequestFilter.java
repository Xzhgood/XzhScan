package com.xzhscan.auth;

import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.HashSet;

/**
 * AuthScan 请求过滤器（进入越权检测队列前的统一闸门）。
 *
 * 精准过滤原则（任务书 5.4）：
 *  - 只看「标准化 path 的扩展名」，绝不因 query 里出现 .png/.js 就过滤整个 API；
 *  - 不因路径包含 "js" 两个字母过滤；
 *  - 扩展名大小写不敏感、URL 解码后再判定（%2E%6A%73 伪装）；
 *  - 结合响应 Content-Type / Content-Disposition / Method / Accept 多信号；
 *  - text/html 不作为静态判据（API 错误页常为 text/html）；
 *  - 证据不足（无扩展名且无响应头）标记 UNKNOWN，不编造资源类型；
 *  - 下载型（Content-Disposition: attachment / octet-stream 等）默认不进自动
 *    复核但保留完整过滤记录，允许人工审查；
 *  - 非幂等方法（PUT/DELETE/PATCH）拒；POST 标记 UNKNOWN（自动重放有业务
 *    副作用风险，交人工）；GET/HEAD 正常评估。
 *
 * 每个决策返回 FilterRecord（requestId/method/url/resourceType/contentType/
 * decision/filterReason/timestamp），全程可追踪。
 */
public final class AuthScanRequestFilter {

    /** 决策三态。 */
    public enum Decision {
        ALLOW, REJECT, UNKNOWN
    }

    /** 一条过滤决策记录。 */
    public static final class FilterRecord {
        public final String requestId;
        public final String method;
        public final String url;
        public final String resourceType;
        public final String contentType;
        public final Decision decision;
        public final String filterReason;
        public final long timestamp = System.currentTimeMillis();

        FilterRecord(String requestId, String method, String url, String resourceType,
                     String contentType, Decision decision, String filterReason) {
            this.requestId = requestId;
            this.method = method;
            this.url = url;
            this.resourceType = resourceType;
            this.contentType = contentType;
            this.decision = decision;
            this.filterReason = filterReason;
        }

        public boolean submitToQueue() {
            return decision == Decision.ALLOW;
        }
    }

    /** 过滤器配置（UI 可改）。 */
    public static final class FilterConfig {
        /** 静态资源过滤总开关（默认启用）。 */
        public boolean enabled = true;
        /** 在内置清单外追加的扩展名（小写，逗号分隔）。 */
        public String extraExtensions = "";
        /** 移除的内置扩展名（小写，逗号分隔，用于豁免个别类型）。 */
        public String exemptExtensions = "";
    }

    // ---- 5.1 九大类默认过滤扩展名 ----
    private static final Set<String> STATIC_EXTS = Set.of(
            // JavaScript
            "js", "mjs", "cjs",
            // HTML 页面
            "html", "htm", "xhtml",
            // 图标
            "ico",
            // 图片
            "png", "jpg", "jpeg", "gif", "bmp", "webp", "svg", "avif", "tif", "tiff",
            // 字体
            "woff", "woff2", "ttf", "otf", "eot",
            // CSS
            "css",
            // 音视频
            "mp3", "wav", "ogg", "mp4", "webm", "avi", "mov", "m3u8",
            // 压缩包/安装包
            "zip", "rar", "7z", "tar", "gz", "tgz", "exe", "msi", "apk", "ipa", "jar", "war",
            // 文档/下载
            "pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx", "csv", "txt", "log"
    );

    /** .map 属于 source map（js.map/css.map），以 map 后缀一并过滤。 */
    private static final Set<String> STATIC_EXTS_EXTRA = Set.of("map");

    /** 静态资源 MIME 前缀/精确表（text/html 刻意不在内：API 错误页常见）。 */
    private static final Set<String> STATIC_MIME_EXACT = Set.of(
            "text/css", "text/javascript", "application/javascript", "application/x-javascript",
            "application/zip", "application/gzip", "application/x-tar", "application/x-7z-compressed",
            "application/x-rar-compressed", "application/pdf", "application/msdownload",
            "application/vnd.android.package-archive", "application/java-archive",
            "application/x-msdownload", "application/font-woff", "application/font-woff2",
            "application/x-font-ttf", "application/vnd.ms-fontobject", "image/svg+xml",
            "application/octet-stream"
    );
    private static final List<String> STATIC_MIME_PREFIX = List.of(
            "image/", "font/", "audio/", "video/"
    );

    private FilterConfig cfg = new FilterConfig();

    public void configure(FilterConfig c) {
        this.cfg = c == null ? new FilterConfig() : c;
    }

    public FilterConfig config() {
        return cfg;
    }

    /**
     * 评估一个请求是否进入越权检测候选池。
     *
     * @param requestId         请求标识
     * @param method            HTTP 方法
     * @param url               完整 URL
     * @param statusCode        原始响应状态码
     * @param responseHeaders   观测响应头（小写键 -> 值；无响应传 null/空）
     * @param acceptHeader      请求 Accept 头（可空）
     */
    public FilterRecord evaluate(String requestId, String method, String url,
                                 int statusCode,
                                 Map<String, String> responseHeaders, String acceptHeader) {
        String m = method == null ? "GET" : method.toUpperCase(Locale.ROOT);

        // 0) 状态码硬准入：只允许 200（任务追加审计要求）
        if (statusCode != 200) {
            return rec(requestId, m, url, "non-200", "", Decision.REJECT,
                    "原始响应状态码 " + statusCode + " ≠ 200，不进入越权审计");
        }

        Map<String, String> headers = responseHeaders == null ? Map.of() : responseHeaders;
        String contentType = orEmpty(headers.get("content-type"));
        String disposition = orEmpty(headers.get("content-disposition"));
        String ct = contentType.toLowerCase(Locale.ROOT);

        // 1) path 扩展名（标准化：解码 + 去 query/fragment + 小写）
        String path = normalizePath(url);
        String ext = extensionOf(path);

        if (cfg.enabled && ext != null && isStaticExt(ext)) {
            return rec(requestId, m, url, "static:" + ext, contentType, Decision.REJECT,
                    "static resource extension ." + ext + " (path-based)");
        }
        // 2) Content-Disposition: attachment —— 下载型（默认不自动复核，留记录供人工）
        if (disposition.toLowerCase(Locale.ROOT).contains("attachment")) {
            return rec(requestId, m, url, "download", contentType, Decision.REJECT,
                    "Content-Disposition: attachment（下载型，默认不自动复核，可人工审查）");
        }
        // 3) 响应 Content-Type 静态 MIME（注意 text/html 不在此表）
        if (cfg.enabled && isStaticMime(ct)) {
            return rec(requestId, m, url, "static-mime", contentType, Decision.REJECT,
                    "static Content-Type: " + contentType);
        }
        // 4) 方法风险
        if (m.equals("PUT") || m.equals("DELETE") || m.equals("PATCH")) {
            return rec(requestId, m, url, "non-idempotent", contentType, Decision.REJECT,
                    "非幂等方法 " + m + "，自动复具有副作用风险");
        }
        if (m.equals("POST")) {
            // POST 自动重放可能执行业务写操作：默认不进自动队列，保留 UNKNOWN 供人工
            return rec(requestId, m, url, "post-manual", contentType, Decision.UNKNOWN,
                    "POST 请求需人工确认后复核（自动重放有副作用风险）");
        }
        // 5) 证据不足：无扩展名且无响应头 —— 但 API 形态路径优先入候选池（任务书 5.3），
        //    其余标记 UNKNOWN，不编造资源类型
        if (ext == null && contentType.isEmpty()) {
            if (looksLikeApiPath(path)) {
                return rec(requestId, m, url, "api", "", Decision.ALLOW,
                        "API 形态路径（无扩展名/无响应头）优先进入候选池");
            }
            return rec(requestId, m, url, "unknown", "", Decision.UNKNOWN,
                    "无扩展名且无响应 Content-Type，证据不足");
        }
        // 6) 正常候选（API 形态）
        return rec(requestId, m, url, ext != null ? "api:" + ext : "api", contentType,
                Decision.ALLOW, "candidate API request");
    }

    /** API 形态判定：路径段命中 api/rest/graphql 等常见前缀（仅用于无扩展名场景）。 */
    static boolean looksLikeApiPath(String path) {
        String low = path.toLowerCase(Locale.ROOT);
        for (String prefix : new String[]{"/api/", "/api", "/rest/", "/graphql", "/v1/", "/v2/", "/v3/", "/rpc/", "/service/"}) {
            if (low.startsWith(prefix) || low.contains(prefix)) {
                return true;
            }
        }
        return false;
    }

    private FilterRecord rec(String id, String m, String url, String type, String ct,
                             Decision d, String reason) {
        return new FilterRecord(id, m, url, type, ct, d, reason);
    }

    private boolean isStaticExt(String ext) {
        if (STATIC_EXTS.contains(ext) || STATIC_EXTS_EXTRA.contains(ext)) {
            return !splitCsv(cfg.exemptExtensions).contains(ext);
        }
        return splitCsv(cfg.extraExtensions).contains(ext);
    }

    static boolean isStaticMime(String lowerCt) {
        String base = lowerCt.contains(";") ? lowerCt.substring(0, lowerCt.indexOf(';')).trim() : lowerCt.trim();
        if (base.isEmpty()) {
            return false;
        }
        if (STATIC_MIME_EXACT.contains(base)) {
            return true;
        }
        for (String p : STATIC_MIME_PREFIX) {
            if (base.startsWith(p)) {
                return true;
            }
        }
        return false;
    }

    /** URL 解码 + 去 query/fragment + 取纯 path（保留合法 % 编码不炸）。 */
    static String normalizePath(String url) {
        if (url == null || url.isEmpty()) {
            return "/";
        }
        int scheme = url.indexOf("://");
        int start = url.indexOf('/', scheme >= 0 ? scheme + 3 : 0);
        String pq = start < 0 ? "/" : url.substring(start);
        int q = pq.indexOf('?');
        String path = q >= 0 ? pq.substring(0, q) : pq;
        int hash = path.indexOf('#');
        if (hash >= 0) {
            path = path.substring(0, hash);
        }
        try {
            path = URLDecoder.decode(path, StandardCharsets.UTF_8);
        } catch (IllegalArgumentException ignored) {
            // 非法编码序列：按原文继续（不因解码失败放行静态资源）
        }
        return path;
    }

    /** path 的扩展名（仅最后一段，目录点号不算；小写）。 */
    static String extensionOf(String path) {
        if (path == null) {
            return null;
        }
        int slash = Math.max(path.lastIndexOf('/'), 0);
        String file = path.substring(slash + 1);
        int dot = file.lastIndexOf('.');
        if (dot <= 0 || dot == file.length() - 1) {
            return null;
        }
        return file.substring(dot + 1).toLowerCase(Locale.ROOT);
    }

    private static List<String> splitCsv(String s) {
        if (s == null || s.isBlank()) {
            return List.of();
        }
        List<String> out = new ArrayList<>();
        for (String p : s.split(",")) {
            String t = p.trim().toLowerCase(Locale.ROOT);
            if (t.startsWith(".")) {
                t = t.substring(1);
            }
            if (!t.isEmpty()) {
                out.add(t);
            }
        }
        return out;
    }

    private static String orEmpty(String s) {
        return s == null ? "" : s;
    }

    /** 全部默认静态扩展名（UI 展示用）。 */
    public static List<String> defaultExtensions() {
        List<String> all = new ArrayList<>(STATIC_EXTS);
        all.addAll(STATIC_EXTS_EXTRA);
        Collections.sort(all);
        return all;
    }
}
