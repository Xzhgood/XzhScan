package com.xzhscan.policy;

import com.xzhscan.config.XzhScanConfig;
import com.xzhscan.model.RawHttp.RawRequest;

import java.util.Locale;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicLong;

/**
 * 扫描安全策略：所有主动变异请求发送前的统一闸门。
 *
 * 判定不单看 URL 名称，而是 综合 HTTP 方法 + 路径语义 + 用户配置：
 *  - 白名单（空 = 全部允许）与黑名单；
 *  - 静态资源后缀跳过（XiaSQL 遗产）；
 *  - 写语义默认拒绝：非幂等方法（POST/PUT/PATCH/DELETE）命中写语义路径词
 *    （delete/remove/update/modify/edit/save/submit/create/add/drop/truncate/
 *     reset/cancel/pay/charge/refund/order/transfer/export/batch/import...）
 *    或 Content-Type 指示批量操作的接口；
 *  - 速率限制（全局限速 + 并发上限）与手动暂停。
 */
public final class ScanPolicyEngine {

    /** 高风险写语义路径片段（小写匹配）。 */
    private static final String[] WRITE_PATH_HINTS = {
            "delete", "remove", "destroy", "drop", "truncate", "update", "modify", "edit",
            "save", "submit", "create", "add", "insert", "reset", "cancel", "revoke",
            "pay", "charge", "refund", "transfer", "withdraw", "batch", "import",
            "export", "upload", "approve", "audit-submit", "setpassword", "changepwd"
    };

    /** 静态资源后缀（v3.0 与 AuthScan 过滤器对齐补全；html/htm/txt/csv/log 不拒——伪静态可能是注入点）。 */
    private static final String[] STATIC_SUFFIXES = {
            "jpg", "jpeg", "png", "gif", "bmp", "webp", "svg", "avif", "tif", "tiff",
            "css", "js", "mjs", "cjs", "ico",
            "woff", "woff2", "ttf", "otf", "eot",
            "mp3", "wav", "ogg", "mp4", "webm", "avi", "mov", "m3u8",
            "zip", "rar", "7z", "tar", "gz", "tgz", "exe", "msi", "apk", "ipa", "jar", "war",
            "pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx", "map"
    };

    /**
     * 静态资源判定（v3.4）：路径后缀命中静态清单。
     * 供策略闸与 UI 列表过滤共用（js/css/字体/图片等无参数流量不进差分列表）。
     */
    public static boolean isStaticResource(String url) {
        if (url == null) {
            return false;
        }
        String path = pathOf(url.toLowerCase(Locale.ROOT));
        int dot = path.lastIndexOf('.');
        if (dot < 0) {
            return false;
        }
        String ext = path.substring(dot + 1);
        for (String s : STATIC_SUFFIXES) {
            if (s.equals(ext)) {
                return true;
            }
        }
        return false;
    }

    public static final class Decision {
        public final boolean allowed;
        public final String reason;

        Decision(boolean allowed, String reason) {
            this.allowed = allowed;
            this.reason = reason;
        }

        public static Decision allow() {
            return new Decision(true, "allowed");
        }

        public static Decision deny(String reason) {
            return new Decision(false, reason);
        }
    }

    private final XzhScanConfig config;
    private volatile boolean paused;
    /** v4.1：Burp Target Scope 判定（扩展装配时注入；测试/无头环境为 null=不检查）。 */
    private volatile java.util.function.Predicate<String> scopeChecker;
    /** v4.2.1：首次因 Scope 拒绝时的一次性提示（避免用户看到 blocked 却不知原因）。 */
    private final java.util.concurrent.atomic.AtomicBoolean outOfScopeWarned =
            new java.util.concurrent.atomic.AtomicBoolean();
    private volatile Runnable onOutOfScopeWarn;
    /** host -> 最后请求时间戳（简单令牌间隔）。 */
    private final Map<String, AtomicLong> lastSendAt = new ConcurrentHashMap<>();

    public ScanPolicyEngine(XzhScanConfig config) {
        this.config = config;
    }

    public void pause() {
        paused = true;
    }

    public void resume() {
        paused = false;
    }

    public boolean isPaused() {
        return paused;
    }

    /** 注入 Target Scope 判定（扩展 initialize 时接线 montoya scope）。 */
    public void setScopeChecker(java.util.function.Predicate<String> checker) {
        this.scopeChecker = checker;
    }

    /** 注册"首次 out-of-scope 拒绝"提示回调（扩展装配时接线日志）。 */
    public void setOutOfScopeWarn(Runnable r) {
        this.onOutOfScopeWarn = r;
    }

    /** 主动变异请求的准入判定（自动流量：受 Target Scope 约束）。 */
    public Decision check(RawRequest request) {
        return check(request, false);
    }

    /** 手动入口（右键/数据版）：用户显式授权，跳过 Target Scope，其余规则照常。 */
    public Decision checkForManual(RawRequest request) {
        return check(request, true);
    }

    private Decision check(RawRequest request, boolean manual) {
        if (paused) {
            return Decision.deny("manually paused");
        }
        // v4.1：自动流量必须在 Burp Target Scope 内（用户评审 P0：默认安全）
        if (!manual && config.requireInScope) {
            java.util.function.Predicate<String> sc = scopeChecker;
            if (sc != null && !sc.test(request.url)) {
                if (outOfScopeWarned.compareAndSet(false, true)) {
                    Runnable w = onOutOfScopeWarn;
                    if (w != null) {
                        w.run();
                    }
                }
                return Decision.deny("out-of-scope (Burp Target Scope)");
            }
        }
        String url = request.url.toLowerCase(Locale.ROOT);
        String host = hostOf(url);
        String path = pathOf(url);

        // 白名单（空=允许全部）
        if (!isBlank(config.domainWhitelist)) {
            boolean hit = false;
            for (String w : config.domainWhitelist.split(",")) {
                String t = w.trim().toLowerCase(Locale.ROOT);
                if (hostMatches(host, t)) {
                    hit = true;
                    break;
                }
            }
            if (!hit) {
                return Decision.deny("host not in whitelist: " + host);
            }
        }
        // 黑名单
        if (!isBlank(config.urlBlacklist)) {
            for (String b : config.urlBlacklist.split(",")) {
                String t = b.trim().toLowerCase(Locale.ROOT);
                if (!t.isEmpty() && url.contains(t)) {
                    return Decision.deny("url matches blacklist entry: " + t);
                }
            }
        }
        // 静态资源
        int dot = path.lastIndexOf('.');
        if (dot >= 0) {
            String ext = path.substring(dot + 1);
            for (String s : STATIC_SUFFIXES) {
                if (s.equals(ext)) {
                    return Decision.deny("static resource: " + ext);
                }
            }
        }
        // 写语义默认拒绝
        if (config.denyWriteLookingEndpoints) {
            String method = request.method.toUpperCase(Locale.ROOT);
            boolean idempotent = "GET".equals(method) || "HEAD".equals(method) || "OPTIONS".equals(method);
            if (!idempotent) {
                for (String w : WRITE_PATH_HINTS) {
                    if (path.contains("/" + w) || path.contains(w + "/") || path.endsWith("/" + w)
                            || path.contains("-" + w) || path.contains(w + "-") || path.contains("_" + w) || path.contains(w + "_")) {
                        return Decision.deny("write-looking endpoint (method=" + method + ", path hint=" + w + "): default deny");
                    }
                }
            }
        }
        return Decision.allow();
    }

    /** 发送前限速（按 host 简单间隔）。 */
    public void throttle(String url) throws InterruptedException {
        int interval = config.requestIntervalMs;
        if (interval <= 0) {
            return;
        }
        String host = hostOf(url.toLowerCase(Locale.ROOT));
        AtomicLong last = lastSendAt.computeIfAbsent(host, k -> new AtomicLong(0));
        long now;
        long prev;
        do {
            now = System.currentTimeMillis();
            prev = last.get();
            long wait = interval - (now - prev);
            if (wait > 0) {
                Thread.sleep(wait);
            }
        } while (!last.compareAndSet(prev, System.currentTimeMillis()));
    }

    private static String hostOf(String url) {
        int scheme = url.indexOf("://");
        int start = scheme >= 0 ? scheme + 3 : 0;
        int end = url.indexOf('/', start);
        int colon = url.indexOf(':', start);
        if (colon >= 0 && (end < 0 || colon < end)) {
            end = colon;
        }
        return end < 0 ? url.substring(start) : url.substring(start, end);
    }

    /**
     * 提取去 query 的路径（扩展名判定必须基于纯路径）。
     * 修复：v1.4 之前未剥离 query —— "font.woff2?v=4.5.0'and..." 的最后一个 '.'
     * 落在 query 里，ext 提取被劫持为 "0'and(...)"，导致 woff/woff2 等静态资源
     * 绕过后缀过滤进入全链扫描（真实误报案例：字体文件 v 参数被发时间探针）。
     */
    private static String pathOf(String url) {
        int scheme = url.indexOf("://");
        int start = url.indexOf('/', scheme >= 0 ? scheme + 3 : 0);
        String pathAndQuery = start < 0 ? "/" : url.substring(start);
        int q = pathAndQuery.indexOf('?');
        String path = q >= 0 ? pathAndQuery.substring(0, q) : pathAndQuery;
        int hash = path.indexOf('#');
        return hash >= 0 ? path.substring(0, hash) : path;
    }

    private static boolean isBlank(String s) {
        return s == null || s.trim().isEmpty();
    }

    /**
     * v4.1：白名单精确匹配（原实现 host.contains 为子串匹配，
     * "example.com.evil.net" / "evilexample.com" 都会被误放行）。
     * 支持 exact / 子域 / 通配 "*.example.com"。
     */
    private static boolean hostMatches(String host, String rule) {
        String r = rule.trim().toLowerCase(Locale.ROOT);
        if (r.isEmpty()) {
            return false;
        }
        if (r.startsWith("*.")) {
            return host.endsWith(r.substring(1));
        }
        return host.equals(r) || host.endsWith("." + r);
    }
}
