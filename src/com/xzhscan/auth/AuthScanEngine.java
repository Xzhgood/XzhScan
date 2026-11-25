package com.xzhscan.auth;

import com.xzhscan.model.RawHttp.RawRequest;
import com.xzhscan.model.RawHttp.RawResponse;
import com.xzhscan.model.RawHttp.Transport;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Map;

/**
 * 越权检测引擎（三态重放判定，迁移自 gatherBurp PermUI.Check，PermUI.java:364-479）。
 *
 * 保留的 gatherBurp 判定语义：
 *  - 原始 / 低权限（整行替换同名头，缺则追加）/ 无权限（删除指定头名）三次重放；
 *  - 「存在越权」要求 状态码相等 且 响应体字节数相等；
 *  - 「未授权（无鉴权）」要求三态全部相等；
 *  - 探测响应为 null 时中止该请求（不记 0 参与判定）。
 *
 * 按任务书第六节的增强（原版没有）：
 *  - 不得仅因长度相同就认定权限一致：码+长相等后再做归一化 token 相似度（>=0.9）确认
 *    「同一资源」，空响应/极短响应(<64B)不判越权；
 *  - 结论四态：CONFIRMED（越权成立）/ UNAUTHORIZED（无鉴权）/ SUSPECTED（码长相等但
 *    相似度不足或响应异常）/ SAFE（不存在）/ INVALID（探测失败）；
 *  - 原始/低权限/无权限三组完整请求响应证据全部保留（供 UI 原生编辑器四视图）。
 */
public final class AuthScanEngine {

    /** 判定结果。 */
    public enum Verdict {
        CONFIRMED("存在越权"),
        UNAUTHORIZED("未授权访问"),
        SUSPECTED("疑似（证据不足）"),
        SAFE("不存在"),
        INVALID("探测无效");

        public final String label;

        Verdict(String label) {
            this.label = label;
        }
    }

    /** 一条越权检测结果。 */
    public static final class PermResult {
        public String requestId;
        public String method;
        public String url;
        public Verdict verdict;
        /** 组合场景展示结论（低权限/未授权 200 状态组合，覆盖 verdict 的单一标签）。 */
        public String displayVerdict;
        public String evidenceSummary;
        public RawRequest originalRequest;
        public RawResponse originalResponse;
        public RawRequest lowRequest;
        public RawResponse lowResponse;
        public RawRequest noAuthRequest;
        public RawResponse noAuthResponse;
    }

    /** 身份配置（对应 gatherBurp 三个快照列表）。 */
    public static final class IdentityConfig {
        /** 低权限认证头（每行 "Name: value"；同名替换，缺则追加）。 */
        public List<String> lowAuthHeaders = new ArrayList<>();
        /** 待移除的鉴权头名。 */
        public List<String> noAuthHeaderNames = new ArrayList<>();
        /** 白名单域名（支持 * 通配，从右往左段匹配；空=全部允许）。 */
        public List<String> whitelistDomains = new ArrayList<>();
    }

    private static final double SAME_RESOURCE_SIMILARITY = 0.9;

    private final Transport transport;

    public AuthScanEngine(Transport transport) {
        this.transport = transport;
    }

    /** 域名通配匹配（gatherBurp Utils.isMatchDomainName 语义迁移）。 */
    public static boolean domainMatches(String host, List<String> allowed) {
        if (host == null || host.isBlank() || allowed == null || allowed.isEmpty()) {
            return false;
        }
        String target = host.trim().toLowerCase(Locale.ROOT);
        for (String raw : allowed) {
            String pattern = raw == null ? "" : raw.trim().toLowerCase(Locale.ROOT);
            if (pattern.isEmpty()) {
                continue;
            }
            if (target.equals(pattern)) {
                return true;
            }
            if (pattern.contains("*")) {
                String[] t = target.split("\\.");
                String[] p = pattern.split("\\.");
                int ti = t.length - 1;
                int pi = p.length - 1;
                boolean ok = true;
                while (ti >= 0 && pi >= 0) {
                    if ("*".equals(p[pi])) {
                        return true; // 从右到左遇 * 短路
                    }
                    if (!t[ti].equals(p[pi])) {
                        ok = false;
                        break;
                    }
                    ti--;
                    pi--;
                }
                if (ok && pi < 0) {
                    return true;
                }
            }
        }
        return false;
    }

    /**
     * 对单个（已通过 AuthScanRequestFilter 的）请求执行三态重放。
     * 调用方保证：幂等方法、授权范围、静态资源已过滤。
     */
    public PermResult check(RawRequest original, IdentityConfig identity) {
        PermResult r = new PermResult();
        r.originalRequest = original;
        r.method = original.method;
        r.url = original.url;
        r.originalResponse = send(original);
        if (r.originalResponse == null) {
            r.verdict = Verdict.INVALID;
            r.evidenceSummary = "原始请求重放失败（无响应）";
            return r;
        }
        // 低权限：同名整行替换，缺则追加
        RawRequest lowReq = rewriteHeaders(original, identity.lowAuthHeaders, List.of());
        r.lowRequest = lowReq;
        r.lowResponse = send(lowReq);
        if (r.lowResponse == null) {
            r.verdict = Verdict.INVALID;
            r.evidenceSummary = "低权限请求无响应（可能被拦截或身份失效）";
            return r;
        }
        // 无权限：删除指定头名
        RawRequest noReq = rewriteHeaders(original, List.of(), identity.noAuthHeaderNames);
        r.noAuthRequest = noReq;
        r.noAuthResponse = send(noReq);
        if (r.noAuthResponse == null) {
            r.verdict = Verdict.INVALID;
            r.evidenceSummary = "无鉴权请求无响应";
            return r;
        }
        r.verdict = judge(r);
        r.displayVerdict = combinedVerdict(r);
        r.evidenceSummary = summaryOf(r);
        return r;
    }

    /**
     * 组合场景结论（v3.10.1）：低权限请求/未授权请求的状态码组合，明确区分
     * 「越权」与「未授权」是否可能同时存在：
     *  低 200 + 无 200 -> 存在越权 OR 存在未授权
     *  低 非200 + 无 200 -> 不存在越权 OR 存在未授权
     *  低 200 + 无 非200 -> 存在越权
     *  其余（低/无均非 200）-> 鉴权正常（不显示）
     * INVALID（探测失败）保留原标签，避免把失败误当鉴权正常。
     */
    private static String combinedVerdict(PermResult r) {
        if (r.verdict == Verdict.INVALID) {
            return r.verdict.label;
        }
        boolean lowOk = is2xx(r.lowResponse);
        boolean noOk = is2xx(r.noAuthResponse);
        if (lowOk && noOk) {
            return "存在越权 OR 存在未授权";
        }
        if (!lowOk && noOk) {
            return "不存在越权 OR 存在未授权";
        }
        if (lowOk) {
            return "存在越权";
        }
        return "鉴权正常";
    }

    private static boolean is2xx(RawResponse resp) {
        return resp != null && resp.statusCode >= 200 && resp.statusCode < 300;
    }

    private Verdict judge(PermResult r) {
        int so = r.originalResponse.statusCode;
        int sl = r.lowResponse.statusCode;
        int sn = r.noAuthResponse.statusCode;
        int lo = bodyLength(r.originalResponse);
        int ll = bodyLength(r.lowResponse);
        int ln = bodyLength(r.noAuthResponse);

        boolean lowSameCodeLen = so == sl && lo == ll;
        boolean allSame = lowSameCodeLen && so == sn && lo == ln;

        // 空响应/极短响应：不能作为"获得资源"的证据（任务书 6.8）
        boolean emptyEvidence = lo < 64 || ll < 64;
        if (allSame) {
            return emptyEvidence ? Verdict.SUSPECTED : Verdict.UNAUTHORIZED;
        }
        if (lowSameCodeLen) {
            if (emptyEvidence) {
                return Verdict.SUSPECTED; // 码长相等但拿到的可能只是同一个错误/空页
            }
            // 长度相同不能直接定罪：归一化相似度确认"同一资源"（任务书 6.7/6.9）
            double sim = com.xzhscan.differential.ResponseNormalizer.similarity(
                    r.originalResponse.bodyAsString(), r.lowResponse.bodyAsString());
            if (sim >= SAME_RESOURCE_SIMILARITY) {
                return Verdict.CONFIRMED;
            }
            return Verdict.SUSPECTED;
        }
        return Verdict.SAFE;
    }

    private static String summaryOf(PermResult r) {
        return "code " + r.originalResponse.statusCode + "/" + r.lowResponse.statusCode + "/" + r.noAuthResponse.statusCode
                + ", bodyLen " + bodyLength(r.originalResponse) + "/" + bodyLength(r.lowResponse) + "/" + bodyLength(r.noAuthResponse);
    }

    private static int bodyLength(RawResponse resp) {
        return resp == null ? -1 : resp.body.length;
    }

    private RawResponse send(RawRequest request) {
        try {
            RawResponse r = transport.send(request);
            return r == null || r.statusCode <= 0 ? null : r;
        } catch (Exception e) {
            return null;
        }
    }

    /** 头重写：replacements 整行替换同名（缺则追加）；removals 按名删除。 */
    static RawRequest rewriteHeaders(RawRequest original, List<String> replacements, List<String> removals) {
        List<String> out = new ArrayList<>();
        List<String[]> applied = new ArrayList<>(); // [name, line] 已替换
        for (String h : original.headers) {
            int c = h.indexOf(':');
            if (c <= 0) {
                out.add(h);
                continue;
            }
            String name = h.substring(0, c).trim();
            String rep = findReplacement(name, replacements);
            if (rep != null) {
                out.add(rep);
                applied.add(new String[]{name.toLowerCase(Locale.ROOT), rep});
            } else if (isRemoved(name, removals)) {
                // 删除
            } else {
                out.add(h);
            }
        }
        for (String rep : replacements) {
            int c = rep.indexOf(':');
            if (c <= 0) {
                continue;
            }
            String name = rep.substring(0, c).trim().toLowerCase(Locale.ROOT);
            boolean replaced = applied.stream().anyMatch(a -> a[0].equals(name));
            if (!replaced) {
                out.add(rep);
            }
        }
        return new RawRequest(original.method, original.url, out, original.body);
    }

    private static String findReplacement(String name, List<String> replacements) {
        for (String rep : replacements) {
            int c = rep.indexOf(':');
            if (c > 0 && rep.substring(0, c).trim().equalsIgnoreCase(name)) {
                return rep;
            }
        }
        return null;
    }

    private static boolean isRemoved(String name, List<String> removals) {
        for (String rm : removals) {
            String n = rm.contains(":") ? rm.substring(0, rm.indexOf(':')) : rm;
            if (n.trim().equalsIgnoreCase(name)) {
                return true;
            }
        }
        return false;
    }

    /** 从 URL 取 host（供白名单校验）。 */
    public static String hostOf(String url) {
        return com.xzhscan.model.RawHttpRequests.hostOf(url);
    }
}
