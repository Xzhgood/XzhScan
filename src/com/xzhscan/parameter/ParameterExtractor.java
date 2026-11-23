package com.xzhscan.parameter;

import com.xzhscan.model.Models.Location;
import com.xzhscan.model.Models.ParamType;
import com.xzhscan.model.Models.ParameterIdentity;
import com.xzhscan.model.RawHttp.RawRequest;

import java.io.UnsupportedEncodingException;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * 参数提取：QUERY / POST FORM / JSON（嵌套对象 + 数组元素，AST 叶子路径）。
 *
 * 与 XiaSQL 原版（BurpExtender#checkVuln 依赖 helpers.getParameters + type==6 再
 * 二次正则解析）不同，这里对 JSON 使用 MiniJson AST 遍历，路径形如
 * $.user.profile.name、$.items[1].id，天然支持嵌套与数组且不会错位。
 */
public final class ParameterExtractor {

    private ParameterExtractor() {
    }

    public static final class ExtractResult {
        public final List<ParameterIdentity> parameters = new ArrayList<>();
        /** JSON body 解析失败等基线异常说明；null = 正常。 */
        public String baselineAnomaly;
        /** 原始 JSON body（解析成功时缓存，供变异复用）。 */
        public String jsonBody;
    }

    public static ExtractResult extract(RawRequest request) {
        ExtractResult result = new ExtractResult();
        String url = request.url;

        // ---- 1. QUERY 参数（保序、保重复） ----
        int q = url.indexOf('?');
        if (q >= 0) {
            String query = url.substring(q + 1);
            int hash = query.indexOf('#');
            if (hash >= 0) {
                query = query.substring(0, hash);
            }
            splitPairs(query, result.parameters, Location.QUERY);
        }

        // ---- 2. POST body ----
        String method = request.method.toUpperCase();
        if ("POST".equals(method) || "PUT".equals(method) || "PATCH".equals(method) || "DELETE".equals(method)) {
            String body = request.bodyAsString();
            String ct = orEmpty(request.headerValue("Content-Type")).toLowerCase();
            if (!body.isEmpty()) {
                if (ct.contains("application/json") || (!ct.isEmpty() && ct.contains("+json")) || body.trim().startsWith("{") || body.trim().startsWith("[")) {
                    extractJson(body, result);
                } else if (ct.contains("multipart/form-data")) {
                    // multipart 暂不主动变异（第二阶段同样跳过），只做计数提示
                    result.baselineAnomaly = result.baselineAnomaly == null ? "multipart not mutable" : result.baselineAnomaly;
                } else {
                    splitPairs(body, result.parameters, Location.FORM);
                }
            }
        }
        return result;
    }

    private static String orEmpty(String s) {
        return s == null ? "" : s;
    }

    /** k=v&k2=v2 拆分（保留重复键与空值；同名参数按出现顺序编号 occurrence，原始 raw 由 Mutator 使用）。 */
    private static void splitPairs(String s, List<ParameterIdentity> out, Location loc) {
        Map<String, Integer> seen = new LinkedHashMap<>();
        for (String pair : s.split("&")) {
            if (pair.isEmpty()) {
                continue;
            }
            int eq = pair.indexOf('=');
            String rawName = eq < 0 ? pair : pair.substring(0, eq);
            String rawValue = eq < 0 ? "" : pair.substring(eq + 1);
            String name = urlDecode(rawName);
            String value = urlDecode(rawValue);
            int occurrence = seen.getOrDefault(name, 0);
            seen.put(name, occurrence + 1);
            out.add(new ParameterIdentity(loc, name, name, value, guessType(value), occurrence));
        }
    }

    public static String urlDecode(String s) {
        try {
            return URLDecoder.decode(s.replace("+", "%2B"), StandardCharsets.UTF_8.name());
        } catch (IllegalArgumentException | UnsupportedEncodingException e) {
            return s;
        }
    }

    private static ParamType guessType(String v) {
        return ParamType.STRING;
    }

    /** JSON AST 叶子提取；解析失败记 baselineAnomaly，绝不做基于正则的降级提取。 */
    private static void extractJson(String body, ExtractResult result) {
        try {
            MiniJson.JsonValue root = MiniJson.parse(body);
            List<String> paths = new ArrayList<>();
            MiniJson.collectLeafPaths(root, "$", paths);
            for (String p : paths) {
                MiniJson.JsonValue v = MiniJson.getByPath(root, p);
                String leafName = leafName(p);
                ParamType t = toType(v);
                String value = scalarText(v);
                result.parameters.add(new ParameterIdentity(Location.JSON, leafName, p, value, t));
            }
            result.jsonBody = body;
        } catch (MiniJson.JsonParseException e) {
            // 输入本身非法 JSON：基线异常，不做 JSON 自动变异（任务书第三节要求）
            result.baselineAnomaly = "invalid JSON body: " + e.getMessage();
        }
    }

    private static String scalarText(MiniJson.JsonValue v) {
        if (v instanceof MiniJson.JsonString s) {
            return s.value();
        }
        if (v instanceof MiniJson.JsonNumber n) {
            return n.rawToken();
        }
        if (v instanceof MiniJson.JsonBool b) {
            return b.value() ? "true" : "false";
        }
        if (v instanceof MiniJson.JsonNull) {
            return "null";
        }
        return "";
    }

    private static ParamType toType(MiniJson.JsonValue v) {
        if (v instanceof MiniJson.JsonString) return ParamType.STRING;
        if (v instanceof MiniJson.JsonNumber) return ParamType.NUMBER;
        if (v instanceof MiniJson.JsonBool) return ParamType.BOOLEAN;
        if (v instanceof MiniJson.JsonNull) return ParamType.NULL;
        if (v instanceof MiniJson.JsonObject) return ParamType.OBJECT;
        return ParamType.ARRAY;
    }

    static String leafName(String path) {
        int bracket = path.lastIndexOf('[');
        int dot = path.lastIndexOf('.');
        if (bracket > dot) {
            return "[" + path.substring(bracket + 1, path.lastIndexOf(']')) + "]";
        }
        return dot >= 0 ? path.substring(dot + 1) : path;
    }
}
