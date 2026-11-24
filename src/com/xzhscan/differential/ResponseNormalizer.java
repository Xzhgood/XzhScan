package com.xzhscan.differential;

import com.xzhscan.parameter.MiniJson;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * 响应归一化：把天然动态内容抹平后再比较，避免把时间戳/随机 token/请求 ID
 * 当成注入差分（DifferentialGate 规则 C 的基础）。
 *
 * 两层归一：
 *  1. 文本层：unix 时间戳、ISO 时间、UUID、长 hex（md5/sha）、纯数字 id、
 *     token/nonce/csrf 类键值、Set-Cookie 动态值；
 *  2. JSON 结构层：AST 解析后取“键路径集合”作为结构指纹，字段级对比时
 *     排除基线采样期间就自变化的动态字段。
 */
public final class ResponseNormalizer {

    private ResponseNormalizer() {
    }

    private static final Pattern UUID = Pattern.compile("[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}");
    private static final Pattern LONG_HEX = Pattern.compile("\\b[0-9a-fA-F]{16,}\\b");
    private static final Pattern UNIX_TS = Pattern.compile("\\b1[0-9]{9}(\\d{3})?\\b");
    private static final Pattern ISO_TIME = Pattern.compile("\\d{4}-\\d{2}-\\d{2}[T ]\\d{2}:\\d{2}(:\\d{2})?(\\.\\d+)?(Z|[+-]\\d{2}:?\\d{2})?");
    private static final Pattern PURE_NUMBER = Pattern.compile("\\b\\d+\\b");
    private static final Pattern TOKEN_KEY_VALUE = Pattern.compile(
            "(?i)(csrf|xsrf|token|nonce|request[_-]?id|trace[_-]?id|session[_-]?id|captcha|timestamp|signature|sign|noncestr)([\"'=:\\s]\\s*)([\"']?)[A-Za-z0-9+/_.=-]{8,}\\3");
    private static final Pattern SET_COOKIE_DYNAMIC = Pattern.compile("(?i)(set-cookie\\s*:[^;]*=)[^;]*");
    private static final Pattern RANDOM_LOOKING = Pattern.compile("\\b[A-Za-z0-9]{20,}\\b");

    /** JSON 解析错误特征（规则 A 辅助证据，与 HTTP 400 组合判定）。 */
    private static final Pattern JSON_PARSE_ERROR = Pattern.compile(
            "(?i)(json[ _-]?parse[ _-]?error|unexpected[ _-]?token|invalid[ _-]?json|json[ _-]?syntax|malformed[ _-]?json|json_decode|not[ _-]?a[ _-]?valid[ _-]?json|jsoninputerror|error[ _-]?parsing[ _-]?json)");

    public static boolean looksLikeJsonParseError(String body) {
        return body != null && JSON_PARSE_ERROR.matcher(body).find();
    }

    /** 归一化结果。 */
    public static final class Normalized {
        public final int statusCode;
        public final String normalizedText;
        public final boolean json;
        public final MiniJson.JsonValue jsonTree; // 解析失败为 null
        /** JSON 结构指纹：叶子键路径集合（含类型后缀）。 */
        public final Set<String> structureFingerprint;
        /** 叶子值表：path -> 标量文本（动态字段对比用）。 */
        public final Map<String, String> leafValues;

        Normalized(int statusCode, String normalizedText, boolean json, MiniJson.JsonValue jsonTree,
                   Set<String> structureFingerprint, Map<String, String> leafValues) {
            this.statusCode = statusCode;
            this.normalizedText = normalizedText;
            this.json = json;
            this.jsonTree = jsonTree;
            this.structureFingerprint = structureFingerprint;
            this.leafValues = leafValues;
        }
    }

    public static Normalized normalize(com.xzhscan.model.RawHttp.RawResponse response) {
        String body = response.bodyAsString();
        MiniJson.JsonValue tree = null;
        try {
            tree = MiniJson.parse(body);
        } catch (MiniJson.JsonParseException ignored) {
            // 非 JSON 或非法 JSON：按纯文本归一化
        }
        String normalized = normalizeText(body);
        if (tree != null) {
            Set<String> fp = new HashSet<>();
            Map<String, String> leaves = new LinkedHashMap<>();
            collect(tree, "$", fp, leaves);
            return new Normalized(response.statusCode, normalized, true, tree, fp, leaves);
        }
        return new Normalized(response.statusCode, normalized, false, null, new HashSet<>(), new LinkedHashMap<>());
    }

    private static void collect(MiniJson.JsonValue node, String prefix, Set<String> fp, Map<String, String> leaves) {
        if (node instanceof MiniJson.JsonObject o) {
            for (Map.Entry<String, MiniJson.JsonValue> e : o.members().entrySet()) {
                String p = prefix + "." + e.getKey();
                MiniJson.JsonValue v = e.getValue();
                if (v instanceof MiniJson.JsonObject || v instanceof MiniJson.JsonArray) {
                    fp.add(p + "/" + MiniJson.typeName(v));
                    collect(v, p, fp, leaves);
                } else {
                    fp.add(p + "/" + MiniJson.typeName(v));
                    leaves.put(p, scalar(v));
                }
            }
        } else if (node instanceof MiniJson.JsonArray a) {
            fp.add(prefix + "/array");
            for (int i = 0; i < a.items().size(); i++) {
                MiniJson.JsonValue v = a.items().get(i);
                String p = prefix + "[" + i + "]";
                if (v instanceof MiniJson.JsonObject || v instanceof MiniJson.JsonArray) {
                    fp.add(p + "/" + MiniJson.typeName(v));
                    collect(v, p, fp, leaves);
                } else {
                    fp.add(p + "/" + MiniJson.typeName(v));
                    leaves.put(p, scalar(v));
                }
            }
        } else {
            leaves.put(prefix, scalar(node));
        }
    }

    private static String scalar(MiniJson.JsonValue v) {
        if (v instanceof MiniJson.JsonString s) return s.value();
        if (v instanceof MiniJson.JsonNumber n) return n.rawToken();
        if (v instanceof MiniJson.JsonBool b) return Boolean.toString(b.value());
        if (v instanceof MiniJson.JsonNull) return "null";
        return "";
    }

    /** 文本归一化：动态内容替换为占位符。 */
    public static String normalizeText(String body) {
        if (body == null) {
            return "";
        }
        String s = body;
        s = SET_COOKIE_DYNAMIC.matcher(s).replaceAll("$1#");
        s = TOKEN_KEY_VALUE.matcher(s).replaceAll("$1$2$3#$3");
        s = UUID.matcher(s).replaceAll("#");
        s = ISO_TIME.matcher(s).replaceAll("#");
        s = LONG_HEX.matcher(s).replaceAll("#");
        s = UNIX_TS.matcher(s).replaceAll("#");
        s = RANDOM_LOOKING.matcher(s).replaceAll("#");
        s = PURE_NUMBER.matcher(s).replaceAll("#");
        return s;
    }

    /** token 相似度（Jaccard），与 SQL 引擎同款归一化前处理。 */
    public static double similarity(String a, String b) {
        Set<String> ta = tokens(a);
        Set<String> tb = tokens(b);
        if (ta.isEmpty() && tb.isEmpty()) {
            return 1.0;
        }
        if (ta.isEmpty() || tb.isEmpty()) {
            return 0.0;
        }
        Set<String> union = new HashSet<>(ta);
        union.addAll(tb);
        Set<String> inter = new HashSet<>(ta);
        inter.retainAll(tb);
        return (double) inter.size() / union.size();
    }

    private static final Pattern TOKEN = Pattern.compile("[a-z0-9#]{2,}");

    static Set<String> tokens(String text) {
        Set<String> out = new HashSet<>();
        if (text == null) {
            return out;
        }
        String low = text.toLowerCase(Locale.ROOT);
        Matcher mt = TOKEN.matcher(low);
        while (mt.find()) {
            out.add(mt.group());
        }
        return out;
    }

    /** 提取响应文本前 N 行的预览（证据展示用）。 */
    public static List<String> headLines(String text, int n) {
        List<String> out = new ArrayList<>();
        if (text == null) {
            return out;
        }
        for (String line : text.split("\n")) {
            out.add(line.length() > 300 ? line.substring(0, 300) + "..." : line);
            if (out.size() >= n) {
                break;
            }
        }
        return out;
    }
}
