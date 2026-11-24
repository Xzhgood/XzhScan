package com.xzhscan.parameter;

import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * 严格的最小 JSON AST 解析/序列化实现（RFC 8259）。
 *
 * 设计目标（对应 XzhScan 任务第三节）：
 *  - 解析为结构化对象树后按路径修改，再序列化，杜绝字符串拼接破坏语法；
 *  - 字符串转义（引号、反斜杠、控制字符、'u'XXXX 码点与代理对）严格处理；
 *  - 数字保留原始 token，序列化原样回写，避免 1.10 -> 1.1 的格式漂移；
 *  - 重复键、尾逗号、单引号、注释、NaN、前导零等在严格模式下直接报错，
 *    不允许静默修改错误字段；
 *  - 序列化结果必须能被自身（以及任何标准解析器）重新解析。
 *
 * 该类不依赖任何第三方库与 Burp API，可独立单元测试。
 */
public final class MiniJson {

    private static final String LF = String.valueOf((char) 10);

    private MiniJson() {
    }

    /** 所有 JSON 值节点。 */
    public sealed interface JsonValue permits JsonObject, JsonArray, JsonString, JsonNumber, JsonBool, JsonNull {
    }

    /** JSON 对象：保持插入顺序，键唯一。 */
    public static final class JsonObject implements JsonValue {
        private final Map<String, JsonValue> members;

        public JsonObject(Map<String, JsonValue> members) {
            this.members = members;
        }

        public Map<String, JsonValue> members() {
            return members;
        }

        public JsonValue get(String key) {
            return members.get(key);
        }
    }

    /** JSON 数组。 */
    public static final class JsonArray implements JsonValue {
        private final List<JsonValue> items;

        public JsonArray(List<JsonValue> items) {
            this.items = items;
        }

        public List<JsonValue> items() {
            return items;
        }
    }

    /** JSON 字符串（已解码为 Java String）。 */
    public record JsonString(String value) implements JsonValue {
    }

    /** JSON 数字：保留原始 token，保证序列化不漂移。 */
    public record JsonNumber(String rawToken, Number number) implements JsonValue {
        public static JsonNumber of(String token) {
            return new JsonNumber(token, parseNumber(token));
        }

        private static Number parseNumber(String t) {
            try {
                if (t.indexOf('.') >= 0 || t.indexOf('e') >= 0 || t.indexOf('E') >= 0) {
                    return Double.parseDouble(t);
                }
                long l = Long.parseLong(t);
                if (l >= Integer.MIN_VALUE && l <= Integer.MAX_VALUE) {
                    return (int) l;
                }
                return l;
            } catch (NumberFormatException e) {
                return Double.parseDouble(t);
            }
        }
    }

    /** JSON 布尔。 */
    public record JsonBool(boolean value) implements JsonValue {
    }

    /** JSON null。 */
    public static final class JsonNull implements JsonValue {
        public static final JsonNull INSTANCE = new JsonNull();

        private JsonNull() {
        }
    }

    /** 解析失败（含具体位置与原因）。 */
    public static final class JsonParseException extends RuntimeException {
        public final int position;
        public final String reason;

        public JsonParseException(String reason, int position) {
            super(reason + " at position " + position);
            this.reason = reason;
            this.position = position;
        }
    }

    /** 重复键处理策略。 */
    public enum DuplicateKeyPolicy {
        /** 严格：重复键视为非法输入，抛出异常。 */
        REJECT,
        /** 宽容：保留第一个键值（并可通过 parseInfo 获知）。 */
        KEEP_FIRST
    }

    /** 一次解析的附加信息。 */
    public static final class ParseInfo {
        public boolean hasDuplicateKeys;
        public List<String> duplicateKeys = new ArrayList<>();
    }

    // ------------------------------------------------------------------
    // 解析
    // ------------------------------------------------------------------

    public static JsonValue parse(String text) {
        return parse(text, DuplicateKeyPolicy.REJECT, null);
    }

    /** 宽松入口：重复键保留第一个，不抛异常（用于展示与对比）。 */
    public static JsonValue parseLenient(String text) {
        return parse(text, DuplicateKeyPolicy.KEEP_FIRST, null);
    }

    public static JsonValue parse(String text, DuplicateKeyPolicy policy, ParseInfo info) {
        if (text == null) {
            throw new JsonParseException("null input", 0);
        }
        Parser p = new Parser(text, policy, info);
        p.skipWs();
        JsonValue v = p.parseValue();
        p.skipWs();
        if (!p.eof()) {
            throw new JsonParseException("trailing content", p.pos);
        }
        return v;
    }

    private static final class Parser {
        private final String s;
        private final DuplicateKeyPolicy policy;
        private final ParseInfo info;
        private int pos;

        Parser(String s, DuplicateKeyPolicy policy, ParseInfo info) {
            this.s = s;
            this.policy = policy == null ? DuplicateKeyPolicy.REJECT : policy;
            this.info = info == null ? new ParseInfo() : info;
        }

        boolean eof() {
            return pos >= s.length();
        }

        char peek() {
            if (eof()) {
                throw new JsonParseException("unexpected end of input", pos);
            }
            return s.charAt(pos);
        }

        void skipWs() {
            while (!eof()) {
                char c = s.charAt(pos);
                if (c == ' ' || c == '\t' || c == '\n' || c == '\r') {
                    pos++;
                } else {
                    break;
                }
            }
        }

        void expect(char c) {
            if (eof() || s.charAt(pos) != c) {
                throw new JsonParseException("expected '" + c + "'", pos);
            }
            pos++;
        }

        JsonValue parseValue() {
            char c = peek();
            switch (c) {
                case '{':
                    return parseObject();
                case '[':
                    return parseArray();
                case '"':
                    return new JsonString(parseString());
                case 't':
                    expectWord("true");
                    return new JsonBool(true);
                case 'f':
                    expectWord("false");
                    return new JsonBool(false);
                case 'n':
                    expectWord("null");
                    return JsonNull.INSTANCE;
                default:
                    if (c == '-' || (c >= '0' && c <= '9')) {
                        return parseNumber();
                    }
                    throw new JsonParseException("unexpected character '" + c + "'", pos);
            }
        }

        private void expectWord(String w) {
            if (!s.startsWith(w, pos)) {
                throw new JsonParseException("invalid literal", pos);
            }
            pos += w.length();
        }

        private JsonObject parseObject() {
            expect('{');
            Map<String, JsonValue> map = new LinkedHashMap<>();
            skipWs();
            if (!eof() && peek() == '}') {
                pos++;
                return new JsonObject(map);
            }
            while (true) {
                skipWs();
                if (eof() || peek() != '"') {
                    throw new JsonParseException("expected object key string", pos);
                }
                String key = parseString();
                skipWs();
                expect(':');
                skipWs();
                JsonValue value = parseValue();
                if (map.containsKey(key)) {
                    if (policy == DuplicateKeyPolicy.REJECT) {
                        throw new JsonParseException("duplicate key \"" + key + "\"", pos);
                    }
                    info.hasDuplicateKeys = true;
                    if (info.duplicateKeys.size() < 32) {
                        info.duplicateKeys.add(key);
                    }
                    // KEEP_FIRST：保留第一个
                } else {
                    map.put(key, value);
                }
                skipWs();
                char c = peek();
                if (c == ',') {
                    pos++;
                    skipWs();
                    if (!eof() && peek() == '}') {
                        throw new JsonParseException("trailing comma in object", pos);
                    }
                } else if (c == '}') {
                    pos++;
                    return new JsonObject(map);
                } else {
                    throw new JsonParseException("expected ',' or '}'", pos);
                }
            }
        }

        private JsonArray parseArray() {
            expect('[');
            List<JsonValue> list = new ArrayList<>();
            skipWs();
            if (!eof() && peek() == ']') {
                pos++;
                return new JsonArray(list);
            }
            while (true) {
                skipWs();
                list.add(parseValue());
                skipWs();
                char c = peek();
                if (c == ',') {
                    pos++;
                    skipWs();
                    if (!eof() && peek() == ']') {
                        throw new JsonParseException("trailing comma in array", pos);
                    }
                } else if (c == ']') {
                    pos++;
                    return new JsonArray(list);
                } else {
                    throw new JsonParseException("expected ',' or ']'", pos);
                }
            }
        }

        private String parseString() {
            expect('"');
            StringBuilder sb = new StringBuilder();
            while (true) {
                if (eof()) {
                    throw new JsonParseException("unterminated string", pos);
                }
                char c = s.charAt(pos++);
                if (c == '"') {
                    return sb.toString();
                }
                if (c == '\\') {
                    char e = peek();
                    pos++;
                    switch (e) {
                        case '"': sb.append('"'); break;
                        case '\\': sb.append('\\'); break;
                        case '/': sb.append('/'); break;
                        case 'b': sb.append('\b'); break;
                        case 'f': sb.append('\f'); break;
                        case 'n': sb.append('\n'); break;
                        case 'r': sb.append('\r'); break;
                        case 't': sb.append('\t'); break;
                        case 'u':
                            if (pos + 4 > s.length()) {
                                throw new JsonParseException("invalid \\uXXXX escape", pos);
                            }
                            int hex = 0;
                            for (int i = 0; i < 4; i++) {
                                char h = s.charAt(pos + i);
                                int d = Character.digit(h, 16);
                                if (d < 0) {
                                    throw new JsonParseException("invalid \\uXXXX escape", pos);
                                }
                                hex = (hex << 4) | d;
                            }
                            pos += 4;
                            sb.append((char) hex);
                            break;
                        default:
                            throw new JsonParseException("invalid escape '\\" + e + "'", pos - 1);
                    }
                } else if (c < 0x20) {
                    throw new JsonParseException("unescaped control character in string", pos - 1);
                } else {
                    sb.append(c);
                }
            }
        }

        private JsonNumber parseNumber() {
            int start = pos;
            if (!eof() && s.charAt(pos) == '-') {
                pos++;
            }
            // 整数部分
            if (eof()) {
                throw new JsonParseException("invalid number", pos);
            }
            char c = s.charAt(pos);
            if (c == '0') {
                pos++;
            } else if (c >= '1' && c <= '9') {
                while (!eof() && Character.isDigit(s.charAt(pos))) {
                    pos++;
                }
            } else {
                throw new JsonParseException("invalid number", pos);
            }
            // 小数
            if (!eof() && s.charAt(pos) == '.') {
                pos++;
                if (eof() || !Character.isDigit(s.charAt(pos))) {
                    throw new JsonParseException("invalid number fraction", pos);
                }
                while (!eof() && Character.isDigit(s.charAt(pos))) {
                    pos++;
                }
            }
            // 指数
            if (!eof() && (s.charAt(pos) == 'e' || s.charAt(pos) == 'E')) {
                pos++;
                if (!eof() && (s.charAt(pos) == '+' || s.charAt(pos) == '-')) {
                    pos++;
                }
                if (eof() || !Character.isDigit(s.charAt(pos))) {
                    throw new JsonParseException("invalid number exponent", pos);
                }
                while (!eof() && Character.isDigit(s.charAt(pos))) {
                    pos++;
                }
            }
            return JsonNumber.of(s.substring(start, pos));
        }
    }

    // ------------------------------------------------------------------
    // 序列化
    // ------------------------------------------------------------------

    public static String serialize(JsonValue value) {
        StringBuilder sb = new StringBuilder();
        write(value, sb);
        return sb.toString();
    }

    private static void write(JsonValue v, StringBuilder sb) {
        if (v instanceof JsonObject o) {
            sb.append('{');
            boolean first = true;
            for (Map.Entry<String, JsonValue> e : o.members().entrySet()) {
                if (!first) {
                    sb.append(',');
                }
                first = false;
                writeString(e.getKey(), sb);
                sb.append(':');
                write(e.getValue(), sb);
            }
            sb.append('}');
        } else if (v instanceof JsonArray a) {
            sb.append('[');
            List<JsonValue> items = a.items();
            for (int i = 0; i < items.size(); i++) {
                if (i > 0) {
                    sb.append(',');
                }
                write(items.get(i), sb);
            }
            sb.append(']');
        } else if (v instanceof JsonString str) {
            writeString(str.value(), sb);
        } else if (v instanceof JsonNumber n) {
            // 原始 token 回写，保证数字格式不漂移
            sb.append(n.rawToken());
        } else if (v instanceof JsonBool b) {
            sb.append(b.value() ? "true" : "false");
        } else if (v instanceof JsonNull) {
            sb.append("null");
        } else {
            throw new IllegalStateException("unknown json node: " + v);
        }
    }

    private static void writeString(String s, StringBuilder sb) {
        sb.append('"');
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            switch (c) {
                case '"': sb.append("\\\""); break;
                case '\\': sb.append("\\\\"); break;
                case '\b': sb.append("\\b"); break;
                case '\f': sb.append("\\f"); break;
                case '\n': sb.append("\\n"); break;
                case '\r': sb.append("\\r"); break;
                case '\t': sb.append("\\t"); break;
                default:
                    if (c < 0x20) {
                        sb.append(String.format("\\u%04x", (int) c));
                    } else {
                        sb.append(c);
                    }
            }
        }
        sb.append('"');
    }

    /** 缩进美化序列化（Chinese 消息查看用；异常降级紧凑输出）。 */
    public static String prettyPrint(JsonValue value) {
        try {
            StringBuilder sb = new StringBuilder();
            writePretty(value, 0, sb);
            return sb.toString();
        } catch (RuntimeException e) {
            return serialize(value);
        }
    }

    private static void writePretty(JsonValue v, int indent, StringBuilder sb) {
        String pad = "  ".repeat(indent);
        String padIn = "  ".repeat(indent + 1);
        if (v instanceof JsonObject o) {
            if (o.members().isEmpty()) {
                sb.append("{}");
                return;
            }
            sb.append("{").append(LF);
            int i = 0;
            for (Map.Entry<String, JsonValue> e : o.members().entrySet()) {
                sb.append(padIn);
                writeString(e.getKey(), sb);
                sb.append(": ");
                writePretty(e.getValue(), indent + 1, sb);
                if (++i < o.members().size()) {
                    sb.append(',');
                }
                sb.append(LF);
            }
            sb.append(pad).append('}');
        } else if (v instanceof JsonArray a) {
            if (a.items().isEmpty()) {
                sb.append("[]");
                return;
            }
            sb.append("[").append(LF);
            List<JsonValue> items = a.items();
            for (int j = 0; j < items.size(); j++) {
                sb.append(padIn);
                writePretty(items.get(j), indent + 1, sb);
                if (j < items.size() - 1) {
                    sb.append(',');
                }
                sb.append(LF);
            }
            sb.append(pad).append(']');
        } else {
            write(v, sb);
        }
    }

    // ------------------------------------------------------------------
    // 路径定位与修改（$.a.b[0].c，支持 ['weird.key'] 形式的键名）
    // ------------------------------------------------------------------

    /** 路径词法单元。 */
    public record PathToken(String key, Integer index) {
    }

    /** 把 "$.user.profile.name" / "$.items[1].id" 解析成 token 列表。 */
    public static List<PathToken> parsePath(String path) {
        if (path == null || path.isEmpty() || path.equals("$")) {
            return Collections.emptyList();
        }
        String p = path.startsWith("$") ? path.substring(1) : path;
        List<PathToken> tokens = new ArrayList<>();
        int i = 0;
        while (i < p.length()) {
            char c = p.charAt(i);
            if (c == '.') {
                i++;
                continue;
            }
            if (c == '[') {
                int close = p.indexOf(']', i);
                if (close < 0) {
                    throw new IllegalArgumentException("invalid path (unclosed bracket): " + path);
                }
                String inner = p.substring(i + 1, close).trim();
                if (inner.startsWith("'") && inner.endsWith("'") && inner.length() >= 2) {
                    tokens.add(new PathToken(inner.substring(1, inner.length() - 1), null));
                } else {
                    try {
                        tokens.add(new PathToken(null, Integer.parseInt(inner)));
                    } catch (NumberFormatException e) {
                        throw new IllegalArgumentException("invalid array index in path: " + path);
                    }
                }
                i = close + 1;
            } else {
                int j = i;
                while (j < p.length() && p.charAt(j) != '.' && p.charAt(j) != '[') {
                    j++;
                }
                tokens.add(new PathToken(p.substring(i, j), null));
                i = j;
            }
        }
        return tokens;
    }

    /** 按路径读取节点；不存在返回 null。 */
    public static JsonValue getByPath(JsonValue root, String path) {
        JsonValue cur = root;
        for (PathToken t : parsePath(path)) {
            if (cur == null) {
                return null;
            }
            if (t.index() != null) {
                if (!(cur instanceof JsonArray a) || t.index() < 0 || t.index() >= a.items().size()) {
                    return null;
                }
                cur = a.items().get(t.index());
            } else {
                if (!(cur instanceof JsonObject o)) {
                    return null;
                }
                cur = o.get(t.key());
            }
        }
        return cur;
    }

    /**
     * 不可变替换：返回一棵新树，仅 path 处的值被替换为 newValue，其余节点原样共享。
     * path 必须已存在，否则抛出 IllegalArgumentException（不允许静默新增字段）。
     */
    public static JsonValue setByPath(JsonValue root, String path, JsonValue newValue) {
        List<PathToken> tokens = parsePath(path);
        return setByTokens(root, tokens, 0, newValue, path);
    }

    private static JsonValue setByTokens(JsonValue cur, List<PathToken> tokens, int depth, JsonValue newValue, String fullPath) {
        if (depth == tokens.size()) {
            return newValue;
        }
        PathToken t = tokens.get(depth);
        if (t.index() != null) {
            if (!(cur instanceof JsonArray a)) {
                throw new IllegalArgumentException("path mismatch: expected array at depth " + depth + " in " + fullPath);
            }
            List<JsonValue> copy = new ArrayList<>(a.items());
            if (t.index() < 0 || t.index() >= copy.size()) {
                throw new IllegalArgumentException("array index out of range in " + fullPath);
            }
            copy.set(t.index(), setByTokens(copy.get(t.index()), tokens, depth + 1, newValue, fullPath));
            return new JsonArray(copy);
        } else {
            if (!(cur instanceof JsonObject o)) {
                throw new IllegalArgumentException("path mismatch: expected object at depth " + depth + " in " + fullPath);
            }
            if (!o.members().containsKey(t.key())) {
                throw new IllegalArgumentException("key not found: " + t.key() + " in " + fullPath);
            }
            Map<String, JsonValue> copy = new LinkedHashMap<>(o.members());
            copy.put(t.key(), setByTokens(o.get(t.key()), tokens, depth + 1, newValue, fullPath));
            return new JsonObject(copy);
        }
    }

    /** 节点类型名（用于类型保持记录）。 */
    public static String typeName(JsonValue v) {
        if (v instanceof JsonObject) return "object";
        if (v instanceof JsonArray) return "array";
        if (v instanceof JsonString) return "string";
        if (v instanceof JsonNumber) return "number";
        if (v instanceof JsonBool) return "boolean";
        if (v instanceof JsonNull) return "null";
        return "unknown";
    }

    /** 遍历所有叶子标量路径（对象值与数组元素中的标量）。 */
    public static void collectLeafPaths(JsonValue node, String prefix, List<String> out) {
        if (node instanceof JsonObject o) {
            for (Map.Entry<String, JsonValue> e : o.members().entrySet()) {
                String child = prefix + "." + e.getKey();
                JsonValue v = e.getValue();
                if (v instanceof JsonObject || v instanceof JsonArray) {
                    if (isEmpty(v)) {
                        // 空对象/空数组本身视为不可变异叶子
                        out.add(child);
                    } else {
                        collectLeafPaths(v, child, out);
                    }
                } else {
                    out.add(child);
                }
            }
        } else if (node instanceof JsonArray a) {
            for (int i = 0; i < a.items().size(); i++) {
                String child = prefix + "[" + i + "]";
                JsonValue v = a.items().get(i);
                if (v instanceof JsonObject || v instanceof JsonArray) {
                    if (isEmpty(v)) {
                        out.add(child);
                    } else {
                        collectLeafPaths(v, child, out);
                    }
                } else {
                    out.add(child);
                }
            }
        }
    }

    private static boolean isEmpty(JsonValue v) {
        if (v instanceof JsonObject o) return o.members().isEmpty();
        if (v instanceof JsonArray a) return a.items().isEmpty();
        return false;
    }
}
