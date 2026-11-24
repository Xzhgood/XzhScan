package com.xzhscan.parameter;

import com.xzhscan.model.Models.InvalidRequestType;
import com.xzhscan.model.Models.Location;
import com.xzhscan.model.Models.ParameterIdentity;
import com.xzhscan.model.RawHttp.RawRequest;

import java.math.BigDecimal;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

/**
 * 受控参数变异器：QUERY / FORM / JSON 三种位置的统一入口。
 *
 * 关键保证（v2.2 修订）：
 *  - 只改目标参数，其余参数字节保持原样；
 *  - APPEND 变异保留原始报文片段（rawName=rawValue 原样 + 追加编码后的 payload），
 *    不做 解码→重编码 往返，杜绝 +/空格/百分号语义漂移与非 ASCII 损坏；
 *  - JSON 走 MiniJson AST：解析 -> setByPath -> serialize -> 重新 parse 校验；
 *    校验失败时 success=false，绝不发送非法 JSON；
 *  - 数字字段默认保持数字类型（算术变异），字符串化变异显式标记 typeChanged；
 *  - 同名参数按 occurrence 精确定位（第 N 个同名 query/form 参数独立可测）；
 *  - MutationResult 携带本地 JSON 合法性与失败原因，供 DifferentialGate 使用。
 */
public final class ParameterMutators {

    private ParameterMutators() {
    }

    /** 变异模式。 */
    public enum Mode {
        /** 字符串参数：值末尾追加 payload（payload 中的引号将被正确转义）。 */
        APPEND,
        /** 数字参数：保持 JSON 数字类型做算术变异（-1 / -0），payload 形如 "-1"。 */
        NUMBER_ARITH,
        /** 数字参数：转为 "值+payload" 字符串（typeChanged=true，弱证据）。 */
        NUMBER_TO_STRING_APPEND
    }

    /** 变异结果（失败原因带分类，不吞异常语义）。 */
    public static final class MutationResult {
        public final boolean success;
        public final RawRequest request;
        /** 本地序列化后的 JSON 是否通过重新解析校验。 */
        public final boolean jsonValid;
        public final boolean typeChanged;
        public final String originalType;
        public final String mutatedValue;
        public final String failureReason;
        /** 失败分类（NONE=成功）。 */
        public final InvalidRequestType failureType;

        private MutationResult(boolean success, RawRequest request, boolean jsonValid, boolean typeChanged,
                               String originalType, String mutatedValue, String failureReason,
                               InvalidRequestType failureType) {
            this.success = success;
            this.request = request;
            this.jsonValid = jsonValid;
            this.typeChanged = typeChanged;
            this.originalType = originalType;
            this.mutatedValue = mutatedValue;
            this.failureReason = failureReason;
            this.failureType = failureType;
        }

        static MutationResult ok(RawRequest r, boolean jsonValid, boolean typeChanged, String origType, String mutated) {
            return new MutationResult(true, r, jsonValid, typeChanged, origType, mutated, null, InvalidRequestType.NONE);
        }

        static MutationResult fail(String reason, InvalidRequestType type) {
            return new MutationResult(false, null, false, false, null, null, reason, type);
        }
    }

    /** 统一入口：按参数位置分派。 */
    public static MutationResult mutate(RawRequest original, ParameterIdentity param, Mode mode, String payload) {
        if (param.location == Location.QUERY) {
            return mutateQuery(original, param, payload);
        }
        if (param.location == Location.FORM) {
            return mutateForm(original, param, payload);
        }
        return mutateJson(original, param, mode, payload);
    }

    /**
     * 完整值替换（第二阶段专用，与被移植引擎 ScanParams.mutate 的语义一致）：
     * 目标参数的新值就是 fullNewValue 本身（xray replace 语义），其余参数原样。
     * JSON 数字字段被字符串化时 typeChanged=true。
     */
    public static MutationResult replaceValue(RawRequest original, ParameterIdentity param, String fullNewValue) {
        switch (param.location) {
            case QUERY:
                return replaceQueryValue(original, param, fullNewValue);
            case FORM:
                return replaceFormValue(original, param, fullNewValue);
            default:
                return replaceJsonValue(original, param, fullNewValue);
        }
    }

    private static MutationResult replaceQueryValue(RawRequest original, ParameterIdentity param, String fullNewValue) {
        String url = original.url;
        int q = url.indexOf('?');
        if (q < 0) {
            return MutationResult.fail("no query string", InvalidRequestType.MUTATION_UNSUPPORTED);
        }
        String base = url.substring(0, q);
        String query = url.substring(q + 1);
        int hash = query.indexOf('#');
        String frag = "";
        if (hash >= 0) {
            frag = query.substring(hash);
            query = query.substring(0, hash);
        }
        StringBuilder sb = new StringBuilder();
        int seen = 0;
        boolean replaced = false;
        for (String pair : query.split("&")) {
            if (pair.isEmpty()) {
                continue;
            }
            if (sb.length() > 0) {
                sb.append('&');
            }
            int eq = pair.indexOf('=');
            String rawName = eq < 0 ? pair : pair.substring(0, eq);
            if (ParameterExtractor.urlDecode(rawName).equals(param.name)) {
                if (!replaced && seen == param.occurrence) {
                    replaced = true;
                    sb.append(rawName).append('=').append(urlEncodeValue(fullNewValue));
                } else {
                    sb.append(pair);
                }
                seen++;
            } else {
                sb.append(pair);
            }
        }
        if (!replaced) {
            return MutationResult.fail("query parameter not found: " + param.name + "#" + param.occurrence,
                    InvalidRequestType.PARAM_NOT_FOUND);
        }
        return MutationResult.ok(new RawRequest(original.method, base + "?" + sb + frag, original.headers, original.body),
                true, false, "string", fullNewValue);
    }

    private static MutationResult replaceFormValue(RawRequest original, ParameterIdentity param, String fullNewValue) {
        String body = original.bodyAsString();
        StringBuilder sb = new StringBuilder();
        int seen = 0;
        boolean replaced = false;
        for (String pair : body.split("&")) {
            if (pair.isEmpty()) {
                continue;
            }
            if (sb.length() > 0) {
                sb.append('&');
            }
            int eq = pair.indexOf('=');
            String rawName = eq < 0 ? pair : pair.substring(0, eq);
            if (ParameterExtractor.urlDecode(rawName).equals(param.name)) {
                if (!replaced && seen == param.occurrence) {
                    replaced = true;
                    sb.append(rawName).append('=').append(formEncode(fullNewValue));
                } else {
                    sb.append(pair);
                }
                seen++;
            } else {
                sb.append(pair);
            }
        }
        if (!replaced) {
            return MutationResult.fail("form parameter not found: " + param.name + "#" + param.occurrence,
                    InvalidRequestType.PARAM_NOT_FOUND);
        }
        return MutationResult.ok(original.withBody(sb.toString().getBytes(StandardCharsets.UTF_8)),
                true, false, "string", fullNewValue);
    }

    private static MutationResult replaceJsonValue(RawRequest original, ParameterIdentity param, String fullNewValue) {
        String body = original.bodyAsString();
        MiniJson.JsonValue root;
        try {
            root = MiniJson.parse(body);
        } catch (MiniJson.JsonParseException e) {
            return MutationResult.fail("baseline body is not valid JSON: " + e.getMessage(), InvalidRequestType.BASELINE_JSON_INVALID);
        }
        MiniJson.JsonValue target = MiniJson.getByPath(root, param.path);
        if (target == null) {
            return MutationResult.fail("json path not found: " + param.path, InvalidRequestType.PARAM_NOT_FOUND);
        }
        String originalType = MiniJson.typeName(target);
        boolean typeChanged = !(target instanceof MiniJson.JsonString);
        MiniJson.JsonValue newRoot;
        try {
            newRoot = MiniJson.setByPath(root, param.path, new MiniJson.JsonString(fullNewValue));
        } catch (IllegalArgumentException e) {
            return MutationResult.fail(e.getMessage(), InvalidRequestType.MUTATION_UNSUPPORTED);
        }
        String serialized = MiniJson.serialize(newRoot);
        try {
            MiniJson.parse(serialized);
        } catch (MiniJson.JsonParseException e) {
            return MutationResult.fail("re-serialized JSON failed local validation: " + e.getMessage(), InvalidRequestType.JSON_MUTATION_INVALID);
        }
        return MutationResult.ok(original.withBody(serialized.getBytes(StandardCharsets.UTF_8)),
                true, typeChanged, originalType, fullNewValue);
    }

    // ------------------------------------------------------------------
    // QUERY
    // ------------------------------------------------------------------

    /**
     * URL 参数最小编码（xray 风格：只编码会破坏 URL 结构的字符 + 非 ASCII 走 UTF-8
     * 百分号编码，保证 ISO-8859-1 请求行不损坏）。
     */
    static String urlEncodeValue(String s) {
        StringBuilder sb = new StringBuilder(s.length() + 8);
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if (c < 0x80) {
                switch (c) {
                    case '\n': sb.append("%0A"); break;
                    case '\r': sb.append("%0D"); break;
                    case ' ': sb.append("%20"); break;
                    case '#': sb.append("%23"); break;
                    case '%': sb.append("%25"); break;
                    case '&': sb.append("%26"); break;
                    case '?': sb.append("%3F"); break;
                    case '+': sb.append("%2B"); break;
                    default: sb.append(c);
                }
            } else {
                // 非 ASCII：按 UTF-8 逐字节百分号编码（补充字符走代理对，各自独立编码）
                byte[] bytes = String.valueOf(c).getBytes(StandardCharsets.UTF_8);
                for (byte b : bytes) {
                    sb.append('%').append(String.format("%02X", b & 0xFF));
                }
            }
        }
        return sb.toString();
    }

    /**
     * APPEND 变异（QUERY）：原始报文片段原样保留，仅追加 url 编码后的 payload。
     * 不做 解码→重编码 往返，服务端所见值语义 = 原值语义 + 注入串。
     */
    static MutationResult mutateQuery(RawRequest original, ParameterIdentity param, String payload) {
        String url = original.url;
        int q = url.indexOf('?');
        String base = q >= 0 ? url.substring(0, q) : url;
        String query = q >= 0 ? url.substring(q + 1) : "";
        int hash = query.indexOf('#');
        String frag = "";
        if (hash >= 0) {
            frag = query.substring(hash);
            query = query.substring(0, hash);
        }

        String mutatedValue = param.originalValue + payload;
        StringBuilder sb = new StringBuilder();
        int seen = 0;
        boolean replaced = false;
        for (String pair : query.split("&")) {
            if (pair.isEmpty()) {
                continue;
            }
            if (sb.length() > 0) {
                sb.append('&');
            }
            int eq = pair.indexOf('=');
            String rawName = eq < 0 ? pair : pair.substring(0, eq);
            String rawValue = eq < 0 ? "" : pair.substring(eq + 1);
            if (ParameterExtractor.urlDecode(rawName).equals(param.name)) {
                if (!replaced && seen == param.occurrence) {
                    replaced = true;
                    sb.append(rawName).append('=').append(rawValue).append(urlEncodeValue(payload));
                } else {
                    sb.append(pair);
                }
                seen++;
            } else {
                sb.append(pair);
            }
        }
        if (!replaced) {
            return MutationResult.fail("query parameter not found: " + param.name + "#" + param.occurrence,
                    InvalidRequestType.PARAM_NOT_FOUND);
        }
        String newUrl = sb.length() > 0 ? base + "?" + sb + frag : base + frag;
        RawRequest mutated = new RawRequest(original.method, newUrl, original.headers, original.body);
        return MutationResult.ok(mutated, true, false, "string", mutatedValue);
    }

    // ------------------------------------------------------------------
    // FORM
    // ------------------------------------------------------------------

    /**
     * APPEND 变异（FORM）：原始片段原样保留 + 追加编码后的 payload（同 QUERY 保真策略）。
     */
    static MutationResult mutateForm(RawRequest original, ParameterIdentity param, String payload) {
        String body = original.bodyAsString();
        String mutatedValue = param.originalValue + payload;
        StringBuilder sb = new StringBuilder();
        int seen = 0;
        boolean replaced = false;
        for (String pair : body.split("&")) {
            if (pair.isEmpty()) {
                continue;
            }
            if (sb.length() > 0) {
                sb.append('&');
            }
            int eq = pair.indexOf('=');
            String rawName = eq < 0 ? pair : pair.substring(0, eq);
            String rawValue = eq < 0 ? "" : pair.substring(eq + 1);
            if (ParameterExtractor.urlDecode(rawName).equals(param.name)) {
                if (!replaced && seen == param.occurrence) {
                    replaced = true;
                    sb.append(rawName).append('=').append(rawValue).append(formEncode(payload));
                } else {
                    sb.append(pair);
                }
                seen++;
            } else {
                sb.append(pair);
            }
        }
        if (!replaced) {
            return MutationResult.fail("form parameter not found: " + param.name + "#" + param.occurrence,
                    InvalidRequestType.PARAM_NOT_FOUND);
        }
        RawRequest mutated = original.withBody(sb.toString().getBytes(StandardCharsets.UTF_8));
        return MutationResult.ok(mutated, true, false, "string", mutatedValue);
    }

    /** 表单值编码（同 urlEncodeValue 语义）。 */
    static String formEncode(String s) {
        return urlEncodeValue(s);
    }

    // ------------------------------------------------------------------
    // JSON（AST）
    // ------------------------------------------------------------------

    static MutationResult mutateJson(RawRequest original, ParameterIdentity param, Mode mode, String payload) {
        String body = original.bodyAsString();
        MiniJson.JsonValue root;
        try {
            root = MiniJson.parse(body);
        } catch (MiniJson.JsonParseException e) {
            return MutationResult.fail("baseline body is not valid JSON: " + e.getMessage(), InvalidRequestType.BASELINE_JSON_INVALID);
        }
        MiniJson.JsonValue target;
        try {
            target = MiniJson.getByPath(root, param.path);
        } catch (IllegalArgumentException e) {
            return MutationResult.fail(e.getMessage(), InvalidRequestType.MUTATION_UNSUPPORTED);
        }
        if (target == null) {
            return MutationResult.fail("json path not found: " + param.path, InvalidRequestType.PARAM_NOT_FOUND);
        }
        String originalType = MiniJson.typeName(target);

        MiniJson.JsonValue newValue;
        boolean typeChanged = false;
        String mutatedValue;
        if (target instanceof MiniJson.JsonNumber num && mode == Mode.NUMBER_ARITH) {
            BigDecimal dec;
            try {
                dec = new BigDecimal(num.rawToken());
            } catch (NumberFormatException e) {
                return MutationResult.fail("unparseable number token: " + num.rawToken(), InvalidRequestType.MUTATION_UNSUPPORTED);
            }
            BigDecimal out;
            try {
                out = dec.subtract(new BigDecimal(payload));
            } catch (NumberFormatException e) {
                return MutationResult.fail("bad arith payload: " + payload, InvalidRequestType.MUTATION_UNSUPPORTED);
            }
            mutatedValue = out.stripTrailingZeros().toPlainString();
            newValue = MiniJson.JsonNumber.of(mutatedValue);
        } else if (target instanceof MiniJson.JsonString str) {
            mutatedValue = str.value() + payload;
            newValue = new MiniJson.JsonString(mutatedValue);
        } else if (target instanceof MiniJson.JsonNumber num2 && mode == Mode.NUMBER_TO_STRING_APPEND) {
            mutatedValue = num2.rawToken() + payload;
            newValue = new MiniJson.JsonString(mutatedValue);
            typeChanged = true;
        } else if (target instanceof MiniJson.JsonNumber num3 && mode == Mode.APPEND) {
            // APPEND 落在数字上：默认不允许隐式字符串化
            return MutationResult.fail("numeric field requires NUMBER_* mode, refusing implicit stringify (path=" + param.path + ")", InvalidRequestType.MUTATION_UNSUPPORTED);
        } else if (target instanceof MiniJson.JsonBool || target instanceof MiniJson.JsonNull
                || target instanceof MiniJson.JsonObject || target instanceof MiniJson.JsonArray) {
            return MutationResult.fail("unsupported target type for mutation: " + originalType, InvalidRequestType.MUTATION_UNSUPPORTED);
        } else {
            return MutationResult.fail("unsupported target: " + param.path, InvalidRequestType.MUTATION_UNSUPPORTED);
        }

        MiniJson.JsonValue newRoot;
        try {
            newRoot = MiniJson.setByPath(root, param.path, newValue);
        } catch (IllegalArgumentException e) {
            return MutationResult.fail(e.getMessage(), InvalidRequestType.MUTATION_UNSUPPORTED);
        }
        String serialized = MiniJson.serialize(newRoot);
        // 重新用标准解析器验证
        try {
            MiniJson.parse(serialized);
        } catch (MiniJson.JsonParseException e) {
            return MutationResult.fail("re-serialized JSON failed local validation: " + e.getMessage(), InvalidRequestType.JSON_MUTATION_INVALID);
        }
        RawRequest mutated = original.withBody(serialized.getBytes(StandardCharsets.UTF_8));
        return MutationResult.ok(mutated, true, typeChanged, originalType, mutatedValue);
    }

    /** 构造保持除目标参数外全部原样的替换头列表（Content-Length 由传输层处理）。 */
    static List<String> stripContentLength(List<String> headers) {
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
