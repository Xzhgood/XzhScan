package com.xzhscan;

import com.xzhscan.parameter.MiniJson;
import com.xzhscan.parameter.ParameterExtractor;
import com.xzhscan.parameter.ParameterMutators;

import static com.xzhscan.MiniTest.TestContext;

/** 测试一：JSON 双引号 —— 变异后必须仍是合法 JSON，不得引发本地拼接错误。 */
public final class Test1JsonQuoteMutation {

    public static void run(TestContext t) {
        // 1. {"name":"admin"} + 双引号
        RawHttp0 req = new RawHttp0("POST", "http://t.local/api/q", "{\"name\":\"admin\"}");
        ParameterExtractor.ExtractResult ex = ParameterExtractor.extract(req.raw);
        t.check(ex.parameters.size() == 1, "flat json: one param extracted");
        t.checkEq("$.name", ex.parameters.get(0).path, "flat json path");

        ParameterMutators.MutationResult m = ParameterMutators.mutate(
                req.raw, ex.parameters.get(0), ParameterMutators.Mode.APPEND, "\"");
        t.check(m.success, "mutation succeeds");
        String body = new String(m.request.body, java.nio.charset.StandardCharsets.UTF_8);
        t.checkEq("{\"name\":\"admin\\\"\"}", body, "double quote properly escaped");
        try {
            MiniJson.parse(body);
            t.check(true, "mutated body re-parses as valid JSON");
        } catch (MiniJson.JsonParseException e) {
            t.check(false, "mutated body re-parses as valid JSON: " + e.getMessage());
        }

        // 2. 值内已有引号/反斜杠/Unicode 转义
        String tricky = "{\"s\":\"a\\\"b\\\\c\\u4e2d\"}";
        RawHttp0 req2 = new RawHttp0("POST", "http://t.local/api/q", tricky);
        ParameterExtractor.ExtractResult ex2 = ParameterExtractor.extract(req2.raw);
        ParameterMutators.MutationResult m2 = ParameterMutators.mutate(
                req2.raw, ex2.parameters.get(0), ParameterMutators.Mode.APPEND, "\"");
        t.check(m2.success, "tricky value mutation succeeds");
        String body2 = new String(m2.request.body, java.nio.charset.StandardCharsets.UTF_8);
        try {
            MiniJson.JsonValue reparsed = MiniJson.parse(body2);
            String value = ((MiniJson.JsonString) MiniJson.getByPath(reparsed, "$.s")).value();
            t.checkEq("a\"b\\c中\"", value, "decoded value = original + payload");
            t.check(true, "tricky mutated body re-parses");
        } catch (MiniJson.JsonParseException e) {
            t.check(false, "tricky mutated body re-parses: " + e.getMessage());
        }

        // 3. 数字字段：默认 APPEND 拒绝隐式字符串化；算术变异保持数字类型
        RawHttp0 req3 = new RawHttp0("POST", "http://t.local/api/q", "{\"page\":1}");
        ParameterExtractor.ExtractResult ex3 = ParameterExtractor.extract(req3.raw);
        ParameterMutators.MutationResult m3a = ParameterMutators.mutate(
                req3.raw, ex3.parameters.get(0), ParameterMutators.Mode.APPEND, "'");
        t.check(!m3a.success, "numeric field refuses implicit stringify append");
        ParameterMutators.MutationResult m3b = ParameterMutators.mutate(
                req3.raw, ex3.parameters.get(0), ParameterMutators.Mode.NUMBER_ARITH, "1");
        t.check(m3b.success, "numeric arith mutation succeeds");
        t.check(!m3b.typeChanged, "numeric type preserved");
        t.checkEq("{\"page\":0}", new String(m3b.request.body, java.nio.charset.StandardCharsets.UTF_8),
                "1-1 computed as number");

        // 4. null/bool 不变异
        RawHttp0 req4 = new RawHttp0("POST", "http://t.local/api/q", "{\"a\":null,\"b\":true}");
        ParameterExtractor.ExtractResult ex4 = ParameterExtractor.extract(req4.raw);
        for (var p : ex4.parameters) {
            ParameterMutators.MutationResult mr = ParameterMutators.mutate(req4.raw, p, ParameterMutators.Mode.APPEND, "'");
            t.check(!mr.success, "non-scalar " + p.path + " not mutable");
        }

        // 5. 重复键拒绝（不静默改错字段）
        try {
            MiniJson.parse("{\"a\":1,\"a\":2}");
            t.check(false, "duplicate key rejected by strict parser");
        } catch (MiniJson.JsonParseException e) {
            t.check(true, "duplicate key rejected by strict parser");
        }
        MiniJson.ParseInfo info = new MiniJson.ParseInfo();
        MiniJson.parse("{\"a\":1,\"a\":2}", MiniJson.DuplicateKeyPolicy.KEEP_FIRST, info);
        t.check(info.hasDuplicateKeys, "lenient parse reports duplicate keys");

        // 6. 非法 JSON 基线 -> baselineAnomaly，不变异
        RawHttp0 req5 = new RawHttp0("POST", "http://t.local/api/q", "{\"name\":\"admin\"\",\"page\":1}");
        ParameterExtractor.ExtractResult ex5 = ParameterExtractor.extract(req5.raw);
        t.check(ex5.baselineAnomaly != null && ex5.jsonBody == null,
                "broken baseline json flagged, no auto mutation");
    }

    /** 小构造器（POST JSON 请求）。 */
    static final class RawHttp0 {
        final com.xzhscan.model.RawHttp.RawRequest raw;

        RawHttp0(String method, String url, String body) {
            java.util.List<String> headers = new java.util.ArrayList<>();
            headers.add("Host: t.local");
            headers.add("Content-Type: application/json");
            this.raw = new com.xzhscan.model.RawHttp.RawRequest(method, url, headers,
                    body.getBytes(java.nio.charset.StandardCharsets.UTF_8));
        }
    }
}
