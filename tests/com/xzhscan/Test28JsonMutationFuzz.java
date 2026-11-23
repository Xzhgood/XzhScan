package com.xzhscan;

import com.xzhscan.model.Models.ParameterIdentity;
import com.xzhscan.model.RawHttp.RawRequest;
import com.xzhscan.parameter.MiniJson;
import com.xzhscan.parameter.ParameterExtractor;
import com.xzhscan.parameter.ParameterMutators;

import static com.xzhscan.MiniTest.TestContext;

/**
 * 测试二十八：JSON 变异全形态自测（v3.3，用户报告"变异引擎 JSON bug"的排查落地）。
 *
 * 结论先行：变异引擎本体（AST setByPath + writeString 完备转义 + UTF-8 字节 +
 * 重解析校验）在全形态下无 bug；此前怀疑点均为校验侧比对形态错误（拿未转义原文
 * 比序列化文本）。本套件用 **AST 值级断言** 锁死保真语义：
 *
 *  - 变异 success 且 body 仍是合法 JSON（MiniJson 重解析）；
 *  - 目标路径：变为字符串值，值 = 原标量 + payload（数字为 rawToken+payload，
 *    大数/科学计数原始 token 不漂移）；
 *  - 非目标路径：AST 值逐一相等（真零漂移，与转义形态无关）；
 *  - 含引号/反斜杠/中文/unicode 转义值往返无损。
 *
 * 覆盖：嵌套/纯数组/对象数组/大数与科学计数/中文/引号反斜杠值/unicode 转义/
 * null与bool与空容器/深层嵌套/顶层数组。
 */
public final class Test28JsonMutationFuzz {

    private static final String NOISE = "\u9397'\"\\" + "("; // 鎈'"\(

    public static void run(TestContext t) {
        String[][] cases = {
                {"嵌套对象", "{\"user\":{\"name\":\"Tom\",\"id\":7},\"flag\":true}"},
                {"纯数组", "{\"ids\":[1,2,3],\"names\":[\"a\",\"b\"]}"},
                {"对象数组", "{\"rows\":[{\"k\":\"v1\"},{\"k\":\"v2\"}]}"},
                {"大数/科学计数", "{\"n\":12345678901234567890,\"f\":1.5e10,\"neg\":-3}"},
                {"中文值", "{\"name\":\"好班长\",\"city\":\"成都\"}"},
                {"引号反斜杠值", "{\"q\":\"a\\\"b\\\\c\",\"s\":\"it's\"}"},
                {"unicode转义值", "{\"u\":\"\\u4f60\\u597d\",\"e\":\"ok\"}"},
                {"null与bool与空容器", "{\"n\":null,\"b\":false,\"empty\":{},\"arr\":[]}"},
                {"深层嵌套", "{\"a\":{\"b\":{\"c\":{\"d\":\"x\"}}}}"},
                {"顶层数组", "[{\"k\":1},{\"k\":2}]"},
        };
        String[] payloads = {
                "' AND SLEEP(6)-- -",
                "0'XOR(IF(1=1,SLEEP(6),0))XOR'Z",
                "1\"and\"q\"=\"q",
                NOISE,
                "好班长' AND 1=1-- -",
        };
        int mutations = 0;
        for (String[] c : cases) {
            RawRequest req = Support.postJson("http://t.local/j", c[1]);
            ParameterExtractor.ExtractResult ex = ParameterExtractor.extract(req);
            t.check(ex.baselineAnomaly == null, c[0] + " 基线可解析"
                    + (ex.baselineAnomaly == null ? "" : ": " + ex.baselineAnomaly));
            MiniJson.JsonValue originalRoot;
            try {
                originalRoot = MiniJson.parse(c[1]);
            } catch (RuntimeException e) {
                continue;
            }
            for (ParameterIdentity p : ex.parameters) {
                if (!p.mutable()) {
                    continue;
                }
                String scalar = p.originalValue; // 字符串为解码值；数字为 rawToken
                for (String payload : payloads) {
                    ParameterMutators.Mode mode = p.type == com.xzhscan.model.Models.ParamType.NUMBER
                            ? ParameterMutators.Mode.NUMBER_TO_STRING_APPEND
                            : ParameterMutators.Mode.APPEND;
                    ParameterMutators.MutationResult m = ParameterMutators.mutate(req, p, mode, payload);
                    mutations++;
                    String ctx = c[0] + " " + p.path + " payload=" + safe(payload);
                    if (!m.success) {
                        t.check(false, ctx + " 变异失败: " + m.failureReason);
                        continue;
                    }
                    String body = m.request.bodyAsString();
                    MiniJson.JsonValue newRoot;
                    try {
                        newRoot = MiniJson.parse(body);
                    } catch (RuntimeException e) {
                        t.check(false, ctx + " 变异后非法 JSON: " + e.getMessage());
                        continue;
                    }
                    // 目标路径：字符串值 = 原标量 + payload（APPEND 语义，数字字符串化）
                    MiniJson.JsonValue target = MiniJson.getByPath(newRoot, p.path);
                    String expected = (scalar == null ? "" : scalar) + payload;
                    if (target instanceof MiniJson.JsonString js) {
                        t.checkEq(expected, js.value(), ctx + " 目标值=原标量+payload（AST 值级）");
                    } else {
                        t.check(false, ctx + " 目标路径未字符串化: " + MiniJson.typeName(target));
                    }
                    // 非目标路径：AST 值逐一相等（零漂移）
                    boolean drift = false;
                    for (ParameterIdentity other : ex.parameters) {
                        if (other.path.equals(p.path)) {
                            continue;
                        }
                        MiniJson.JsonValue before = MiniJson.getByPath(originalRoot, other.path);
                        MiniJson.JsonValue after = MiniJson.getByPath(newRoot, other.path);
                        if (!astEquals(before, after)) {
                            drift = true;
                            t.check(false, ctx + " 非目标漂移: " + other.path + " "
                                    + MiniJson.typeName(before) + "->" + MiniJson.typeName(after));
                        }
                    }
                    if (!drift) {
                        t.check(true, ctx + " 非目标零漂移");
                    }
                }
            }
        }
        t.check(mutations >= 100, "变异样本量足够: " + mutations);
    }

    /** AST 值等价（标量比值；容器递归）。 */
    private static boolean astEquals(MiniJson.JsonValue a, MiniJson.JsonValue b) {
        if (a == null || b == null) {
            return a == b;
        }
        if (a instanceof MiniJson.JsonString sa) {
            return b instanceof MiniJson.JsonString sb && sa.value().equals(sb.value());
        }
        if (a instanceof MiniJson.JsonNumber na) {
            return b instanceof MiniJson.JsonNumber nb && na.rawToken().equals(nb.rawToken());
        }
        if (a instanceof MiniJson.JsonBool ba) {
            return b instanceof MiniJson.JsonBool bb && ba.value() == bb.value();
        }
        if (a instanceof MiniJson.JsonNull) {
            return b instanceof MiniJson.JsonNull;
        }
        if (a instanceof MiniJson.JsonObject oa) {
            if (!(b instanceof MiniJson.JsonObject ob) || oa.members().size() != ob.members().size()) {
                return false;
            }
            for (var e : oa.members().entrySet()) {
                if (!ob.members().containsKey(e.getKey())
                        || !astEquals(e.getValue(), ob.members().get(e.getKey()))) {
                    return false;
                }
            }
            return true;
        }
        if (a instanceof MiniJson.JsonArray aa) {
            if (!(b instanceof MiniJson.JsonArray ab) || aa.items().size() != ab.items().size()) {
                return false;
            }
            for (int i = 0; i < aa.items().size(); i++) {
                if (!astEquals(aa.items().get(i), ab.items().get(i))) {
                    return false;
                }
            }
            return true;
        }
        return false;
    }

    private static String safe(String payload) {
        return payload.replace("\n", "\\n");
    }
}
