package com.xzhscan;

import com.xzhscan.parameter.MiniJson;
import com.xzhscan.parameter.ParameterExtractor;
import com.xzhscan.parameter.ParameterMutators;

import java.nio.charset.StandardCharsets;
import java.util.List;

import static com.xzhscan.MiniTest.TestContext;

/**
 * 测试五：嵌套 JSON 精确定位。
 * $.user.profile.name 与 $.items[1].id 可独立变异，其他参数一字节不动。
 */
public final class Test5NestedJson {

    static final String BODY = "{"
            + "\"user\":{\"id\":1,\"profile\":{\"name\":\"test\"}},"
            + "\"items\":[{\"id\":100},{\"id\":200}]"
            + "}";

    public static void run(TestContext t) throws Exception {
        var req = Support.postJson("http://t.local/api/submit", BODY);
        ParameterExtractor.ExtractResult ex = ParameterExtractor.extract(req);
        List<String> paths = ex.parameters.stream().map(p -> p.path).toList();
        t.check(paths.contains("$.user.id"), "leaf $.user.id found");
        t.check(paths.contains("$.user.profile.name"), "leaf $.user.profile.name found");
        t.check(paths.contains("$.items[0].id"), "leaf $.items[0].id found");
        t.check(paths.contains("$.items[1].id"), "leaf $.items[1].id found");

        // ---- 变异 $.user.profile.name ----
        var nameParam = ex.parameters.stream().filter(p -> p.path.equals("$.user.profile.name")).findFirst().orElseThrow();
        var mName = ParameterMutators.mutate(req, nameParam, ParameterMutators.Mode.APPEND, "'");
        t.check(mName.success, "mutate $.user.profile.name ok");
        MiniJson.JsonValue v1 = MiniJson.parse(new String(mName.request.body, StandardCharsets.UTF_8));
        t.checkEq("test'", ((MiniJson.JsonString) MiniJson.getByPath(v1, "$.user.profile.name")).value(),
                "name mutated");
        t.checkEq("1", ((MiniJson.JsonNumber) MiniJson.getByPath(v1, "$.user.id")).rawToken(), "user.id untouched");
        t.checkEq("100", ((MiniJson.JsonNumber) MiniJson.getByPath(v1, "$.items[0].id")).rawToken(), "items[0].id untouched");
        t.checkEq("200", ((MiniJson.JsonNumber) MiniJson.getByPath(v1, "$.items[1].id")).rawToken(), "items[1].id untouched");

        // ---- 变异 $.items[1].id（数字 -> 字符串化追加） ----
        var idParam = ex.parameters.stream().filter(p -> p.path.equals("$.items[1].id")).findFirst().orElseThrow();
        var mId = ParameterMutators.mutate(req, idParam, ParameterMutators.Mode.NUMBER_TO_STRING_APPEND, "'");
        t.check(mId.success, "mutate $.items[1].id ok");
        t.check(mId.typeChanged, "numeric->string flagged typeChanged");
        MiniJson.JsonValue v2 = MiniJson.parse(new String(mId.request.body, StandardCharsets.UTF_8));
        t.checkEq("200'", ((MiniJson.JsonString) MiniJson.getByPath(v2, "$.items[1].id")).value(),
                "items[1].id mutated");
        t.checkEq("100", ((MiniJson.JsonNumber) MiniJson.getByPath(v2, "$.items[0].id")).rawToken(),
                "items[0].id untouched");
        t.checkEq("test", ((MiniJson.JsonString) MiniJson.getByPath(v2, "$.user.profile.name")).value(),
                "user.profile.name untouched");

        // ---- 变异 $.user.id（数字算术保持类型） ----
        var uidParam = ex.parameters.stream().filter(p -> p.path.equals("$.user.id")).findFirst().orElseThrow();
        var mUid = ParameterMutators.mutate(req, uidParam, ParameterMutators.Mode.NUMBER_ARITH, "1");
        t.check(mUid.success && !mUid.typeChanged, "user.id arith keeps number");
        MiniJson.JsonValue v3 = MiniJson.parse(new String(mUid.request.body, StandardCharsets.UTF_8));
        t.checkEq("0", ((MiniJson.JsonNumber) MiniJson.getByPath(v3, "$.user.id")).rawToken(), "user.id 1-1=0");

        // ---- 完整值替换（第二阶段语义） ----
        var rep = ParameterMutators.replaceValue(req, nameParam, "test' AND 1=1-- -");
        t.check(rep.success, "replaceValue ok");
        MiniJson.JsonValue v4 = MiniJson.parse(new String(rep.request.body, StandardCharsets.UTF_8));
        t.checkEq("test' AND 1=1-- -",
                ((MiniJson.JsonString) MiniJson.getByPath(v4, "$.user.profile.name")).value(),
                "full-value replacement");
        t.checkEq("200", ((MiniJson.JsonNumber) MiniJson.getByPath(v4, "$.items[1].id")).rawToken(),
                "others untouched after replace");
    }
}
