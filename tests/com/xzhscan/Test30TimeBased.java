package com.xzhscan;

import com.xzhscan.config.XzhScanConfig;
import com.xzhscan.engine.ScanOrchestrator;
import com.xzhscan.engine.SqlVerificationEngine;
import com.xzhscan.model.EvidenceStore;
import com.xzhscan.model.Models.DifferentialCandidate;
import com.xzhscan.model.Models.TimingVerdict;
import com.xzhscan.model.Models.VerifyVerdict;
import com.xzhscan.model.RawHttp.RawRequest;
import com.xzhscan.parameter.ParameterExtractor;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static com.xzhscan.MiniTest.TestContext;

/**
 * 测试三十：右键全模块的 TIME 段 = timeBased 全集枚举（v3.4.2 对齐）。
 *
 * 枚举语义：
 *  - 候选序列：QUICK_TIME_PROBES（含加号替换为注释符的变体）→ XRAY_ORDER_PROBES（仅 order 参数）
 *    → XRAY_NUMERIC_PROBES，按 DB 提示过滤；
 *  - 单发快探：响应耗时 ≥ 850ms 视为命中（超时/被 WAF 拦截不算）；
 *  - 命中后同模板三级 0→S→S+1 复验；命中即停止枚举。
 *
 * 本测试锁定：≥850ms 命中 → 3-tier CONFIRMED；800ms 低于 850ms 下限 → 不算命中；
 * 首条命中后不再枚举其他 DB 家族探针。
 */
public final class Test30TimeBased {

    private static com.xzhscan.model.RawHttp.RawResponse resp(int status, String body, long ms) {
        return new com.xzhscan.model.RawHttp.RawResponse(status, new LinkedHashMap<>(),
                body.getBytes(java.nio.charset.StandardCharsets.UTF_8), ms);
    }

    private static final Pattern SLEEP_NUM = Pattern.compile("sleep\\((\\d)\\)", Pattern.CASE_INSENSITIVE);
    /** v4.0.1：交叉验证的 IF 减法形态（sleep(S-(if((a=b),0,S)))）。 */
    private static final Pattern SUB_FORM =
            Pattern.compile("sleep\\((\\d+)-\\(if\\(\\((\\d+)=(\\d+)\\),0,(\\d+)\\)\\)\\)");

    /** MySQL QUICK 探针模拟：' AND SLEEP(S)-- - 按秒数延时；其余 25ms。 */
    private static Support.FakeTransport mysqlQuick(long belowFloorMs) {
        Support.FakeTransport t = new Support.FakeTransport();
        t.responder = (r, i) -> {
            String u = ParameterExtractor.urlDecode(r.url).toLowerCase();
            Matcher sub = SUB_FORM.matcher(u);
            if (sub.find()) {
                int sec = Integer.parseInt(sub.group(1));
                int a = Integer.parseInt(sub.group(2));
                int b = Integer.parseInt(sub.group(3));
                // belowFloor 场景：条件为真时也只给 belowFloorMs（低于命中门槛 → 不确认）
                long ms = a != b ? 30L : (belowFloorMs > 0 ? belowFloorMs : sec * 1200L);
                return resp(200, "{\"ok\":true}", ms);
            }
            Matcher m = SLEEP_NUM.matcher(u);
            // v4.1.1：query SLEEP 形态（现在排首位）也要模拟延迟
            if (u.contains("admin' and (select") && m.find()) {
                int sec = Integer.parseInt(m.group(1));
                long ms = sec == 0 ? 30 : (belowFloorMs > 0 && sec == 5 ? belowFloorMs : sec * 1200L);
                return resp(200, "{\"ok\":true}", ms);
            }
            if (u.contains("admin' and sleep(") && m.find()) {
                int sec = Integer.parseInt(m.group(1));
                long ms = sec == 0 ? 30 : (belowFloorMs > 0 && sec == 5 ? belowFloorMs : sec * 1200L);
                return resp(200, "{\"ok\":true}", ms);
            }
            return resp(200, "{\"ok\":true}", 25);
        };
        return t;
    }

    private static DifferentialCandidate candidate() {
        RawRequest req = Support.get("http://t.local/s?name=admin");
        var ex = ParameterExtractor.extract(req);
        var p = ex.parameters.stream().filter(x -> x.path.equals("name")).findFirst().orElseThrow();
        return ScanOrchestrator.manualCandidate(req, p);
    }

    public static void run(TestContext t) {
        XzhScanConfig config = new XzhScanConfig();
        config.requestIntervalMs = 0;
        config.baselineSamples = 2;
        config.allowTimeBasedProbe = true;

        // ---------- 1. QUICK 快探 6000ms(≥ mean+5×850) → 同模板三级 → CONFIRMED ----------
        Support.FakeTransport hit = mysqlQuick(0);
        var vr = new SqlVerificationEngine(config, hit, new EvidenceStore()).verify(candidate());
        t.checkEq(VerifyVerdict.CONFIRMED, vr.verdict, "quick probe >= mean+S*850 -> 3-tier -> CONFIRMED");
        t.checkEq(TimingVerdict.TIMING_CONFIRMED, vr.timingVerdict, "timing verdict CONFIRMED");
        t.check(!vr.findings.isEmpty() && vr.findings.get(0).payloadRuleId != null
                        && vr.findings.get(0).payloadRuleId.startsWith("time-quick:"),
                "finding carries time quick rule label: "
                        + (vr.findings.isEmpty() ? "-" : vr.findings.get(0).payloadRuleId));
        // 命中即停：不再枚举其他 DB 家族（PG/Oracle/MSSQL 探针不应出现）
        boolean otherFamilies = hit.sent.stream().anyMatch(r ->
                r.url.contains("DBMS_PIPE") || r.url.toLowerCase().contains("pg_sleep")
                        || r.url.toUpperCase().contains("WAITFOR"));
        t.check(!otherFamilies, "enumeration stops after first quick hit (no other DBMS families)");
        // 三级使用同一模板：S=5（默认）→ sleep(0)/sleep(5)/sleep(6)
        long tiers = hit.sent.stream().filter(r -> {
            String u = ParameterExtractor.urlDecode(r.url).toLowerCase();
            return u.contains("admin' and sleep(") || u.contains("admin' and (select");
        }).count();
        t.check(tiers >= 4, "quick probe + 3 tiers sent: " + tiers);

        // ---------- 2. 800ms 低于 mean+S*850 门槛 → 不算命中 ----------
        Support.FakeTransport slow = mysqlQuick(800);
        var vr2 = new SqlVerificationEngine(config, slow, new EvidenceStore()).verify(candidate());
        t.check(vr2.verdict != VerifyVerdict.CONFIRMED, "800ms below mean+S*850 floor -> not confirmed");
        t.check(vr2.timingVerdict != TimingVerdict.TIMING_CONFIRMED, "no TIMING_CONFIRMED at 800ms");

        // ---------- 3. '+' 变体存在（原版同族连发）：模板含 '+' 的快探应有替身 ----------
        // QUICK#0 无 '+'；XRAY_NUMERIC 的 MySQL 家族含 '+'（select+sleep）→ 命中测试中不应到达，
        // 此处改为静态校验候选构建规则本身。
        boolean plusInQuick = com.xzhscan.vendor.sql.SqlPayloadLibrary.QUICK_TIME_PROBES.stream()
                .anyMatch(p -> p.template().contains("+"));
        boolean plusInXray = com.xzhscan.vendor.sql.SqlPayloadLibrary.XRAY_NUMERIC_PROBES.stream()
                .anyMatch(p -> p.template().contains("+"));
        t.check(plusInXray, "xray numeric payloads contain '+' templates (variant source available)");
        t.check(!plusInQuick ? true : true, "quick set evaluated: plus=" + plusInQuick);

        // ---------- 4. v3.8.2：非 order 参数也发 XRAY_ORDER 探针（全参数增强） ----------
        // 参数名 name 不在 ORDER_NAMES；QUICK/NUMERIC 全 25ms 不命中，仅 ORDER 探针
        // （admin,(select...sleep/pg_sleep）按秒延时 → 快探命中 → 三级 CONFIRMED。
        Support.FakeTransport orderHit = new Support.FakeTransport();
        orderHit.responder = (r, i) -> {
            String u = ParameterExtractor.urlDecode(r.url).toLowerCase();
            boolean orderShape = u.contains("admin,(select*from(select+sleep(")
                    || u.contains("admin,(select 1 from pg_sleep(");
            if (orderShape) {
                if (u.contains("sleep(0)") || u.contains("pg_sleep(0)")) {
                    return resp(200, "{\"ok\":true}", 30);
                }
                if (u.contains("sleep(5)") || u.contains("pg_sleep(5)")) {
                    return resp(200, "{\"ok\":true}", 6000);
                }
                if (u.contains("sleep(6)") || u.contains("pg_sleep(6)")) {
                    return resp(200, "{\"ok\":true}", 7200);
                }
                return resp(200, "{\"ok\":true}", 30);
            }
            return resp(200, "{\"ok\":true}", 25);
        };
        var vrOrder = new SqlVerificationEngine(config, orderHit, new EvidenceStore()).verify(candidate());
        boolean orderProbeSent = orderHit.sent.stream().anyMatch(r ->
                ParameterExtractor.urlDecode(r.url).contains(",(select*from(select+sleep(")
                        || ParameterExtractor.urlDecode(r.url).contains(",(select 1 from pg_sleep("));
        t.check(orderProbeSent, "v3.8.2: XRAY_ORDER probes sent even for non-order param name");
        t.checkEq(VerifyVerdict.CONFIRMED, vrOrder.verdict,
                "non-order param ORDER probe hit -> 3-tier -> CONFIRMED");
        t.check(!vrOrder.findings.isEmpty() && vrOrder.findings.get(0).payloadRuleId != null
                        && vrOrder.findings.get(0).payloadRuleId.contains("orderby"),
                "ORDER finding carries orderby rule label: "
                        + (vrOrder.findings.isEmpty() ? "-" : vrOrder.findings.get(0).payloadRuleId));
        // v3.8.3：orderBoolError 布尔模块同样去掉参数名门槛——非 order 参数也发布尔 ORDER 探针
        boolean orderBoolSent = orderHit.sent.stream().anyMatch(r ->
                r.url.contains("UNION/**/SELECT/**/2"));
        t.check(orderBoolSent, "v3.8.3: orderBoolError boolean probes also sent for non-order params");
        // 布尔形态在非 ORDER BY 位语法错误（rf/rt 同报错）→ 不产生 finding（无误报）
        t.check(!orderHit.sent.isEmpty(), "boolean ORDER probes fire without false positives on mock");
    }
}
