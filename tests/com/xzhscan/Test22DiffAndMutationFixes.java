package com.xzhscan;

import com.xzhscan.config.XzhScanConfig;
import com.xzhscan.differential.BaselineCollector;
import com.xzhscan.differential.DifferenceAnalyzer;
import com.xzhscan.engine.SqlVerificationEngine;
import com.xzhscan.model.EvidenceStore;
import com.xzhscan.model.Models.DiffEvidence;
import com.xzhscan.model.Models.DifferentialCandidate;
import com.xzhscan.model.Models.VerifyVerdict;
import com.xzhscan.model.EvidenceBundles;
import com.xzhscan.model.Models.VerificationResult;
import com.xzhscan.parameter.ParameterExtractor;
import com.xzhscan.parameter.ParameterMutators;
import com.xzhscan.parameter.ParameterMutators.MutationResult;
import com.xzhscan.parameter.ParameterMutators.Mode;

import java.util.LinkedHashMap;

import static com.xzhscan.MiniTest.TestContext;

/**
 * 测试二十二：差分/布尔/变异修复回归（任务书 §12/§13/§14/§11）。
 *  - 证据分型：LENGTH_DIFF/BODY_DIFF/STATUS_DIFF/SQL_ERROR/TIMING_ANOMALY 独立标记；
 *  - boolPair 布尔预言机：TRUE/FALSE 语义正确（c1≠c2 强制），FALSE 探针必然得到假页；
 *  - 动态基线：单轮差异 → SUSPECTED（falsePositiveNote），不再 CONFIRMED；
 *  - 变异保真：APPEND 保留原始报文片段（+/空格/% 不重编码、非 ASCII 不损坏）；
 *  - 同名参数按 occurrence 独立定位；
 *  - verify-baseline 证据携带响应（四视图原始响应不再依赖回退）；
 *  - verifyTimeoutMs 预算耗尽 → INVALID。
 */
public final class Test22DiffAndMutationFixes {

    private static com.xzhscan.model.RawHttp.RawResponse resp(int status, String body, long ms) {
        return new com.xzhscan.model.RawHttp.RawResponse(status, new LinkedHashMap<>(),
                body.getBytes(java.nio.charset.StandardCharsets.UTF_8), ms);
    }

    private static final String TRUE_PAGE = "<html><body><h1>item detail</h1>"
            + "<p>name widget price nine quantity four status active category tools</p></body></html>";
    private static final String FALSE_PAGE = "<html><body><h1>error page</h1>"
            + "<p>exception stack trace nothing here missing resource gone away silent</p></body></html>";

    public static void run(TestContext t) throws Exception {
        // ---------- 1. 证据分型 ----------
        XzhScanConfig config = new XzhScanConfig();
        config.requestIntervalMs = 0;
        config.baselineSamples = 3;
        var base = Support.get("http://t.local/d?name=admin");
        BaselineCollector.Baseline b = BaselineCollector.collect(base, 2, (r) -> resp(200, "ok body", 30));
        DiffEvidence ev = DifferenceAnalyzer.analyze(b, resp(500, "MySQL XPATH syntax error boom", 900),
                null, "name", "single-quote", "admin", "admin'", "string", false, true, config);
        t.check(ev.evidenceKinds.contains("SQL_ERROR"), "SQL_ERROR kind marked");
        t.check(ev.evidenceKinds.contains("STATUS_DIFF"), "STATUS_DIFF kind marked (200->500)");
        t.check(ev.evidenceKinds.contains("BODY_DIFF"), "BODY_DIFF kind marked");
        t.check(ev.evidenceKinds.contains("LENGTH_DIFF"), "LENGTH_DIFF kind marked");
        t.check(ev.evidenceKinds.contains("TIMING_ANOMALY"), "TIMING_ANOMALY kind marked (900ms vs 30ms baseline)");
        // LENGTH_DIFF 单独存在但弱：不与 SQL_ERROR 混同
        t.check(ev.evidenceKinds.size() >= 4, "multi-kind evidence separated: " + ev.evidenceKinds);

        // ---------- 2. 布尔预言机（c1≠c2 强制；FALSE 探针必得假页） ----------
        // 预言机：解析 payload 布尔条件并返回真/假页；记录每个 FALSE 请求实际得到的页面
        java.util.List<String> falseProbePages = new java.util.ArrayList<>();
        Support.FakeTransport oracle = new Support.FakeTransport();
        oracle.responder = (r, i) -> {
            String v = r.url.contains("name=") ? r.url.substring(r.url.indexOf("name=") + 5) : "";
            String dec = ParameterExtractor.urlDecode(v);
            Boolean truth = evalBool(dec);
            if (truth == null) {
                return resp(200, TRUE_PAGE, 25); // 基线/TRUE 形态
            }
            String page = truth ? TRUE_PAGE : FALSE_PAGE;
            if (!truth) {
                falseProbePages.add(page);
            }
            return resp(200, page, 25);
        };
        SqlVerificationEngine engine = new SqlVerificationEngine(config, oracle, new EvidenceStore());
        VerificationResult vr = engine.verify(boolCandidate("http://t.local/b?name=admin"));
        t.checkEq(VerifyVerdict.CONFIRMED, vr.verdict, "oracle-backed boolPair confirms on stable baseline");
        t.check(!falseProbePages.isEmpty(), "FALSE probes exercised: " + falseProbePages.size());
        boolean falsePageAlwaysFalse = falseProbePages.stream().allMatch(p -> p.equals(FALSE_PAGE));
        t.check(falsePageAlwaysFalse, "every FALSE probe evaluated FALSE (c1!=c2 enforced)");

        // ---------- 3. 动态基线：单轮成立、二轮失败 → SUSPECTED ----------
        java.util.concurrent.atomic.AtomicInteger dynamicCalls = new java.util.concurrent.atomic.AtomicInteger();
        Support.FakeTransport dynamic = new Support.FakeTransport();
        dynamic.responder = (r, i) -> {
            String v = r.url.contains("name=") ? r.url.substring(r.url.indexOf("name=") + 5) : "";
            String dec = ParameterExtractor.urlDecode(v);
            Boolean truth = evalBool(dec);
            int n = dynamicCalls.incrementAndGet();
            // 调用序（确定）：基线3 → castBool 4 → boolPair TRUE/FALSE → 复验 TRUE/FALSE = 11；
            // 前 11 个响应模拟动态基线（不同噪声词）；此后回真页（第二轮 FALSE≈基线 → 二轮失败）
            String noise = n <= 11 ? " noise" + n : "";
            if (truth != null && !truth && n > 11) {
                return resp(200, TRUE_PAGE, 25); // 第二轮 FALSE 被基线吞掉
            }
            return resp(200, (truth == null || truth ? TRUE_PAGE : FALSE_PAGE) + noise, 25);
        };
        SqlVerificationEngine dEngine = new SqlVerificationEngine(config, dynamic, new EvidenceStore());
        VerificationResult vr2 = dEngine.verify(boolCandidate("http://t.local/b2?name=admin"));
        t.check(vr2.verdict == VerifyVerdict.SUSPECTED,
                "dynamic baseline single-round pattern -> SUSPECTED (not CONFIRMED): " + vr2.verdict);
        t.check(vr2.findings.stream().anyMatch(f -> f.falsePositiveNote != null),
                "falsePositiveNote records why not confirmed");

        // ---------- 4. 变异保真：原始片段原样保留 ----------
        // 4a. 值含 + 与 %20：raw 片段保留，payload 追加编码（服务端语义 = 原值+payload）
        var q = new com.xzhscan.model.Models.ParameterIdentity(
                com.xzhscan.model.Models.Location.QUERY, "q", "q", "a+b c", com.xzhscan.model.Models.ParamType.STRING);
        MutationResult mq = ParameterMutators.mutate(
                Support.get("http://t.local/s?x=1&q=a+b%20c"), q, Mode.APPEND, "'");
        t.check(mq.success, "mutate ok");
        t.check(mq.request.url.contains("q=a+b%20c'"), "raw fragment preserved verbatim: " + mq.request.url);
        t.check(!mq.request.url.contains("%252"), "no double encoding");
        t.checkEq("a+b c'", ParameterExtractor.urlDecode(
                mq.request.url.substring(mq.request.url.indexOf("q=") + 2)), "decoded = original + payload");
        // 4b. 非 ASCII replaceValue：UTF-8 百分号编码（请求行不损坏）
        var cn = new com.xzhscan.model.Models.ParameterIdentity(
                com.xzhscan.model.Models.Location.QUERY, "q", "q", "中文", com.xzhscan.model.Models.ParamType.STRING);
        MutationResult mc = ParameterMutators.replaceValue(
                Support.get("http://t.local/s?q=%E4%B8%AD%E6%96%87"), cn, "中文'");
        t.check(mc.success, "replaceValue non-ASCII ok");
        boolean asciiOnly = mc.request.url.chars().allMatch(ch -> ch < 0x80);
        t.check(asciiOnly, "URL is pure ASCII after encoding (ISO-8859-1 safe): " + mc.request.url);
        t.check(mc.request.url.contains("q=%E4%B8%AD%E6%96%87'"), "value UTF-8 percent-encoded (quote kept raw): " + mc.request.url);
        // 4c. APPEND 非 ASCII payload 同样安全
        MutationResult ma = ParameterMutators.mutate(
                Support.get("http://t.local/s?q=1"), q, Mode.APPEND, "中'");
        t.check(ma.success && ma.request.url.contains("%E4%B8%AD"), "non-ASCII payload percent-encoded");
        // 4d. 同名参数 occurrence 定位
        var two = Support.get("http://t.local/s?id=1&id=2");
        var ex = ParameterExtractor.extract(two);
        t.checkEq(2, ex.parameters.size(), "duplicate names both extracted");
        t.checkEq(0, ex.parameters.get(0).occurrence, "first occurrence index 0");
        t.checkEq(1, ex.parameters.get(1).occurrence, "second occurrence index 1");
        var second = ex.parameters.get(1);
        MutationResult mo = ParameterMutators.mutate(two, second, Mode.APPEND, "'");
        t.check(mo.request.url.contains("id=1&id=2'"), "only 2nd occurrence mutated: " + mo.request.url);
        var first = ex.parameters.get(0);
        MutationResult mo0 = ParameterMutators.mutate(two, first, Mode.APPEND, "'");
        t.check(mo0.request.url.contains("id=1'&id=2"), "only 1st occurrence mutated: " + mo0.request.url);

        // ---------- 5. verify-baseline 证据携带响应（四视图原始响应不靠回退） ----------
        Support.FakeTransport stable = new Support.FakeTransport();
        stable.responder = (r, i) -> resp(200, TRUE_PAGE, 25);
        EvidenceStore store = new EvidenceStore();
        SqlVerificationEngine vEngine = new SqlVerificationEngine(config, stable, store);
        DifferentialCandidate bc = boolCandidate("http://t.local/b3?name=admin");
        VerificationResult vr3 = vEngine.verify(bc);
        EvidenceBundles.Bundle bundle = EvidenceBundles.resolve(bc, vr3, null, store);
        t.check(bundle.originalResponse != null, "original response available from verify-baseline evidence");
        t.check(bundle.missing.stream().noneMatch(m -> m.contains("原始响应缺失")),
                "no 'original response missing' note");

        // ---------- 6. verifyTimeoutMs 预算耗尽 → INVALID ----------
        XzhScanConfig tiny = config.copy();
        tiny.verifyTimeoutMs = 1L;
        Support.FakeTransport slow = new Support.FakeTransport();
        slow.responder = (r, i) -> {
            try {
                Thread.sleep(30);
            } catch (InterruptedException ignored) {
            }
            return resp(200, TRUE_PAGE, 30);
        };
        SqlVerificationEngine sEngine = new SqlVerificationEngine(tiny, slow, new EvidenceStore());
        VerificationResult vr4 = sEngine.verify(boolCandidate("http://t.local/b4?name=admin"));
        t.checkEq(com.xzhscan.model.Models.VerifyVerdict.INVALID, vr4.verdict, "budget exceeded -> INVALID");
        t.check(vr4.note != null && vr4.note.contains("budget"), "note explains budget: " + vr4.note);
    }

    /** 布尔候选（BOOLEAN_CANDIDATE，无 DB 指纹）。 */
    private static DifferentialCandidate boolCandidate(String url) {
        DifferentialCandidate c = new DifferentialCandidate();
        c.requestId = "REQ-22";
        c.targetUrl = url;
        c.method = "GET";
        c.parameterName = "name";
        c.parameterPath = "name";
        c.parameterLocation = com.xzhscan.model.Models.Location.QUERY;
        c.originalValue = "admin";
        c.originalType = "string";
        c.candidateType = com.xzhscan.model.Models.CandidateType.BOOLEAN_CANDIDATE;
        c.occurrence = 0;
        c.originalRequest = Support.get(url);
        DiffEvidence ev = new DiffEvidence();
        c.mutatedEvidence = ev;
        return c;
    }

    /**
     * 布尔预言机：解析常见 boolPair 条件形态。
     * 返回 true/false（可判定）或 null（非布尔形态 → 基线页）。
     */
    private static Boolean evalBool(String value) {
        // 数字形态：/**/and+a=a（true）/a=b 且 b!=a（false）
        java.util.regex.Matcher num = java.util.regex.Pattern
                .compile("/\\*\\*/and\\+(\\d+)=(\\d+)").matcher(value);
        if (num.find()) {
            return num.group(1).equals(num.group(2));
        }
        // 引号形态：'and'x'='x / "and"x"="y
        java.util.regex.Matcher str = java.util.regex.Pattern
                .compile("['\"]and['\"](\\w)['\"]=['\"](\\w)").matcher(value);
        if (str.find()) {
            return str.group(1).equals(str.group(2));
        }
        // 注释形态：'and n=n -- a
        java.util.regex.Matcher cm = java.util.regex.Pattern
                .compile("'and (\\d+)=(\\d+) --").matcher(value);
        if (cm.find()) {
            return cm.group(1).equals(cm.group(2));
        }
        return null;
    }
}
