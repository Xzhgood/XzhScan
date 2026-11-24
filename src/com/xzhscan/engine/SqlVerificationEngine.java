package com.xzhscan.engine;

import com.xzhscan.config.XzhScanConfig;
import com.xzhscan.differential.ResponseNormalizer;
import com.xzhscan.model.EvidenceStore;
import com.xzhscan.model.Models.CandidateType;
import com.xzhscan.model.Models.DiffEvidence;
import com.xzhscan.model.Models.DifferentialCandidate;
import com.xzhscan.model.Models.InjectionFinding;
import com.xzhscan.model.Models.ParamType;
import com.xzhscan.model.Models.TimingVerdict;
import com.xzhscan.model.Models.VerificationResult;
import com.xzhscan.model.Models.VerifyState;
import com.xzhscan.model.Models.VerifyVerdict;
import com.xzhscan.model.RawHttp.RawRequest;
import com.xzhscan.model.RawHttp.RawResponse;
import com.xzhscan.model.RawHttp.Transport;
import com.xzhscan.payload.PayloadRegistry;
import com.xzhscan.payload.PayloadRegistry.PayloadRule;
import com.xzhscan.parameter.ParameterExtractor;
import com.xzhscan.parameter.ParameterMutators;
import com.xzhscan.vendor.http.EvidenceCollector;
import com.xzhscan.vendor.http.SimpleHttpResponse;
import com.xzhscan.vendor.sql.SqlPayloadLibrary;
import com.xzhscan.vendor.sql.SqlWafDetector;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.ThreadLocalRandom;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * 第二阶段 SQL 注入验证引擎（v2.2 证据分型调度）。
 *
 * 时间盲注判定阈值与 xray sqldet 检测集对齐；差异：
 *  - 按第一阶段候选分型（任务书 §8）选择验证模块，不再全模块遍历：
 *      ERROR_CANDIDATE   → 引号噪声 heuristic（含原值）+ errConfirm md5 回显 + 裸表达式
 *      BOOLEAN_CANDIDATE → castBool / boolPair / orderBoolError（含基线稳定性门）
 *      TIME_CANDIDATE    → 仅对命中规则做三级 sleep 定向复验（不重新枚举时间规则）
 *  - 时间确认四态：TIMING_CONFIRMED / TIMING_ANOMALY / TIMING_INCONCLUSIVE /
 *    TIMING_TIMEOUT（一次变慢不直接确认；正文一致不删除时间证据）；
 *  - 布尔判定加固：FALSE 条件随机字符强制不同（c1≠c2）、TRUE 独立复验、
 *    动态基线要求两轮复验，动态页不再单轮 CONFIRMED；
 *  - heuristic 修复：实际发送 原值+噪声（与证据文本一致，对齐 SQLIScanner 原语义）；
 *  - verify-baseline 证据携带响应（四视图原始响应不再依赖回退）；
 *  - 验证预算：config.verifyTimeoutMs 超时停止并标记 INVALID。
 *
 * 输出结论四态：CONFIRMED / SUSPECTED / REJECTED / INVALID。
 */
public final class SqlVerificationEngine {

    private final XzhScanConfig config;
    private final Transport transport;
    private final EvidenceStore evidence;
    /** 当前 verify() 收集的证据 id（ThreadLocal，多候选并行验证安全）。 */
    private final ThreadLocal<List<String>> evidenceCollector = new ThreadLocal<>();
    /** 验证预算截止时间（ThreadLocal）。 */
    private final ThreadLocal<Long> deadline = new ThreadLocal<>();

    public SqlVerificationEngine(XzhScanConfig config, Transport transport, EvidenceStore evidence) {
        this.config = config;
        this.transport = transport;
        this.evidence = evidence;
    }

    // ------------------------------------------------------------------
    // 对外入口：只验证候选里的那一个参数
    // ------------------------------------------------------------------

    public VerificationResult verify(DifferentialCandidate candidate) {
        VerificationResult result = new VerificationResult();
        result.requestId = candidate.requestId;
        result.url = candidate.targetUrl;
        result.parameterName = candidate.parameterName;
        result.parameterPath = candidate.parameterPath;
        result.verifyType = "xray-sqldet-typed";
        result.state = VerifyState.RUNNING;
        result.startedAt = System.currentTimeMillis();
        evidenceCollector.set(new ArrayList<>());

        try {
            verify0(candidate, result);
            if (result.state == VerifyState.DONE && result.verdict == VerifyVerdict.INVALID) {
                // verify0 已给出 INVALID（参数不可变异/基线不可达/预算耗尽）：保留结论，不再覆盖
            } else if (result.findings.isEmpty()) {
                result.verdict = VerifyVerdict.REJECTED;
                result.note = (result.note == null || result.note.isEmpty() ? "" : result.note + "; ")
                        + "no reproducible injection evidence";
            } else {
                InjectionFinding strongest = null;
                for (InjectionFinding f : result.findings) {
                    if (strongest == null || rank(f.verdict) > rank(strongest.verdict)) {
                        strongest = f;
                    }
                }
                result.verdict = strongest.verdict;
                // 只有 finding 明确携带时间结论时才覆盖（避免用 null 抹掉引擎已判定的时间四态）
                if (strongest.timingVerdict != null) {
                    result.timingVerdict = strongest.timingVerdict;
                }
            }
        } catch (Exception e) {
            result.state = VerifyState.FAILED;
            result.verdict = VerifyVerdict.INVALID;
            result.note = "engine error: " + e;
            return result;
        } finally {
            List<String> ids = evidenceCollector.get();
            evidenceCollector.remove();
            deadline.remove();
            if (ids != null) {
                result.evidenceIds.addAll(ids);
                for (InjectionFinding f : result.findings) {
                    f.evidenceIds.addAll(ids);
                }
            }
            result.elapsedMs = System.currentTimeMillis() - result.startedAt;
        }
        result.state = VerifyState.DONE;
        return result;
    }

    private static int rank(VerifyVerdict v) {
        return switch (v) {
            case CONFIRMED -> 3;
            case SUSPECTED -> 2;
            case REJECTED -> 1;
            case INVALID -> 0;
        };
    }

    /** 全模块序列：仅 CONFIRMED 短路（SUSPECTED 保留为兜底并继续更强模块）。 */
    private static boolean isConfirmed(Optional<InjectionFinding> f) {
        return f.isPresent() && f.get().verdict == VerifyVerdict.CONFIRMED;
    }

    /**
     * gatherBurp 语义安全门：5xx 响应视为应用异常而非布尔差异；
     * 且 TRUE/FALSE 响应自身必须不同（三角第三边 normal≠abnormal）。
     */
    private static boolean booleanSideSafe(RawResponse rt, RawResponse rf) {
        if (rt == null || rf == null) {
            return false;
        }
        if (rt.statusCode >= 500 || rf.statusCode >= 500) {
            return false;
        }
        return sim(rt.bodyAsString(), rf.bodyAsString()) < 0.9;
    }

    /** 验证预算（§16 超时保留）：超出 config.verifyTimeoutMs 停止后续探针。 */
    private boolean budgetLeft() {
        Long dl = deadline.get();
        return dl == null || System.currentTimeMillis() < dl;
    }

    // ------------------------------------------------------------------
    // 主流程：按候选分型调度（任务书 §8）
    // ------------------------------------------------------------------

    private void verify0(DifferentialCandidate candidate, VerificationResult result) {
        deadline.set(result.startedAt + config.verifyTimeoutMs);
        RawRequest base = candidate.originalRequest;

        // 定位目标参数（用第一阶段同款提取，保证路径/同名序号语义一致）
        ParameterExtractor.ExtractResult ex = ParameterExtractor.extract(base);
        com.xzhscan.model.Models.ParameterIdentity target = null;
        for (com.xzhscan.model.Models.ParameterIdentity p : ex.parameters) {
            if (p.location == candidate.parameterLocation && p.path.equals(candidate.parameterPath)
                    && p.occurrence == candidate.occurrence) {
                target = p;
                break;
            }
        }
        if (target == null || !target.mutable()) {
            result.verdict = VerifyVerdict.INVALID;
            result.note = "parameter no longer mutable in original request";
            result.state = VerifyState.DONE;
            return;
        }

        // 基线：原始请求 N 次（时间统计 + WAF 基线 + 内容稳定性评估）
        List<Long> timings = new ArrayList<>();
        List<String> baselineBodies = new ArrayList<>();
        SimpleHttpResponse baselineResp = null;
        RawResponse baselineRaw = null;
        int samples = Math.max(2, Math.min(3, config.baselineSamples));
        for (int i = 0; i < samples; i++) {
            long t0 = System.currentTimeMillis();
            RawResponse r = send(base);
            timings.add(System.currentTimeMillis() - t0);
            if (r != null) {
                baselineResp = toSimple(r);
                baselineRaw = r;
                baselineBodies.add(r.bodyAsString());
            }
        }
        if (baselineResp == null || baselineRaw == null) {
            result.verdict = VerifyVerdict.INVALID;
            result.note = "baseline unreachable";
            result.state = VerifyState.DONE;
            return;
        }
        collect(evidence.put("verify-baseline", base, baselineRaw));
        result.probeCount += samples;

        double mean = timings.stream().mapToLong(Long::longValue).average().orElse(0);
        double std = Math.sqrt(timings.stream().mapToDouble(x -> (x - mean) * (x - mean)).average().orElse(0));
        long timeThreshold = (long) (mean + 3.0 * Math.max(std, 30.0) + 1500.0);
        // v3.9.7：延迟秒数改用配置值（默认 5）。原版按基线浮动 2/3 秒——实测
        // 2-3 秒落在系统卡顿/负载抖动的抖动带内，是时间盲注误报的主要来源。
        int sleepSeconds = Math.max(2, Math.min(10, config.timeDelaySeconds));

        // 基线内容稳定性（任务书 §12.4）：两两相似度 >= 0.98 视为稳定
        boolean baselineStable = baselineBodies.size() >= 2;
        outer:
        for (int i = 0; i < baselineBodies.size() && baselineStable; i++) {
            for (int j = i + 1; j < baselineBodies.size(); j++) {
                if (ResponseNormalizer.similarity(baselineBodies.get(i), baselineBodies.get(j)) < 0.98) {
                    baselineStable = false;
                    break outer;
                }
            }
        }
        String baselineBody = baselineBodies.get(baselineBodies.size() - 1);

        String url = base.url;
        String hint = candidate.mutatedEvidence != null && candidate.mutatedEvidence.dbErrorFamily != null
                ? candidate.mutatedEvidence.dbErrorFamily : null;

        // 验证预算（§16）：基线后预算已耗尽 → 标记 INVALID，不继续探针
        if (!budgetLeft()) {
            result.verdict = VerifyVerdict.INVALID;
            result.note = "verify budget exceeded (verifyTimeoutMs=" + config.verifyTimeoutMs + ")";
            result.state = VerifyState.DONE;
            return;
        }

        WafWatch waf = new WafWatch(baselineResp);

        Optional<InjectionFinding> f = Optional.empty();
        if (candidate.candidateType == null) {
            // v3.0 右键指定参数验证（无差分上下文）：全模块验证序列，
            // 依次 报错噪声 → md5 回显 → 布尔 cast → 布尔对 → ORDER BY → 时间全家族；
            // verifyTimeoutMs 预算内跑多少算多少，CONFIRMED 才短路（SUSPECTED 继续试更强模块）。
            f = heuristic(base, target, SqlPayloadLibrary.detectError(baselineBody) != null, waf, hint, url, result);
            if (!isConfirmed(f) && budgetLeft()) {
                Optional<InjectionFinding> f2 = errConfirm(base, target, waf, hint, url, result);
                f = isConfirmed(f2) ? f2 : (f.isPresent() ? f : f2);
            }
            if (!isConfirmed(f) && budgetLeft()) {
                Optional<InjectionFinding> f2 = castBool(base, target, baselineBody, waf, hint, url, baselineStable, result);
                f = isConfirmed(f2) ? f2 : (f.isPresent() ? f : f2);
            }
            if (!isConfirmed(f) && budgetLeft()) {
                Optional<InjectionFinding> f2 = boolPair(base, target, baselineBody, waf, url, baselineStable, result);
                f = isConfirmed(f2) ? f2 : (f.isPresent() ? f : f2);
            }
            if (!isConfirmed(f) && budgetLeft()) {
                Optional<InjectionFinding> f2 = orderBoolError(base, target, baselineBody, waf, url, result);
                f = isConfirmed(f2) ? f2 : (f.isPresent() ? f : f2);
            }
            if (!isConfirmed(f) && budgetLeft() && config.allowTimeBasedProbe) {
                // v3.4.2：timeBased 全集枚举（QUICK+变体/ORDER/NUMERIC → ≥850ms → 3-tier）
                Optional<InjectionFinding> f2 = verifyTimeBased(base, target, waf, url, mean, std,
                        sleepSeconds, result, hint);
                f = isConfirmed(f2) ? f2 : (f.isPresent() ? f : f2);
            }
            if (!isConfirmed(f) && budgetLeft() && config.allowTimeBasedProbe) {
                // v4.0：sqlmap 注入模型（boundary + clause 解耦 + 条件对）——
                // 覆盖旧 payload 集够不着的注入上下文（数字型/嵌套引号/双层括号/补全闭合）
                Optional<InjectionFinding> f2 = verifySqlmapTime(base, target, waf, url, mean, std,
                        sleepSeconds, result, hint);
                f = isConfirmed(f2) ? f2 : (f.isPresent() ? f : f2);
            }
        } else switch (candidate.candidateType) {
            case ERROR_CANDIDATE -> {
                // 错误型模块：heuristic（引号噪声，含原值）+ errConfirm（md5 回显）+ 裸表达式
                f = heuristic(base, target, SqlPayloadLibrary.detectError(baselineBody) != null, waf, hint, url, result);
                if (f.isEmpty() && budgetLeft()) {
                    f = errConfirm(base, target, waf, hint, url, result);
                }
            }
            case TIME_CANDIDATE -> {
                // 定向时间复验：只用第一阶段命中规则，不重新枚举（任务书 §8/§9）
                f = verifyTimeTargeted(candidate, base, target, waf, url, mean, std, sleepSeconds, result);
            }
            case BOOLEAN_CANDIDATE -> {
                // 布尔差分模块：castBool / boolPair / orderBoolError
                f = castBool(base, target, baselineBody, waf, hint, url, baselineStable, result);
                if (f.isEmpty() && budgetLeft()) {
                    f = boolPair(base, target, baselineBody, waf, url, baselineStable, result);
                }
                if (f.isEmpty() && budgetLeft()) {
                    f = orderBoolError(base, target, baselineBody, waf, url, result);
                }
            }
        }
        if (f.isPresent()) {
            result.findings.add(f.get());
            return;
        }

        // ---- WAF 拦截通报（非漏洞结论；§8 WAF_BLOCKED 记录拦截证据） ----
        if (config.reportWafBlocked && waf.intercepted()) {
            InjectionFinding wf = new InjectionFinding();
            wf.requestId = candidate.requestId;
            wf.parameterName = target.name;
            wf.parameterPath = target.path;
            wf.verdict = VerifyVerdict.SUSPECTED;
            wf.injectionType = "WAF-Blocked";
            wf.timingVerdict = TimingVerdict.TIMING_INCONCLUSIVE;
            wf.evidenceText = new EvidenceCollector()
                    .addTitle("SQLi probes blocked by WAF")
                    .add("Param", target.name)
                    .add("Intercept", waf.summary())
                    .add("Note", "注入探测被拦截，本参数无法判定（非漏洞结论）")
                    .build();
            wf.evidenceKinds.add("WAF_BLOCKED");
            result.findings.add(wf);
        } else if (candidate.candidateType == CandidateType.TIME_CANDIDATE && result.timingVerdict == null) {
            result.timingVerdict = TimingVerdict.TIMING_INCONCLUSIVE;
        }
    }

    // ------------------------------------------------------------------
    // 变异 + 发送（单参数；probeCount 统计 §15）
    // ------------------------------------------------------------------

    /**
     * 单参数受控变异 + 发送。newValue 是目标参数的完整新值
     * （与被移植引擎 ScanParams.mutate 相同的替换语义）。
     */
    private RawResponse sendMutated(RawRequest base, com.xzhscan.model.Models.ParameterIdentity target,
                                    String newValue, WafWatch waf, VerificationResult result) {
        return sendMutated(base, target, newValue, waf, result, 0);
    }

    /** 带单次超时预算的变体（时间探针：sleep 可能被逐行放大，见 Transport 接口注释）。 */
    private RawResponse sendMutated(RawRequest base, com.xzhscan.model.Models.ParameterIdentity target,
                                    String newValue, WafWatch waf, VerificationResult result, long perCallTimeoutMs) {
        if (!budgetLeft()) {
            return null;
        }
        ParameterMutators.MutationResult m = ParameterMutators.replaceValue(base, target, newValue);
        if (!m.success) {
            return null;
        }
        long t0 = System.currentTimeMillis();
        RawResponse r;
        try {
            r = perCallTimeoutMs > 0 ? transport.send(m.request, perCallTimeoutMs) : transport.send(m.request);
        } catch (Exception e) {
            return null;
        }
        result.probeCount++;
        if (r != null) {
            // 耗时取传输层测量值（Burp 端 nanoTime / Mock 端模拟延迟）；
            // 引擎墙钟仅在传输层未测量（elapsedMs<0）时兜底。
            long cost = r.elapsedMs >= 0 ? r.elapsedMs : System.currentTimeMillis() - t0;
            r = new RawResponse(r.statusCode, r.headers, r.body, cost);
            collect(evidence.put("verify-probe", m.request, r));
            waf.observe(toSimple(r));
        }
        return r;
    }

    private RawResponse send(RawRequest request) {
        try {
            RawResponse r = transport.send(request);
            if (r != null && r.elapsedMs < 0) {
                r = new RawResponse(r.statusCode, r.headers, r.body, 0);
            }
            return r;
        } catch (Exception e) {
            return null;
        }
    }

    // ------------------------------------------------------------------
    // 1. heuristic（SQLIScanner.heuristic 语义：原值+噪声 → DB 错误指纹）
    //    v2.2 修复：实际发送 原值+noise；v3.3 吸收 gatherBurp：指纹分级
    //    （厂商明确指纹=HIGH 直接 CONFIRMED；弱/泛化特征只升 SUSPECTED）
    // ------------------------------------------------------------------

    /** gatherBurp 风格弱错误特征（LOW 置信，不足以单独 CONFIRMED，含中文报错形态）。 */
    private static final Pattern[] WEAK_SQL_ERROR = {
            Pattern.compile("syntax\\s+error", Pattern.CASE_INSENSITIVE),
            Pattern.compile("sql\\s+error", Pattern.CASE_INSENSITIVE),
            Pattern.compile("database\\s+error", Pattern.CASE_INSENSITIVE),
            Pattern.compile("unclosed\\s+quotation", Pattern.CASE_INSENSITIVE),
            Pattern.compile("(?:执行(?:本地)?sql|数据库查询|查询语句).{0,40}(?:出错|错误|失败)"),
    };

    /** 弱错误特征命中（LOW 置信）：仅当强指纹（detectError）未命中时调用。 */
    private static String weakSqlErrorHit(String body) {
        if (body == null || body.isEmpty()) {
            return null;
        }
        for (Pattern p : WEAK_SQL_ERROR) {
            if (p.matcher(body).find()) {
                return "weak-fingerprint";
            }
        }
        return null;
    }

    private Optional<InjectionFinding> heuristic(RawRequest base, com.xzhscan.model.Models.ParameterIdentity target,
                                                 boolean baselineHasDbError, WafWatch waf, String hint, String url,
                                                 VerificationResult result) {
        if (baselineHasDbError) {
            return Optional.empty(); // gatherBurp 语义：基线已有的错误特征不构成新证据
        }
        String weakPayload = null;
        // v3.9.4：引号噪声改为**纯噪声替换原值**（原版是 originalValue + 噪声）。
        // 理由（实测误报根因）：Intruder/fuzz 场景参数原值本身就是载荷（' " -1 0 ,
        // DBMS_PIPE(...) 等），再追加噪声会与之拼接成双重注入（如 -1'、''、"'"\(），
        // 服务端语法错误被误判为 Error-based 注入。改为替换后，发出的参数值是干净
        // 的噪声串，不含任何原值；后续 errConfirm/castBool/boolPair 同样只发纯 payload，
        // 与"发给二阶段的参数不得携带原值"的约束一致。
        for (String payload : new String[]{"鎈'\"\\(", "'\"\\("}) {
            RawResponse r = sendMutated(base, target, payload, waf, result);
            if (r != null) {
                String family = SqlPayloadLibrary.detectError(r.bodyAsString());
                if (family != null) {
                    return Optional.of(finding(VerifyVerdict.CONFIRMED, "Error-based (heuristic)",
                            family, payload, url, target, new EvidenceCollector()
                            .addTitle("SQL Injection (Error)")
                            .addVulnerability("SQL Injection (Error-based, heuristic)")
                            .add("DB family", family)
                            .add("Param", target.name)
                            .add("Payload", payload)
                            .addRequest(base.method, url)
                            .addMatchedFeature("DB error fingerprint in response")
                            .build()));
                }
                if (weakPayload == null && weakSqlErrorHit(r.bodyAsString()) != null) {
                    weakPayload = payload; // 弱特征（含中文报错）记录，无强指纹时降级疑似
                }
            }
        }
        if (weakPayload != null) {
            // gatherBurp LOW 语义：泛化特征（syntax error/中文报错）只升 SUSPECTED
            return Optional.of(suspected("Error-like weak fingerprint (not confirmed)",
                    weakPayload, url, target, base,
                    "response matches weak/generic SQL error keywords (no vendor fingerprint); "
                            + "confirm manually or via md5-echo module"));
        }
        return Optional.empty();
    }

    // ------------------------------------------------------------------
    // 2. errConfirm（SQLIScanner.errConfirm 1:1；裸表达式来自 Registry）
    // ------------------------------------------------------------------

    private Optional<InjectionFinding> errConfirm(RawRequest base, com.xzhscan.model.Models.ParameterIdentity target,
                                                  WafWatch waf, String hint, String url, VerificationResult result) {
        String v = target.originalValue;
        // MySQL extractvalue（单引号）
        if (hintAllows(hint, "MySQL")) {
            String rand = SqlPayloadLibrary.newRand();
            String payload = v + "'and/**/extractvalue(1,concat(char(126),md5(" + rand + ")))and'";
            RawResponse r = sendMutated(base, target, payload, waf, result);
            if (r != null && isRealMd5Echo(r.bodyAsString(), rand)) {
                return Optional.of(confirmed("MySQL extractvalue md5-echo", payload, url, target, base));
            }
        }
        // MSSQL hashbytes
        if (hintAllows(hint, "MSSQL")) {
            String rand = SqlPayloadLibrary.newRand();
            String mid = target.type == ParamType.NUMBER
                    ? "/**/and/**/convert(int,sys.fn_sqlvarbasetostr(HashBytes('MD5'," + rand + ")))>'0"
                    : "'and/**/convert(int,sys.fn_sqlvarbasetostr(HashBytes('MD5'," + rand + ")))>'0";
            String payload = v + mid;
            RawResponse r = sendMutated(base, target, payload, waf, result);
            if (r != null && isRealMd5Echo(r.bodyAsString(), rand)) {
                return Optional.of(confirmed("MSSQL hashbytes md5-echo", payload, url, target, base));
            }
        }
        // MySQL extractvalue（双引号）
        String rand2 = SqlPayloadLibrary.newRand();
        String mid2 = "\"and/**/extractvalue(1,concat(char(126),md5(" + rand2 + ")))and\"";
        RawResponse r2 = sendMutated(base, target, v + mid2, waf, result);
        if (r2 != null && isRealMd5Echo(r2.bodyAsString(), rand2)) {
            return Optional.of(confirmed("MySQL extractvalue md5-echo (dquote)", v + mid2, url, target, base));
        }
        // XRAY_BARE_ERROR_PROBES（Registry：BE-MYSQL-ERR-01 / BE-MSSQL-ERR-01）
        for (PayloadRule rule : PayloadRegistry.phase2BareErrorRules()) {
            if (!hintAllows(hint, rule.dbms())) {
                continue;
            }
            String rand = SqlPayloadLibrary.newRand();
            String expr = renderRule(rule, rand);
            String payload = rule.replace() ? expr : v + expr;
            RawResponse r = sendMutated(base, target, payload, waf, result);
            if (r != null && isRealMd5Echo(r.bodyAsString(), rand)) {
                InjectionFinding fnd = confirmed(rule.dbms() + " bare-expr md5-echo", payload, url, target, base);
                fnd.payloadRuleId = rule.id();
                return Optional.of(fnd);
            }
        }
        return Optional.empty();
    }

    /** 渲染 Registry 规则模板（{S}/{R}/{C}/[Space] 占位）。 */
    private static String renderRule(PayloadRule rule, String rand) {
        return rule.template()
                .replace("{S}", "0")
                .replace("{R}", rand)
                .replace("{C}", String.valueOf((char) ('a' + ThreadLocalRandom.current().nextInt(20))))
                .replace("[Space]", "/**/");
    }

    // ------------------------------------------------------------------
    // 3. castBool（阈值 0.95/0.85 + TRUE 独立复验 + 动态基线两轮要求）
    // ------------------------------------------------------------------

    private Optional<InjectionFinding> castBool(RawRequest base, com.xzhscan.model.Models.ParameterIdentity target,
                                                String baselineBody, WafWatch waf, String hint, String url,
                                                boolean baselineStable, VerificationResult result) {
        if (hint != null && (hint.equalsIgnoreCase("MSSQL") || hint.equalsIgnoreCase("Oracle"))) {
            return Optional.empty();
        }
        String v = target.originalValue;
        String[][] pairs = {
                {"/**/and/**/cast(md5('{R}')as/**/int)>0", "/**/and/**/cast(md5('{R}')as/**/int)>9999999999"},
                {"'and(select'1'from/**/cast(md5({R})as/**/int))>'0", "'and(select'1'from/**/cast(md5({R})as/**/int))>'9999999999"}
        };
        for (String[] pair : pairs) {
            String rTrue = SqlPayloadLibrary.newRand();
            String trueExpr = pair[0].replace("{R}", rTrue);
            RawResponse rt = sendMutated(base, target, v + trueExpr, waf, result);
            if (rt == null) {
                continue;
            }
            String rFalse = SqlPayloadLibrary.newRand();
            String falseExpr = pair[1].replace("{R}", rFalse);
            RawResponse rf = sendMutated(base, target, v + falseExpr, waf, result);
            if (rf == null) {
                continue;
            }
            double simTrue = sim(rt.bodyAsString(), baselineBody);
            double simFalse = sim(rf.bodyAsString(), baselineBody);
            if (booleanSideSafe(rt, rf) && simTrue > 0.95 && simFalse < 0.85) {
                // 复验：TRUE 重新发送仍须≈基线；动态基线还要求 FALSE 复发仍偏离
                RawResponse rt2 = sendMutated(base, target, v + trueExpr.replace(rTrue, SqlPayloadLibrary.newRand()),
                        waf, new VerificationResult());
                boolean trueRecheck = rt2 != null && sim(rt2.bodyAsString(), baselineBody) > 0.95;
                boolean falseRecheck = true;
                if (!baselineStable) {
                    RawResponse rf2 = sendMutated(base, target, v + falseExpr.replace(rFalse, SqlPayloadLibrary.newRand()),
                            waf, new VerificationResult());
                    falseRecheck = rf2 != null && sim(rf2.bodyAsString(), baselineBody) < 0.85;
                }
                if (trueRecheck && falseRecheck) {
                    String payloadTrue = v + trueExpr;
                    String payloadFalse = v + falseExpr;
                    return Optional.of(confirmed("MySQL cast(md5) boolean", payloadTrue, url, target, base,
                            new EvidenceCollector()
                                    .addTitle("SQL Injection (Boolean)")
                                    .addVulnerability("SQL Injection (Boolean-based blind, cast-md5)")
                                    .add("Param", target.name)
                                    .add("TRUE payload", payloadTrue)
                                    .add("FALSE payload", payloadFalse)
                                    .add("sim(TRUE,base)", String.format(Locale.ROOT, "%.2f", simTrue))
                                    .add("sim(FALSE,base)", String.format(Locale.ROOT, "%.2f", simFalse))
                                    .add("baselineStable", String.valueOf(baselineStable))
                                    .addRequest(base.method, url)
                                    .addMatchedFeature("cast(md5) true~baseline (rechecked), false differs")
                                    .build(), payloadFalse, rf));
                }
            }
        }
        return Optional.empty();
    }

    // ------------------------------------------------------------------
    // 4. boolPair（布尔真伪对 + 复验；v2.2：c1≠c2 强制、TRUE 复验、动态基线两轮）
    // ------------------------------------------------------------------

    private Optional<InjectionFinding> boolPair(RawRequest base, com.xzhscan.model.Models.ParameterIdentity target,
                                                String baselineBody, WafWatch waf, String url,
                                                boolean baselineStable, VerificationResult result) {
        ThreadLocalRandom rnd = ThreadLocalRandom.current();
        String v = target.originalValue;
        String payloadTrue;
        String payloadFalse;
        if (target.type == ParamType.NUMBER && target.location != com.xzhscan.model.Models.Location.JSON) {
            int a = 1 + rnd.nextInt(8);
            int b = a + 1 + rnd.nextInt(8);
            payloadTrue = "/**/and+" + a + "=" + a;
            payloadFalse = "/**/and+" + a + "=" + b;
        } else {
            char c1 = (char) ('a' + rnd.nextInt(20));
            char c2 = (char) ('a' + rnd.nextInt(20));
            // 修复：随机字符相同会使"假条件"变真（'and'x'='x 恒真）——强制 c2 ≠ c1
            while (c2 == c1) {
                c2 = (char) ('a' + rnd.nextInt(20));
            }
            int q = rnd.nextBoolean() ? 39 : 34;
            payloadTrue = String.valueOf((char) q) + "and" + (char) q + c1 + (char) q + "=" + (char) q + c1;
            payloadFalse = String.valueOf((char) q) + "and" + (char) q + c1 + (char) q + "=" + (char) q + c2;
        }

        RawResponse rt = sendMutated(base, target, v + payloadTrue, waf, result);
        RawResponse rf = sendMutated(base, target, v + payloadFalse, waf, result);
        if (rt == null || rf == null) {
            return Optional.empty();
        }
        double simTrue = sim(rt.bodyAsString(), baselineBody);
        double simFalse = sim(rf.bodyAsString(), baselineBody);

        // 数字参数补测引号对（SQLIScanner 同款回退序列；同样强制 c1≠c2）
        if (!(simTrue > 0.95 && simFalse < 0.85) && target.type == ParamType.NUMBER
                && target.location != com.xzhscan.model.Models.Location.JSON) {
            for (char[] quotes : new char[][]{{'\'', '\''}, {'"', '"'}}) {
                char q = quotes[0];
                char c1 = (char) ('a' + rnd.nextInt(20));
                char c2 = (char) ('a' + rnd.nextInt(20));
                while (c2 == c1) {
                    c2 = (char) ('a' + rnd.nextInt(20));
                }
                String pt = String.valueOf(q) + "and" + q + c1 + q + "=" + q + c1;
                String pf = String.valueOf(q) + "and" + q + c1 + q + "=" + q + c2;
                RawResponse t2 = sendMutated(base, target, v + pt, waf, result);
                RawResponse f2 = sendMutated(base, target, v + pf, waf, result);
                if (t2 != null && f2 != null) {
                    double st = sim(t2.bodyAsString(), baselineBody);
                    double sf = sim(f2.bodyAsString(), baselineBody);
                    if (st > 0.95 && sf < 0.85) {
                        payloadTrue = pt;
                        payloadFalse = pf;
                        simTrue = st;
                        simFalse = sf;
                        rt = t2;
                        rf = f2;
                        break;
                    }
                }
            }
        }
        // '-- a' 注释变体（n 与 n+1 恒不同，无随机碰撞问题）
        if (!(simTrue > 0.95 && simFalse < 0.85)) {
            int n = 1 + rnd.nextInt(8);
            String pt = "'and " + n + "=" + n + " -- a";
            String pf = "'and " + n + "=" + (n + 1) + " -- a";
            RawResponse t3 = sendMutated(base, target, v + pt, waf, result);
            RawResponse f3 = sendMutated(base, target, v + pf, waf, result);
            if (t3 != null && f3 != null) {
                double st = sim(t3.bodyAsString(), baselineBody);
                double sf = sim(f3.bodyAsString(), baselineBody);
                if (st > 0.95 && sf < 0.85) {
                    payloadTrue = pt;
                    payloadFalse = pf;
                    simTrue = st;
                    simFalse = sf;
                    rt = t3;
                    rf = f3;
                }
            }
        }

        if (booleanSideSafe(rt, rf) && simTrue > 0.95 && simFalse < 0.85) {
            // 复验（任务书 §12.3：单轮差异不 CONFIRMED）：
            //  - TRUE 重新发送仍≈基线（独立对照证据）；
            //  - FALSE + 空格 仍偏离基线；
            //  - 动态基线：另起一轮全新随机对，两轮同时成立才 CONFIRMED，否则降级 SUSPECTED。
            RawResponse recheckTrue = sendMutated(base, target, v + payloadTrue, waf, result);
            RawResponse recheck = sendMutated(base, target, v + payloadFalse + " ", waf, result);
            boolean trueHolds = recheckTrue != null && sim(recheckTrue.bodyAsString(), baselineBody) > 0.95;
            boolean falseHolds = recheck != null && sim(recheck.bodyAsString(), baselineBody) < 0.85;
            if (!trueHolds || !falseHolds) {
                return Optional.empty();
            }
            if (!baselineStable) {
                // 第二轮全新随机对
                char c1 = (char) ('a' + rnd.nextInt(20));
                char c2;
                do {
                    c2 = (char) ('a' + rnd.nextInt(20));
                } while (c2 == c1);
                int q2 = rnd.nextBoolean() ? 39 : 34;
                String t2 = String.valueOf((char) q2) + "and" + (char) q2 + c1 + (char) q2 + "=" + (char) q2 + c1;
                String f2 = String.valueOf((char) q2) + "and" + (char) q2 + c1 + (char) q2 + "=" + (char) q2 + c2;
                RawResponse rt2 = sendMutated(base, target, v + t2, waf, result);
                RawResponse rf2 = sendMutated(base, target, v + f2, waf, result);
                boolean round2 = rt2 != null && rf2 != null
                        && sim(rt2.bodyAsString(), baselineBody) > 0.95
                        && sim(rf2.bodyAsString(), baselineBody) < 0.85;
                if (!round2) {
                    return Optional.of(suspected("Boolean-pattern single round on dynamic baseline",
                            v + payloadTrue, url, target, base,
                            "TRUE/FALSE pattern held once; dynamic baseline prevented second-round confirmation"));
                }
            }
            return Optional.of(confirmed("Boolean-based blind", v + payloadTrue, url, target, base, new EvidenceCollector()
                    .addTitle("SQL Injection (Boolean)")
                    .addVulnerability("SQL Injection (Boolean-based blind)")
                    .add("Param", target.name)
                    .add("TRUE payload", v + payloadTrue)
                    .add("FALSE payload", v + payloadFalse)
                    .add("sim(TRUE,base)", String.format(Locale.ROOT, "%.2f", simTrue))
                    .add("sim(FALSE,base)", String.format(Locale.ROOT, "%.2f", simFalse))
                    .add("baselineStable", String.valueOf(baselineStable))
                    .addRequest(base.method, url)
                    .addMatchedFeature("TRUE~baseline (rechecked), FALSE differs (rechecked)"
                            + (baselineStable ? "" : ", second random round confirmed"))
                    .build(), v + payloadFalse, rf));
        }
        return Optional.empty();
    }

    // ------------------------------------------------------------------
    // 5. orderBoolError（SQLIScanner.orderBoolError 1:1）
    // ------------------------------------------------------------------

    private Optional<InjectionFinding> orderBoolError(RawRequest base, com.xzhscan.model.Models.ParameterIdentity target,
                                                      String baselineBody, WafWatch waf, String url, VerificationResult result) {
        // v3.8.3 增强（与时间型 ORDER 探针同款决策）：原版仅参数名命中 ORDER_NAMES 才跑本模块，
        // 漏掉"参数名不叫 order/sort 但值实际拼进 ORDER BY"的场景。改为全参数发送——
        // 布尔形态拼在 WHERE/数字位语法错误（rf/rt 同报错）→ 判定条件不成立，不产生误报。
        if (SqlPayloadLibrary.errorIndex(baselineBody) >= 0) {
            return Optional.empty();
        }
        String v = target.originalValue;
        String sub = "1*(SELECT/**/1/**/UNION/**/SELECT/**/2)";
        String trueExpr = "/**/(CASE/**/WHEN/**/1=1/**/THEN/**/1/**/ELSE/**/" + sub + "/**/END)";
        String falseExpr = "/**/(CASE/**/WHEN/**/1=2/**/THEN/**/1/**/ELSE/**/" + sub + "/**/END)";
        RawResponse rt = sendMutated(base, target, v + trueExpr, waf, result);
        RawResponse rf = sendMutated(base, target, v + falseExpr, waf, result);
        if (rt == null || rf == null) {
            return Optional.empty();
        }
        if (SqlWafDetector.blockedVsBaseline(toSimple(rf), waf.baseline) != null) {
            return Optional.empty();
        }
        if (SqlPayloadLibrary.errorIndex(rf.bodyAsString()) < 0) {
            return Optional.empty();
        }
        if (SqlPayloadLibrary.errorIndex(rt.bodyAsString()) >= 0) {
            return Optional.empty();
        }
        RawResponse retest = sendMutated(base, target, v + falseExpr + "/**/", waf, result);
        if (retest != null && SqlPayloadLibrary.errorIndex(retest.bodyAsString()) >= 0) {
            return Optional.of(confirmed("Error-based ORDER BY", v + trueExpr, url, target, base, new EvidenceCollector()
                    .addTitle("SQL Injection (Error)")
                    .addVulnerability("SQL Injection (Error-based, ORDER BY)")
                    .add("Param", target.name)
                    .add("TRUE payload", v + trueExpr)
                    .add("FALSE payload", v + falseExpr)
                    .addRequest(base.method, url)
                    .addMatchedFeature("FALSE errors, TRUE ~ baseline, FALSE re-test errors")
                    .build(), v + falseExpr, rf));
        }
        return Optional.empty();
    }

    // ------------------------------------------------------------------
    // 6. TIME_CANDIDATE 定向复验（任务书 §8/§9/§10/§11）
    //    只用第一阶段命中规则；三级 sleep(0→S→S+1) 相对差分定罪；
    //    不重新枚举任何时间规则序列。
    // ------------------------------------------------------------------

    private Optional<InjectionFinding> verifyTimeTargeted(DifferentialCandidate candidate, RawRequest base,
                                                          com.xzhscan.model.Models.ParameterIdentity target,
                                                          WafWatch waf, String url, double mean, double std,
                                                          int sleepSeconds, VerificationResult result) {
        PayloadRule rule = PayloadRegistry.phase2TimeRuleFor(candidate.payloadRuleId);
        DiffEvidence quick = candidate.mutatedEvidence;
        if (rule == null) {
            // 规则丢失（理论不可达）：保留第一阶段时间证据，判定不升级
            result.timingVerdict = quick != null && quick.timingAnomaly ? TimingVerdict.TIMING_ANOMALY
                    : TimingVerdict.TIMING_INCONCLUSIVE;
            return Optional.empty();
        }
        if (quick != null && quick.mutatedStatus <= 0) {
            // 第一阶段即为超时形态：不可作为延迟证据
            result.timingVerdict = TimingVerdict.TIMING_TIMEOUT;
            result.note = "phase-1 probe timed out (status<=0); not usable as delay evidence";
            return Optional.empty();
        }
        return threeTierRule(rule, base, target, waf, url, mean, std, sleepSeconds, result, quick);
    }

    /**
     * timeBased 全集枚举（v3.4.2 对齐，右键全模块序列时间段）：
     * 候选序列 = QUICK_TIME_PROBES（含加号替换为斜杠星号注释的变体）→ XRAY_ORDER_PROBES（仅 order 参数）
     * → XRAY_NUMERIC_PROBES；按 DB 提示过滤；逐条发送，**响应耗时 ≥850ms 即命中**，
     * 命中后用同一模板做三级 0→S→S+1 复验；CONFIRMED 即停。
     * 预算 verifyTimeoutMs 内跑多少算多少；超时/被 WAF 拦截不算命中。
     */
    private Optional<InjectionFinding> verifyTimeBased(RawRequest base,
                                                          com.xzhscan.model.Models.ParameterIdentity target,
                                                          WafWatch waf, String url, double mean, double std,
                                                          int sleepSeconds, VerificationResult result, String hint) {
        // 1) 候选构建（固定顺序：QUICK + '+'变体 → ORDER(按参数名) → XRAY_NUMERIC）
        List<QuickProbeSpec> probes = new ArrayList<>();
        for (SqlPayloadLibrary.TimeProbe p : SqlPayloadLibrary.QUICK_TIME_PROBES) {
            if (hintAllows(hint, p.db())) {
                probes.add(new QuickProbeSpec(p.template(), p.db(), false));
            }
        }
        int quickCount = probes.size();
        for (int i = 0; i < quickCount; i++) {
            QuickProbeSpec p = probes.get(i);
            // v3.9.7 修复：原版变体是 template.replace(" ", "/**/")（替换**空格**）；
            // 此前误写成替换 "+"，而 QUICK 模板全是空格形态 → 变体一条都没生成。
            String spaced = p.template.replace(" ", "/**/");
            String variant = spaced.equals(p.template)
                    ? p.template.replace("+", "/**/")   // 兼容 '+' 代表空格的模板形态
                    : spaced;
            if (!variant.equals(p.template)) {
                probes.add(new QuickProbeSpec(variant, p.db, p.replace));
            }
        }
        // v3.8.2 增强（有意偏离原版）：原版仅参数名命中 ORDER_NAMES 才发 ORDER 探针，
        // 漏掉"参数名不叫 order/sort 但值实际拼进 ORDER BY"的注入点。改为全参数发送——
        // 探针为拼接形态（原值+逗号子查询），在 WHERE/数字位语法错误→不命中，不产生误报，
        // 代价仅为每参数至多 5 个额外请求（命中即停）。
        for (SqlPayloadLibrary.XrayProbe p : SqlPayloadLibrary.XRAY_ORDER_PROBES) {
            if (hintAllows(hint, p.db())) {
                probes.add(new QuickProbeSpec(p.template(), p.db(), p.replace()));
            }
        }
        for (SqlPayloadLibrary.XrayProbe p : SqlPayloadLibrary.XRAY_NUMERIC_PROBES) {
            if (hintAllows(hint, p.db())) {
                probes.add(new QuickProbeSpec(p.template(), p.db(), p.replace()));
            }
        }

        // 2) 逐条快探：耗时 ≥ 850ms 视为命中（原版阈值），随后三级复验
        Optional<InjectionFinding> retained = Optional.empty();
        for (QuickProbeSpec p : probes) {
            if (!budgetLeft()) {
                break;
            }
            String rendered = renderTemplate(p.template, sleepSeconds);
            String value = p.replace ? rendered : appendBase(p.template, target) + rendered;
            RawResponse r = sendMutated(base, target, value, waf, result,
                    (long) sleepSeconds * 12_000L + 15_000L);
            if (r == null || r.statusCode <= 0) {
                continue; // 构造失败/超时：不可作为延迟证据（原版 droppedVsBaseline 语义）
            }
            if (SqlWafDetector.blockedVsBaseline(toSimple(r), waf.baseline) != null) {
                continue;
            }
            // 原版语义：响应被判为"被丢弃/空响应"时同样不可作为延迟证据
            if (SqlWafDetector.droppedVsBaseline(toSimple(r), waf.baseline != null)) {
                continue;
            }
            // v3.9.7 关键修复：对齐原版命中门槛 mean + S*850ms（原先只用固定 850ms）。
            // 示例：基线 200ms、S=5 → 需 ≥ 4450ms 才算命中；此前 850ms 即命中，
            // 慢查询/卡顿轻松过线，是时间盲注误报的主要来源。
            long hitFloor = (long) mean + (long) sleepSeconds * 850L;
            if (r.elapsedMs < hitFloor) {
                continue;
            }
            Optional<InjectionFinding> f = threeTierTemplate(p.template, p.db, p.replace,
                    "time-quick:" + p.db, base, target, waf, url, mean, std, sleepSeconds, result, null);
            if (f.isPresent() && f.get().verdict == VerifyVerdict.CONFIRMED) {
                return f;
            }
            retained = f.isPresent() ? f : retained;
            // 原版命中即停（首条延迟命中后不再继续枚举）
            break;
        }
        if (retained.isEmpty() && result.timingVerdict == null) {
            result.timingVerdict = TimingVerdict.TIMING_INCONCLUSIVE;
        }
        return retained;
    }

    /**
     * v4.0：sqlmap 注入模型时间盲注（boundary 与 clause 解耦）。
     *
     * <p>两阶段，均复用 {@link #threeTierTemplate} 做三级阶梯定罪与证据构造：</p>
     * <ol>
     *   <li><b>条件对</b>（最强证据）：同一 boundary 下发 TRUE 延迟子句与 FALSE 不延迟子句，
     *       差值 ≥ S×750ms 且 FALSE 接近基线，才进入三级阶梯——单模板内建对照，
     *       等效 sqlmap 的 {@code SLEEP(S-(IF(INFERENCE,0,S)))} 思想；</li>
     *   <li><b>boundary 枚举</b>：按参数类型排序的 boundary（数字型 / 单引号 / 嵌套括号 /
     *       双引号 / 补全闭合）× 各 DBMS 核心子句快探，命中即三级阶梯。</li>
     * </ol>
     */
    private Optional<InjectionFinding> verifySqlmapTime(RawRequest base,
                                                        com.xzhscan.model.Models.ParameterIdentity target,
                                                        WafWatch waf, String url, double mean, double std,
                                                        int sleepSeconds, VerificationResult result, String hint) {
        java.util.List<com.xzhscan.vendor.sql.SqlmapTimeModel.Boundary> bounds =
                com.xzhscan.vendor.sql.SqlmapTimeModel.boundariesFor(target.originalValue);
        // 只取前 3 个 boundary（类型匹配的优先），否则请求数失控
        int boundCap = Math.min(3, bounds.size());
        long hitFloor = (long) mean + (long) sleepSeconds * 850L;

        // ---------- 阶段 1：条件对（TRUE 延迟 / FALSE 不延迟） ----------
        Optional<InjectionFinding> retained = Optional.empty();
        for (com.xzhscan.vendor.sql.SqlmapTimeModel.ConditionPair pair
                : com.xzhscan.vendor.sql.SqlmapTimeModel.CONDITION_PAIRS) {
            if (!budgetLeft()) {
                break;
            }
            if (!hintAllows(hint, pair.db())) {
                continue;
            }
            for (int bi = 0; bi < boundCap && budgetLeft(); bi++) {
                com.xzhscan.vendor.sql.SqlmapTimeModel.Boundary b = bounds.get(bi);
                String trueTpl = b.wrap(pair.trueClause());
                String falseTpl = b.wrap(pair.falseClause());
                RawResponse rTrue = sendMutated(base, target,
                        com.xzhscan.vendor.sql.SqlmapTimeModel.render(trueTpl, sleepSeconds),
                        waf, result, (long) sleepSeconds * 12_000L + 15_000L);
                if (rTrue == null || rTrue.statusCode <= 0) {
                    continue;
                }
                if (SqlWafDetector.blockedVsBaseline(toSimple(rTrue), waf.baseline) != null
                        || SqlWafDetector.droppedVsBaseline(toSimple(rTrue), waf.baseline != null)) {
                    continue;
                }
                RawResponse rFalse = sendMutated(base, target,
                        com.xzhscan.vendor.sql.SqlmapTimeModel.render(falseTpl, sleepSeconds),
                        waf, result, (long) sleepSeconds * 12_000L + 15_000L);
                if (rFalse == null || rFalse.statusCode <= 0) {
                    continue;
                }
                long delta = rTrue.elapsedMs - rFalse.elapsedMs;
                // TRUE 明显慢（≈S 秒）、FALSE 接近基线 → 时间条件对成立
                if (delta >= (long) sleepSeconds * 750L && rFalse.elapsedMs <= mean + 1_500L
                        && rTrue.elapsedMs >= hitFloor) {
                    // sqlmap retry 语义：同一 TRUE 子句复测一次，确认可重复
                    RawResponse again = sendMutated(base, target,
                            com.xzhscan.vendor.sql.SqlmapTimeModel.render(trueTpl, sleepSeconds),
                            waf, result, (long) sleepSeconds * 12_000L + 15_000L);
                    if (again == null || again.elapsedMs < hitFloor) {
                        continue;
                    }
                    // v4.0：sqlmap checkFalsePositives 交叉验证——随机三数构造
                    // "必须延迟/必须不延迟/非法语句不延迟"矩阵，任一不符即判假阳性，
                    // 不进入定罪（这是 sqlmap 排除抖动误报的核心步骤）
                    if (!sqlmapFalsePositivePass(base, target, waf, mean, sleepSeconds, result, b)) {
                        result.note = (result.note == null || result.note.isEmpty() ? "" : result.note + "; ")
                                + "sqlmap false-positive check failed (" + pair.label() + "@" + b.label() + ")";
                        continue;
                    }
                    // 复用三级阶梯定罪（同一 boundary+clause，replace=true 表示纯模板值）
                    Optional<InjectionFinding> f = threeTierTemplate(trueTpl, pair.db(), true,
                            "sqlmap-pair:" + pair.label() + "@" + b.label(), base, target, waf, url,
                            mean, std, sleepSeconds, result, null);
                    if (f.isPresent() && f.get().verdict == VerifyVerdict.CONFIRMED) {
                        return f;
                    }
                    retained = f.isPresent() ? f : retained;
                }
            }
        }

        // ---------- 阶段 2：boundary 枚举（快探 → 三级阶梯） ----------
        for (int bi = 0; bi < boundCap && budgetLeft(); bi++) {
            com.xzhscan.vendor.sql.SqlmapTimeModel.Boundary b = bounds.get(bi);
            for (com.xzhscan.vendor.sql.SqlmapTimeModel.TimeClause c
                    : com.xzhscan.vendor.sql.SqlmapTimeModel.TIME_CLAUSES) {
                if (!budgetLeft()) {
                    break;
                }
                if (!hintAllows(hint, c.db())) {
                    continue;
                }
                String tpl = b.wrap(c.clause());
                RawResponse r = sendMutated(base, target,
                        com.xzhscan.vendor.sql.SqlmapTimeModel.render(tpl, sleepSeconds),
                        waf, result, (long) sleepSeconds * 12_000L + 15_000L);
                if (r == null || r.statusCode <= 0) {
                    continue;
                }
                if (SqlWafDetector.blockedVsBaseline(toSimple(r), waf.baseline) != null
                        || SqlWafDetector.droppedVsBaseline(toSimple(r), waf.baseline != null)) {
                    continue;
                }
                if (r.elapsedMs < hitFloor) {
                    continue;
                }
                Optional<InjectionFinding> f = threeTierTemplate(tpl, c.db(), true,
                        "sqlmap:" + c.label() + "@" + b.label(), base, target, waf, url,
                        mean, std, sleepSeconds, result, null);
                if (f.isPresent() && f.get().verdict == VerifyVerdict.CONFIRMED) {
                    return f;
                }
                retained = f.isPresent() ? f : retained;
                break;  // 该 boundary 已出现延迟命中 → 直接复验，不再试同 boundary 其他子句
            }
        }
        return retained;
    }

    /**
     * v4.0：sqlmap 假阳性交叉验证（等价 {@code checkFalsePositives}）。
     *
     * <p>随机取 r1&lt;r2&lt;r3，依次发送：</p>
     * <ul>
     *   <li>{@code r1=r1}、{@code r2=r2} —— 必须延迟（真条件）；</li>
     *   <li>{@code r1=r2}、{@code r1=r3}、{@code r3=r2} —— 必须不延迟（假条件）；</li>
     *   <li>{@code "r3 r2"} —— 非法语句，必须不延迟。</li>
     * </ul>
     * <p>任一不符合 → 该点不按 SQL 条件执行（延迟来自抖动/缓存），判假阳性。</p>
     */
    private boolean sqlmapFalsePositivePass(RawRequest base,
                                            com.xzhscan.model.Models.ParameterIdentity target,
                                            WafWatch waf, double mean, int sleepSeconds,
                                            VerificationResult result,
                                            com.xzhscan.vendor.sql.SqlmapTimeModel.Boundary b) {
        java.util.concurrent.ThreadLocalRandom rnd = java.util.concurrent.ThreadLocalRandom.current();
        int r1 = 2 + rnd.nextInt(4);
        int r2 = r1 + 1 + rnd.nextInt(3);
        int r3 = r2 + 1 + rnd.nextInt(3);
        long hitFloor = (long) mean + (long) sleepSeconds * 850L;
        long fastCeil = (long) mean + 1_500L;
        for (com.xzhscan.vendor.sql.SqlmapTimeModel.FalsePositiveProbe probe
                : com.xzhscan.vendor.sql.SqlmapTimeModel.falsePositiveProbes(r1, r2, r3)) {
            if (!budgetLeft()) {
                return false; // 预算不足无法完成交叉验证 → 不当成已确认
            }
            RawResponse r = sendMutated(base, target,
                    com.xzhscan.vendor.sql.SqlmapTimeModel.render(b.wrap(probe.clause()), sleepSeconds),
                    waf, result, (long) sleepSeconds * 12_000L + 15_000L);
            if (r == null || r.statusCode <= 0) {
                return false;
            }
            if (probe.shouldDelay()) {
                if (r.elapsedMs < hitFloor) {
                    return false; // 真条件没变慢 → 假阳性
                }
            } else {
                if (r.elapsedMs > fastCeil) {
                    return false; // 假条件也变慢 → 假阳性
                }
            }
        }
        return true;
    }

    /** 时间快探候选（模板 + DB + replace 语义）。 */
    private static final class QuickProbeSpec {
        final String template;
        final String db;
        final boolean replace;

        QuickProbeSpec(String template, String db, boolean replace) {
            this.template = template;
            this.db = db;
            this.replace = replace;
        }
    }

    /**
     * v3.9.4：二阶段变异基值（append 语义的探针用作左操作数）。
     * 原值已含注入特征（fuzz 载荷形态：引号 / 注释符 / 括号 / DB 函数等）时，
     * 用干净占位符替代——数字型上下文 "1"、字符型上下文 "a"，
     * 避免 原值+探针 拼接成双重注入（如 `-1'`、`''`、`'...'='a and 1=...`）造成误报。
     * 纯字母数字原值保持原样（检测能力不变）。
     */
    public static String appendBase(String template, com.xzhscan.model.Models.ParameterIdentity target) {
        String v = target == null ? null : target.originalValue;
        String t = template == null ? "" : template.strip();
        boolean stringCtx = t.startsWith("'") || t.startsWith("\"");
        if (looksLikeInjection(v)) {
            return stringCtx ? "a" : "1";
        }
        return v == null ? "" : v;
    }

    /** 原值是否已含注入特征（fuzz 载荷 / 手工闭合引号等）。 */
    public static boolean looksLikeInjection(String v) {
        if (v == null || v.isEmpty()) {
            return false;
        }
        String lower = v.toLowerCase(Locale.ROOT);
        for (String kw : new String[]{"select", "union", "sleep", "waitfor", "dbms_pipe",
                "extractvalue", "updatexml", "case when", "1=1", "1 = 1", " and ", " or "}) {
            if (lower.contains(kw)) {
                return true;
            }
        }
        for (char c : new char[]{'\'', '"', '\\', '(', ')', ',', ';', '=', '<', '>', '#', '-'}) {
            if (v.indexOf(c) >= 0) {
                return true;
            }
        }
        return v.contains("--") || v.contains("/*");
    }

    /** 渲染模板占位（{S}/{R}/{C}/[Space]），供时间快探候选与 Registry 规则共用。 */
    private static String renderTemplate(String template, int seconds) {
        return template
                .replace("{S}", Integer.toString(seconds))
                .replace("{R}", SqlPayloadLibrary.newRand())
                .replace("{C}", String.valueOf((char) ('a' + ThreadLocalRandom.current().nextInt(20))))
                .replace("[Space]", "/**/");
    }

    /**
     * 三级 sleep 阶梯复验一条规则：sleep(0)→S→S+1 相对差分（任务书 §9/§10/§11）。
     * quick 为第一阶段命中证据（可为 null=右键全模块直验，无阶段一上下文）。
     */
    private Optional<InjectionFinding> threeTierRule(PayloadRule rule, RawRequest base,
                                                     com.xzhscan.model.Models.ParameterIdentity target,
                                                     WafWatch waf, String url, double mean, double std,
                                                     int sleepSeconds, VerificationResult result,
                                                     DiffEvidence quick) {
        return threeTierTemplate(rule.template(), rule.dbms(), rule.replace(),
                rule.id() + " (" + String.join(", ", rule.sourceRefs()) + ")",
                base, target, waf, url, mean, std, sleepSeconds, result, quick);
    }

    /** 三级复验核心（模板级；时间快探与 Registry 规则共用）。 */
    private Optional<InjectionFinding> threeTierTemplate(String template, String dbms, boolean replace,
                                                         String ruleLabel, RawRequest base,
                                                         com.xzhscan.model.Models.ParameterIdentity target,
                                                         WafWatch waf, String url, double mean, double std,
                                                         int sleepSeconds, VerificationResult result,
                                                         DiffEvidence quick) {
        // 三级阶梯：sleep(0) → sleep(S) → sleep(S+1)，相对差分（S 由基线速度决定，§10 模型）
        boolean confirmed = false;
        boolean sawTimeout = false;
        List<Long> t = new ArrayList<>(3);
        for (int round = 0; round < 2 && !confirmed && budgetLeft(); round++) {
            t.clear();
            boolean aborted = false;
            for (int sec : new int[]{0, sleepSeconds, sleepSeconds + 1}) {
                String rendered = renderTemplate(template, sec);
                String payload = replace ? rendered : appendBase(template, target) + rendered;
                // 逐行放大预算：sec 秒 × 行数未知 → sec×12s+15s（与第一阶段同策略）
                RawResponse r = sendMutated(base, target, payload, waf, result,
                        (long) sec * 12_000L + 15_000L);
                if (r == null) {
                    aborted = true;
                    break;
                }
                if (r.statusCode <= 0) {
                    sawTimeout = true;
                    aborted = true;
                    break;
                }
                if (SqlWafDetector.blockedVsBaseline(toSimple(r), waf.baseline) != null) {
                    aborted = true;
                    break;
                }
                t.add(r.elapsedMs);
            }
            if (aborted || t.size() < 3) {
                continue;
            }
            long t0 = t.get(0);
            long tS = t.get(1);
            long tS1 = t.get(2);
            // 相对差分判定（不叠加绝对阈值）：S 级延迟与 (S+1)-S 增量都须超过抗抖动下限
            confirmed = tS - t0 >= sleepSeconds * 750L && tS1 - tS >= 500L;
        }

        String renderedShown = renderTemplate(template, sleepSeconds);
        String payloadShown = replace ? renderedShown : appendBase(template, target) + renderedShown;
        if (confirmed) {
            result.timingVerdict = TimingVerdict.TIMING_CONFIRMED;
            InjectionFinding f = finding(VerifyVerdict.CONFIRMED, "Time-based blind (" + dbms + ")",
                    dbms, payloadShown, url, target, new EvidenceCollector()
                    .addTitle("SQL Injection Time Delay")
                    .addVulnerability("SQL Injection (Time-based blind)")
                    .add("Param", target.name)
                    .add("DB family", dbms)
                    .add("Rule", ruleLabel)
                    .add("Payload", payloadShown)
                    .add("Model", "3-tier relative Δt: sleep(0)→S→S+1, S=" + sleepSeconds
                            + ", baseline mean=" + String.format(Locale.ROOT, "%.0fms", mean)
                            + " σ=" + String.format(Locale.ROOT, "%.0fms", std))
                    .add("Verdict", "TIMING_CONFIRMED (relative Δt self-compare)")
                    .addRequest(base.method, url)
                    .addMatchedFeature("three-tier sleep(0→" + sleepSeconds + "→" + (sleepSeconds + 1)
                            + ") delays monotonically confirmed")
                    .build());
            f.timingVerdict = TimingVerdict.TIMING_CONFIRMED;
            f.payloadRuleId = ruleLabel;
            f.evidenceKinds.add("TIMING_ANOMALY");
            return Optional.of(f);
        }
        if (sawTimeout) {
            result.timingVerdict = TimingVerdict.TIMING_TIMEOUT;
            result.note = "3-tier probe timed out; delay evidence not usable";
            return Optional.empty();
        }
        // 未确认但第一阶段确有延迟命中：保留为 TIMING_ANOMALY（不删除时间证据，不直接定罪）
        result.timingVerdict = TimingVerdict.TIMING_ANOMALY;
        if (quick == null) {
            // 右键全模块直验：无阶段一命中证据，家族未确认不留 SUSPECTED（继续试下一族）
            return Optional.empty();
        }
        return Optional.of(suspected("Time-pattern retained (not confirmed by 3-tier)",
                payloadShown, url, target, base,
                "delay hit Δ=" + (quick == null ? -1 : quick.timingDeltaMs) + "ms on " + ruleLabel
                        + "; 3-tier relative Δt below confirm floor (possible queuing/jitter/WAF)"));
    }

    // ------------------------------------------------------------------
    // 工具（SQLIScanner 同款判定）
    // ------------------------------------------------------------------

    private static boolean hintAllows(String hint, String db) {
        if (hint == null || db == null) {
            return true;
        }
        String h = hint.toLowerCase(Locale.ROOT);
        String d = db.toLowerCase(Locale.ROOT);
        boolean hKnown = h.contains("mysql") || h.contains("mssql") || h.contains("postgres") || h.contains("oracle");
        if (!hKnown) {
            return true;
        }
        boolean dKnown = d.contains("mysql") || d.contains("mssql") || d.contains("postgres") || d.contains("oracle");
        if (!dKnown) {
            return true;
        }
        return d.contains(h) || h.contains(d);
    }

    static boolean isRealMd5Echo(String body, String rand) {
        if (body == null || body.isEmpty() || rand == null || rand.isEmpty()) {
            return false;
        }
        String low = body.toLowerCase(Locale.ROOT);
        String dec = SqlPayloadLibrary.md5HexOfDecimal(rand);
        String le = SqlPayloadLibrary.md5HexOfInt32Le(rand);
        boolean echoed = (!dec.isEmpty() && low.contains(dec)) || (!le.isEmpty() && low.contains(le));
        if (!echoed) {
            return false;
        }
        // 排除 payload 原样回显（未执行的报错回波）
        return !low.contains("md5(" + rand + ")") && !low.contains("md5('" + rand + "')");
    }

    /** token 相似度（与 SQLIScanner.sim 相同算法）。 */
    static double sim(String a, String b) {
        if (a == null) a = "";
        if (b == null) b = "";
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

    private static Set<String> tokens(String s) {
        Set<String> out = new HashSet<>();
        String low = s.toLowerCase(Locale.ROOT)
                .replaceAll("[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", "#")
                .replaceAll("\\b[0-9a-f]{16,}\\b", "#")
                .replaceAll("\\d+", "#");
        Matcher m = TOKEN.matcher(low);
        while (m.find()) {
            out.add(m.group());
        }
        return out;
    }

    private void collect(String evidenceId) {
        List<String> ids = evidenceCollector.get();
        if (ids != null && evidenceId != null) {
            ids.add(evidenceId);
        }
    }

    private static SimpleHttpResponse toSimple(RawResponse r) {
        if (r == null) {
            return null;
        }
        return SimpleHttpResponse.builder()
                .statusCode(r.statusCode)
                .headers(new java.util.HashMap<>(r.headers))
                .body(r.body)
                .responseTime(r.elapsedMs)
                .build();
    }

    private InjectionFinding finding(VerifyVerdict verdict, String type, String db, String payload, String url,
                                     com.xzhscan.model.Models.ParameterIdentity target, String evidenceText) {
        InjectionFinding f = new InjectionFinding();
        f.verdict = verdict;
        f.injectionType = type;
        f.dbFamily = db;
        f.payload = payload;
        f.evidenceText = evidenceText;
        f.parameterName = target.name;
        f.parameterPath = target.path;
        return f;
    }

    /** SUSPECTED 级 finding（不可复现/动态基线/时间异常保留）。 */
    private InjectionFinding suspected(String method, String payload, String url,
                                       com.xzhscan.model.Models.ParameterIdentity target, RawRequest base,
                                       String note) {
        InjectionFinding f = new InjectionFinding();
        f.verdict = VerifyVerdict.SUSPECTED;
        f.injectionType = method;
        f.payload = payload;
        f.falsePositiveNote = note;
        f.evidenceText = new EvidenceCollector()
                .addTitle("SQL Injection suspicion (not reproducible)")
                .add("Confirm method", method)
                .add("Param", target.name)
                .add("Payload", payload)
                .add("Note", note)
                .addRequest(base.method, url)
                .addMatchedFeature("pattern observed once; confirmation thresholds not met")
                .build();
        f.parameterName = target.name;
        f.parameterPath = target.path;
        return f;
    }

    private InjectionFinding confirmed(String method, String payload, String url,
                                       com.xzhscan.model.Models.ParameterIdentity target, RawRequest base) {
        return confirmed(method, payload, url, target, base, new EvidenceCollector()
                .addTitle("SQL Injection (Error)")
                .addVulnerability("SQL Injection (Error-based, md5-echo confirmed)")
                .add("Confirm method", method)
                .add("Param", target.name)
                .add("Payload", payload)
                .addRequest(base.method, url)
                .addMatchedFeature("Random md5 marker echoed in error")
                .build(), null, null);
    }

    private InjectionFinding confirmed(String method, String payload, String url,
                                       com.xzhscan.model.Models.ParameterIdentity target, RawRequest base,
                                       String evidenceText, String extraPayload, RawResponse extraResponse) {
        InjectionFinding f = new InjectionFinding();
        f.verdict = VerifyVerdict.CONFIRMED;
        f.injectionType = "Error-based (" + method + ")";
        f.dbFamily = method;
        f.payload = payload;
        f.evidenceText = evidenceText;
        f.parameterName = target.name;
        f.parameterPath = target.path;
        return f;
    }

    /** WAF 观察（SQLIScanner.WafWatch 1:1）。 */
    static final class WafWatch {
        final SimpleHttpResponse baseline;
        int blocked;
        int dropped;
        final List<String> reasons = new ArrayList<>(4);

        WafWatch(SimpleHttpResponse baseline) {
            this.baseline = baseline;
        }

        void observe(SimpleHttpResponse r) {
            if (r == null) {
                if (baseline != null) {
                    dropped++;
                }
                return;
            }
            String reason = SqlWafDetector.blockedVsBaseline(r, baseline);
            if (reason != null && reasons.size() < 4) {
                reasons.add(reason);
                blocked++;
            }
        }

        boolean intercepted() {
            return baseline != null && (blocked >= 2 || (blocked >= 1 && dropped >= 2) || dropped >= 4);
        }

        String summary() {
            return "blocked=" + blocked + ",dropped=" + dropped + (reasons.isEmpty() ? "" : ",reasons=" + reasons);
        }
    }
}
