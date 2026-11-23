package com.xzhscan;

import com.xzhscan.config.XzhScanConfig;
import com.xzhscan.engine.PassiveDetectionEngine;
import com.xzhscan.engine.SqlVerificationEngine;
import com.xzhscan.model.EvidenceStore;
import com.xzhscan.model.Models.CandidateType;
import com.xzhscan.model.Models.DiffEvidence;
import com.xzhscan.model.Models.DifferentialCandidate;
import com.xzhscan.model.Models.TrafficRecord;
import com.xzhscan.model.Models.VerifyVerdict;
import com.xzhscan.vendor.sql.SqlPayloadLibrary;

import java.util.LinkedHashMap;
import java.util.List;

import static com.xzhscan.MiniTest.TestContext;

/**
 * 测试二十三：本地 Mock 数据库兼容性（任务书 步骤 8 / §15 实测计数）。
 * 用 Mock HTTP 传输模拟各数据库对探针的真实反应（不发起任何真实目标请求）：
 *  - MySQL extractvalue md5 回显 → errConfirm CONFIRMED；
 *  - MSSQL hashbytes md5 回显（hint=MSSQL 跳过 MySQL 分支）→ CONFIRMED；
 *  - Oracle DBMS_PIPE（CONDITIONAL 开启后第一阶段命中 → 第二阶段定向复验）→ CONFIRMED；
 *  - WAF 拦截模拟 → SUSPECTED/WAF-Blocked（非漏洞结论）；
 *  - §15 实测：单参数第一阶段请求数（基线 3 + 引号 2 + 默认时间集 6 = 11，v2.3）。
 */
public final class Test23MockDb {

    private static com.xzhscan.model.RawHttp.RawResponse resp(int status, String body, long ms) {
        return new com.xzhscan.model.RawHttp.RawResponse(status, new LinkedHashMap<>(),
                body.getBytes(java.nio.charset.StandardCharsets.UTF_8), ms);
    }

    private static DifferentialCandidate candidate(String url, CandidateType type, String dbHint, String ruleId) {
        DifferentialCandidate c = new DifferentialCandidate();
        c.requestId = "REQ-23";
        c.targetUrl = url;
        c.method = "GET";
        c.parameterName = "name";
        c.parameterPath = "name";
        c.parameterLocation = com.xzhscan.model.Models.Location.QUERY;
        c.originalValue = "admin";
        c.originalType = "string";
        c.candidateType = type;
        c.payloadRuleId = ruleId;
        c.occurrence = 0;
        c.originalRequest = Support.get(url);
        DiffEvidence ev = new DiffEvidence();
        ev.dbErrorFamily = dbHint;
        c.mutatedEvidence = ev;
        return c;
    }

    /** 从请求 URL 提取 rand（兼容 md5(123) 与 HashBytes('MD5',123) 两种形态）并回显其 md5。 */
    private static String echoMd5(String url) {
        java.util.regex.Matcher m1 = java.util.regex.Pattern
                .compile("md5[(](\\d+)", java.util.regex.Pattern.CASE_INSENSITIVE).matcher(url);
        java.util.regex.Matcher m2 = java.util.regex.Pattern
                .compile("md5',(\\d+)", java.util.regex.Pattern.CASE_INSENSITIVE).matcher(url);
        String rand = "";
        if (m1.find()) {
            rand = m1.group(1);
        } else if (m2.find()) {
            rand = m2.group(1);
        }
        return rand.isEmpty() ? "" : SqlPayloadLibrary.md5HexOfDecimal(rand);
    }

    public static void run(TestContext t) {
        // v3.5：被动时间探针子系统已移除，本套件聚焦 Phase2 报错回显/WAF/预算口径
        XzhScanConfig config = new XzhScanConfig();
        config.requestIntervalMs = 0;
        config.baselineSamples = 3;

        // ---------- 1. MySQL extractvalue md5 回显 ----------
        Support.FakeTransport mysql = new Support.FakeTransport();
        mysql.responder = (r, i) -> {
            String hash = echoMd5(r.url);
            if (!hash.isEmpty() && r.url.contains("extractvalue")) {
                return resp(200, "XPATH syntax error: '~" + hash + "' not valid", 25);
            }
            return resp(200, "{\"ok\":true}", 25);
        };
        var vr = new SqlVerificationEngine(config, mysql, new EvidenceStore())
                .verify(candidate("http://t.local/m?name=admin", CandidateType.ERROR_CANDIDATE, "MySQL", null));
        t.checkEq(VerifyVerdict.CONFIRMED, vr.verdict, "MySQL extractvalue md5-echo -> CONFIRMED");
        t.check(vr.findings.get(0).injectionType.contains("md5-echo"), "confirm method recorded");

        // ---------- 2. MSSQL hashbytes md5 回显（hint=MSSQL） ----------
        Support.FakeTransport mssql = new Support.FakeTransport();
        mssql.responder = (r, i) -> {
            String hash = echoMd5(r.url);
            if (!hash.isEmpty() && r.url.contains("HashBytes")) {
                return resp(200, "Conversion failed when converting the nvarchar value '" + hash + "'", 25);
            }
            return resp(200, "{\"ok\":true}", 25);
        };
        var vr2 = new SqlVerificationEngine(config, mssql, new EvidenceStore())
                .verify(candidate("http://t.local/s?name=1", CandidateType.ERROR_CANDIDATE, "MSSQL", null));
        t.checkEq(VerifyVerdict.CONFIRMED, vr2.verdict, "MSSQL hashbytes md5-echo -> CONFIRMED");
        // hint=MSSQL 时不发 MySQL extractvalue 探针
        t.check(mssql.sent.stream().noneMatch(r -> r.url.contains("extractvalue")),
                "hint gating: MySQL branch skipped for MSSQL hint");

        // v3.5：原 §3 Oracle DBMS_PIPE 被动命中节已随被动时间探针子系统移除；
        // Oracle 时间链路由 Test30（时间枚举 QUICK→XRAY + 三级阶梯）覆盖。

        // ---------- 4. WAF 拦截模拟 → SUSPECTED（非漏洞结论） ----------
        Support.FakeTransport waf = new Support.FakeTransport();
        waf.responder = (r, i) -> {
            if (i > 3) { // 基线 3 次之后全部拦截
                return resp(403, "Request blocked by Web Application Firewall (safedog)", 20);
            }
            return resp(200, "{\"ok\":true}", 20);
        };
        var vr4 = new SqlVerificationEngine(config, waf, new EvidenceStore())
                .verify(candidate("http://t.local/w?name=admin", CandidateType.BOOLEAN_CANDIDATE, null, null));
        t.check(vr4.verdict != VerifyVerdict.CONFIRMED, "WAF-blocked never confirms injection");
        t.check(vr4.findings.stream().anyMatch(f -> "WAF-Blocked".equals(f.injectionType)),
                "WAF-Blocked finding recorded (non-vuln verdict)");
        t.check(vr4.findings.stream().filter(f -> "WAF-Blocked".equals(f.injectionType))
                        .allMatch(f -> f.verdict == VerifyVerdict.SUSPECTED),
                "WAF-Blocked stays SUSPECTED");

        // ---------- 5. §15 实测：单参数第一阶段请求预算 ----------
        Support.FakeTransport counter = new Support.FakeTransport();
        counter.responder = (r, i) -> resp(200, "stable content body", 20);
        PassiveDetectionEngine p1 = new PassiveDetectionEngine(config, counter, new EvidenceStore());
        TrafficRecord rec = new TrafficRecord();
        rec.requestId = "REQ-23C";
        p1.process(Support.get("http://t.local/c?name=admin"), null, rec, null);
        // 基线 3 + 引号 2 = 5（v3.5 被动=纯差分，无时间探针）
        t.checkEq(5, rec.httpRequests, "single-param phase-1 HTTP budget = 5 (baseline3+quote2)");
        t.checkEq(0, rec.timeRequests, "no passive time probes (v3.5)");
        t.check(rec.rulesTotal > 0, "rule accounting recorded");
    }
}
