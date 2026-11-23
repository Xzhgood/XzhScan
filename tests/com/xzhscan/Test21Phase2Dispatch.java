package com.xzhscan;

import com.xzhscan.config.XzhScanConfig;
import com.xzhscan.engine.SqlVerificationEngine;
import com.xzhscan.model.EvidenceStore;
import com.xzhscan.model.Models.CandidateType;
import com.xzhscan.model.Models.DiffEvidence;
import com.xzhscan.model.Models.DifferentialCandidate;
import com.xzhscan.model.Models.TimingVerdict;
import com.xzhscan.model.Models.VerifyVerdict;
import com.xzhscan.parameter.ParameterExtractor;

import java.util.LinkedHashMap;

import static com.xzhscan.MiniTest.TestContext;

/**
 * 测试二十一：第二阶段证据分型调度（任务书 §8/§9）。
 *  - TIME_CANDIDATE：仅对命中规则做三级复验，不重新枚举时间规则
 *    （探针请求数 ≤ 基线+3-tier×2，且探针 URL 全部属于命中规则家族）；
 *  - 三级相对差分确认 → CONFIRMED + TIMING_CONFIRMED；
 *  - ERROR_CANDIDATE：heuristic 发送 原值+噪声（修复证据与实际报文一致）；
 *  - 无效 JSON（INVALID_REQUEST）不进入第二阶段。
 */
public final class Test21Phase2Dispatch {

    /** 构造带快照请求的候选。 */
    private static DifferentialCandidate candidate(RawRequestSnap snap, CandidateType type, String ruleId) {
        DifferentialCandidate c = new DifferentialCandidate();
        c.requestId = "REQ-21";
        c.targetUrl = snap.url;
        c.method = "GET";
        c.parameterName = "name";
        c.parameterPath = "name";
        c.parameterLocation = com.xzhscan.model.Models.Location.QUERY;
        c.originalValue = "admin";
        c.originalType = "string";
        c.candidateType = type;
        c.payloadRuleId = ruleId;
        c.occurrence = 0;
        c.originalRequest = snap.request;
        DiffEvidence ev = new DiffEvidence();
        ev.dbErrorFamily = type == CandidateType.ERROR_CANDIDATE ? "MySQL" : null;
        ev.timingDeltaMs = type == CandidateType.TIME_CANDIDATE ? 6400 : 0;
        ev.mutatedStatus = 200;
        ev.payloadRuleId = ruleId;
        c.mutatedEvidence = ev;
        return c;
    }

    private record RawRequestSnap(String url, com.xzhscan.model.RawHttp.RawRequest request) {
    }

    private static RawRequestSnap snap(String url) {
        return new RawRequestSnap(url, Support.get(url));
    }

    private static com.xzhscan.model.RawHttp.RawResponse resp(int status, String body, long ms) {
        return new com.xzhscan.model.RawHttp.RawResponse(status, new LinkedHashMap<>(),
                body.getBytes(java.nio.charset.StandardCharsets.UTF_8), ms);
    }

    public static void run(TestContext t) {
        XzhScanConfig config = new XzhScanConfig();
        config.requestIntervalMs = 0;
        config.baselineSamples = 3;

        // ---------- 1. TIME_CANDIDATE：定向复验（PG 命中规则） ----------
        Support.FakeTransport pg = new Support.FakeTransport();
        pg.responder = (r, i) -> {
            String u = r.url.toLowerCase();
            if (u.contains("pg_sleep(0)")) {
                return resp(200, "{\"ok\":true}", 30);
            }
            if (u.contains("pg_sleep(5)")) {
                return resp(200, "{\"ok\":true}", 6000);
            }
            if (u.contains("pg_sleep(6)")) {
                return resp(200, "{\"ok\":true}", 7200);
            }
            return resp(200, "{\"ok\":true}", 30); // 基线
        };
        SqlVerificationEngine engine = new SqlVerificationEngine(config, pg, new EvidenceStore());
        var vr = engine.verify(candidate(snap("http://t.local/q?name=admin"),
                CandidateType.TIME_CANDIDATE, "QT-PG-PGSLEEP-01"));
        t.checkEq(VerifyVerdict.CONFIRMED, vr.verdict, "targeted 3-tier confirms -> CONFIRMED");
        t.checkEq(TimingVerdict.TIMING_CONFIRMED, vr.timingVerdict, "timing verdict = TIMING_CONFIRMED");
        // §9：不重新枚举——探针 URL 全部属于 pg_sleep 家族，无 SLEEP(/WAITFOR/DBMS_PIPE/XOR
        int totalSends = pg.sent.size();
        t.check(totalSends <= 3 + 3 * 2, "request count small (baseline 3 + <=2 rounds x 3-tier): " + totalSends);
        boolean foreignProbe = pg.sent.stream().anyMatch(r -> {
            String u = r.url.toLowerCase();
            // 注意：pg_sleep 本身含子串 "sleep("，需排除命中规则家族自身
            return u.contains("waitfor") || u.contains("dbms_pipe")
                    || (u.contains("sleep(") && !u.contains("pg_sleep"));
        });
        t.check(!foreignProbe, "no other time-family probes sent (no re-enumeration)");
        long pgProbes = pg.sent.stream().filter(r -> r.url.contains("pg_sleep")).count();
        t.check(pgProbes >= 3, "3-tier probes of the HIT rule only: " + pgProbes);
        t.check(vr.probeCount >= 3, "probeCount accumulated: " + vr.probeCount);

        // ---------- 2. TIME_CANDIDATE：三级不确认 → TIMING_ANOMALY（证据保留不删除） ----------
        Support.FakeTransport jitter = new Support.FakeTransport();
        jitter.responder = (r, i) -> {
            String u = r.url.toLowerCase();
            if (u.contains("pg_sleep(5)")) {
                return resp(200, "{\"ok\":true}", 800);
            }
            if (u.contains("pg_sleep(6)")) {
                return resp(200, "{\"ok\":true}", 900);
            }
            return resp(200, "{\"ok\":true}", 30);
        };
        SqlVerificationEngine jEngine = new SqlVerificationEngine(config, jitter, new EvidenceStore());
        var vr2 = jEngine.verify(candidate(snap("http://t.local/q?name=admin"),
                CandidateType.TIME_CANDIDATE, "QT-PG-PGSLEEP-01"));
        t.check(vr2.verdict == VerifyVerdict.SUSPECTED || vr2.verdict == VerifyVerdict.REJECTED,
                "unconfirmed time pattern not CONFIRMED: " + vr2.verdict);
        t.checkEq(TimingVerdict.TIMING_ANOMALY, vr2.timingVerdict, "timing verdict = TIMING_ANOMALY (evidence kept)");

        // ---------- 3. TIME_CANDIDATE：超时 → TIMING_TIMEOUT，不定罪 ----------
        Support.FakeTransport timeout = new Support.FakeTransport();
        timeout.responder = (r, i) -> {
            if (r.url.contains("pg_sleep")) {
                return resp(0, "", 21000);
            }
            return resp(200, "{\"ok\":true}", 30);
        };
        SqlVerificationEngine toEngine = new SqlVerificationEngine(config, timeout, new EvidenceStore());
        var vr3 = toEngine.verify(candidate(snap("http://t.local/q?name=admin"),
                CandidateType.TIME_CANDIDATE, "QT-PG-PGSLEEP-01"));
        t.check(vr3.verdict != VerifyVerdict.CONFIRMED, "timeout never confirms");
        t.checkEq(TimingVerdict.TIMING_TIMEOUT, vr3.timingVerdict, "timing verdict = TIMING_TIMEOUT");

        // ---------- 4. ERROR_CANDIDATE：heuristic 发送纯噪声（v3.9.4 不再拼原值） ----------
        Support.FakeTransport err = new Support.FakeTransport();
        err.responder = (r, i) -> {
            String qv = r.url.contains("name=") ? r.url.substring(r.url.indexOf("name=") + 5) : "";
            String decoded = ParameterExtractor.urlDecode(qv);
            // 噪声形态触发 DB 错误（模拟应用把参数拼进 SQL 后报错）
            if (decoded.contains("鎈") || decoded.contains("(")) {
                return resp(200, "MySQL XPATH syntax error: extra junk", 30);
            }
            return resp(200, "{\"data\":\"normal\"}", 20);
        };
        SqlVerificationEngine eEngine = new SqlVerificationEngine(config, err, new EvidenceStore());
        var vr4 = eEngine.verify(candidate(snap("http://t.local/e?name=admin"),
                CandidateType.ERROR_CANDIDATE, null));
        t.checkEq(VerifyVerdict.CONFIRMED, vr4.verdict, "heuristic error fingerprint -> CONFIRMED");
        // v3.9.4 语义：发送的参数值 = 纯噪声（不含原值）——fuzz 原值叠加会误报
        boolean noiseOnly = err.sent.stream().anyMatch(r -> {
            String qv = r.url.contains("name=") ? r.url.substring(r.url.indexOf("name=") + 5) : "";
            String decoded = ParameterExtractor.urlDecode(qv);
            return (decoded.contains("鎈") || decoded.contains("'\"\\("))
                    && !decoded.startsWith("admin");
        });
        t.check(noiseOnly, "heuristic probe carries pure noise (no original value prepended)");
        t.check(vr4.findings.stream().findFirst().orElseThrow().payload != null
                        && !vr4.findings.get(0).payload.startsWith("admin"),
                "evidence Payload text matches sent value (no original prefix)");

        // ---------- 5. v3.9.4：脏原值判定（fuzz 载荷不得作为 append 基值） ----------
        // 实测误报：原值本身是 ' / -1 / DBMS_PIPE(...) 时，append 会拼成双重注入
        t.check(SqlVerificationEngine.looksLikeInjection(
                        "' AND (CASE WHEN 1=1 THEN DBMS_PIPE.RECEIVE_MESSAGE('a',2) ELSE 1 END)='a"),
                "DBMS_PIPE fuzz 载荷判定为脏值（不叠加原值）");
        for (String dirty : new String[]{"'", "\"", "-1", "-0", ",0", "/-1", "a'", "1=1", "x--", "/*c*/"}) {
            t.check(SqlVerificationEngine.looksLikeInjection(dirty), "脏值判定: " + dirty);
        }
        for (String clean : new String[]{"admin", "123", "user_name", "test2024", ""}) {
            t.check(!SqlVerificationEngine.looksLikeInjection(clean), "正常值保持原样: " + clean);
        }

        // ---------- 5. INVALID_REQUEST（非法 JSON）不进入第二阶段 ----------
        Support.FakeTransport badJson = new Support.FakeTransport();
        badJson.responder = (r, i) -> resp(200, "{\"ok\":true}", 20);
        var p1 = new com.xzhscan.engine.PassiveDetectionEngine(config, badJson, new EvidenceStore());
        var rec = new com.xzhscan.model.Models.TrafficRecord();
        rec.requestId = "REQ-21J";
        var cands = p1.process(Support.postJson("http://t.local/b", "{\"a\":1"), null, rec, null);
        t.check(cands.isEmpty(), "invalid JSON yields zero candidates (INVALID_REQUEST)");
        t.check("baseline-anomaly".equals(rec.phase1Status) || "no-params".equals(rec.phase1Status),
                "phase1 marks baseline-anomaly: " + rec.phase1Status);
        int before = badJson.sent.size();
        t.check(before <= 0, "no mutation probes sent against invalid JSON baseline");
    }
}
