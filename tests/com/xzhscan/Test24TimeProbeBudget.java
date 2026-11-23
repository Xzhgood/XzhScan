package com.xzhscan;

import com.xzhscan.config.XzhScanConfig;
import com.xzhscan.engine.PassiveDetectionEngine;
import com.xzhscan.engine.SqlVerificationEngine;
import com.xzhscan.model.EvidenceStore;
import com.xzhscan.model.Models.CandidateType;
import com.xzhscan.model.Models.DifferentialCandidate;
import com.xzhscan.model.Models.TimingVerdict;
import com.xzhscan.model.Models.TrafficRecord;
import com.xzhscan.model.Models.VerifyVerdict;
import com.xzhscan.model.RawHttp.RawRequest;
import com.xzhscan.model.RawHttp.RawResponse;
import com.xzhscan.model.RawHttp.Transport;

import java.util.LinkedHashMap;
import java.util.List;

import static com.xzhscan.MiniTest.TestContext;

/**
 * 测试二十四：时间探针超时预算（v2.2.2 回归；v3.5 重写为 Phase2 口径）。
 *
 * 历史（pikachu sqli_blind_t 实测缺陷）：AND 短路使 `' AND SLEEP(6)` 对不存在的值
 * 不触发；XOR 变体强制求值 → sleep 逐行放大（7 行 × 6s = 42s）→ 旧实现
 * requestTimeoutMs=20s 掐死该探针（status=0）→ 时间差分不落库。修复 =
 * Transport 按调用超时（时间探针预算 = 期望延迟×12+15s）。
 *
 * v3.5 被动时间探针子系统移除后：
 *  - §1 锁死"被动纯差分不发送 sleep 探针、不产生时间候选"（v3.5 行为守护）；
 *  - §2 逐行放大场景由 Phase2 verifyTimeBased 的三级复验 + 按调用预算承接
 *    （QUICK/XRAY 模板仍走 Transport.send(r, expected*12+15s)，Test30 覆盖枚举顺序）。
 */
public final class Test24TimeProbeBudget {

    /** 模拟逐行放大的服务端：sleep 类请求 → 42s；其余 25ms。 */
    private static Transport amplifying() {
        return new Transport() {
            @Override
            public RawResponse send(RawRequest r) {
                return send(r, 60_000L); // 默认预算 = requestTimeoutMs（旧缺陷形态）
            }

            @Override
            public RawResponse send(RawRequest r, long timeoutMs) {
                String wire = (r.url + " " + r.bodyAsString()).toUpperCase();
                long delay = (wire.contains("XOR") || wire.contains("SLEEP")
                        || wire.contains("WAITFOR") || wire.contains("DBMS_PIPE"))
                        ? 42_000L   // sleep 逐行放大
                        : 25L;      // 基线/引号/数字探针
                if (delay > timeoutMs) {
                    return new RawResponse(0, new LinkedHashMap<>(), new byte[0], timeoutMs); // 客户端超时
                }
                return new RawResponse(200, new LinkedHashMap<>(),
                        "{\"ok\":true}".getBytes(java.nio.charset.StandardCharsets.UTF_8), delay);
            }
        };
    }

    private static DifferentialCandidate candidate(String url, String ruleId) {
        DifferentialCandidate c = new DifferentialCandidate();
        c.requestId = "REQ-24";
        c.targetUrl = url;
        c.method = "GET";
        c.parameterName = "name";
        c.parameterPath = "name";
        c.parameterLocation = com.xzhscan.model.Models.Location.QUERY;
        c.originalValue = "11";
        c.originalType = "string";
        c.candidateType = CandidateType.TIME_CANDIDATE;
        c.payloadRuleId = ruleId;
        c.occurrence = 0;
        c.originalRequest = Support.get(url);
        com.xzhscan.model.Models.DiffEvidence ev = new com.xzhscan.model.Models.DiffEvidence();
        ev.timingDeltaMs = 41_970L;
        ev.mutatedStatus = 200;
        ev.payloadRuleId = ruleId;
        c.mutatedEvidence = ev;
        return c;
    }

    public static void run(TestContext t) {
        XzhScanConfig config = new XzhScanConfig();
        config.requestIntervalMs = 0;
        config.baselineSamples = 3;
        config.requestTimeoutMs = 20_000; // 用户实机默认：默认预算 20s

        // ---------- 1. 被动纯差分：sleep 放大服务器上也不发时间探针（v3.5 守护） ----------
        Transport amp = new com.xzhscan.policy.ThrottledTransport(
                amplifying(), new com.xzhscan.policy.ScanPolicyEngine(config));
        PassiveDetectionEngine p1 = new PassiveDetectionEngine(config, amp, new EvidenceStore());
        TrafficRecord rec = new TrafficRecord();
        rec.requestId = "REQ-24";
        List<DifferentialCandidate> cands = p1.process(
                Support.get("http://t.local/b?name=11"), null, rec, null);
        t.check(cands.stream().noneMatch(c -> c.candidateType == CandidateType.TIME_CANDIDATE),
                "passive phase never emits TIME_CANDIDATE (v3.5: no passive sleep probes)");
        t.checkEq(0, rec.timeRequests, "passive phase sends no sleep-classified probes");

        // ---------- 2. AND 短路形态：无服务器延迟 → 不产生差分候选（正确行为） ----------
        Support.FakeTransport shortCircuit = new Support.FakeTransport();
        shortCircuit.responder = (r, i) -> Support.text(200, "{\"ok\":true}");
        PassiveDetectionEngine p1b = new PassiveDetectionEngine(config, shortCircuit, new EvidenceStore());
        TrafficRecord recB = new TrafficRecord();
        recB.requestId = "REQ-24B";
        List<DifferentialCandidate> candsB = p1b.process(
                Support.get("http://t.local/b2?name=11"), null, recB, null);
        t.check(candsB.isEmpty(), "static responses produce no candidates");

        // ---------- 3. Phase2 三级复验：三级 0/14s/21s（逐行放大）→ CONFIRMED ----------
        Transport tiered = new Transport() {
            @Override
            public RawResponse send(RawRequest r) {
                return send(r, 60_000L);
            }

            @Override
            public RawResponse send(RawRequest r, long timeoutMs) {
                String u = r.url.toLowerCase();
                long delay = 25L;
                if (u.contains("pg_sleep(5)")) {
                    delay = 35_000L; // S=5 × 7 行
                } else if (u.contains("pg_sleep(6)")) {
                    delay = 42_000L; // S+1=6 × 7 行
                }
                if (delay > timeoutMs) {
                    return new RawResponse(0, new LinkedHashMap<>(), new byte[0], timeoutMs);
                }
                return new RawResponse(200, new LinkedHashMap<>(),
                        "{\"ok\":true}".getBytes(java.nio.charset.StandardCharsets.UTF_8), delay);
            }
        };
        SqlVerificationEngine p2 = new SqlVerificationEngine(config, tiered, new EvidenceStore());
        var vr = p2.verify(candidate("http://t.local/b?name=11", "QT-PG-PGSLEEP-01"));
        t.checkEq(VerifyVerdict.CONFIRMED, vr.verdict,
                "3-tier with per-row amplification (0/14s/21s) -> CONFIRMED, lands in report");
        t.checkEq(TimingVerdict.TIMING_CONFIRMED, vr.timingVerdict, "timing verdict = TIMING_CONFIRMED");
    }
}
