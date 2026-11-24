package com.xzhscan.engine;

import com.xzhscan.config.XzhScanConfig;
import com.xzhscan.model.EvidenceStore;
import com.xzhscan.model.Models.DifferentialCandidate;
import com.xzhscan.model.Models.TrafficRecord;
import com.xzhscan.model.Models.VerificationResult;
import com.xzhscan.model.RawHttp.RawRequest;
import com.xzhscan.model.RawHttp.RawResponse;
import com.xzhscan.model.RawHttp.Transport;
import com.xzhscan.policy.ScanPolicyEngine;
import com.xzhscan.policy.ThrottledTransport;

import com.xzhscan.parameter.ParameterExtractor;

import java.util.List;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.RejectedExecutionException;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * 扫描调度器：串起两阶段。
 *
 *  流量/手动请求 -> 安全策略 -> [阶段1 PassiveDetectionEngine]
 *        -> DifferentialGate（PASS 候选） -> [阶段2 SqlVerificationEngine，仅该参数]
 *        -> VerificationResult / InjectionFinding -> UI + Burp issue 上报。
 *
 * 去重：同 (method + 去参数 URL + 参数集签名) 在窗口期内只跑一次第一阶段。
 * 不因第一阶段异常无限重试：每请求单次执行，异常直接计入 TrafficRecord 状态。
 */
public final class ScanOrchestrator {

    private final XzhScanConfig config;
    private final EvidenceStore evidence;
    private final ScanPolicyEngine policy;
    private final PassiveDetectionEngine phase1;
    private final SqlVerificationEngine phase2;
    /** 有界任务队列：容量 200，饱和时丢弃新任务并回执 queue-full（不阻塞 Burp 线程）。 */
    static final int QUEUE_CAPACITY = 200;
    private final ExecutorService executor;
    private final AtomicInteger requestSeq = new AtomicInteger();
    /** 请求级去重：key -> 上次受理时间戳（dedupWindowMinutes 窗口，0=关闭）。 */
    private final ConcurrentHashMap<String, Long> recentKeys = new ConcurrentHashMap<>();

    /** 上层（Burp/UI）回调。 */
    public interface HostCallback {
        void onTraffic(TrafficRecord record);

        void onGateView(com.xzhscan.model.Models.GateProbeView view);

        void onCandidate(DifferentialCandidate candidate);

        void onRejected(String requestId, com.xzhscan.model.Models.ParameterIdentity param, String probe, String reason, double score);

        void onVerification(VerificationResult result);

        void onFinding(DifferentialCandidate candidate, VerificationResult result, com.xzhscan.model.Models.InjectionFinding finding);
    }

    public ScanOrchestrator(XzhScanConfig config, Transport transport, EvidenceStore evidence, ScanPolicyEngine policy) {
        this.config = config;
        this.evidence = evidence;
        this.policy = policy;
        Transport throttled = new ThrottledTransport(transport, policy);
        this.phase1 = new PassiveDetectionEngine(config, throttled, evidence);
        this.phase2 = new SqlVerificationEngine(config, throttled, evidence);
        int threads = Math.max(1, config.maxConcurrentScans);
        this.executor = new ThreadPoolExecutor(threads, threads, 30L, TimeUnit.SECONDS,
                new ArrayBlockingQueue<>(QUEUE_CAPACITY), r -> {
                    Thread t = new Thread(r, "xzhscan-scan");
                    t.setDaemon(true);
                    return t;
                }, new ThreadPoolExecutor.AbortPolicy());
    }

    /**
     * 提交一个观测到的请求（来源：Proxy/Repeater/Scanner/手动菜单）。异步执行。
     *
     * @param force 手动提交（右键菜单）时绕过去重窗口，与 XiaSQL 原版语义一致
     */
    public void submit(RawRequest request, RawResponse observed, String sourceLabel, HostCallback cb) {
        submit(request, observed, sourceLabel, cb, "Manual".equals(sourceLabel));
    }

    public void submit(RawRequest request, RawResponse observed, String sourceLabel, HostCallback cb, boolean force) {
        // v3.8.6 修复：暂停=完全离岗（不发包也不入库）——原实现只挡主动变异请求，
        // 流量记录/观察行仍会入库；现在暂停状态下所有入口（Proxy/Repeater/Manual）直接丢弃。
        if (policy.isPaused()) {
            return;
        }
        ScanPolicyEngine.Decision decision = policy.check(request);
        TrafficRecord record = new TrafficRecord();
        record.id = requestSeq.incrementAndGet();
        record.requestId = "REQ-" + record.id;
        record.source = sourceLabel;
        record.url = request.url;
        record.method = request.method;
        record.startedAtMs = System.currentTimeMillis();
        if (!decision.allowed) {
            record.phase1Status = "blocked-by-policy";
            record.phase2Status = "-";
            record.elapsedMs = 0;
            cb.onTraffic(record);
            return;
        }
        // 请求级去重：同 (method + 去参 URL + 参数集签名) 在窗口内只跑一次第一阶段
        String dedupKey = dedupKeyOf(request);
        if (!force && config.dedupWindowMinutes > 0) {
            Long seenAt = recentKeys.get(dedupKey);
            long now = System.currentTimeMillis();
            if (seenAt != null && now - seenAt < config.dedupWindowMinutes * 60_000L) {
                record.phase1Status = "deduplicated";
                record.phase2Status = "-";
                record.elapsedMs = 0;
                cb.onTraffic(record);
                return;
            }
            recentKeys.put(dedupKey, now);
            if (recentKeys.size() > 4096) {
                recentKeys.keySet().removeIf(k -> {
                    Long at = recentKeys.get(k);
                    return at == null || now - at >= config.dedupWindowMinutes * 60_000L;
                });
            }
        }
        try {
        executor.submit(() -> {
            try {
                List<DifferentialCandidate> candidates = phase1.process(request, observed, record, new PassiveDetectionEngine.Callback() {
                    @Override
                    public void onTrafficUpdate(TrafficRecord r) {
                        r.elapsedMs = System.currentTimeMillis() - r.startedAtMs;
                        cb.onTraffic(r);
                    }

                    @Override
                    public void onCandidate(DifferentialCandidate c) {
                        cb.onCandidate(c);
                    }

                    @Override
                    public void onRejected(String requestId, com.xzhscan.model.Models.ParameterIdentity param,
                                           String probe, String reason, double score) {
                        cb.onRejected(requestId, param, probe, reason, score);
                    }

                    @Override
                    public void onGateView(com.xzhscan.model.Models.GateProbeView view) {
                        cb.onGateView(view);
                    }
                });
                record.elapsedMs = System.currentTimeMillis() - record.startedAtMs;
                cb.onTraffic(record);

                // ---- 第二阶段：v3.1 起不自动执行（autoVerify 路径已删除）----
                // 被动职责到"列出候选"为止；二阶段一律人工触发：
                // 右键「XzhScan SQL 验证」或差分页右键 -> verifyNow（同款安全闸/回流）。
                record.phase2Status = candidates.isEmpty()
                        ? (config.phase2Enabled ? "no-candidates" : "disabled")
                        : "manual-mode";
                record.elapsedMs = System.currentTimeMillis() - record.startedAtMs;
                cb.onTraffic(record);
            } catch (Throwable t) {
                record.phase1Status = "error: " + t.getClass().getSimpleName();
                record.phase2Status = "-";
                record.elapsedMs = System.currentTimeMillis() - record.startedAtMs;
                // 去重污染修复（§8 任务书）：失败结果不占用去重窗口，允许后续重扫
                recentKeys.remove(dedupKey);
                cb.onTraffic(record);
            }
        });
        } catch (RejectedExecutionException saturated) {
            record.phase1Status = "queue-full";
            record.phase2Status = "-";
            record.elapsedMs = 0;
            recentKeys.remove(dedupKey);
            cb.onTraffic(record);
        }
    }

    /** 去重键：方法 + 去查询 URL + 参数（位置:路径）有序签名 —— 与参数值无关。 */
    public static String dedupKeyOf(RawRequest request) {
        StringBuilder sb = new StringBuilder(128);
        sb.append(request.method.toUpperCase()).append('|');
        int q = request.url.indexOf('?');
        sb.append(q >= 0 ? request.url.substring(0, q) : request.url);
        ParameterExtractor.ExtractResult ex = ParameterExtractor.extract(request);
        ex.parameters.stream()
                .map(p -> p.location + ":" + p.path)
                .sorted()
                .forEach(k -> sb.append('|').append(k));
        return sb.toString();
    }

    /**
     * v3.0 右键指定参数验证：从原始请求 + 参数构造无差分上下文的候选
     * （candidateType=null → 二阶段走全模块验证序列）。
     */
    public static DifferentialCandidate manualCandidate(RawRequest request,
                                                        com.xzhscan.model.Models.ParameterIdentity p) {
        DifferentialCandidate c = new DifferentialCandidate();
        c.requestId = "MANUAL-" + Long.toHexString(System.currentTimeMillis());
        c.targetUrl = request.url;
        c.method = request.method;
        c.parameterName = p.name;
        c.parameterPath = p.path;
        c.parameterLocation = p.location;
        c.originalValue = p.originalValue;
        c.originalType = p.type.name().toLowerCase(java.util.Locale.ROOT);
        c.candidateType = null;
        c.occurrence = p.occurrence;
        c.originalRequest = request;
        c.jsonValid = true;
        c.baselineStable = true;
        c.filterDecision = com.xzhscan.model.Models.FilterDecision.PASS;
        c.filterReason = "manual param verify (v3.0 right-click)";
        return c;
    }

    /**
     * UI 手动触发对某候选的第二阶段验证（差分候选页右键「发送到二阶段」）。
     * 与自动路径同款语义：线程池异步（不阻塞 EDT）、发送前安全闸二次复核
     * （写语义/黑名单可能已变化）、结论经 onVerification/onFinding 完整回流 UI。
     */
    public void verifyNow(DifferentialCandidate candidate, HostCallback cb) {
        if (candidate == null || cb == null) {
            return;
        }
        try {
            executor.submit(() -> {
                try {
                    // v4.1：手动验证 = 用户显式授权，跳过 Target Scope（其余规则照常）
                    ScanPolicyEngine.Decision d = policy.checkForManual(candidate.originalRequest);
                    if (!d.allowed) {
                        cb.onVerification(manualResult(candidate, com.xzhscan.model.Models.VerifyVerdict.INVALID,
                                "blocked-by-policy (manual verify): " + d.reason));
                        return;
                    }
                    VerificationResult vr = phase2.verify(candidate);
                    vr.note = (vr.note == null || vr.note.isEmpty() ? "" : vr.note + "; ")
                            + "manual verify param=" + candidate.parameterPath;
                    cb.onVerification(vr);
                    if (vr.findings.isEmpty()) {
                        // 无注入发现也以四态落结果页（与自动路径一致）
                        com.xzhscan.model.Models.InjectionFinding summary =
                                new com.xzhscan.model.Models.InjectionFinding();
                        summary.requestId = candidate.requestId;
                        summary.parameterName = candidate.parameterName;
                        summary.parameterPath = candidate.parameterPath;
                        summary.verdict = vr.verdict;
                        summary.injectionType = "None";
                        summary.evidenceText = vr.note == null ? "" : vr.note;
                        summary.evidenceIds.addAll(vr.evidenceIds);
                        cb.onFinding(candidate, vr, summary);
                    } else {
                        for (com.xzhscan.model.Models.InjectionFinding f : vr.findings) {
                            f.requestId = candidate.requestId;
                            cb.onFinding(candidate, vr, f);
                        }
                    }
                } catch (Throwable t) {
                    cb.onVerification(manualResult(candidate, com.xzhscan.model.Models.VerifyVerdict.INVALID,
                            "manual verify error: " + t));
                }
            });
        } catch (RejectedExecutionException saturated) {
            cb.onVerification(manualResult(candidate, com.xzhscan.model.Models.VerifyVerdict.INVALID,
                    "manual verify rejected: scan queue full"));
        }
    }

    private static VerificationResult manualResult(DifferentialCandidate c,
                                                   com.xzhscan.model.Models.VerifyVerdict verdict,
                                                   String note) {
        VerificationResult r = new VerificationResult();
        r.requestId = c.requestId;
        r.url = c.targetUrl;
        r.parameterName = c.parameterName;
        r.parameterPath = c.parameterPath;
        r.state = com.xzhscan.model.Models.VerifyState.DONE;
        r.verdict = verdict;
        r.note = note;
        r.startedAt = System.currentTimeMillis();
        return r;
    }

    public void shutdown() {
        executor.shutdownNow();
    }
}
