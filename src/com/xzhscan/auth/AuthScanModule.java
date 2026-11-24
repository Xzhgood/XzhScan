package com.xzhscan.auth;

import com.xzhscan.model.RawHttp.RawRequest;
import com.xzhscan.model.RawHttp.RawResponse;
import com.xzhscan.model.RawHttp.Transport;
import com.xzhscan.auth.AuthScanRequestFilter.FilterRecord;
import com.xzhscan.auth.AuthScanEngine.IdentityConfig;
import com.xzhscan.auth.AuthScanEngine.PermResult;

import java.util.List;
import java.util.Map;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.RejectedExecutionException;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;

/**
 * AuthScan 模块装配：流量入口（由共享 TrafficListener 分发，不重复注册
 * 全局 HttpHandler）→ AuthScanRequestFilter → 有界队列 → AuthScanEngine 三态判定
 * → 结果回调（UI）。
 *
 * 模块隔离：独立线程池/去重/启停状态；异常吞在本模块内不上抛；
 * shutdown 幂等。配置持久化走 Burp extensionData（由 Extension 侧读写）。
 */
public final class AuthScanModule {

    public interface Callback {
        void onFilterRecord(FilterRecord record);

        void onResult(PermResult result);
    }

    private final AuthScanRequestFilter filter = new AuthScanRequestFilter();
    private final AuthScanEngine engine;
    private final ThreadPoolExecutor executor;
    private final AtomicInteger seq = new AtomicInteger();
    private final AtomicReference<Callback> callback = new AtomicReference<>();
    private volatile boolean enabled = true;
    /** v3.9.3：UI 用户启停回调（扩展注册，用于即时持久化）。 */
    private volatile Runnable onUserToggle;
    private volatile IdentityConfig identity = new IdentityConfig();
    /** 请求去重（method+url+path 参数特征，LRU 语义简化为窗口集合上限）。 */
    private final Map<String, Long> recent = new java.util.concurrent.ConcurrentHashMap<>();

    public AuthScanModule(Transport transport) {
        this.engine = new AuthScanEngine(transport);
        this.executor = new ThreadPoolExecutor(2, 2, 30L, TimeUnit.SECONDS,
                new ArrayBlockingQueue<>(100), r -> {
                    Thread t = new Thread(r, "xzhscan-auth");
                    t.setDaemon(true);
                    return t;
                }, new ThreadPoolExecutor.AbortPolicy());
    }

    public void setCallback(Callback cb) {
        callback.set(cb);
    }

    public void setEnabled(boolean enabled) {
        this.enabled = enabled;
    }

    /** 注册用户启停回调（扩展装配时调用一次）。 */
    public void setOnUserToggle(Runnable r) {
        this.onUserToggle = r;
    }

    /** UI 用户勾选启停专用：改状态 + 触发即时持久化。 */
    public void setEnabledByUser(boolean enabled) {
        this.enabled = enabled;
        Runnable r = onUserToggle;
        if (r != null) {
            r.run();
        }
    }

    public boolean isEnabled() {
        return enabled;
    }

    public AuthScanRequestFilter filter() {
        return filter;
    }

    public void updateIdentity(IdentityConfig cfg) {
        this.identity = cfg == null ? new IdentityConfig() : cfg;
    }

    public IdentityConfig identity() {
        return identity;
    }

    /**
     * 流量入口（共享监听器调用）。过滤与去重在此完成；
     * REJECT/UNKNOWN 也回调（保留过滤记录供人工审查）。
     */
    public void onTraffic(RawRequest request, RawResponse observed, String source) {
        if (!enabled) {
            return;
        }
        String id = "PERM-" + seq.incrementAndGet();

        // 无响应：直接拒绝（状态码检查的前置条件）
        if (observed == null) {
            FilterRecord noResp = new FilterRecord(id, request.method, request.url, "no-response",
                    "", AuthScanRequestFilter.Decision.REJECT,
                    "无响应，不进入越权审计");
            emitFilter(noResp);
            return;
        }

        Map<String, String> headers = observed.headers;
        FilterRecord record = filter.evaluate(id, request.method, request.url,
                observed.statusCode, headers, request.headerValue("Accept"));
        emitFilter(record);
        if (!record.submitToQueue()) {
            return;
        }
        // 身份配置完备性：低/无权限任一为空则不测（gatherBurp 语义：必误报）
        if (identity.lowAuthHeaders.isEmpty() || identity.noAuthHeaderNames.isEmpty()) {
            FilterRecord skip = new FilterRecord(id, request.method, request.url, "identity-missing",
                    record.contentType, AuthScanRequestFilter.Decision.UNKNOWN,
                    "低权限/无权限身份未配置完整，跳过自动复核");
            emitFilter(skip);
            return;
        }
        // 白名单（空 = 全部允许；仅约束被动流量，手动入口由 UI 直接调用 scanNow）
        if (!identity.whitelistDomains.isEmpty()
                && !AuthScanEngine.domainMatches(AuthScanEngine.hostOf(request.url), identity.whitelistDomains)) {
            FilterRecord out = new FilterRecord(id, request.method, request.url, "scope",
                    record.contentType, AuthScanRequestFilter.Decision.REJECT,
                    "host 不在越权检测白名单内");
            emitFilter(out);
            return;
        }
        // 去重（窗口 60 分钟）
        String key = request.method + "|" + request.url;
        Long seen = recent.get(key);
        long now = System.currentTimeMillis();
        if (seen != null && now - seen < 60 * 60_000L) {
            FilterRecord dup = new FilterRecord(id, request.method, request.url, "deduplicated",
                    record.contentType, AuthScanRequestFilter.Decision.REJECT,
                    "窗口期内已检测过（60 分钟）");
            emitFilter(dup);
            return;
        }
        recent.put(key, now);
        if (recent.size() > 2048) {
            recent.keySet().removeIf(k -> {
                Long at = recent.get(k);
                return at == null || now - at >= 60 * 60_000L;
            });
        }
        try {
            executor.submit(() -> {
                try {
                    PermResult result = engine.check(request, identity);
                    result.requestId = id;
                    emitResult(result);
                } catch (Throwable t) {
                    PermResult fail = new PermResult();
                    fail.requestId = id;
                    fail.method = request.method;
                    fail.url = request.url;
                    fail.verdict = AuthScanEngine.Verdict.INVALID;
                    fail.evidenceSummary = "模块内部错误: " + t.getClass().getSimpleName();
                    emitResult(fail);
                }
            });
        } catch (RejectedExecutionException saturated) {
            FilterRecord full = new FilterRecord(id, request.method, request.url, "queue-full",
                    record.contentType, AuthScanRequestFilter.Decision.REJECT,
                    "越权检测队列饱和，已丢弃");
            emitFilter(full);
            recent.remove(key);
        }
    }

    /** UI 手动触发（绕过白名单与去重）。 */
    public PermResult scanNow(RawRequest request) {
        return engine.check(request, identity);
    }

    private final java.util.concurrent.atomic.AtomicLong allowCount = new java.util.concurrent.atomic.AtomicLong();
    private final java.util.concurrent.atomic.AtomicLong rejectCount = new java.util.concurrent.atomic.AtomicLong();
    private final java.util.concurrent.atomic.AtomicLong unknownCount = new java.util.concurrent.atomic.AtomicLong();

    /** 过滤决策计数（UI 设置页展示；完整记录走 [filter] 日志）。 */
    public long[] filterCounters() {
        return new long[]{allowCount.get(), rejectCount.get(), unknownCount.get()};
    }

    private void emitFilter(FilterRecord r) {
        if (r.decision == AuthScanRequestFilter.Decision.ALLOW) {
            allowCount.incrementAndGet();
        } else if (r.decision == AuthScanRequestFilter.Decision.REJECT) {
            rejectCount.incrementAndGet();
        } else {
            unknownCount.incrementAndGet();
        }
        Callback cb = callback.get();
        if (cb != null) {
            cb.onFilterRecord(r);
        }
    }

    private void emitResult(PermResult r) {
        Callback cb = callback.get();
        if (cb != null) {
            cb.onResult(r);
        }
    }

    public void shutdown() {
        executor.shutdownNow();
    }
}
