package com.xzhscan.policy;

import com.xzhscan.model.RawHttp.RawRequest;
import com.xzhscan.model.RawHttp.RawResponse;
import com.xzhscan.model.RawHttp.Transport;

/**
 * 传输包装：所有主动请求经 ScanPolicyEngine 限速后发出，
 * 超时由底层传输（Burp/测试实现）负责。
 */
public final class ThrottledTransport implements Transport {

    private final Transport delegate;
    private final ScanPolicyEngine policy;

    public ThrottledTransport(Transport delegate, ScanPolicyEngine policy) {
        this.delegate = delegate;
        this.policy = policy;
    }

    @Override
    public RawResponse send(RawRequest request) throws Exception {
        policy.throttle(request.url);
        return delegate.send(request);
    }

    /**
     * v2.2.3 修复：必须转发按调用超时——否则接口默认实现会回落到单参 send，
     * 时间探针的放大预算（延迟×12+15s）在包装层丢失，被 requestTimeoutMs 掐死。
     */
    @Override
    public RawResponse send(RawRequest request, long timeoutMs) throws Exception {
        policy.throttle(request.url);
        return delegate.send(request, timeoutMs);
    }
}
