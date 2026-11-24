package com.xzhscan.model;

import com.xzhscan.model.RawHttp.RawRequest;
import com.xzhscan.model.RawHttp.RawResponse;

import java.util.ArrayDeque;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Queue;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicLong;

/**
 * 证据存储：所有阶段产出的原始/测试请求响应都以此处 id 引用，
 * UI 与报告通过 id 取回完整 HTTP 报文（任务书：完整证据和排除原因）。
 */
public final class EvidenceStore {

    public static final class Evidence {
        public final String id;
        public final String kind;      // baseline / mutated / verify-request / verify-response
        public final RawRequest request;   // 可为 null（纯响应）
        public final RawResponse response; // 可为 null
        public final long capturedAt = System.currentTimeMillis();

        Evidence(String id, String kind, RawRequest request, RawResponse response) {
            this.id = id;
            this.kind = kind;
            this.request = request;
            this.response = response;
        }

        public String preview() {
            StringBuilder sb = new StringBuilder();
            sb.append("[").append(id).append("/").append(kind).append("]\n");
            if (request != null) {
                sb.append("> ").append(request.method).append(' ').append(request.url).append('\n');
                for (String h : request.headers) {
                    sb.append("> ").append(h).append('\n');
                }
                String body = request.bodyAsString();
                if (!body.isEmpty()) {
                    sb.append("> (").append(body.length()).append(" bytes body) ")
                      .append(body, 0, Math.min(body.length(), 400)).append('\n');
                }
            }
            if (response != null) {
                sb.append("< HTTP ").append(response.statusCode)
                  .append(" (").append(response.length()).append(" bytes, ")
                  .append(response.elapsedMs).append("ms)\n");
                String body = response.bodyAsString();
                sb.append("< ").append(body, 0, Math.min(body.length(), 400)).append('\n');
            }
            return sb.toString();
        }
    }

    /** 容量上限：超限后按插入顺序淘汰最老证据（防长期驻留内存）。 */
    public static final int MAX_ENTRIES = 8000;

    /** v4.1：被容量淘汰的证据 ID（有界，供 UI 区分"没有证据"与"证据已淘汰"）。 */
    private final java.util.Set<String> evicted = java.util.concurrent.ConcurrentHashMap.newKeySet();

    private final Map<String, Evidence> map = new ConcurrentHashMap<>();
    private final Queue<String> order = new ArrayDeque<>();
    private final AtomicLong seq = new AtomicLong();

    /** v4.1：该证据 ID 是否因容量上限被淘汰（UI 据此提示"证据已淘汰"）。 */
    public boolean isEvicted(String id) {
        return id != null && evicted.contains(id);
    }

    public String put(String kind, RawRequest request, RawResponse response) {
        String id = "EV-" + seq.incrementAndGet();
        Evidence e = new Evidence(id, kind, request, response);
        map.put(id, e);
        synchronized (order) {
            order.add(id);
            while (order.size() > MAX_ENTRIES) {
                String oldest = order.poll();
                if (oldest != null) {
                    map.remove(oldest);
                    evicted.add(oldest);
                }
            }
            if (evicted.size() > MAX_ENTRIES * 2) {
                evicted.clear(); // 有界，防止淘汰集合自身成为泄漏源
            }
        }
        return id;
    }

    public Evidence get(String id) {
        return map.get(id);
    }

    public List<Evidence> all() {
        synchronized (order) {
            return order.stream().map(map::get).filter(java.util.Objects::nonNull).toList();
        }
    }

    public int size() {
        return map.size();
    }

    public void clear() {
        map.clear();
        order.clear();
    }
}
