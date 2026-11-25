package com.xzhscan.differential;

import com.xzhscan.model.RawHttp.RawRequest;
import com.xzhscan.model.RawHttp.RawResponse;
import com.xzhscan.model.RawHttp.Transport;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/**
 * 基线采集与稳定性评估：
 *  - 对原始请求采样 N 次（默认 3）；
 *  - 归一化后两两比较：全部相似度 >= 0.98 且状态码一致 -> stable；
 *  - 基线间值自变化的 JSON 字段记为 dynamicFields，后续差分比较剔除；
 *  - 同时为第二阶段提供响应时间统计（time-based 探针的阈值基准）。
 */
public final class BaselineCollector {

    /** 基线窗口稳定阈值：低于该相似度视为天然动态页面。 */
    public static final double STABLE_SIMILARITY = 0.98;

    public static final class Baseline {
        public final List<RawResponse> responses = new ArrayList<>();
        public final List<ResponseNormalizer.Normalized> normalized = new ArrayList<>();
        public boolean stable = true;
        public int statusCode;
        public int minLen;
        public int maxLen;
        public int medianLen;
        /** 基线间自变化的 JSON 字段路径。 */
        public final Set<String> dynamicFields = new HashSet<>();
        /** 基线响应耗时（ms）。 */
        public final List<Long> elapsed = new ArrayList<>();
        public double meanElapsed;
        public double stdElapsed;
        public long minElapsedMs;
        public String anomaly;

        public RawResponse last() {
            return responses.isEmpty() ? null : responses.get(responses.size() - 1);
        }
    }

    /**
     * 采集基线。sampleCount < 1 视为 1；采集异常（网络失败）记录 anomaly，
     * 至少拿到 1 个响应才返回非 null。
     */
    public static Baseline collect(RawRequest request, int sampleCount, Transport transport) {
        Baseline b = new Baseline();
        int n = Math.max(1, sampleCount);
        for (int i = 0; i < n; i++) {
            try {
                RawResponse r = transport.send(request);
                if (r == null) {
                    b.anomaly = "null response at sample " + i;
                    break; // v3.10.2：失败立即停止采样（原实现继续打满 N 次超时，慢目标白耗数分钟）
                }
                if (r.statusCode <= 0) {
                    // 传输层超时/不可达形态：后续采样只会重复超时，直接结束
                    b.anomaly = "transport timeout/unreachable at sample " + i;
                    break;
                }
                b.responses.add(r);
                b.normalized.add(ResponseNormalizer.normalize(r));
                b.elapsed.add(r.elapsedMs >= 0 ? r.elapsedMs : 0);
            } catch (Exception e) {
                b.anomaly = "transport error at sample " + i + ": " + e.getMessage();
                break; // v3.10.2：异常同样不再重试剩余采样
            }
        }
        if (b.responses.isEmpty()) {
            return b;
        }
        // 长度统计
        b.minLen = Integer.MAX_VALUE;
        b.maxLen = Integer.MIN_VALUE;
        List<Integer> lens = new ArrayList<>();
        for (RawResponse r : b.responses) {
            lens.add(r.length());
            b.minLen = Math.min(b.minLen, r.length());
            b.maxLen = Math.max(b.maxLen, r.length());
        }
        lens.sort(Integer::compareTo);
        b.medianLen = lens.get(lens.size() / 2);
        b.statusCode = b.responses.get(0).statusCode;

        // 状态码一致性 + 相似度矩阵
        b.stable = true;
        for (RawResponse r : b.responses) {
            if (r.statusCode != b.statusCode) {
                b.stable = false;
            }
        }
        for (int i = 0; i < b.normalized.size() && b.stable; i++) {
            for (int j = i + 1; j < b.normalized.size(); j++) {
                double sim = ResponseNormalizer.similarity(
                        b.normalized.get(i).normalizedText, b.normalized.get(j).normalizedText);
                if (sim < STABLE_SIMILARITY) {
                    b.stable = false;
                    break;
                }
            }
        }
        // 动态 JSON 字段识别：基线间叶子值不同（且非全部不同——全部不同说明整体动态）
        if (b.normalized.size() >= 2 && b.normalized.get(0).json) {
            Set<String> first = new HashSet<>(b.normalized.get(0).leafValues.keySet());
            for (int k = 1; k < b.normalized.size(); k++) {
                first.retainAll(b.normalized.get(k).leafValues.keySet());
            }
            for (String path : first) {
                String v0 = b.normalized.get(0).leafValues.get(path);
                boolean differs = false;
                for (int k = 1; k < b.normalized.size(); k++) {
                    String vk = b.normalized.get(k).leafValues.get(path);
                    if (vk == null || v0 == null || !v0.equals(vk)) {
                        differs = true;
                        break;
                    }
                }
                if (differs) {
                    b.dynamicFields.add(path);
                }
            }
        }
        // 耗时统计
        b.minElapsedMs = b.elapsed.stream().mapToLong(Long::longValue).min().orElse(0);
        double mean = b.elapsed.stream().mapToLong(Long::longValue).average().orElse(0);
        double var = b.elapsed.stream().mapToDouble(x -> (x - mean) * (x - mean)).average().orElse(0);
        b.meanElapsed = mean;
        b.stdElapsed = Math.sqrt(var);
        return b;
    }
}
