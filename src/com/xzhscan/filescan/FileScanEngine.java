package com.xzhscan.filescan;

import com.xzhscan.burp.BurpTransport;
import com.xzhscan.model.RawHttp.RawRequest;
import com.xzhscan.model.RawHttp.RawResponse;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * 文件读取扫描引擎（移植自 mingdong-pro FileReadScanner）
 * 支持被动扫描和主动扫描
 * v4.0.4 紧急修复：异步执行扫描，避免阻塞 EDT 线程导致 Burp 卡死
 */
public class FileScanEngine {
    private final com.xzhscan.model.RawHttp.Transport transport;  // 修复：使用 Transport 接口
    private final Set<String> tested = ConcurrentHashMap.newKeySet();  // 去重：url|method|param
    private final AtomicBoolean enabled = new AtomicBoolean(false);
    private Callback callback;

    // v4.0.4 紧急修复：添加线程池，所有扫描任务异步执行
    private final ExecutorService executor = new ThreadPoolExecutor(
        1, 3,  // 核心线程 1，最大线程 3
        60L, TimeUnit.SECONDS,
        new ArrayBlockingQueue<>(50),  // 队列容量 50
        r -> {
            Thread t = new Thread(r, "xzhscan-filescan");
            t.setDaemon(true);
            return t;
        },
        new ThreadPoolExecutor.DiscardOldestPolicy()  // 队列满时丢弃最旧任务
    );

    public interface Callback {
        void onResult(FileScanResult result);
    }

    public FileScanEngine(com.xzhscan.model.RawHttp.Transport transport) {  // 修复：接受 Transport
        this.transport = transport;
    }

    public void setCallback(Callback callback) {
        this.callback = callback;
    }

    public void setEnabled(boolean enabled) {
        this.enabled.set(enabled);
    }

    public boolean isEnabled() {
        return enabled.get();
    }

    /** v4.0.4: 关闭线程池，清理资源 */
    public void shutdown() {
        executor.shutdownNow();
    }

    /** 被动扫描：监听流量自动测试（v4.0.4 紧急修复：异步执行，立即返回，避免阻塞调用线程） */
    public void scanPassive(RawRequest originalRequest) {
        if (!enabled.get()) return;
        if (originalRequest == null || originalRequest.url == null) return;

        // v4.0.4 紧急修复：在后台线程中执行扫描，立即返回，避免阻塞 EDT 或 Burp 主线程
        executor.submit(() -> {
            try {
                // 只测试 GET/POST 参数，排除 Cookie 和 Multipart
                List<Parameter> params = extractParameters(originalRequest);
                if (params.isEmpty()) return;

                // 限制：最多测试 20 个参数
                if (params.size() > 20) {
                    params = params.subList(0, 20);
                }

                // 异步测试每个参数
                for (Parameter param : params) {
                    // v4.0.4: 检查线程中断
                    if (Thread.currentThread().isInterrupted()) {
                        break;
                    }

                    String key = originalRequest.url + "|" + originalRequest.method + "|" + param.name;
                    if (tested.contains(key)) continue;
                    tested.add(key);

                    // 在当前后台线程中测试（已经不在 EDT 中了）
                    testParameter(originalRequest, param);
                }
            } catch (Exception e) {
                // 忽略异常，避免影响其他扫描
            }
        });
    }

    /** 主动扫描：手动触发（右键菜单） */
    public void scanActive(RawRequest originalRequest, String parameterName) {
        if (originalRequest == null) return;

        List<Parameter> params = extractParameters(originalRequest);
        Parameter target = params.stream()
                .filter(p -> p.name.equals(parameterName))
                .findFirst()
                .orElse(null);

        if (target != null) {
            testParameter(originalRequest, target);
        }
    }

    /** 测试单个参数（v4.0.4: 添加中断检查，避免无限运行） */
    private void testParameter(RawRequest originalRequest, Parameter param) {
        try {
            // v4.0.4: 检查线程中断
            if (Thread.currentThread().isInterrupted()) {
                return;
            }

            // 获取原始响应（基线）
            RawResponse baseline = transport.send(originalRequest);
            if (baseline == null) return;

            String baselineBody = baseline.bodyAsString();

            // 生成并测试每个 payload
            List<String> payloads = FileScanPayload.generatePayloads(param.value);

            // v4.0.4: 限制 payload 数量，避免过多请求
            if (payloads.size() > 10) {
                payloads = payloads.subList(0, 10);
            }

            for (String payload : payloads) {
                // v4.0.4: 每个 payload 前检查中断
                if (Thread.currentThread().isInterrupted()) {
                    break;
                }

                // 构造测试请求
                RawRequest testReq = replaceParameter(originalRequest, param, payload);
                if (testReq == null) continue;

                // 发送请求
                RawResponse testResp = transport.send(testReq);
                if (testResp == null) continue;

                String testBody = testResp.bodyAsString();

                // 检测文件读取命中
                if (FileScanPayload.isFileReadHit(testBody) && !FileScanPayload.isFileReadHit(baselineBody)) {
                    // 命中！
                    String hitType = FileScanPayload.getHitType(testBody);
                    FileScanResult result = new FileScanResult(
                            originalRequest.url,  // requestId
                            originalRequest.url,
                            originalRequest.method,
                            param.name,
                            param.location,
                            payload,
                            hitType,
                            testBody
                    );

                    if (callback != null) {
                        callback.onResult(result);
                    }
                    break;  // 找到一个即停止
                }
            }
        } catch (Exception e) {
            // 忽略异常，继续测试其他参数
        }
    }

    /** 提取参数（只提取 GET/POST 参数，排除 Cookie 和 Multipart） */
    private List<Parameter> extractParameters(RawRequest request) {
        List<Parameter> params = new ArrayList<>();

        // GET 参数（从 URL 提取）
        if (request.url != null && request.url.contains("?")) {
            String query = request.url.substring(request.url.indexOf("?") + 1);
            for (String pair : query.split("&")) {
                String[] kv = pair.split("=", 2);
                if (kv.length >= 1) {
                    String name = kv[0];
                    String value = kv.length == 2 ? kv[1] : "";
                    params.add(new Parameter(name, value, "GET"));
                }
            }
        }

        // POST 参数（从 body 提取，仅支持 application/x-www-form-urlencoded）
        if ("POST".equalsIgnoreCase(request.method) && request.body != null) {
            String contentType = getHeader(request, "Content-Type");
            if (contentType != null && contentType.contains("application/x-www-form-urlencoded")) {
                String body = request.bodyAsString();
                if (body != null && !body.isEmpty()) {
                    for (String pair : body.split("&")) {
                        String[] kv = pair.split("=", 2);
                        if (kv.length >= 1) {
                            String name = kv[0];
                            String value = kv.length == 2 ? kv[1] : "";
                            params.add(new Parameter(name, value, "POST"));
                        }
                    }
                }
            }
        }

        return params;
    }

    /** 替换参数值 */
    private RawRequest replaceParameter(RawRequest original, Parameter param, String newValue) {
        if ("GET".equals(param.location)) {
            // 替换 URL 中的参数
            String url = original.url;
            String query = url.contains("?") ? url.substring(url.indexOf("?") + 1) : "";
            String newQuery = replaceQueryParam(query, param.name, newValue);
            String newUrl = url.substring(0, url.indexOf("?") + 1) + newQuery;
            return new RawRequest(original.method, newUrl, original.headers, original.body);
        } else if ("POST".equals(param.location)) {
            // 替换 body 中的参数
            String body = original.bodyAsString();
            String newBody = replaceQueryParam(body, param.name, newValue);
            byte[] newBodyBytes = newBody.getBytes(java.nio.charset.StandardCharsets.UTF_8);
            return new RawRequest(original.method, original.url, original.headers, newBodyBytes);
        }
        return null;
    }

    private String replaceQueryParam(String query, String name, String newValue) {
        if (query == null || query.isEmpty()) return "";
        StringBuilder sb = new StringBuilder();
        boolean first = true;
        for (String pair : query.split("&")) {
            String[] kv = pair.split("=", 2);
            if (!first) sb.append("&");
            first = false;
            if (kv.length >= 1 && kv[0].equals(name)) {
                sb.append(name).append("=").append(newValue);
            } else {
                sb.append(pair);
            }
        }
        return sb.toString();
    }

    private String getHeader(RawRequest request, String name) {
        if (request.headers == null) return null;
        for (String header : request.headers) {
            if (header.toLowerCase().startsWith(name.toLowerCase() + ":")) {
                return header.substring(name.length() + 1).trim();
            }
        }
        return null;
    }

    static class Parameter {
        String name;
        String value;
        String location;  // GET / POST

        Parameter(String name, String value, String location) {
            this.name = name;
            this.value = value;
            this.location = location;
        }
    }
}
