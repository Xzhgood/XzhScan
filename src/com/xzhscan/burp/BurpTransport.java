package com.xzhscan.burp;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import com.xzhscan.model.RawHttp.RawRequest;
import com.xzhscan.model.RawHttp.RawResponse;
import com.xzhscan.model.RawHttp.Transport;

import java.nio.charset.StandardCharsets;
import java.util.LinkedHashMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;

/**
 * Montoya 适配层：RawRequest/Response 与 Burp HTTP 对象互转。
 *
 * 请求侧手动重组原始报文（保留原始头顺序），Content-Length 重算；
 * 响应侧带回状态码/头/体/耗时。引擎层对此完全无感知。
 *
 * v2.2：请求超时落地（此前 requestTimeoutMs 为空转配置）——sendRequest 在独立
 * 守护线程池执行，超过 timeoutMs 返回 status=0 形态（引擎按 TIMING_TIMEOUT/
 * 网络失败处理，不作为延迟证据）；底层 Burp 请求无法强制中断，仅不再等待。
 */
public final class BurpTransport implements Transport {

    /** 共享守护线程池（超时等待用；线程数按并发扫描上限弹性扩展）。 */
    private static final ExecutorService SEND_POOL = Executors.newCachedThreadPool(r -> {
        Thread t = new Thread(r, "xzhscan-send");
        t.setDaemon(true);
        return t;
    });

    private final MontoyaApi api;
    private final long timeoutMs;

    public BurpTransport(MontoyaApi api, long timeoutMs) {
        this.api = api;
        this.timeoutMs = Math.max(1000, timeoutMs);
    }

    @Override
    public RawResponse send(RawRequest request) throws Exception {
        return send(request, timeoutMs);
    }

    /** 按调用超时（时间探针预算 > requestTimeoutMs；见 Transport 接口注释）。 */
    @Override
    public RawResponse send(RawRequest request, long perCallTimeoutMs) throws Exception {
        HttpService service = serviceOf(request.url);
        HttpRequest httpRequest = build(service, request);
        long t0 = System.nanoTime(); // 单调时钟：不受系统时间回拨影响
        Future<HttpResponse> fut = SEND_POOL.submit(() -> api.http().sendRequest(httpRequest).response());
        HttpResponse resp;
        try {
            resp = fut.get(Math.max(1000, perCallTimeoutMs), TimeUnit.MILLISECONDS);
        } catch (TimeoutException te) {
            fut.cancel(true);
            long cost = (System.nanoTime() - t0) / 1_000_000L;
            // 客户端超时形态：status=0（引擎按 TIMING_TIMEOUT/不可判定处理）
            return new RawResponse(0, new LinkedHashMap<>(), new byte[0], cost);
        }
        long cost = (System.nanoTime() - t0) / 1_000_000L;
        if (resp == null) {
            return new RawResponse(0, new LinkedHashMap<>(), new byte[0], cost);
        }
        LinkedHashMap<String, String> headers = new LinkedHashMap<>();
        for (HttpHeader h : resp.headers()) {
            headers.putIfAbsent(h.name().toLowerCase(), h.value());
        }
        return new RawResponse(resp.statusCode(), headers, resp.body().getBytes(), cost);
    }

    /** http(s)://host[:port]/... -> HttpService。 */
    public static HttpService serviceOf(String url) {
        String u = url.toLowerCase();
        boolean secure = u.startsWith("https://");
        int scheme = url.indexOf("://");
        String rest = scheme >= 0 ? url.substring(scheme + 3) : url;
        int slash = rest.indexOf('/');
        String hostPort = slash >= 0 ? rest.substring(0, slash) : rest;
        int colon = hostPort.lastIndexOf(':');
        String host;
        int port;
        if (colon > 0 && hostPort.indexOf(']') < colon) {
            host = hostPort.substring(0, colon);
            port = Integer.parseInt(hostPort.substring(colon + 1));
        } else {
            host = hostPort;
            port = secure ? 443 : 80;
        }
        return HttpService.httpService(host, port, secure);
    }

    /** RawRequest -> Montoya HttpRequest（报文构造委托 RawHttpRequests，CL 重算）。 */
    public static HttpRequest build(HttpService service, RawRequest request) {
        byte[] raw = com.xzhscan.model.RawHttpRequests.buildRaw(request, service.host(), service.port(), service.secure());
        return HttpRequest.httpRequest(service, burp.api.montoya.core.ByteArray.byteArray(raw));
    }
}
