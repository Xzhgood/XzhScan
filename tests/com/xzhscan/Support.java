package com.xzhscan;

import com.xzhscan.model.RawHttp.RawRequest;
import com.xzhscan.model.RawHttp.RawResponse;
import com.xzhscan.model.RawHttp.Transport;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.function.BiFunction;

/** 测试支撑：可控假传输层与常用构造。 */
public final class Support {

    private Support() {
    }

    /** 记录全部发送请求、按序/按匹配返回响应的假传输。 */
    public static final class FakeTransport implements Transport {
        public final List<RawRequest> sent = new ArrayList<>();
        public BiFunction<RawRequest, Integer, RawResponse> responder = (r, i) -> text(200, "ok");

        @Override
        public RawResponse send(RawRequest request) {
            sent.add(request);
            return responder.apply(request, sent.size());
        }

        public List<RawRequest> mutatedOnly(RawRequest original) {
            List<RawRequest> out = new ArrayList<>();
            for (RawRequest r : sent) {
                if (!r.url.equals(original.url) || !java.util.Arrays.equals(r.body, original.body)) {
                    out.add(r);
                }
            }
            return out;
        }
    }

    public static RawResponse text(int status, String body) {
        return new RawResponse(status, new LinkedHashMap<>(), body.getBytes(StandardCharsets.UTF_8), 5);
    }

    public static RawResponse json(int status, String body) {
        LinkedHashMap<String, String> h = new LinkedHashMap<>();
        h.put("content-type", "application/json");
        return new RawResponse(status, h, body.getBytes(StandardCharsets.UTF_8), 5);
    }

    public static RawRequest get(String url) {
        List<String> headers = new ArrayList<>();
        headers.add("Host: " + hostOf(url));
        headers.add("User-Agent: xzhscan-test");
        return new RawRequest("GET", url, headers, new byte[0]);
    }

    public static RawRequest postJson(String url, String body) {
        List<String> headers = new ArrayList<>();
        headers.add("Host: " + hostOf(url));
        headers.add("Content-Type: application/json");
        return new RawRequest("POST", url, headers, body.getBytes(StandardCharsets.UTF_8));
    }

    public static RawRequest postForm(String url, String body) {
        List<String> headers = new ArrayList<>();
        headers.add("Host: " + hostOf(url));
        headers.add("Content-Type: application/x-www-form-urlencoded");
        return new RawRequest("POST", url, headers, body.getBytes(StandardCharsets.UTF_8));
    }

    static String hostOf(String url) {
        int s = url.indexOf("://") + 3;
        int e = url.indexOf('/', s);
        return e < 0 ? url.substring(s) : url.substring(s, e);
    }
}
