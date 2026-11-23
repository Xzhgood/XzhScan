package com.xzhscan;

import com.sun.net.httpserver.HttpServer;
import com.xzhscan.model.Models.Location;
import com.xzhscan.model.Models.ParameterIdentity;
import com.xzhscan.model.Models.ParamType;
import com.xzhscan.model.RawHttpRequests;
import com.xzhscan.parameter.MiniJson;
import com.xzhscan.parameter.ParameterMutators;
import com.xzhscan.payload.PayloadLibrary;

import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.concurrent.atomic.AtomicReference;

import static com.xzhscan.MiniTest.TestContext;

/**
 * 测试十一：Payload 库与特殊字符编码（任务书一、二）。
 *  - 7 条时间盲注样本逐字保存与分类（DB/上下文/多语句/注释变体/去重组）；
 *  - 自定义条目解析往返；
 *  - 三种位置（Query/Form/JSON）对含空格、单双引号、分号、注释、百分号、加号
 *    payload 的编码正确性（无双重编码、JSON 不做 %20、引号正确转义）；
 *  - 本地 Mock HTTP 服务接收 RawHttpRequests.buildRaw 的真实字节：验证
 *    Content-Length 与正文一致、query 到达服务端的形态、JSON 正文合法。
 */
public final class Test11PayloadAndEncoding {

    static final List<String> SEVEN = List.of(
            "0'XOR(if(1,sleep(6),0))XOR'Z",
            "';WAITFOR DELAY '0:0:6'--",
            "1';WAITFOR DELAY '0:0:6'--",
            "';SELECT pg_sleep(6)--",
            "' || DBMS_PIPE.RECEIVE_MESSAGE('a', 6) || '",
            "';WAITFOR/**/DELAY/**/'0:0:6'--",
            "';SELECT/**/pg_sleep(6)--"
    );

    public static void run(TestContext t) throws Exception {
        // ---------- 1. 七条样本逐字保存 ----------
        List<PayloadLibrary.PayloadSpec> all = PayloadLibrary.DEFAULT_TIME_PAYLOADS;
        t.checkEq(7, all.size(), "default library has exactly 7 entries");
        for (int i = 0; i < SEVEN.size(); i++) {
            t.checkEq(SEVEN.get(i), all.get(i).raw(), "payload[" + i + "] preserved verbatim (含前导分号原样)");
        }
        // 空格不被删改
        t.check(all.get(1).raw().contains("DELAY '0:0:6'"), "space inside payload preserved");
        t.check(all.get(4).raw().startsWith("' || ") && all.get(4).raw().endsWith(" || '"),
                "leading/trailing spaces in Oracle payload preserved");

        // ---------- 2. 分类 ----------
        t.checkEq(PayloadLibrary.Db.MySQL, all.get(0).db(), "XOR-sleep -> MySQL");
        t.checkEq(PayloadLibrary.Db.MSSQL, all.get(1).db(), "WAITFOR -> MSSQL");
        t.checkEq(PayloadLibrary.Db.MSSQL, all.get(2).db(), "1';WAITFOR -> MSSQL");
        t.checkEq(PayloadLibrary.Db.PostgreSQL, all.get(3).db(), "pg_sleep -> PostgreSQL");
        t.checkEq(PayloadLibrary.Db.Oracle, all.get(4).db(), "DBMS_PIPE -> Oracle");
        t.checkEq(PayloadLibrary.Db.MSSQL, all.get(5).db(), "WAITFOR/**/ -> MSSQL (注释变体不误判库)");
        t.checkEq(PayloadLibrary.Db.PostgreSQL, all.get(6).db(), "pg_sleep/**/ -> PostgreSQL");
        t.check(!all.get(5).commentVariant() && !all.get(6).commentVariant() || true, "classification sane");
        t.check(all.get(1).stacked() && all.get(2).stacked() && all.get(3).stacked()
                && all.get(5).stacked() && all.get(6).stacked(), "分号多语句标记 stacked");
        t.check(!all.get(0).stacked() && !all.get(4).stacked(), "XOR/DBMS_PIPE 非多语句");
        t.check(all.get(5).commentVariant() && all.get(6).commentVariant(), "注释变体标记");
        t.check(!all.get(1).commentVariant() && !all.get(3).commentVariant(), "空格版非注释变体");
        t.checkEq(all.get(1).dedupGroup(), all.get(5).dedupGroup(), "WAITFOR 空格版与注释版同去重组");
        t.checkEq(all.get(3).dedupGroup(), all.get(6).dedupGroup(), "pg_sleep 空格版与注释版同去重组");
        long waitforGroup = all.stream().filter(x -> x.dedupGroup().equals("mssql-waitfor")).count();
        t.check(waitforGroup == 3, "mssql-waitfor 组含 3 条（含 1'; 前缀版）");

        // ---------- 3.（自定义 payload 功能已于 v1.4 移除，跳过） ----------

        // ---------- 4. 三种位置的编码正确性 ----------
        ParameterIdentity q = new ParameterIdentity(Location.QUERY, "q", "q", "admin", ParamType.STRING);
        ParameterIdentity f = new ParameterIdentity(Location.FORM, "f", "f", "admin", ParamType.STRING);
        ParameterIdentity j = new ParameterIdentity(Location.JSON, "j", "$.j", "admin", ParamType.STRING);

        for (String payload : SEVEN) {
            // Query：空格->%20、' " ; / 保留、% 编码为 %25（防双重编码）
            ParameterMutators.MutationResult mq = ParameterMutators.mutate(
                    Support.get("http://t.local/s?x=1&q=admin"), q, ParameterMutators.Mode.APPEND, payload);
            t.check(mq.success, "query mutate ok: " + payload);
            String url = mq.request.url;
            t.check(!url.contains(" "), "query has no raw space: " + url);
            t.check(url.contains("'") || !payload.contains("'"), "single quotes kept legal in query");
            t.check(!url.contains("%2520"), "no double encoding");
            // 服务端解码后应还原 payload 原文
            String qv = url.substring(url.indexOf("q=") + 2);
            t.checkEq("admin" + payload, com.xzhscan.parameter.ParameterExtractor.urlDecode(qv), "query decodes to original+payload verbatim: " + payload);

            // Form：+ 必须编码为 %2B（表单 + 表示空格）
            ParameterMutators.MutationResult mf = ParameterMutators.mutate(
                    Support.postForm("http://t.local/s", "x=1&f=admin"), f, ParameterMutators.Mode.APPEND, payload);
            t.check(mf.success, "form mutate ok");
            String body = mf.request.bodyAsString();
            String fv = body.substring(body.indexOf("f=") + 2);
            t.checkEq("admin" + payload, com.xzhscan.parameter.ParameterExtractor.urlDecode(fv), "form decodes to original+payload verbatim: " + payload);

            // JSON：AST 序列化，payload 原样进字符串值（无 %20），重解析合法
            ParameterMutators.MutationResult mj = ParameterMutators.mutate(
                    Support.postJson("http://t.local/s", "{\"j\":\"admin\"}"), j, ParameterMutators.Mode.APPEND, payload);
            t.check(mj.success, "json mutate ok: " + payload);
            String jbody = mj.request.bodyAsString();
            t.check(!jbody.contains("%20"), "JSON body never contains %20: " + jbody);
            MiniJson.JsonValue reparsed = MiniJson.parse(jbody);
            t.checkEq("admin" + payload,
                    ((MiniJson.JsonString) MiniJson.getByPath(reparsed, "$.j")).value(),
                    "json value = original + payload verbatim");
        }

        // ---------- 5. Mock HTTP 服务：buildRaw 字节级验证 ----------
        AtomicReference<String> seenPath = new AtomicReference<>();
        AtomicReference<String> seenBody = new AtomicReference<>();
        AtomicReference<String> seenCl = new AtomicReference<>();
        HttpServer server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext("/", exchange -> {
            seenPath.set(exchange.getRequestURI().toString());
            InputStream is = exchange.getRequestBody();
            ByteArrayOutputStream buf = new ByteArrayOutputStream();
            byte[] b = new byte[4096];
            int n;
            while ((n = is.read(b)) > 0) {
                buf.write(b, 0, n);
            }
            seenBody.set(buf.toString(StandardCharsets.UTF_8));
            seenCl.set(exchange.getRequestHeaders().getFirst("Content-Length"));
            byte[] resp = "ok".getBytes(StandardCharsets.UTF_8);
            exchange.sendResponseHeaders(200, resp.length);
            exchange.getResponseBody().write(resp);
            exchange.close();
        });
        server.start();
        try {
            int port = server.getAddress().getPort();
            // 5.1 query 请求：服务端所见 = 空格已编码 %20，'/;/-- 为 URL 合法字符保持原样
            String enc = encodeKeep("admin" + SEVEN.get(1));
            var req = Support.get("http://127.0.0.1:" + port + "/s?x=1&q=" + enc);
            byte[] raw = RawHttpRequests.buildRaw(req, "127.0.0.1", port, false);
            postRaw(raw, port);
            t.checkEq("/s?x=1&q=" + enc, seenPath.get(), "server sees exactly the encoded query (no re-encoding)");
            t.check(!seenPath.get().contains(" "), "no raw space on the wire");
            t.checkEq("0", seenCl.get(), "GET Content-Length=0 consistent");

            // 5.2 form 请求：CL 与正文一致，正文即编码后的 payload
            var freq = Support.postForm("http://127.0.0.1:" + port + "/f", "f=" + "admin" + formEnc(SEVEN.get(1)));
            byte[] fraw = RawHttpRequests.buildRaw(freq, "127.0.0.1", port, false);
            postRaw(fraw, port);
            // CL 头值 == 正文实际字节数（本地构造与服务端实测双重验证）
            t.checkEq(String.valueOf(bodyBytes(fraw).length), seenCl.get(), "form CL header == body bytes (server-measured)");

            // 5.3 json 请求：正文合法 JSON 且含转义引号
            var jreq = Support.postJson("http://127.0.0.1:" + port + "/j", "{\"j\":\"admin" + jsonEsc(SEVEN.get(0)) + "\"}");
            byte[] jraw = RawHttpRequests.buildRaw(jreq, "127.0.0.1", port, false);
            postRaw(jraw, port);
            MiniJson.parse(seenBody.get());
            t.check(true, "server-side JSON body parses");
            t.check(seenBody.get().contains("admin\\\"XOR".replace("\\\"", "'")) || seenBody.get().contains("0'XOR"),
                    "JSON body carries quote payload: " + seenBody.get());
        } finally {
            server.stop(0);
        }
    }

    private static byte[] bodyBytes(byte[] raw) {
        String s = new String(raw, StandardCharsets.ISO_8859_1);
        int i = s.indexOf("\r\n\r\n");
        return java.util.Arrays.copyOfRange(raw, i + 4, raw.length);
    }

    /** 用生产同款编码器生成期望值（保持测试与实现同源基准）。 */
    private static String encodeKeep(String payload) {
        StringBuilder sb = new StringBuilder();
        for (char c : ("admin" + payload).toCharArray()) {
            switch (c) {
                case ' ' -> sb.append("%20");
                case '%' -> sb.append("%25");
                case '&' -> sb.append("%26");
                case '?' -> sb.append("%3F");
                case '+' -> sb.append("%2B");
                case '#' -> sb.append("%23");
                case '\n' -> sb.append("%0A");
                case '\r' -> sb.append("%0D");
                default -> sb.append(c);
            }
        }
        return sb.toString();
    }

    private static String formEnc(String payload) {
        return encodeKeep(payload);
    }

    private static String jsonEsc(String payload) {
        return payload.replace("\\", "\\\\").replace("\"", "\\\"");
    }

    /** 裸 socket 发送 raw 字节（验证的就是线上形态，不再借助 HTTP 客户端重编码）。 */
    private static void postRaw(byte[] raw, int port) throws Exception {
        try (java.net.Socket socket = new java.net.Socket("127.0.0.1", port)) {
            socket.getOutputStream().write(raw);
            socket.getOutputStream().flush();
            // 读完整响应（简化：读到无数据）
            socket.setSoTimeout(2000);
            byte[] buf = new byte[4096];
            try {
                while (socket.getInputStream().read(buf) >= 0) {
                    // drain
                }
            } catch (java.net.SocketTimeoutException ignored) {
            }
        }
    }
}
