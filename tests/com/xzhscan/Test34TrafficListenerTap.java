package com.xzhscan;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.ToolType;
import burp.api.montoya.http.handler.HttpResponseReceived;
import com.xzhscan.burp.TrafficListener;
import com.xzhscan.config.XzhScanConfig;
import com.xzhscan.engine.ScanOrchestrator;
import com.xzhscan.model.EvidenceStore;
import com.xzhscan.model.Models.GateProbeView;
import com.xzhscan.model.Models.TrafficRecord;
import com.xzhscan.policy.ScanPolicyEngine;
import com.xzhscan.Support.FakeTransport;

import java.lang.reflect.Method;
import java.lang.reflect.Proxy;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;

import static com.xzhscan.MiniTest.TestContext;

/**
 * 测试三十四：Intruder 流量端到端准入（v3.9.3 无头实机模拟）。
 * 用动态代理伪造 MontoyaApi / HttpResponseReceived（INTRUDER 来源 + 200 响应），
 * 驱动真实 TrafficListener -> ScanOrchestrator -> Phase1 差分引擎全链路：
 *  - 开关开启 + 200：探针真实发出、观察行/候选回流、日志有「200 响应已提交差分扫描」；
 *  - 开关关闭：零探针、零回流；
 *  - 非 200（302）：零探针。
 * 请求形态与用户实机一致：GET /vul/sqli/sqli_search.php?id=..&ok=..&list=..&uid=..&error=..
 */
public final class Test34TrafficListenerTap {

    static final List<String> OUT = new CopyOnWriteArrayList<>();
    static final List<String> ERR = new CopyOnWriteArrayList<>();

    static final String TARGET_URL =
            "http://127.0.0.1:8899/vul/sqli/sqli_search.php?id=a37hbc&ok=pl8soa&list=m5tfws&uid=tga0at&error=ikilot";

    // Montoya 的 ResponseReceivedAction.continueWith 静态工厂依赖 Burp 运行时注入的
    // ObjectFactoryLocator.FACTORY；无头环境自行注入递归空代理（仅返回默认值）。
    static {
        burp.api.montoya.internal.ObjectFactoryLocator.FACTORY =
                (burp.api.montoya.internal.MontoyaObjectFactory) Proxy.newProxyInstance(
                        MontoyaObjectFactoryHolder.class.getClassLoader(),
                        new Class<?>[]{burp.api.montoya.internal.MontoyaObjectFactory.class},
                        (p, m, a) -> defaultValue(m));
    }

    private static final class MontoyaObjectFactoryHolder {
    }

    public static void run(TestContext t) throws Exception {
        // ---------- 1. 开关开启 + 200：端到端进差分引擎 ----------
        XzhScanConfig config = new XzhScanConfig();
        config.watchIntruder = true;
        config.phase1Enabled = true;
        config.requestIntervalMs = 0;
        config.baselineSamples = 2;
        config.maxConcurrentScans = 2;

        FakeTransport transport = new FakeTransport();
        transport.responder = (r, idx) -> {
            String u = com.xzhscan.parameter.ParameterExtractor.urlDecode(r.url);
            if (u.contains("'")) {
                return Support.text(500,
                        "MySQLSyntaxErrorException: You have an error in your SQL syntax near ''");
            }
            return Support.text(200, "stable body content for baseline");
        };

        EvidenceStore evidence = new EvidenceStore();
        ScanPolicyEngine policy = new ScanPolicyEngine(config);
        ScanOrchestrator orchestrator = new ScanOrchestrator(config, transport, evidence, policy);
        TrafficListener listener = new TrafficListener(apiMock(), config, orchestrator);

        List<GateProbeView> gateViews = new CopyOnWriteArrayList<>();
        List<TrafficRecord> traffic = new CopyOnWriteArrayList<>();
        List<Object> candidates = new CopyOnWriteArrayList<>();
        listener.setHostCallback(new ScanOrchestrator.HostCallback() {
            @Override
            public void onTraffic(TrafficRecord r) {
                traffic.add(r);
            }

            @Override
            public void onGateView(GateProbeView v) {
                gateViews.add(v);
            }

            @Override
            public void onCandidate(com.xzhscan.model.Models.DifferentialCandidate c) {
                candidates.add(c);
            }

            @Override
            public void onRejected(String id, com.xzhscan.model.Models.ParameterIdentity p,
                                   String probe, String reason, double score) {
            }

            @Override
            public void onVerification(com.xzhscan.model.Models.VerificationResult r) {
            }

            @Override
            public void onFinding(com.xzhscan.model.Models.DifferentialCandidate c,
                                  com.xzhscan.model.Models.VerificationResult vr,
                                  com.xzhscan.model.Models.InjectionFinding f) {
            }
        });

        int sentBefore = transport.sent.size();
        listener.handleHttpResponseReceived(responseMock(200));

        // phase1 异步执行：轮询等待观察行回流（最多 8 秒）
        long deadline = System.currentTimeMillis() + 8000;
        while (System.currentTimeMillis() < deadline
                && (transport.sent.size() <= sentBefore || gateViews.isEmpty())) {
            Thread.sleep(50);
        }
        Thread.sleep(200); // 尾部余量（record 最终回调）

        t.check(transport.sent.size() > sentBefore,
                "开关开启+200：探针真实发出（sent " + (transport.sent.size() - sentBefore) + " 条）");
        t.check(!gateViews.isEmpty(), "观察行回流差分页/数据版（gateViews=" + gateViews.size() + "）");
        boolean accepted = OUT.stream().anyMatch(s -> s.contains("200 响应已提交差分扫描"));
        t.check(accepted, "Output 日志有提交确认: "
                + OUT.stream().filter(s -> s.contains("Intruder")).reduce((a, b) -> a).orElse("(none)"));
        boolean done = traffic.stream().anyMatch(r -> "done".equals(r.phase1Status));
        t.check(done, "流量记录最终状态 done（phase1 完整跑完）");
        t.check(ERR.isEmpty(), "无错误日志: " + (ERR.isEmpty() ? "-" : ERR.get(0)));

        // ---------- 2. 开关关闭：零探针 ----------
        XzhScanConfig offCfg = new XzhScanConfig();
        offCfg.watchIntruder = false;
        offCfg.phase1Enabled = true;
        offCfg.requestIntervalMs = 0;
        offCfg.baselineSamples = 2;
        FakeTransport transport2 = new FakeTransport();
        transport2.responder = transport.responder;
        ScanOrchestrator orch2 = new ScanOrchestrator(offCfg, transport2, new EvidenceStore(),
                new ScanPolicyEngine(offCfg));
        TrafficListener listener2 = new TrafficListener(apiMock(), offCfg, orch2);
        listener2.setHostCallback(new ScanOrchestrator.HostCallback() {
            @Override
            public void onTraffic(TrafficRecord r) {
            }

            @Override
            public void onGateView(GateProbeView v) {
            }

            @Override
            public void onCandidate(com.xzhscan.model.Models.DifferentialCandidate c) {
            }

            @Override
            public void onRejected(String id, com.xzhscan.model.Models.ParameterIdentity p,
                                   String probe, String reason, double score) {
            }

            @Override
            public void onVerification(com.xzhscan.model.Models.VerificationResult r) {
            }

            @Override
            public void onFinding(com.xzhscan.model.Models.DifferentialCandidate c,
                                  com.xzhscan.model.Models.VerificationResult vr,
                                  com.xzhscan.model.Models.InjectionFinding f) {
            }
        });
        int sent2Before = transport2.sent.size();
        listener2.handleHttpResponseReceived(responseMock(200));
        Thread.sleep(500);
        t.check(transport2.sent.size() == sent2Before,
                "开关关闭：零探针（sent 不增长）");

        // ---------- 3. 非 200：零探针（开关开启也不进） ----------
        XzhScanConfig onCfg3 = new XzhScanConfig();
        onCfg3.watchIntruder = true;
        onCfg3.phase1Enabled = true;
        onCfg3.requestIntervalMs = 0;
        FakeTransport transport3 = new FakeTransport();
        transport3.responder = transport.responder;
        ScanOrchestrator orch3 = new ScanOrchestrator(onCfg3, transport3, new EvidenceStore(),
                new ScanPolicyEngine(onCfg3));
        TrafficListener listener3 = new TrafficListener(apiMock(), onCfg3, orch3);
        listener3.setHostCallback(new ScanOrchestrator.HostCallback() {
            @Override
            public void onTraffic(TrafficRecord r) {
            }

            @Override
            public void onGateView(GateProbeView v) {
            }

            @Override
            public void onCandidate(com.xzhscan.model.Models.DifferentialCandidate c) {
            }

            @Override
            public void onRejected(String id, com.xzhscan.model.Models.ParameterIdentity p,
                                   String probe, String reason, double score) {
            }

            @Override
            public void onVerification(com.xzhscan.model.Models.VerificationResult r) {
            }

            @Override
            public void onFinding(com.xzhscan.model.Models.DifferentialCandidate c,
                                  com.xzhscan.model.Models.VerificationResult vr,
                                  com.xzhscan.model.Models.InjectionFinding f) {
            }
        });
        int sent3Before = transport3.sent.size();
        listener3.handleHttpResponseReceived(responseMock(302));
        Thread.sleep(500);
        t.check(transport3.sent.size() == sent3Before,
                "非 200（302）：零探针（开关开启也不进）");

        orchestrator.shutdown();
        orch2.shutdown();
        orch3.shutdown();
    }

    // ---------------- Montoya 模拟 ----------------

    /** HttpResponseReceived：INTRUDER 来源 + 指定状态码 + 用户实机同款 initiatingRequest。 */
    static HttpResponseReceived responseMock(int status) {
        return (HttpResponseReceived) Proxy.newProxyInstance(
                HttpResponseReceived.class.getClassLoader(),
                new Class<?>[]{HttpResponseReceived.class},
                (proxy, method, args) -> switch (method.getName()) {
                    case "statusCode" -> (short) status;
                    case "toolSource" -> toolSourceMock();
                    case "initiatingRequest" -> requestMock();
                    case "headers" -> List.of();
                    case "body" -> byteArrayMock("OK");
                    case "bodyToString" -> "OK";
                    case "toString" -> "HTTP/1.1 " + status;
                    default -> defaultValue(method);
                });
    }

    static Object toolSourceMock() {
        return Proxy.newProxyInstance(Test34TrafficListenerTap.class.getClassLoader(),
                new Class<?>[]{burp.api.montoya.core.ToolSource.class},
                (proxy, method, args) -> switch (method.getName()) {
                    case "toolType" -> ToolType.INTRUDER;
                    case "isFromTool" -> false;
                    default -> defaultValue(method);
                });
    }

    static Object requestMock() {
        return Proxy.newProxyInstance(Test34TrafficListenerTap.class.getClassLoader(),
                new Class<?>[]{burp.api.montoya.http.message.requests.HttpRequest.class},
                (proxy, method, args) -> switch (method.getName()) {
                    case "url" -> TARGET_URL;
                    case "method" -> "GET";
                    case "headers" -> List.of();
                    case "body" -> byteArrayMock("");
                    case "bodyToString" -> "";
                    case "toString" -> "GET " + TARGET_URL;
                    default -> defaultValue(method);
                });
    }

    static Object byteArrayMock(String s) {
        return Proxy.newProxyInstance(Test34TrafficListenerTap.class.getClassLoader(),
                new Class<?>[]{burp.api.montoya.core.ByteArray.class},
                (proxy, method, args) -> switch (method.getName()) {
                    case "getBytes" -> s.getBytes(java.nio.charset.StandardCharsets.UTF_8);
                    case "length" -> s.length();
                    case "toString" -> s;
                    default -> defaultValue(method);
                });
    }

    /** MontoyaApi：仅 logging 真实收集，其余默认值（TrafficListener 只用 logging）。 */
    static MontoyaApi apiMock() {
        return (MontoyaApi) Proxy.newProxyInstance(MontoyaApi.class.getClassLoader(),
                new Class<?>[]{MontoyaApi.class},
                (proxy, method, args) -> {
                    if (method.getName().equals("logging")) {
                        return Proxy.newProxyInstance(MontoyaApi.class.getClassLoader(),
                                new Class<?>[]{burp.api.montoya.logging.Logging.class},
                                (p2, m2, a2) -> switch (m2.getName()) {
                                    case "logToOutput" -> {
                                        OUT.add(String.valueOf(a2[0]));
                                        yield null;
                                    }
                                    case "logToError" -> {
                                        ERR.add(String.valueOf(a2[0]));
                                        yield null;
                                    }
                                    default -> defaultValue(m2);
                                });
                    }
                    return defaultValue(method);
                });
    }

    /** 接口返回递归空代理、原始类型返回零值、其余 null。 */
    static Object defaultValue(Method method) {
        Class<?> rt = method.getReturnType();
        if (rt == boolean.class) {
            return false;
        }
        if (rt == int.class || rt == short.class || rt == byte.class) {
            return (byte) 0;
        }
        if (rt == long.class) {
            return 0L;
        }
        if (rt == double.class) {
            return 0d;
        }
        if (rt == float.class) {
            return 0f;
        }
        if (rt == char.class) {
            return (char) 0;
        }
        if (rt == List.class) {
            return List.of();
        }
        if (rt == java.util.Optional.class) {
            return java.util.Optional.empty();
        }
        if (rt.isInterface()) {
            return Proxy.newProxyInstance(rt.getClassLoader(), new Class<?>[]{rt},
                    (p, m, a) -> defaultValue(m));
        }
        return null;
    }

    private Test34TrafficListenerTap() {
    }
}
