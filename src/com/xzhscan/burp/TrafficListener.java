package com.xzhscan.burp;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.ToolSource;
import burp.api.montoya.core.ToolType;
import burp.api.montoya.http.handler.HttpHandler;
import burp.api.montoya.http.handler.HttpRequestToBeSent;
import burp.api.montoya.http.handler.HttpResponseReceived;
import burp.api.montoya.http.handler.RequestToBeSentAction;
import burp.api.montoya.http.handler.ResponseReceivedAction;
import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.ui.contextmenu.ContextMenuEvent;
import burp.api.montoya.ui.contextmenu.ContextMenuItemsProvider;
import com.xzhscan.config.XzhScanConfig;
import com.xzhscan.engine.ScanOrchestrator;
import com.xzhscan.model.RawHttp.RawRequest;
import com.xzhscan.model.RawHttp.RawResponse;

import javax.swing.JMenuItem;
import java.awt.Component;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;

/**
 * 流量入口（Montoya 版，替代 XiaSQL 的 IHttpListener + 右键菜单）：
 *  - Proxy / Repeater / Scanner / Intruder 响应后触发（各自独立开关）；
 *  - 右键 "Send to XzhScan sqltest" 手动提交；
 *  - 来源识别使用 Montoya toolSource().toolType() 官方枚举，不依赖 URL/User-Agent 等特征。
 */
public final class TrafficListener implements HttpHandler, ContextMenuItemsProvider {

    private final MontoyaApi api;
    private final XzhScanConfig config;
    private final ScanOrchestrator orchestrator;
    /** AuthScan 模块（可为 null=未装配；共享本监听器，不重复注册 HttpHandler）。 */
    private volatile com.xzhscan.auth.AuthScanModule authModule;
    /** v3.9.3 分诊：首条 Intruder 流量只打一次开关状态自报。 */
    private final java.util.concurrent.atomic.AtomicInteger intruderDiagLogged =
            new java.util.concurrent.atomic.AtomicInteger();
    /** v3.9.3：watchIntruder=false 时的节流提醒（5 秒最多一条，避免刷屏）。 */
    private final java.util.concurrent.atomic.AtomicLong intruderOffLogAt =
            new java.util.concurrent.atomic.AtomicLong();

    public TrafficListener(MontoyaApi api, XzhScanConfig config, ScanOrchestrator orchestrator) {
        this(api, config, orchestrator, null);
    }

    public TrafficListener(MontoyaApi api, XzhScanConfig config, ScanOrchestrator orchestrator,
                           com.xzhscan.auth.AuthScanModule authModule) {
        this.api = api;
        this.config = config;
        this.orchestrator = orchestrator;
        this.authModule = authModule;
    }

    public void setAuthModule(com.xzhscan.auth.AuthScanModule m) {
        this.authModule = m;
    }

    // ---------------- HttpHandler ----------------

    @Override
    public RequestToBeSentAction handleHttpRequestToBeSent(HttpRequestToBeSent requestToBeSent) {
        return RequestToBeSentAction.continueWith(requestToBeSent);
    }

    @Override
    public ResponseReceivedAction handleHttpResponseReceived(HttpResponseReceived responseReceived) {
        try {
            ToolType tool = responseReceived.toolSource().toolType();
            // v3.9.3 分诊：首条 Intruder 流量自报开关状态——watchIntruder=false 一眼定位
            if (tool == ToolType.INTRUDER && intruderDiagLogged.compareAndSet(0, 1)) {
                api.logging().logToOutput("[XzhScan][Intruder] 检测到 Intruder 流量（watchIntruder="
                        + config.watchIntruder + ", phase1Enabled=" + config.phase1Enabled
                        + ", statusCode=" + responseReceived.statusCode()
                        + "）——watchIntruder=false 时请到 SQLScan 设置勾选「监听 Intruder 流量（仅 200 响应）」并点应用设置");
            }
            // v3.9.3：开关关闭期间 5 秒一条持续提醒（勾选+应用后此日志自动消失，
            // 取而代之的是「200 响应已提交差分扫描」）——不再一次性静默误导排障
            if (tool == ToolType.INTRUDER && !config.watchIntruder) {
                long prev = intruderOffLogAt.get();
                long now = System.currentTimeMillis();
                if (now - prev >= 5000
                        && intruderOffLogAt.compareAndSet(prev, now)) {
                    api.logging().logToOutput("[XzhScan][Intruder] 监听开关未启用（watchIntruder=false），"
                            + "流量被跳过——SQLScan 设置勾选后点「应用设置」即时生效");
                }
            }
            boolean watched = sqlScanWants(config, tool, responseReceived.statusCode());
            // v3.9：Intruder 开关开启但响应非 200 —— 显式跳过日志（任务要求可区分非 200 跳过）。
            // Intruder 源于爆破场景可能高频，日志只进 Burp Output，不刷 UI。
            if (!watched && tool == ToolType.INTRUDER && config.watchIntruder) {
                api.logging().logToOutput("[XzhScan][Intruder] 跳过非200响应（" + responseReceived.statusCode() + "）");
            }
            RawRequest raw = null;
            if (watched && config.phase1Enabled) {
                HttpRequest init = responseReceived.initiatingRequest();
                if (init == null) {
                    // v3.9 防御：无关联请求时诚实跳过，绝不构造虚假请求包
                    api.logging().logToOutput("[XzhScan] 响应缺少关联请求，差分扫描跳过");
                } else {
                    if (tool == ToolType.INTRUDER) {
                        api.logging().logToOutput("[XzhScan][Intruder] 200 响应已提交差分扫描: " + init.url());
                    }
                    raw = toRawRequest(init);
                    orchestrator.submit(raw, toRawResponse(responseReceived), tool.name(), dispatcher);
                }
            }
            // 共享分发：AuthScan 消费同一事件（模块内自行过滤/启停/去重）
            com.xzhscan.auth.AuthScanModule auth = authModule;
            if (auth != null && auth.isEnabled() && tool != ToolType.EXTENSIONS) {
                if (raw == null) {
                    HttpRequest init2 = responseReceived.initiatingRequest();
                    if (init2 == null) {
                        return ResponseReceivedAction.continueWith(responseReceived);
                    }
                    raw = toRawRequest(init2);
                }
                auth.onTraffic(raw, toRawResponse(responseReceived), tool.name());
            }
        } catch (Throwable t) {
            api.logging().logToError("[XzhScan] traffic listener error: " + t);
        }
        return ResponseReceivedAction.continueWith(responseReceived);
    }

    /**
     * v3.9：SQLScan 差分扫描准入纯函数（可测）。
     * Proxy/Repeater/Scanner 行为与旧版完全一致（无状态码门槛）；
     * Intruder 受独立开关 watchIntruder 控制（默认关），且仅当收到完整响应、
     * 状态码严格等于 200 时准入（handleHttpResponseReceived 收到的即完整响应，
     * 无需额外完整性判断）。200 只是准入条件，不是注入判定。
     */
    public static boolean sqlScanWants(XzhScanConfig config, ToolType tool, int statusCode) {
        return (config.watchProxy && tool == ToolType.PROXY)
                || (config.watchRepeater && tool == ToolType.REPEATER)
                || (config.watchScanner && (tool == ToolType.SCANNER))
                || (config.watchIntruder && tool == ToolType.INTRUDER && statusCode == 200);
    }

    // ---------------- 右键菜单 ----------------

    @Override
    public List<Component> provideMenuItems(ContextMenuEvent event) {
        List<Component> items = new ArrayList<>();
        if (!config.watchManualMenu) {
            return items;
        }
        boolean relevant = event.messageEditorRequestResponse().isPresent()
                || !event.selectedRequestResponses().isEmpty();
        if (!relevant) {
            return items;
        }
        // v3.0：整包被动初筛（原 Send to XzhScan，按用户命名改为 sqltest）
        JMenuItem send = new JMenuItem("Send to XzhScan sqltest");
        send.addActionListener(e -> {
            try {
                burp.api.montoya.http.message.HttpRequestResponse rr = pick(event);
                if (rr == null) {
                    return;
                }
                RawRequest raw = toRawRequest(rr.request());
                RawResponse observed = rr.response() == null ? null : toRawResponse(rr);
                orchestrator.submit(raw, observed, "Manual", dispatcher);
            } catch (Throwable t) {
                api.logging().logToError("[XzhScan] manual send error: " + t);
            }
        });
        items.add(send);

        // v3.0 核心入口：右键找到包 -> 全部参数全模块验证 或 指定参数验证（全模块序列）
        try {
            burp.api.montoya.http.message.HttpRequestResponse rr = pick(event);
            if (rr != null) {
                RawRequest raw = toRawRequest(rr.request());
                com.xzhscan.parameter.ParameterExtractor.ExtractResult ex =
                        com.xzhscan.parameter.ParameterExtractor.extract(raw);
                java.util.List<com.xzhscan.model.Models.ParameterIdentity> mutable = new ArrayList<>();
                for (com.xzhscan.model.Models.ParameterIdentity p : ex.parameters) {
                    if (p.mutable()) {
                        mutable.add(p);
                    }
                }
                javax.swing.JMenu menu = new javax.swing.JMenu("XzhScan SQL 验证");
                if (mutable.isEmpty()) {
                    javax.swing.JMenuItem none = new javax.swing.JMenuItem("（无可测参数）");
                    none.setEnabled(false);
                    menu.add(none);
                } else {
                    // 全量：所有可测参数逐个全模块验证（预算各自独立，截断到 30 与被动一致）
                    int allCount = Math.min(mutable.size(), 30);
                    javax.swing.JMenuItem all = new javax.swing.JMenuItem(
                            "全部参数（" + allCount + " 个）全模块验证");
                    all.setToolTipText("每个参数依次跑：报错噪声→md5回显→布尔→ORDER BY→时间全家族");
                    all.addActionListener(e -> {
                        for (int i = 0; i < allCount; i++) {
                            com.xzhscan.model.Models.DifferentialCandidate c =
                                    ScanOrchestrator.manualCandidate(raw, mutable.get(i));
                            api.logging().logToOutput("[XzhScan] 右键全量验证[" + (i + 1) + "/" + allCount + "]: "
                                    + c.parameterPath + " @" + c.targetUrl);
                            orchestrator.verifyNow(c, dispatcher);
                        }
                    });
                    menu.add(all);
                    menu.addSeparator();
                    // 指定参数：单参数全模块验证
                    int added = 0;
                    for (com.xzhscan.model.Models.ParameterIdentity p : mutable) {
                        if (added >= 15) {
                            break;
                        }
                        String val = p.originalValue == null ? "" : p.originalValue;
                        if (val.length() > 18) {
                            val = val.substring(0, 18) + "…";
                        }
                        javax.swing.JMenuItem mi = new javax.swing.JMenuItem(
                                p.location + "｜" + p.path + (p.occurrence > 0 ? "[" + p.occurrence + "]" : "")
                                        + " = " + val);
                        mi.setToolTipText("仅验证该参数：报错噪声→md5回显→布尔→ORDER BY→时间全家族（预算内）");
                        mi.addActionListener(e -> {
                            com.xzhscan.model.Models.DifferentialCandidate c =
                                    ScanOrchestrator.manualCandidate(raw, p);
                            api.logging().logToOutput("[XzhScan] 右键参数验证: " + c.parameterPath
                                    + " @" + c.targetUrl + "（全模块序列）");
                            orchestrator.verifyNow(c, dispatcher);
                        });
                        menu.add(mi);
                        added++;
                    }
                    if (mutable.size() > 15) {
                        javax.swing.JMenuItem more = new javax.swing.JMenuItem(
                                "…仅列前 15 个参数；更多请用「全部参数」或 Send to XzhScan sqltest");
                        more.setEnabled(false);
                        menu.add(more);
                    }
                    menu.addSeparator();
                    // 手填参数名：支持名字（id）或 JSON 路径（$.user.id）；EDT 上弹输入框
                    javax.swing.JMenuItem custom = new javax.swing.JMenuItem("指定参数（手填）…");
                    custom.setToolTipText("填参数名或 JSON 路径（如 $.user.id），按名匹配请求中的可测参数");
                    custom.addActionListener(e -> {
                        String input = javax.swing.JOptionPane.showInputDialog(
                                null, "参数名或 JSON 路径（如 id / name / $.user.id）：",
                                "XzhScan 指定参数验证", javax.swing.JOptionPane.PLAIN_MESSAGE);
                        if (input == null) {
                            return;
                        }
                        String want = input.trim();
                        if (want.isEmpty()) {
                            return;
                        }
                        com.xzhscan.model.Models.ParameterIdentity found = matchParam(mutable, want);
                        if (found == null) {
                            api.logging().logToError("[XzhScan] 参数 \"" + want + "\" 不在请求可测参数中（query/form/json），"
                                    + "可测：" + mutable.stream().map(p -> p.path).limit(20).toList());
                            javax.swing.JOptionPane.showMessageDialog(null,
                                    "参数 \"" + want + "\" 不在请求中。\n可测参数见 Burp Output 日志。",
                                    "XzhScan", javax.swing.JOptionPane.WARNING_MESSAGE);
                            return;
                        }
                        com.xzhscan.model.Models.DifferentialCandidate c =
                                ScanOrchestrator.manualCandidate(raw, found);
                        api.logging().logToOutput("[XzhScan] 右键手填参数验证: " + c.parameterPath
                                + " @" + c.targetUrl + "（全模块序列）");
                        orchestrator.verifyNow(c, dispatcher);
                    });
                    menu.add(custom);
                }
                items.add(menu);
            }
        } catch (Throwable t) {
            api.logging().logToError("XzhScan param menu error: " + t);
        }
        return items;
    }

    /** 手填参数名/路径 -> 匹配可测参数（路径全等 或 名字忽略大小写）。 */
    public static com.xzhscan.model.Models.ParameterIdentity matchParam(
            java.util.List<com.xzhscan.model.Models.ParameterIdentity> mutable, String want) {
        if (want == null || want.isEmpty()) {
            return null;
        }
        String w = want.trim();
        for (com.xzhscan.model.Models.ParameterIdentity p : mutable) {
            if (p.path.equals(w) || p.name.equalsIgnoreCase(w)) {
                return p;
            }
        }
        return null;
    }

    private burp.api.montoya.http.message.HttpRequestResponse pick(ContextMenuEvent event) {
        var editor = event.messageEditorRequestResponse();
        if (editor.isPresent()) {
            return editor.get().requestResponse();
        }
        var sel = event.selectedRequestResponses();
        if (!sel.isEmpty()) {
            return sel.get(0);
        }
        return null;
    }

    /**
     * 线程安全回调分发器。
     *
     * 修复初始化竞态：扩展注册 HttpHandler 是同步的，而 UI 回调在 EDT 上异步装配；
     * 装配完成前到达的流量事件先进有界暂存（防丢），setHostCallback 时回放。
     */
    static final class CallbackDispatcher implements ScanOrchestrator.HostCallback {
        private static final int PENDING_LIMIT = 512;
        private volatile ScanOrchestrator.HostCallback delegate;
        private final java.util.ArrayDeque<Runnable> pending = new java.util.ArrayDeque<>();

        synchronized void bind(ScanOrchestrator.HostCallback cb) {
            this.delegate = cb;
            Runnable r;
            while ((r = pending.poll()) != null) {
                r.run(); // 回放暂存事件
            }
        }

        private void dispatch(Runnable event) {
            ScanOrchestrator.HostCallback d = delegate;
            if (d != null) {
                event.run();
                return;
            }
            synchronized (this) {
                if (delegate != null) {
                    event.run();
                    return;
                }
                if (pending.size() < PENDING_LIMIT) {
                    pending.add(event);
                }
                // 超限丢弃：宁丢事件不积压内存
            }
        }

        @Override
        public void onTraffic(com.xzhscan.model.Models.TrafficRecord r) {
            dispatch(() -> delegate.onTraffic(r));
        }

        @Override
        public void onGateView(com.xzhscan.model.Models.GateProbeView v) {
            dispatch(() -> delegate.onGateView(v));
        }

        @Override
        public void onCandidate(com.xzhscan.model.Models.DifferentialCandidate c) {
            dispatch(() -> delegate.onCandidate(c));
        }

        @Override
        public void onRejected(String id, com.xzhscan.model.Models.ParameterIdentity p, String probe, String reason, double score) {
            dispatch(() -> delegate.onRejected(id, p, probe, reason, score));
        }

        @Override
        public void onVerification(com.xzhscan.model.Models.VerificationResult r) {
            dispatch(() -> delegate.onVerification(r));
        }

        @Override
        public void onFinding(com.xzhscan.model.Models.DifferentialCandidate c,
                              com.xzhscan.model.Models.VerificationResult vr,
                              com.xzhscan.model.Models.InjectionFinding f) {
            dispatch(() -> delegate.onFinding(c, vr, f));
        }
    }

    final CallbackDispatcher dispatcher = new CallbackDispatcher();

    public void setHostCallback(ScanOrchestrator.HostCallback cb) {
        dispatcher.bind(cb);
    }

    // ---------------- 转换 ----------------

    public static RawRequest toRawRequest(HttpRequest request) {
        List<String> headers = new ArrayList<>();
        for (HttpHeader h : request.headers()) {
            headers.add(h.name() + ": " + h.value());
        }
        // url() 已含 query
        return new RawRequest(request.method(), request.url(), headers, request.body().getBytes());
    }

    public static RawResponse toRawResponse(HttpResponseReceived responseReceived) {
        LinkedHashMap<String, String> headers = new LinkedHashMap<>();
        for (HttpHeader h : responseReceived.headers()) {
            headers.putIfAbsent(h.name().toLowerCase(), h.value());
        }
        return new RawResponse(responseReceived.statusCode(), headers,
                responseReceived.body().getBytes(), -1);
    }

    private static RawResponse toRawResponse(burp.api.montoya.http.message.HttpRequestResponse rr) {
        LinkedHashMap<String, String> headers = new LinkedHashMap<>();
        for (HttpHeader h : rr.response().headers()) {
            headers.putIfAbsent(h.name().toLowerCase(), h.value());
        }
        return new RawResponse(rr.response().statusCode(), headers, rr.response().body().getBytes(), -1);
    }
}
