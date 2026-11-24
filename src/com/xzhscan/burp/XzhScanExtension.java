package com.xzhscan.burp;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import com.xzhscan.config.XzhScanConfig;
import com.xzhscan.engine.ScanOrchestrator;
import com.xzhscan.model.EvidenceStore;
import com.xzhscan.policy.ScanPolicyEngine;
import com.xzhscan.ui.SqlScanUi;

/**
 * XzhScan 独立 Burp 插件入口（Montoya API）。
 *
 * 加载方式：Burp -> Extensions -> Add -> Java -> 选择 XzhScan.jar，
 * 无任何对第三方 Burp 插件的运行时依赖。
 *
 * 初始化顺序（v2.2 修复生产竞态）：Burp 在非 EDT 线程调用 initialize()，
 * 此前 UI 构建任务与 authModule 赋值并发——模块页签可能以 null 模块构建。
 * 现在 UI 主体先挂载，模块页签在模块实例化完成后的独立 EDT 任务中追加。
 */
public final class XzhScanExtension implements BurpExtension {

    public static final String VERSION = "4.2.0";

    private static final String NL = String.valueOf((char) 10);

    private MontoyaApi api;
    private XzhScanConfig config;
    private EvidenceStore evidence;
    private ScanPolicyEngine policy;
    private ScanOrchestrator orchestrator;
    private TrafficListener listener;
    private SqlScanUi ui;
    private com.xzhscan.ui.XzhScanMainPanel mainPanel;
    private com.xzhscan.auth.AuthScanModule authModule;

    @Override
    public void initialize(MontoyaApi api) {
        this.api = api;
        api.extension().setName("XzhScan");
        config = loadConfig(api);
        evidence = new EvidenceStore();
        policy = new ScanPolicyEngine(config);
        // v4.1：自动发包默认受 Burp Target Scope 约束（用户评审 P0）
        policy.setScopeChecker(url -> {
            try {
                return api.scope().isInScope(url);
            } catch (Throwable t) {
                return false; // scope 不可用时保守拒绝
            }
        });
        orchestrator = new ScanOrchestrator(config, new BurpTransport(api, config.requestTimeoutMs), evidence, policy);
        listener = new TrafficListener(api, config, orchestrator);

        // ---- AuthScan 模块（同步段创建：EDT 任务捕获局部 final 引用，无竞态） ----
        com.xzhscan.model.RawHttp.Transport sharedTransport =
                new BurpTransport(api, config.requestTimeoutMs);
        final com.xzhscan.auth.AuthScanModule module = new com.xzhscan.auth.AuthScanModule(sharedTransport);
        this.authModule = module;
        listener.setAuthModule(module);
        // v3.9.3：UI 启停 AuthScan 即时持久化（未启用=完全不干活、零日志输出）
        module.setOnUserToggle(() -> {
            snapshotModulesToConfig();
            saveConfig(api, config);
        });
        applyModulesFromConfig();
        api.logging().logToOutput("[XzhScan] AuthScan identity: lowAuthHeaders="
                + module.identity().lowAuthHeaders.size() + " line(s), noAuthHeaders="
                + module.identity().noAuthHeaderNames.size() + " name(s), whitelist="
                + module.identity().whitelistDomains.size() + " line(s), filterEnabled="
                + config.authFilterEnabled + ", enabled=" + config.authEnabled);

        // ---- Chinese 中文查看（全局消息编辑器附签，请求/响应各一） ----
        api.userInterface().registerHttpRequestEditorProvider(new com.xzhscan.codec.U2cEditorTab.RequestProvider());
        api.userInterface().registerHttpResponseEditorProvider(new com.xzhscan.codec.U2cEditorTab.ResponseProvider());

        // ---- UI + 全部接线（单个 EDT 任务；流量监听最后注册，保证回调先于流量就绪） ----
        // v2.2.1 修复：此前重写 initialize 时丢失 setHostCallback（orchestrator 事件全被
        // 未绑定的 CallbackDispatcher 吞掉 → 差分候选/漏洞结果/审计日志全盲），
        // 且流量注册先于 AuthScan UI 回调绑定（启动窗口的越权事件被丢）。
        final MontoyaApi apiRef = api;
        SwingEdt.run(() -> {
            try {
                mainPanel = new com.xzhscan.ui.XzhScanMainPanel(apiRef, config, evidence, policy);
                apiRef.userInterface().registerSuiteTab("XzhScan", mainPanel.build());
                ui = mainPanel.sqlScanUi();
                ui.log("INFO", "XzhScan v" + VERSION + " 已加载（Phase1=受控差分初筛，Phase2=证据分型复核）");

                // orchestrator 事件 -> UI（v2.1 接线原样恢复）
                final ScanOrchestrator.HostCallback hostCb = new ScanOrchestrator.HostCallback() {
                    @Override
                    public void onTraffic(com.xzhscan.model.Models.TrafficRecord r) {
                        ui.onTraffic(r, r.phase1Status);
                    }

                    @Override
                    public void onGateView(com.xzhscan.model.Models.GateProbeView v) {
                        ui.onGateView(v);
                    }

                    @Override
                    public void onCandidate(com.xzhscan.model.Models.DifferentialCandidate c) {
                        ui.onCandidate(c);
                    }

                    @Override
                    public void onRejected(String requestId, com.xzhscan.model.Models.ParameterIdentity param,
                                           String probe, String reason, double score) {
                        // 排除项已在 GateProbeView 中呈现（engine 内部触发）
                    }

                    @Override
                    public void onVerification(com.xzhscan.model.Models.VerificationResult r) {
                        ui.onVerification(r);
                    }

                    @Override
                    public void onFinding(com.xzhscan.model.Models.DifferentialCandidate c,
                                          com.xzhscan.model.Models.VerificationResult vr,
                                          com.xzhscan.model.Models.InjectionFinding f) {
                        ui.onFinding(c, vr, f);
                        if (f.verdict == com.xzhscan.model.Models.VerifyVerdict.CONFIRMED) {
                            apiRef.logging().raiseInfoEvent("[XzhScan] CONFIRMED " + f.injectionType
                                    + " " + c.targetUrl + " param=" + f.parameterPath);
                        }
                    }
                };
                listener.setHostCallback(hostCb);
                // v3.9.2 数据版：注入引擎引用（一键送二阶段 = verifyNow 同款链路）
                ui.setScanEngine(orchestrator, hostCb);
                // v3.9.3 修复：应用设置立即持久化（此前只改内存，扩展重载后回滚——
                // watchIntruder 等开关"勾了又丢"的根因）
                ui.onApplyConfig(() -> saveConfig(apiRef, config));
                // v4.0：任何配置字段变更立即落盘（单一真相源——不再依赖"卸载时才存"）
                config.addListener(() -> saveConfig(apiRef, config));

                // AuthScan 页签（module 为同步段 final 引用，必然非 null）
                mainPanel.attachModuleTab("AuthScan",
                        new com.xzhscan.ui.AuthScanUi(apiRef, module).build());

                // ---- 全部接线就绪后再注册流量监听（最后一步） ----
                apiRef.http().registerHttpHandler(listener);
                apiRef.userInterface().registerContextMenuItemsProvider(listener);
                apiRef.logging().logToOutput("[XzhScan] traffic listener registered (callbacks bound)");
            } catch (Throwable t) {
                apiRef.logging().logToError("XzhScan UI init failed: " + t);
            }
        });

        api.extension().registerUnloadingHandler(() -> {
            orchestrator.shutdown();
            snapshotModulesToConfig();
            saveConfig(api, config);
            SwingEdt.run(() -> {
                if (ui != null) {
                    ui.dispose();
                }
                if (authModule != null) {
                    authModule.shutdown();
                }
            });
        });

        api.logging().logToOutput("XzhScan v" + VERSION + " loaded (phase1=gated differential scan, "
                + "phase2=evidence-typed SQL verification, registry-based payloads)");
    }

    private static XzhScanConfig loadConfig(MontoyaApi api) {
        XzhScanConfig c = new XzhScanConfig();
        String saved = api.persistence().extensionData().getString("xzhscan.config");
        if (saved != null && !saved.isEmpty()) {
            boolean migrated = com.xzhscan.config.ConfigCodec.fromProperties(saved, c);
            if (migrated) {
                // 迁移结果立即持久化（写入 configVersion），用户此后显式关闭不再被覆盖
                api.persistence().extensionData().setString("xzhscan.config",
                        com.xzhscan.config.ConfigCodec.toProperties(c));
                api.logging().logToOutput("[XzhScan] config migrated (pre-"
                        + com.xzhscan.config.ConfigCodec.CONFIG_VERSION + "): "
                        + com.xzhscan.config.ConfigCodec.MIGRATION_NOTES);
            }
        }
        return c;
    }

    /** 模块运行态 -> 配置对象（卸载时随 saveConfig 持久化）。 */
    private void snapshotModulesToConfig() {
        if (authModule != null) {
            config.authEnabled = authModule.isEnabled();
            config.authFilterEnabled = authModule.filter().config().enabled;
            config.authExtraExtensions = authModule.filter().config().extraExtensions == null ? ""
                    : authModule.filter().config().extraExtensions;
            com.xzhscan.auth.AuthScanEngine.IdentityConfig id = authModule.identity();
            config.authLowAuthHeaders = String.join(NL, id.lowAuthHeaders);
            config.authNoAuthHeaders = String.join(NL, id.noAuthHeaderNames);
            config.authWhitelistDomains = String.join(NL, id.whitelistDomains);
        }
    }

    /** 配置对象 -> 模块运行态（启动回放；兼容旧版无键场景，缺省保持默认）。 */
    private void applyModulesFromConfig() {
        if (authModule != null) {
            authModule.setEnabled(config.authEnabled);
            authModule.filter().config().enabled = config.authFilterEnabled;
            authModule.filter().config().extraExtensions = config.authExtraExtensions == null ? ""
                    : config.authExtraExtensions;
            com.xzhscan.auth.AuthScanEngine.IdentityConfig id = new com.xzhscan.auth.AuthScanEngine.IdentityConfig();
            for (String l : config.authLowAuthHeaders.split(NL)) {
                if (!l.isBlank()) {
                    id.lowAuthHeaders.add(l.trim());
                }
            }
            for (String l : config.authNoAuthHeaders.split(NL)) {
                if (!l.isBlank()) {
                    id.noAuthHeaderNames.add(l.trim());
                }
            }
            for (String l : config.authWhitelistDomains.split(NL)) {
                if (!l.isBlank()) {
                    id.whitelistDomains.add(l.trim());
                }
            }
            authModule.updateIdentity(id);
        }
    }

    private static void saveConfig(MontoyaApi api, XzhScanConfig c) {
        try {
            api.persistence().extensionData().setString("xzhscan.config", com.xzhscan.config.ConfigCodec.toProperties(c));
        } catch (Throwable ignored) {
        }
    }

    private static final class SwingEdt {
        static void run(Runnable r) {
            javax.swing.SwingUtilities.invokeLater(r);
        }
    }
}
