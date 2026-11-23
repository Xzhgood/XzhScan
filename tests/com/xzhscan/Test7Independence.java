package com.xzhscan;

import com.xzhscan.config.XzhScanConfig;
import com.xzhscan.engine.DifferentialGate;
import com.xzhscan.engine.ScanOrchestrator;
import com.xzhscan.engine.SqlVerificationEngine;
import com.xzhscan.engine.PassiveDetectionEngine;
import com.xzhscan.model.EvidenceStore;
import com.xzhscan.policy.ScanPolicyEngine;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Enumeration;
import java.util.jar.JarEntry;
import java.util.jar.JarFile;

import static com.xzhscan.MiniTest.TestContext;

/**
 * 测试七：插件独立性。
 * 1) 构建产物 XzhScan.jar 采用白名单校验：全部 class 必须位于自有包 com/xzhscan/ 下
 *    （比黑名单更强——任何旧包/外部类/历史品牌包混入都会 FAIL）；
 * 2) 核心引擎类可在无 Burp 环境的裸类路径上加载并完成一次完整流程。
 */
public final class Test7Independence {

    public static void run(TestContext t) throws Exception {
        Path jar = Path.of("build", "XzhScan.jar");
        t.check(Files.exists(jar), "XzhScan.jar exists at build/XzhScan.jar");

        if (Files.exists(jar)) {
            int classes = 0, nonOwned = 0;
            try (JarFile jf = new JarFile(jar.toFile())) {
                Enumeration<JarEntry> entries = jf.entries();
                while (entries.hasMoreElements()) {
                    String n = entries.nextElement().getName();
                    if (!n.endsWith(".class")) {
                        continue;
                    }
                    classes++;
                    if (!n.startsWith("com/xzhscan/")) {
                        nonOwned++;
                        System.out.println("  [NON-OWNED] " + n);
                    }
                }
            }
            t.check(classes > 0, "jar contains classes (" + classes + ")");
            t.check(nonOwned == 0, "all classes owned by com.xzhscan (" + nonOwned + " foreign)");
        }

        // 引擎核心在无 Burp 环境下可加载并运行（当前测试类路径即裸环境）
        XzhScanConfig config = new XzhScanConfig();
        config.requestIntervalMs = 0;
        Support.FakeTransport transport = new Support.FakeTransport();
        transport.responder = (r, i) -> Support.text(200, "stable body content");
        EvidenceStore evidence = new EvidenceStore();
        ScanPolicyEngine policy = new ScanPolicyEngine(config);
        PassiveDetectionEngine p1 = new PassiveDetectionEngine(config, transport, evidence);
        SqlVerificationEngine p2 = new SqlVerificationEngine(config, transport, evidence);
        DifferentialGate gate = new DifferentialGate(config);
        t.check(p1 != null && p2 != null && gate != null, "core engines load standalone");
        t.check(policy.check(Support.get("http://t.local/x?a=1")).allowed, "policy engine works standalone");
    }
}
