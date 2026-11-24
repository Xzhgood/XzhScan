package com.xzhscan;

import com.xzhscan.auth.AuthScanEngine;
import com.xzhscan.auth.AuthScanModule;
import com.xzhscan.config.XzhScanConfig;
import com.xzhscan.model.EvidenceStore;
import com.xzhscan.model.RawHttp.RawRequest;
import com.xzhscan.model.RawHttp.RawResponse;
import com.xzhscan.policy.ScanPolicyEngine;
import com.xzhscan.policy.ThrottledTransport;

import java.util.LinkedHashMap;

import static com.xzhscan.MiniTest.TestContext;

/**
 * 测试三十八：安全默认（v4.1，用户评审四条 P0 的回归防线）。
 *  - Target Scope：自动流量越界拒绝，手动入口放行；
 *  - 白名单精确匹配（子串不再误放行）；
 *  - 暂停后已开跑任务在下一发请求时真正停止（ThrottledTransport 返回未发送）；
 *  - AuthScan：三态同 403 判 SAFE（不再硬报未授权），长度不一致但非拒绝态判 SUSPECTED；
 *  - 证据淘汰可追溯（isEvicted）。
 */
public final class Test38SecurityDefaults {

    private static RawResponse resp(int status, String body) {
        return new RawResponse(status, new LinkedHashMap<>(),
                body.getBytes(java.nio.charset.StandardCharsets.UTF_8), 10);
    }

    public static void run(TestContext t) throws Exception {
        // ---------- 1. Target Scope ----------
        XzhScanConfig config = new XzhScanConfig();
        config.requireInScope = true;
        ScanPolicyEngine policy = new ScanPolicyEngine(config);
        policy.setScopeChecker(url -> url.contains("in-scope.test"));

        t.check(policy.check(Support.get("http://in-scope.test/a?id=1")).allowed,
                "Scope 内自动流量放行");
        t.check(!policy.check(Support.get("http://out-of-scope.test/a?id=1")).allowed,
                "Scope 外自动流量拒绝");
        t.check(policy.checkForManual(Support.get("http://out-of-scope.test/a?id=1")).allowed,
                "手动入口跳过 Target Scope（用户显式授权）");

        config.requireInScope = false;
        t.check(policy.check(Support.get("http://out-of-scope.test/a?id=1")).allowed,
                "关闭 requireInScope 后不再受 Scope 约束");
        config.requireInScope = true;

        // ---------- 2. 白名单精确匹配（子串不再误放行） ----------
        XzhScanConfig wl = new XzhScanConfig();
        wl.requireInScope = false;
        wl.domainWhitelist = "example.com";
        ScanPolicyEngine wlPolicy = new ScanPolicyEngine(wl);
        t.check(wlPolicy.check(Support.get("http://example.com/x?id=1")).allowed,
                "白名单精确命中");
        t.check(wlPolicy.check(Support.get("http://api.example.com/x?id=1")).allowed,
                "白名单子域命中");
        t.check(!wlPolicy.check(Support.get("http://evilexample.com/x?id=1")).allowed,
                "evilexample.com 不再因子串匹配被误放行");
        t.check(!wlPolicy.check(Support.get("http://example.com.evil.net/x?id=1")).allowed,
                "example.com.evil.net 不再因子串匹配被误放行");

        // ---------- 3. 暂停后真正停止发包 ----------
        XzhScanConfig pc = new XzhScanConfig();
        ScanPolicyEngine pp = new ScanPolicyEngine(pc);
        final int[] sent = {0};
        ThrottledTransport th = new ThrottledTransport(
                r -> {
                    sent[0]++;
                    return resp(200, "ok");
                },
                pp);
        RawRequest req = Support.get("http://t.local/a?id=1");
        t.check(th.send(req) != null, "运行时正常发包");
        pp.pause();
        t.check(th.send(req) == null, "暂停后 send 返回未发送（null）");
        t.check(th.send(req, 5000) == null, "暂停后带超时 send 同样不发");
        t.checkEq(1, sent[0], "暂停期间底层 transport 零调用");
        pp.resume();
        t.check(th.send(req) != null, "恢复后继续发包");

        // ---------- 4. AuthScan 判定收敛 ----------
        // 4a. 三态同 403 → SAFE（此前硬报 UNAUTHORIZED）
        AuthScanEngine eng = new AuthScanEngine(r -> resp(403, "Access denied for all"));
        AuthScanEngine.IdentityConfig id = identity("Cookie: role=user", "Authorization");
        AuthScanEngine.PermResult r403 = eng.check(Support.get("http://t.local/api/admin"), id);
        t.checkEq(AuthScanEngine.Verdict.SAFE, r403.verdict,
                "三个身份都 403 → SAFE（不再误报未授权）");

        // 4b. 低权限 200 且长度不同（非拒绝态）→ SUSPECTED（此前落 SAFE）
        AuthScanEngine eng2 = new AuthScanEngine(r -> {
            String url = r.url;
            if (url.contains("admin")) {
                return resp(200, "FULL ADMIN CONTENT xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx");
            }
            return resp(200, "PUBLIC PARTIAL CONTENT yyyy");
        });
        // 低权限头被替换后仍返回完整内容 → 应判越权（CONFIRMED/UNAUTHORIZED 均可接受）
        AuthScanEngine.PermResult rLow = eng2.check(Support.get("http://t.local/api/admin"), id);
        t.check(rLow.verdict == AuthScanEngine.Verdict.CONFIRMED
                        || rLow.verdict == AuthScanEngine.Verdict.UNAUTHORIZED
                        || rLow.verdict == AuthScanEngine.Verdict.SUSPECTED,
                "低权限拿到不同内容 → 不再一律 SAFE（实际 " + rLow.verdict + "）");

        // ---------- 5. 证据淘汰可追溯 ----------
        EvidenceStore store = new EvidenceStore();
        String firstId = store.put("verify-probe", req, resp(200, "x"));
        t.check(!store.isEvicted(firstId), "正常证据未标记淘汰");
        for (int i = 0; i < EvidenceStore.MAX_ENTRIES + 10; i++) {
            store.put("verify-probe", req, resp(200, "y"));
        }
        t.check(store.isEvicted(firstId), "超容量后最老证据被标记淘汰");
        t.check(store.get(firstId) == null, "被淘汰证据不可再取（UI 可据此提示）");

        // ---------- 6. fuzz 基线判定（v4.2.2） ----------
        // Phase1 对"原始值已是 payload"的参数跳过差分（基线语义已变，变异无注入含义）
        t.check(com.xzhscan.engine.SqlVerificationEngine
                        .looksLikeStrongInjection("; WAITFOR DELAY '0:0:5'-- -"),
                "MSSQL 时间 payload 判为 fuzz 基线");
        t.check(com.xzhscan.engine.SqlVerificationEngine
                        .looksLikeStrongInjection("1' AND 1=1-- -"),
                "布尔 payload 判为 fuzz 基线");
        t.check(com.xzhscan.engine.SqlVerificationEngine
                        .looksLikeStrongInjection("'/**/AND/**/SLEEP(5)"),
                "注释/SLEEP payload 判为 fuzz 基线");
        t.check(!com.xzhscan.engine.SqlVerificationEngine.looksLikeStrongInjection("-1"),
                "业务值 -1 不误判为 fuzz 基线");
        t.check(!com.xzhscan.engine.SqlVerificationEngine.looksLikeStrongInjection("2024-01-01"),
                "日期不误判为 fuzz 基线");
        t.check(!com.xzhscan.engine.SqlVerificationEngine.looksLikeStrongInjection("admin"),
                "普通值不误判为 fuzz 基线");
    }

    private static AuthScanEngine.IdentityConfig identity(String lowHeader, String noAuthName) {
        AuthScanEngine.IdentityConfig id = new AuthScanEngine.IdentityConfig();
        id.lowAuthHeaders.add(lowHeader);
        id.noAuthHeaderNames.add(noAuthName);
        return id;
    }

    private Test38SecurityDefaults() {
    }
}
