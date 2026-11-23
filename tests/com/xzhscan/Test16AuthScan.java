package com.xzhscan;

import com.xzhscan.model.RawHttp.RawRequest;
import com.xzhscan.auth.AuthScanModule;
import com.xzhscan.auth.AuthScanRequestFilter;
import com.xzhscan.auth.AuthScanRequestFilter.Decision;
import com.xzhscan.auth.AuthScanRequestFilter.FilterRecord;
import com.xzhscan.auth.AuthScanEngine;
import com.xzhscan.auth.AuthScanEngine.IdentityConfig;
import com.xzhscan.auth.AuthScanEngine.PermResult;
import com.xzhscan.auth.AuthScanEngine.Verdict;

import javax.swing.JComponent;
import javax.swing.JTabbedPane;
import javax.swing.SwingUtilities;
import java.awt.Component;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;

import static com.xzhscan.MiniTest.TestContext;

/**
 * 测试十六：AuthScan（过滤器 + 三态越权判定 + 模块全链）。
 * 全部使用本地 FakeTransport / Mock 数据，不访问任何真实目标。
 */
public final class Test16AuthScan {

    public static void run(TestContext t) throws Exception {
        AuthScanRequestFilter f = new AuthScanRequestFilter();
        Map<String, String> none = Map.of();

        // ---- 1. 九类静态资源过滤（含 query 带点参数不误伤） ----
        reject(t, f, "GET http://t.local/static/app.js", none, "js");
        reject(t, f, "GET http://t.local/favicon.ico", none, "ico");
        reject(t, f, "GET http://t.local/assets/logo.png", none, "png");
        reject(t, f, "GET http://t.local/index.html", none, "html");
        reject(t, f, "GET http://t.local/download/client.zip", none, "zip");
        reject(t, f, "GET http://t.local/disk.apk", none, "apk");
        reject(t, f, "GET http://t.local/files/report.pdf", none, "pdf");
        reject(t, f, "GET http://t.local/app.css?v=1.2.3", none, "css");
        reject(t, f, "GET http://t.local/f.woff2", none, "woff2");
        reject(t, f, "GET http://t.local/a.JS", none, "大小写扩展名");
        reject(t, f, "GET http://t.local/app.js?v=1.0'and/**/1=1", none, "query 混入 payload 仍按 path 过滤");
        // 编码伪装：%2E%6A%73 = .js
        reject(t, f, "GET http://t.local/app%2E%6A%73", none, "URL 编码伪装扩展名");

        // MIME 信号（无扩展名 + 响应头）
        Map<String, String> imgMime = Map.of("content-type", "image/png");
        reject(t, f, "GET http://t.local/getavatar", imgMime, "无扩展名按 Content-Type=image/png");
        // 下载型：Content-Disposition
        Map<String, String> disp = Map.of("content-disposition", "attachment; filename=x.xlsx");
        FilterRecord dl = f.evaluate("r", "GET", "http://t.local/api/export", disp, null);
        t.check(dl.decision == Decision.REJECT && dl.filterReason.contains("下载型"),
                "下载型接口默认不自动复核但留记录");
        // text/html 不当静态（API 错误页常见）
        Map<String, String> htmlMime = Map.of("content-type", "text/html");
        FilterRecord apiHtml = f.evaluate("r", "GET", "http://t.local/api/user/info", htmlMime, null);
        t.check(apiHtml.decision == Decision.ALLOW, "text/html 的 API 不被当静态过滤");

        // ---- 2. 不误伤：普通 API（含路径含 js 字样/参数含图片名） ----
        allow(t, f, "GET http://t.local/api/user/info", none);
        allow(t, f, "GET http://t.local/api/json/config", none); // 路径含 js 字样
        allow(t, f, "GET http://t.local/api/order/list?img=logo.png", none); // 参数含 .png
        allow(t, f, "GET http://t.local/api/project/detail?id=1.5", none);   // 参数小数

        // ---- 3. 三态决策：POST=UNKNOWN、PUT=REJECT、无证据=UNKNOWN ----
        FilterRecord post = f.evaluate("r", "POST", "http://t.local/api/order/create", none, null);
        t.check(post.decision == Decision.UNKNOWN && post.filterReason.contains("POST"),
                "POST 标记 UNKNOWN 供人工");
        FilterRecord put = f.evaluate("r", "PUT", "http://t.local/api/x", none, null);
        t.check(put.decision == Decision.REJECT, "PUT 拒绝");
        FilterRecord unknown = f.evaluate("r", "GET", "http://t.local/whatever", null, null);
        t.check(unknown.decision == Decision.UNKNOWN && unknown.resourceType.equals("unknown"),
                "无扩展名无响应头 -> UNKNOWN（不编造类型）");

        // ---- 4. 自定义规则：追加/豁免 ----
        AuthScanRequestFilter.FilterConfig cfg = new AuthScanRequestFilter.FilterConfig();
        cfg.extraExtensions = "tpl,tmpl";
        f.configure(cfg);
        reject(t, f, "GET http://t.local/tpl/index.tpl", none, "追加扩展名 tpl");
        allow(t, f, "GET http://t.local/api/tpl", none);
        cfg.exemptExtensions = "txt";
        f.configure(cfg);
        allow(t, f, "GET http://t.local/robots.txt", none); // 豁免 txt
        f.configure(new AuthScanRequestFilter.FilterConfig());

        // ---- 5. AuthScanEngine 三态判定 ----
        Support.FakeTransport transport = new Support.FakeTransport();
        AuthScanEngine engine = new AuthScanEngine(transport);
        IdentityConfig id = new IdentityConfig();
        id.lowAuthHeaders = List.of("Cookie: session=lowuser");
        id.noAuthHeaderNames = List.of("Cookie");
        RawRequest req = Support.get("http://t.local/api/user/info?id=7");
        req.headers.add("Cookie: session=admin");

        // 5.1 CONFIRMED：低权限拿到与原始一致的数据
        transport.responder = (r, i) -> {
            String cookie = r.headerValue("Cookie");
            if (cookie == null) {
                return Support.text(200, "user profile data for admin with much detail content here padding"); // 无权限态
            }
            return Support.text(200, "user profile data for admin with much detail content here padding"); // 原始/低权限同
        };
        PermResult confirmed = engine.check(req, id);
        t.checkEq(Verdict.UNAUTHORIZED, confirmed.verdict, "三态全同 -> UNAUTHORIZED");
        t.check(confirmed.lowRequest != null && confirmed.noAuthRequest != null, "三组请求证据保留");

        // 5.2 SAFE：低权限被拒（403 短响应）
        transport.responder = (r, i) -> {
            String cookie = r.headerValue("Cookie");
            if (cookie != null && cookie.contains("lowuser")) {
                return Support.text(403, "forbidden for low privilege user account access denied page");
            }
            return Support.text(200, "user profile data for admin with much detail content here padding");
        };
        PermResult safe = engine.check(req, id);
        t.checkEq(Verdict.SAFE, safe.verdict, "低权限 403 -> SAFE");

        // 5.3 码长相等但内容不同（相似度不足）-> SUSPECTED（不轻易定罪）
        transport.responder = (r, i) -> {
            String cookie = r.headerValue("Cookie");
            if (cookie != null && cookie.contains("lowuser")) {
                return Support.text(200, "totally different page for another user completely unrelated text");
            }
            return Support.text(200, "user profile data for admin with much detail content here padding");
        };
        // 构造等长：两组文本等长
        String a = "aaaa-bbbb-cccc-dddd-eeee-ffff-gggg";
        String b = "zzzz-yyyy-xxxx-wwww-vvvv-uuuu-tttt";
        transport.responder = (r, i) -> {
            String cookie = r.headerValue("Cookie");
            if (cookie != null && cookie.contains("lowuser")) {
                return Support.text(200, b);
            }
            return Support.text(200, a);
        };
        PermResult suspect = engine.check(req, id);
        t.checkEq(Verdict.SUSPECTED, suspect.verdict, "等长不同内容 -> SUSPECTED（长度相同不定罪）");

        // 5.4 空响应不判越权
        transport.responder = (r, i) -> Support.text(200, "");
        PermResult empty = engine.check(req, id);
        t.check(empty.verdict == Verdict.SUSPECTED || empty.verdict == Verdict.SAFE,
                "空响应不判 CONFIRMED/UNAUTHORIZED: " + empty.verdict);

        // 5.5 无响应 -> INVALID
        transport.responder = (r, i) -> new com.xzhscan.model.RawHttp.RawResponse(0, new LinkedHashMap<>(), new byte[0], 1);
        PermResult invalid = engine.check(req, id);
        t.checkEq(Verdict.INVALID, invalid.verdict, "原始重放失败 -> INVALID");

        // ---- 6. 域名通配 ----
        t.check(AuthScanEngine.domainMatches("a.example.com", List.of("*.example.com")), "*.example.com 匹配子域");
        t.check(AuthScanEngine.domainMatches("example.com", List.of("example.com")), "精确匹配");
        t.check(!AuthScanEngine.domainMatches("evil.com", List.of("*.example.com")), "不匹配外域");

        // ---- 7. 模块全链：过滤器拦截静态资源，零引擎调用 ----
        Support.FakeTransport mt = new Support.FakeTransport();
        mt.responder = (r, i) -> Support.text(200, "resp body content padding padding padding padding");
        AuthScanModule module = new AuthScanModule(mt);
        List<FilterRecord> filterEvents = new CopyOnWriteArrayList<>();
        List<PermResult> resultEvents = new CopyOnWriteArrayList<>();
        module.setCallback(new AuthScanModule.Callback() {
            public void onFilterRecord(FilterRecord r) {
                filterEvents.add(r);
            }

            public void onResult(PermResult r) {
                resultEvents.add(r);
            }
        });
        module.updateIdentity(id);
        module.onTraffic(Support.get("http://t.local/static/app.js"), Support.text(200, "js"), "PROXY");
        long deadline = System.currentTimeMillis() + 1500;
        while (System.currentTimeMillis() < deadline && filterEvents.isEmpty()) {
            TimeUnit.MILLISECONDS.sleep(30);
        }
        t.check(filterEvents.stream().anyMatch(fr -> fr.decision == Decision.REJECT),
                "静态资源被过滤器拦截（有记录）");
        t.check(resultEvents.isEmpty() && mt.sent.isEmpty(), "拦截后零重放请求");
        // API 流量 -> 走完整三态
        module.onTraffic(req, Support.text(200, a), "PROXY");
        deadline = System.currentTimeMillis() + 3000;
        while (System.currentTimeMillis() < deadline && resultEvents.isEmpty()) {
            TimeUnit.MILLISECONDS.sleep(30);
        }
        t.check(!resultEvents.isEmpty(), "API 流量产出越权结果");
        module.shutdown();

        // ---- 4b. 无鉴权对照 + identity 热更新（v3.4.5） ----
        // 用户反馈：报告里的"对照"不是删除授权头后的请求；且更新移除头要实时生效。
        Support.FakeTransport rt = new Support.FakeTransport();
        rt.responder = (r, i) -> Support.text(200, "OK " + r.url);
        AuthScanModule idm = new AuthScanModule(rt);
        IdentityConfig idA = new IdentityConfig();
        idA.lowAuthHeaders.add("Cookie: low=1");
        idA.noAuthHeaderNames.add("Cookie");
        idm.updateIdentity(idA);
        RawRequest reqWithAuth = new RawRequest("GET", "http://t.local/api/me",
                List.of("Host: t.local", "Cookie: high=1", "Authorization: Bearer x"), new byte[0]);
        PermResult p1 = idm.scanNow(reqWithAuth);
        t.check(p1.noAuthRequest != null && p1.noAuthRequest.headerValue("Cookie") == null,
                "无鉴权重放实际删除了配置的头（Cookie）");
        t.check(p1.noAuthRequest != null && "Bearer x".equals(p1.noAuthRequest.headerValue("Authorization")),
                "未配置移除的头保留（Authorization）");
        t.check(p1.lowRequest != null && "low=1".equals(p1.lowRequest.headerValue("Cookie")),
                "低权限重放替换同名头（Cookie: low=1）");
        // 热更新：改移除头为 Authorization，下一次检测立即按新配置删除
        IdentityConfig idB = new IdentityConfig();
        idB.lowAuthHeaders.add("Cookie: low=2");
        idB.noAuthHeaderNames.add("Authorization");
        idm.updateIdentity(idB);
        PermResult p2 = idm.scanNow(reqWithAuth);
        t.check(p2.noAuthRequest != null && p2.noAuthRequest.headerValue("Authorization") == null,
                "identity 热更新后新移除头立即生效（Authorization 被删）");
        t.check(p2.noAuthRequest != null && "high=1".equals(p2.noAuthRequest.headerValue("Cookie")),
                "热更新后旧移除头不再删除（Cookie 保留）");
        t.check(p2.lowRequest != null && "low=2".equals(p2.lowRequest.headerValue("Cookie")),
                "低权限头热更新生效（low=2）");
        idm.shutdown();

        // ---- 5. 设置页布局回归（v3.4.3）：任何两个组件不得占用同一 GridBag 单元 ----
        // 用户实机乱码：追加静态扩展名行未自增 gridy，与过滤统计行重叠渲染。
        burp.api.montoya.MontoyaApi api = Test9ExtensionLoadSmoke.proxy(burp.api.montoya.MontoyaApi.class, null);
        AuthScanModule layoutModule = new AuthScanModule(new Support.FakeTransport());
        AtomicReference<java.awt.Container> settingsRef = new AtomicReference<>();
        AtomicReference<Throwable> layoutErr = new AtomicReference<>();
        CountDownLatch layoutBuilt = new CountDownLatch(1);
        SwingUtilities.invokeLater(() -> {
            try {
                com.xzhscan.ui.AuthScanUi ui = new com.xzhscan.ui.AuthScanUi(api, layoutModule);
                JTabbedPane tabs = (JTabbedPane) ui.build();
                Component c = tabs.getComponentAt(1);
                if (c instanceof javax.swing.JScrollPane sp) {
                    c = sp.getViewport().getView(); // 设置页外层是 JScrollPane，取内部 GridBag 面板
                }
                settingsRef.set((java.awt.Container) c);
            } catch (Throwable e) {
                layoutErr.set(e);
            } finally {
                layoutBuilt.countDown();
            }
        });
        t.check(layoutBuilt.await(15, TimeUnit.SECONDS), "AuthScan 设置页构建完成");
        t.check(layoutErr.get() == null, "AuthScan 设置页无异常"
                + (layoutErr.get() == null ? "" : ": " + layoutErr.get()));
        List<String> overlaps = new CopyOnWriteArrayList<>();
        if (settingsRef.get() != null) {
            try {
                SwingUtilities.invokeAndWait(() -> {
                    java.awt.Container panel = settingsRef.get();
                    if (!(panel.getLayout() instanceof GridBagLayout gbl)) {
                        overlaps.add("layout-not-gridbag");
                        return;
                    }
                    Set<String> occupied = new HashSet<>();
                    for (Component comp : panel.getComponents()) {
                        GridBagConstraints c = gbl.getConstraints(comp);
                        int w = Math.max(1, c.gridwidth);
                        for (int dx = 0; dx < w; dx++) {
                            String cell = (c.gridx + dx) + "," + c.gridy;
                            if (!occupied.add(cell) && comp.isVisible()) {
                                overlaps.add(cell + " -> " + describe(comp));
                            }
                        }
                    }
                });
            } catch (Throwable e) {
                overlaps.add("scan-error: " + e);
            }
        }
        t.check(overlaps.isEmpty(), "设置页无组件网格重叠（乱码回归）: " + overlaps);

        // ---- 5b. 设置页初值 = 模块当前身份；结果页含三身份数据版页签（原始/低权限/未授权）----
        IdentityConfig pre = new IdentityConfig();
        pre.lowAuthHeaders.add("Cookie: low=9");
        pre.noAuthHeaderNames.add("Authorization");
        layoutModule.updateIdentity(pre);
        AtomicReference<JTabbedPane> tabsRef = new AtomicReference<>();
        SwingUtilities.invokeAndWait(() -> {
            com.xzhscan.ui.AuthScanUi ui = new com.xzhscan.ui.AuthScanUi(api, layoutModule);
            tabsRef.set((JTabbedPane) ui.build());
        });
        String[] tabsArr = new String[tabsRef.get().getTabCount()];
        for (int i = 0; i < tabsArr.length; i++) {
            tabsArr[i] = tabsRef.get().getTitleAt(i);
        }
        t.checkEq("越权结果|设置|", String.join("|", tabsArr) + "|", "AuthScan 两页签");
        JComponent resultsComp = (JComponent) tabsRef.get().getComponentAt(0);
        JTabbedPane innerEditors = findTabs(resultsComp);
        t.check(innerEditors != null, "结果页编辑器页签可定位");
        boolean hasOrig = false, hasLow = false, hasNoAuth = false;
        if (innerEditors != null) {
            for (int i = 0; i < innerEditors.getTabCount(); i++) {
                hasOrig |= "原始数据版".equals(innerEditors.getTitleAt(i));
                hasLow |= "低权限数据版".equals(innerEditors.getTitleAt(i));
                hasNoAuth |= "未授权数据版".equals(innerEditors.getTitleAt(i));
            }
        }
        t.check(hasOrig && hasLow && hasNoAuth,
                "结果页含三身份数据版页签（原始/低权限/未授权，每页左右分栏）");
        JComponent settingsComp = (JComponent) tabsRef.get().getComponentAt(1);
        java.util.List<javax.swing.JTextArea> areas = new java.util.ArrayList<>();
        collectTextAreas(settingsComp, areas);
        boolean prefilled = areas.stream().anyMatch(area -> area.getText().contains("Cookie: low=9"))
                && areas.stream().anyMatch(area -> area.getText().contains("Authorization"));
        t.check(prefilled, "设置页以模块当前身份为初值（低权限头/移除头已回填）");

        // ---- 6. 越权结果页「清空」按钮（v3.4.4） ----
        AtomicReference<Component> resultsRef = new AtomicReference<>();
        SwingUtilities.invokeAndWait(() -> {
            com.xzhscan.ui.AuthScanUi ui = new com.xzhscan.ui.AuthScanUi(api, layoutModule);
            JTabbedPane tabs = (JTabbedPane) ui.build();
            resultsRef.set(tabs.getComponentAt(0));
        });
        javax.swing.JButton clearBtn = resultsRef.get() instanceof java.awt.Container rc
                ? findButton(rc, "清空") : null;
        t.check(clearBtn != null, "越权结果页有清空按钮");
        if (clearBtn != null) {
            try {
                SwingUtilities.invokeAndWait(clearBtn::doClick);
                t.check(true, "清空按钮点击无异常");
            } catch (Throwable e) {
                t.check(false, "清空按钮点击异常: " + e);
            }
        }
        layoutModule.shutdown();
    }

    private static JTabbedPane findTabs(Component root) {
        if (root instanceof JTabbedPane t) {
            return t;
        }
        if (root instanceof java.awt.Container c) {
            for (Component child : c.getComponents()) {
                JTabbedPane found = findTabs(child);
                if (found != null) {
                    return found;
                }
            }
        }
        return null;
    }

    private static void collectTextAreas(Component root, List<javax.swing.JTextArea> out) {
        if (root instanceof javax.swing.JTextArea a) {
            out.add(a);
            return;
        }
        if (root instanceof java.awt.Container c) {
            for (Component child : c.getComponents()) {
                collectTextAreas(child, out);
            }
        }
    }

    private static javax.swing.JButton findButton(java.awt.Container root, String text) {
        for (Component c : root.getComponents()) {
            if (c instanceof javax.swing.JButton b && text.equals(b.getText())) {
                return b;
            }
            if (c instanceof java.awt.Container cc) {
                javax.swing.JButton found = findButton(cc, text);
                if (found != null) {
                    return found;
                }
            }
        }
        return null;
    }

    private static String describe(Component c) {
        if (c instanceof javax.swing.JLabel l) {
            return "JLabel(" + l.getText() + ")";
        }
        if (c instanceof javax.swing.JTextField) {
            return "JTextField";
        }
        if (c instanceof javax.swing.JCheckBox b) {
            return "JCheckBox(" + b.getText() + ")";
        }
        if (c instanceof javax.swing.JButton b) {
            return "JButton(" + b.getText() + ")";
        }
        return c.getClass().getSimpleName();
    }

    private static void reject(TestContext t, AuthScanRequestFilter f, String url, Map<String, String> headers, String label) {
        FilterRecord r = f.evaluate("t", "GET", url, headers, null);
        t.check(r.decision == Decision.REJECT, "REJECT " + label + " -> " + r.filterReason);
    }

    private static void allow(TestContext t, AuthScanRequestFilter f, String url, Map<String, String> headers) {
        FilterRecord r = f.evaluate("t", "GET", url, headers, null);
        t.check(r.decision == Decision.ALLOW, "ALLOW " + url + " -> " + r.filterReason);
    }
}
