package com.xzhscan;

import burp.api.montoya.MontoyaApi;
import com.xzhscan.burp.XzhScanExtension;

import java.lang.reflect.InvocationHandler;
import java.lang.reflect.Method;
import java.lang.reflect.Proxy;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;

import static com.xzhscan.MiniTest.TestContext;

/**
 * 测试九（附加）：扩展加载冒烟。
 * 用递归动态代理伪造 MontoyaApi 全家桶，在无 Burp 的裸 JVM 上
 * 执行 XzhScanExtension.initialize() 全流程（含 UI 构建、handler 注册、卸载回调），
 * 证明扩展入口在独立类路径上可加载可初始化。
 */
public final class Test9ExtensionLoadSmoke {

    /** 调用记录：EDT 写入与本线程遍历并发，必须用并发安全容器（Vector.stream 非同步 → CME）。 */
    static final List<String> calls = new CopyOnWriteArrayList<>();
    static final AtomicReference<Runnable> unloadHandler = new AtomicReference<>();

    public static void run(TestContext t) throws Exception {
        MontoyaApi api = proxy(MontoyaApi.class, null);

        AtomicReference<Throwable> initError = new AtomicReference<>();
        CountDownLatch edtDone = new CountDownLatch(1);
        javax.swing.SwingUtilities.invokeLater(() -> {
            try {
                new XzhScanExtension().initialize(api);
            } catch (Throwable e) {
                initError.set(e);
            } finally {
                edtDone.countDown();
            }
        });
        boolean finished = edtDone.await(15, TimeUnit.SECONDS);
        t.check(finished, "initialize completed (EDT)");
        t.check(initError.get() == null,
                "initialize threw nothing" + (initError.get() == null ? "" : ": " + initError.get()));

        // initialize 把 UI 构建/回调绑定/流量注册放进同一个 EDT 任务：
        // registerHttpHandler 是任务最后一步——它出现即代表 setHostCallback/AuthScan 页签
        // 全部就绪（v2.2.1 曾丢失 setHostCallback 导致 UI 全盲，此等待+顺序断言防回归）。
        long deadline = System.currentTimeMillis() + 5000;
        while (System.currentTimeMillis() < deadline
                && (calls.stream().noneMatch(c -> c.endsWith(".registerSuiteTab"))
                || calls.stream().noneMatch(c -> c.endsWith(".registerHttpHandler")))) {
            Thread.sleep(50);
        }
        Thread.sleep(150); // EDT 尾部任务余量（主题应用）

        boolean named = calls.stream().anyMatch(c -> c.startsWith("setName:") && c.contains("XzhScan"));
        t.check(named, "extension name registered: " + calls.stream().filter(c -> c.startsWith("setName")).findFirst().orElse("(none)"));
        boolean tabbed = calls.stream().anyMatch(c -> c.endsWith(".registerSuiteTab"));
        t.check(tabbed, "suite tab registered: " + calls.stream().filter(c -> c.contains("SuiteTab")).findFirst().orElse("(none)"));
        boolean httpHandler = calls.stream().anyMatch(c -> c.endsWith(".registerHttpHandler"));
        t.check(httpHandler, "http handler registered: " + calls.stream().filter(c -> c.contains("HttpHandler")).findFirst().orElse("(none)"));
        // 接线顺序：setHostCallback/AuthScan 页签绑定（EDT 任务内）必须先于流量注册
        int suiteIdx = -1, handlerIdx = -1, ctxIdx = -1;
        for (int i = 0; i < calls.size(); i++) {
            if (calls.get(i).endsWith(".registerSuiteTab") && suiteIdx < 0) suiteIdx = i;
            if (calls.get(i).endsWith(".registerHttpHandler") && handlerIdx < 0) handlerIdx = i;
            if (calls.get(i).endsWith(".registerContextMenuItemsProvider") && ctxIdx < 0) ctxIdx = i;
        }
        t.check(suiteIdx >= 0 && handlerIdx > suiteIdx && ctxIdx > suiteIdx,
                "wiring order: suiteTab(" + suiteIdx + ") < handler(" + handlerIdx + ") < ctxMenu(" + ctxIdx + ")");
        boolean ctxMenu = calls.stream().anyMatch(c -> c.endsWith(".registerContextMenuItemsProvider"));
        t.check(ctxMenu, "context menu registered: " + calls.stream().filter(c -> c.contains("ContextMenu")).findFirst().orElse("(none)"));
        boolean unloadReg = calls.stream().anyMatch(c -> c.endsWith(".registerUnloadingHandler"));
        t.check(unloadReg, "unloading handler registered");

        Runnable uh = unloadHandler.get();
        t.check(uh != null, "unload runnable captured");
        if (uh != null) {
            AtomicBoolean unloadOk = new AtomicBoolean(true);
            try {
                uh.run();
            } catch (Throwable e) {
                unloadOk.set(false);
                System.out.println("  unload error: " + e);
            }
            t.check(unloadOk.get(), "unload handler runs clean");
        }
    }

    /** 递归代理：接口 -> 记录调用的代理；非接口返回合理默认值。 */
    @SuppressWarnings("unchecked")
    static <T> T proxy(Class<?> iface, String path) {
        return (T) Proxy.newProxyInstance(iface.getClassLoader(), new Class[]{iface}, new InvocationHandler() {
            @Override
            public Object invoke(Object proxy, Method method, Object[] args) {
                String key = path == null ? method.getName() : path + "." + method.getName();
                String mname = method.getName();
                Class<?> rt = method.getReturnType();
                if (mname.equals("setName") && args != null && args.length == 1 && args[0] instanceof String sv) {
                    calls.add("setName:" + sv);
                    return null;
                }
                if (mname.equals("getString")) {
                    return null; // extensionData().getString -> 未保存配置
                }
                if (mname.equals("setString")) {
                    return null;
                }
                if (mname.equals("registerUnloadingHandler") && args != null && args.length == 1) {
                    Object handler = args[0];
                    unloadHandler.set(() -> {
                        try {
                            Method m = handler.getClass().getMethod("extensionUnloaded");
                            m.setAccessible(true);
                            m.invoke(handler);
                        } catch (ReflectiveOperationException e) {
                            throw new RuntimeException(e);
                        }
                    });
                    calls.add(key);
                    return null;
                }
                if (rt == boolean.class) {
                    calls.add(key);
                    return false;
                }
                if (rt == int.class) {
                    calls.add(key);
                    return 0;
                }
                if (rt == long.class) {
                    calls.add(key);
                    return 0L;
                }
                if (rt == List.class) {
                    calls.add(key);
                    return new java.util.ArrayList<>();
                }
                if (rt == java.util.Optional.class) {
                    calls.add(key);
                    return java.util.Optional.empty();
                }
                if (rt.isInterface()) {
                    calls.add(key);
                    return proxy(rt, key);
                }
                calls.add(key);
                return null;
            }
        });
    }
}
