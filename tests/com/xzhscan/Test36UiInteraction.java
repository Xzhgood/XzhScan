package com.xzhscan;

import com.xzhscan.config.XzhScanConfig;
import com.xzhscan.engine.ScanOrchestrator;
import com.xzhscan.model.EvidenceStore;
import com.xzhscan.ui.SqlScanUi;

import burp.api.montoya.MontoyaApi;

import javax.swing.*;
import java.awt.*;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;

import static com.xzhscan.MiniTest.TestContext;

/**
 * 测试三十六：UI 交互回归（v4.0，替代"GUI 从未点过"的空白）。
 *
 * <p>无头环境下真实构建设置页，找到每个复选框并触发其 action 监听器——
 * 验证"勾选/取消立即写配置 + 立即落盘"，不依赖「应用设置」按钮。
 * 这正是 v3.9.x 连续踩坑（勾了不生效、换 jar 回滚）的回归防线。</p>
 */
public final class Test36UiInteraction {

    public static void run(TestContext t) throws Exception {
        MontoyaApi api = Test9ExtensionLoadSmoke.proxy(MontoyaApi.class, null);
        XzhScanConfig config = new XzhScanConfig();
        config.requestIntervalMs = 0;

        AtomicInteger saves = new AtomicInteger();
        config.addListener(saves::incrementAndGet);

        AtomicReference<JTabbedPane> rootRef = new AtomicReference<>();
        AtomicReference<Throwable> err = new AtomicReference<>();
        CountDownLatch built = new CountDownLatch(1);
        SwingUtilities.invokeLater(() -> {
            try {
                SqlScanUi ui = new SqlScanUi(api, config, new EvidenceStore(),
                        new com.xzhscan.policy.ScanPolicyEngine(config));
                rootRef.set(ui.build());
            } catch (Throwable e) {
                err.set(e);
            } finally {
                built.countDown();
            }
        });
        t.check(built.await(15, TimeUnit.SECONDS), "设置页构建完成");
        t.check(err.get() == null, "构建无异常" + (err.get() == null ? "" : ": " + err.get()));
        if (err.get() != null) {
            return;
        }
        JTabbedPane root = rootRef.get();
        JComponent settings = (JComponent) root.getComponentAt(3);

        // ---------- 1. 每个开关独立可点（真实 action 事件） ----------
        t.check(toggle(settings, "监控 Proxy 流量", false), "找到 Proxy 开关");
        t.check(!config.watchProxy, "取消勾选 Proxy → 配置即时 false");
        t.check(toggle(settings, "监控 Proxy 流量", true), "Proxy 开关可重新勾选");
        t.check(config.watchProxy, "勾选 Proxy → 配置即时 true");

        t.check(toggle(settings, "监听 Intruder 流量（仅 200 响应）", true), "找到 Intruder 开关");
        t.check(config.watchIntruder, "勾选 Intruder → 配置即时 true（不点应用设置）");
        t.check(toggle(settings, "监听 Intruder 流量（仅 200 响应）", false), "Intruder 可取消");
        t.check(!config.watchIntruder, "取消 Intruder → 配置即时 false");

        t.check(toggle(settings, "允许时间盲注探针·第二阶段（sleep 复验）", false), "找到时间探针开关");
        t.check(!config.allowTimeBasedProbe, "关闭时间探针 → 配置即时 false");
        t.check(toggle(settings, "允许时间盲注探针·第二阶段（sleep 复验）", true), "时间探针可恢复");
        t.check(config.allowTimeBasedProbe, "恢复时间探针 → 配置即时 true");

        // ---------- 2. 每次点击都触发落盘通知 ----------
        t.check(saves.get() >= 6, "每次开关点击均触发配置落盘（累计 " + saves.get() + " 次）");

        // ---------- 3. 设置页无遗漏的旧时间开关（v3.5 已删） ----------
        t.check(findCheckBox(settings, "被动时间探针") == null, "被动时间探针开关不回归");
        t.check(findCheckBox(settings, "允许叠加查询（stacked）") == null, "stacked 开关不回归");

        // ---------- 4. 卸载不抛异常 ----------
        AtomicReference<Throwable> disposeErr = new AtomicReference<>();
        SwingUtilities.invokeAndWait(() -> {
            try {
                // 通过 root 卸载模拟扩展 unload
                root.removeAll();
            } catch (Throwable e) {
                disposeErr.set(e);
            }
        });
        t.check(disposeErr.get() == null, "UI 卸载清理不抛异常");
    }

    /** 找到复选框并按目标状态触发真实 action 事件。 */
    private static boolean toggle(JComponent root, String text, boolean target) {
        JCheckBox box = findCheckBox(root, text);
        if (box == null) {
            return false;
        }
        box.setSelected(target);
        for (java.awt.event.ActionListener al : box.getActionListeners()) {
            al.actionPerformed(new java.awt.event.ActionEvent(box, 0, "test"));
        }
        return true;
    }

    static JCheckBox findCheckBox(Component c, String text) {
        if (c instanceof JCheckBox box && text.equals(box.getText())) {
            return box;
        }
        if (c instanceof Container cc) {
            for (Component child : cc.getComponents()) {
                JCheckBox found = findCheckBox(child, text);
                if (found != null) {
                    return found;
                }
            }
        }
        return null;
    }

    private Test36UiInteraction() {
    }
}
