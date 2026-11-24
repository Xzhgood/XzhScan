package com.xzhscan;

import com.xzhscan.config.ConfigCodec;
import com.xzhscan.config.XzhScanConfig;

import java.util.concurrent.atomic.AtomicInteger;

import static com.xzhscan.MiniTest.TestContext;

/**
 * 测试三十五：配置系统单一真相源（v4.0 重写验收）。
 *  - 字段变更 → notifyChanged() → 监听器触发（扩展装配时接 saveConfig 立即落盘）；
 *  - 监听器异常不中断调用方；
 *  - 新增 timeDelaySeconds 往返与范围夹取；
 *  - copy() 不携带监听器（拷贝是纯数据）。
 */
public final class Test35ConfigSingleSource {

    public static void run(TestContext t) {
        // ---------- 1. notifyChanged 触发监听器 ----------
        XzhScanConfig c = new XzhScanConfig();
        AtomicInteger hits = new AtomicInteger();
        c.addListener(hits::incrementAndGet);
        c.watchIntruder = true;
        c.notifyChanged();
        t.checkEq(1, hits.get(), "字段变更 + notifyChanged 触发监听一次");
        c.timeDelaySeconds = 7;
        c.notifyChanged();
        t.checkEq(2, hits.get(), "连续变更累计触发");

        // ---------- 2. 监听器异常不中断 ----------
        XzhScanConfig c2 = new XzhScanConfig();
        AtomicInteger after = new AtomicInteger();
        c2.addListener(() -> {
            throw new RuntimeException("boom");
        });
        c2.addListener(after::incrementAndGet);
        boolean threw = false;
        try {
            c2.notifyChanged();
        } catch (Throwable e) {
            threw = true;
        }
        t.check(!threw, "监听器异常不外抛（不中断 UI 操作）");
        t.checkEq(1, after.get(), "异常监听器不影响后续监听器执行");

        // ---------- 3. 空监听器安全 ----------
        XzhScanConfig c3 = new XzhScanConfig();
        c3.addListener(null);
        c3.notifyChanged();
        t.check(true, "null 监听器安全忽略");

        // ---------- 4. timeDelaySeconds 序列化往返与范围 ----------
        XzhScanConfig out = new XzhScanConfig();
        out.timeDelaySeconds = 8;
        out.watchIntruder = true;
        String props = ConfigCodec.toProperties(out);
        t.check(props.contains("timeDelaySeconds=8"), "序列化包含 timeDelaySeconds");
        XzhScanConfig in = new XzhScanConfig();
        ConfigCodec.fromProperties(props, in);
        t.checkEq(8, in.timeDelaySeconds, "timeDelaySeconds 往返");
        t.check(in.watchIntruder, "watchIntruder 往返");
        t.checkEq(5, new XzhScanConfig().timeDelaySeconds, "timeDelaySeconds 默认 5");

        XzhScanConfig clampLow = new XzhScanConfig();
        ConfigCodec.fromProperties("configVersion=" + ConfigCodec.CONFIG_VERSION
                + (char) 10 + "timeDelaySeconds=99" + (char) 10, clampLow);
        t.check(clampLow.timeDelaySeconds <= 10, "超上限被夹取到 10（实际 "
                + clampLow.timeDelaySeconds + "）");

        // ---------- 5. copy() 不携带监听器 ----------
        XzhScanConfig c4 = new XzhScanConfig();
        AtomicInteger copyHits = new AtomicInteger();
        c4.addListener(copyHits::incrementAndGet);
        XzhScanConfig copied = c4.copy();
        copied.notifyChanged();
        t.checkEq(0, copyHits.get(), "copy() 是纯数据快照（不带监听器）");
    }

    private Test35ConfigSingleSource() {
    }
}
