package com.xzhscan;

import com.xzhscan.burp.TrafficListener;
import com.xzhscan.config.ConfigCodec;
import com.xzhscan.config.XzhScanConfig;
import com.xzhscan.engine.ScanOrchestrator;
import com.xzhscan.model.RawHttp.RawRequest;

import burp.api.montoya.core.ToolType;

import java.util.List;

import static com.xzhscan.MiniTest.TestContext;

/**
 * 测试三十二：Intruder 流量监听（v3.9.0）。
 *  - 开关默认关；copy 不串值；序列化往返与旧配置缺键回退；
 *  - 准入纯函数矩阵：开启时仅 INTRUDER + 严格 200 准入，201/202/204/301/302/
 *    400/401/403/404/429/500 全跳过；Proxy/Repeater/Scanner 行为不受新开关影响；
 *  - 去重键语义：同参数名不同值同键（窗口去重防 fuzz 洪水）、
 *    不同参数集不同键（不按 URL 路径合并）。
 */
public final class Test32IntruderTap {

    public static void run(TestContext t) {
        // ---------- 1. 默认值 ----------
        XzhScanConfig def = new XzhScanConfig();
        t.check(!def.watchIntruder, "watchIntruder 默认关闭");
        t.check(def.watchProxy, "watchProxy 默认开启（回归锚）");
        t.check(def.watchRepeater, "watchRepeater 默认开启");
        t.check(!def.watchScanner, "watchScanner 默认关闭");

        // ---------- 2. copy 保留 ----------
        XzhScanConfig off = new XzhScanConfig();
        XzhScanConfig on = new XzhScanConfig();
        on.watchIntruder = true;
        t.check(!off.copy().watchIntruder, "copy：默认关闭不串值");
        t.check(on.copy().watchIntruder, "copy：开启状态保留");

        // ---------- 3. 准入矩阵（开关关闭 = 旧版行为） ----------
        t.check(!TrafficListener.sqlScanWants(off, ToolType.INTRUDER, 200),
                "关：INTRUDER 200 也不准入");
        t.check(TrafficListener.sqlScanWants(off, ToolType.PROXY, 302),
                "关：PROXY 302 照旧准入（无状态码门槛）");
        t.check(TrafficListener.sqlScanWants(off, ToolType.REPEATER, 404),
                "关：REPEATER 404 照旧准入");
        t.checkEq(off.watchScanner, TrafficListener.sqlScanWants(off, ToolType.SCANNER, 200),
                "关：SCANNER 只随自身开关");

        // ---------- 4. 准入矩阵（开关开启：仅严格 200） ----------
        t.check(TrafficListener.sqlScanWants(on, ToolType.INTRUDER, 200),
                "开：INTRUDER 200 准入");
        int[] rejected = {201, 202, 204, 301, 302, 400, 401, 403, 404, 429, 500};
        for (int code : rejected) {
            t.check(!TrafficListener.sqlScanWants(on, ToolType.INTRUDER, code),
                    "开：INTRUDER " + code + " 跳过");
        }
        // 200 只是准入条件：不能因状态码把其他来源的行为带偏
        t.check(TrafficListener.sqlScanWants(on, ToolType.PROXY, 200), "开：PROXY 不受影响");
        t.check(TrafficListener.sqlScanWants(on, ToolType.REPEATER, 500), "开：REPEATER 无状态码门槛");
        t.checkEq(on.watchScanner, TrafficListener.sqlScanWants(on, ToolType.SCANNER, 200),
                "开：SCANNER 仍只随自身开关");
        t.check(!TrafficListener.sqlScanWants(on, ToolType.EXTENSIONS, 200),
                "开：EXTENSIONS（插件自身流量）永不准入");
        t.check(!TrafficListener.sqlScanWants(on, ToolType.INTRUDER, 200)
                        || on.watchIntruder, "开：准入前提是开关为真（自洽）");

        // ---------- 5. 序列化往返 ----------
        String props = ConfigCodec.toProperties(on);
        t.check(props.contains("watchIntruder=true"), "序列化包含 watchIntruder=true");
        XzhScanConfig back = new XzhScanConfig();
        ConfigCodec.fromProperties(props, back);
        t.check(back.watchIntruder, "反序列化往返为 true");
        XzhScanConfig backOff = new XzhScanConfig();
        ConfigCodec.fromProperties(ConfigCodec.toProperties(off), backOff);
        t.check(!backOff.watchIntruder, "反序列化往返为 false");

        // 旧版配置缺该键 -> 保持默认关（未知键忽略、缺键保持默认）
        String legacy = props.replaceAll("(?m)^watchIntruder=.*\\r?\\n", "");
        XzhScanConfig legacyCfg = new XzhScanConfig();
        ConfigCodec.fromProperties(legacy, legacyCfg);
        t.check(!legacyCfg.watchIntruder, "旧配置缺 watchIntruder 键 -> 默认关闭");

        // ---------- 6. 去重键语义（Intruder 防刷） ----------
        RawRequest r1 = new RawRequest("GET", "http://t/x?id=1&name=a", List.of(), new byte[0]);
        RawRequest r2 = new RawRequest("GET", "http://t/x?id=2&name=a", List.of(), new byte[0]);
        RawRequest r3 = new RawRequest("GET", "http://t/x?other=1", List.of(), new byte[0]);
        t.checkEq(ScanOrchestrator.dedupKeyOf(r1), ScanOrchestrator.dedupKeyOf(r2),
                "同参数名不同值 -> 同键（240min 窗口只扫一次，防 fuzz 洪水）");
        t.check(!ScanOrchestrator.dedupKeyOf(r1).equals(ScanOrchestrator.dedupKeyOf(r3)),
                "不同参数集 -> 不同键（不按 URL 路径合并）");
    }

    private Test32IntruderTap() {
    }
}
