package com.xzhscan;

/** 全量测试入口：java -cp build/classes;build/test-classes com.xzhscan.TestRunner */
public final class TestRunner {

    public static void main(String[] args) {
        // v3.5：Test14（被动时间探针）/Test25（phase1TimeRules 上下文适配）随子系统移除；
        // 保留历史编号不重排（suite 号 = 版本史索引）。
        int[] order = args.length > 0 ? indices(args) : new int[]{1, 2, 3, 4, 5, 6, 7, 9, 10, 11, 12, 13, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39};
        int failures = 0;
        for (int n : order) {
            failures += switch (n) {
                case 1 -> MiniTest.runSuite("Test1: JSON双引号变异", Test1JsonQuoteMutation::run);
                case 2 -> MiniTest.runSuite("Test2: 无效JSON拦截", Test2InvalidJsonGate::run);
                case 3 -> MiniTest.runSuite("Test3: 微弱差分过滤", Test3WeakDelta::run);
                case 4 -> MiniTest.runSuite("Test4: 参数级验证", Test4ParameterLevel::run);
                case 5 -> MiniTest.runSuite("Test5: 嵌套JSON定位", Test5NestedJson::run);
                case 6 -> MiniTest.runSuite("Test6: 动态响应噪声", Test6DynamicResponse::run);
                case 7 -> MiniTest.runSuite("Test7: 插件独立性", Test7Independence::run);
                case 9 -> MiniTest.runSuite("Test9: 扩展加载冒烟", Test9ExtensionLoadSmoke::run);
                case 10 -> MiniTest.runSuite("Test10: 调度器回归", Test10OrchestratorRegression::run);
                case 11 -> MiniTest.runSuite("Test11: Payload库与编码", Test11PayloadAndEncoding::run);
                case 12 -> MiniTest.runSuite("Test12: 时间证据", Test12TimingEvidence::run);
                case 13 -> MiniTest.runSuite("Test13: UI结构与后台", Test13UiAndBackground::run);
                case 15 -> MiniTest.runSuite("Test15: 静态资源守卫", Test15StaticResourceGuard::run);
                case 16 -> MiniTest.runSuite("Test16: AuthScan", Test16AuthScan::run);
                case 17 -> MiniTest.runSuite("Test17: Chinese中文解码", Test17U2C::run);
                case 18 -> MiniTest.runSuite("Test18: XzhScan结构", Test18XzhScanStructure::run);
                case 19 -> MiniTest.runSuite("Test19: 配置兼容", Test19ConfigCompat::run);
                case 20 -> MiniTest.runSuite("Test20: PayloadRegistry", Test20PayloadRegistry::run);
                case 21 -> MiniTest.runSuite("Test21: Phase2证据分型调度", Test21Phase2Dispatch::run);
                case 22 -> MiniTest.runSuite("Test22: 差分布尔与变异修复", Test22DiffAndMutationFixes::run);
                case 23 -> MiniTest.runSuite("Test23: Mock数据库兼容", Test23MockDb::run);
                case 24 -> MiniTest.runSuite("Test24: 时间探针超时预算", Test24TimeProbeBudget::run);
                case 26 -> MiniTest.runSuite("Test26: 手动送二阶段", Test26ManualVerify::run);
                case 27 -> MiniTest.runSuite("Test27: 右键全模块验证", Test27ManualFullScan::run);
                case 28 -> MiniTest.runSuite("Test28: JSON变异全形态", Test28JsonMutationFuzz::run);
                case 29 -> MiniTest.runSuite("Test29: XiaSQL主从表", Test29XiaSqlPanel::run);
                case 30 -> MiniTest.runSuite("Test30: 时间盲注枚举", Test30TimeBased::run);
                case 31 -> MiniTest.runSuite("Test31: Dictionary字典页签", Test31Dictionary::run);
                case 32 -> MiniTest.runSuite("Test32: Intruder监听准入", Test32IntruderTap::run);
                case 33 -> MiniTest.runSuite("Test33: 数据版", Test33DataBoard::run);
                case 34 -> MiniTest.runSuite("Test34: Intruder端到端", Test34TrafficListenerTap::run);
                case 35 -> MiniTest.runSuite("Test35: 配置单一真相源", Test35ConfigSingleSource::run);
                case 36 -> MiniTest.runSuite("Test36: UI交互回归", Test36UiInteraction::run);
                case 37 -> MiniTest.runSuite("Test37: sqlmap注入模型", Test37SqlmapModel::run);
                case 38 -> MiniTest.runSuite("Test38: 安全默认", Test38SecurityDefaults::run);
                case 39 -> MiniTest.runSuite("Test39: 耗时预算", Test39TimeBudget::run);
                default -> throw new IllegalArgumentException("unknown test " + n);
            };
        }
        if (failures != 0) {
            System.exit(1);
        }
        System.out.println("ALL DONE");
    }

    private static int[] indices(String[] args) {
        int[] r = new int[args.length];
        for (int i = 0; i < args.length; i++) {
            r[i] = Integer.parseInt(args[i]);
        }
        return r;
    }
}
