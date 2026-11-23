package com.xzhscan;

import java.util.ArrayList;
import java.util.List;

/**
 * 零依赖微型测试运行器：每个测试类提供静态 run(TestContext)；
 * TestRunner 跑全部并输出 PASS/FAIL 统计，失败退出码 1。
 */
public final class MiniTest {

    public static final class TestContext {
        public final String suite;
        public int passed;
        public int failed;
        public final List<String> failures = new ArrayList<>();

        public TestContext(String suite) {
            this.suite = suite;
        }

        public void check(boolean cond, String label) {
            if (cond) {
                passed++;
            } else {
                failed++;
                failures.add(label);
                System.out.println("  [FAIL] " + suite + " :: " + label);
            }
        }

        public void checkEq(Object expected, Object actual, String label) {
            boolean eq = expected == null ? actual == null : expected.equals(actual);
            if (eq) {
                passed++;
            } else {
                failed++;
                failures.add(label + " (expected=" + expected + " actual=" + actual + ")");
                System.out.println("  [FAIL] " + suite + " :: " + label
                        + " (expected=" + expected + " actual=" + actual + ")");
            }
        }

        public void checkNear(double expected, double actual, double eps, String label) {
            check(Math.abs(expected - actual) <= eps, label + " (expected~" + expected + " actual=" + actual + ")");
        }
    }

    @FunctionalInterface
    public interface Suite {
        void run(TestContext t) throws Exception;
    }

    public static int runSuite(String name, Suite suite) {
        System.out.println("== " + name + " ==");
        TestContext ctx = new TestContext(name);
        long t0 = System.currentTimeMillis();
        try {
            suite.run(ctx);
        } catch (Throwable e) {
            ctx.failed++;
            ctx.failures.add("exception: " + e);
            System.out.println("  [FAIL] " + name + " threw " + e);
            e.printStackTrace(System.out);
        }
        long cost = System.currentTimeMillis() - t0;
        System.out.println(String.format("   %s: %d passed, %d failed (%dms)",
                ctx.failed == 0 ? "OK" : "BROKEN", ctx.passed, ctx.failed, cost));
        return ctx.failed;
    }
}
