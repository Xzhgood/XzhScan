package com.xzhscan;

import com.xzhscan.payload.PayloadRegistry;
import com.xzhscan.payload.PayloadRegistry.PayloadRule;
import com.xzhscan.payload.PayloadRegistry.RuleStatus;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import static com.xzhscan.MiniTest.TestContext;

/**
 * 测试二十：统一 Payload Registry 完整性（任务书 §2-§7；v3.5 重写）。
 *  - ID 全局唯一、状态齐备；
 *  - 时间规则资产仍登记（审计/扩展点）；v3.5 起 phase1TimeRules 选择器随被动
 *    时间子系统移除，运行时仅 Phase2 QUICK/XRAY 序列消费时间规则；
 *  - 高资源规则（benchmark/spatial/rblob）保持 DISABLED；
 *  - OOB 全部 ISOLATED，phase2 定向取规则不可达；
 *  - 跨来源模板去重合并（QUICK↔TIME、XRAY_NUMERIC↔XRAY_STRING），sourceRef 保留；
 *  - 旧 7 条遗产规则保留为 DISABLED 资产。
 */
public final class Test20PayloadRegistry {

    public static void run(TestContext t) {
        List<PayloadRule> all = PayloadRegistry.all();

        // ---------- 1. 唯一性与状态齐备 ----------
        Set<String> ids = new HashSet<>();
        for (PayloadRule r : all) {
            t.check(ids.add(r.id()), "unique id: " + r.id());
            t.check(r.status() != null, "status set: " + r.id());
            t.check(!r.meta().family().isEmpty() && !r.meta().dbms().isEmpty(), "family/dbms set: " + r.id());
            t.check(!r.sourceRefs().isEmpty(), "sourceRef kept: " + r.id());
        }

        // ---------- 2. 时间规则资产保留（v3.5：phase1TimeRules 已移除，资产仍登记） ----------
        List<PayloadRule> timeAssets = new ArrayList<>();
        for (PayloadRule r : all) {
            if (r.meta().evidenceType().startsWith("time")) {
                timeAssets.add(r);
                // 运行态时间资产模板占位符完好（Phase2 渲染依赖 {S}；
                // P1-*/DISABLED/ISOLATED 资产为历史/隔离形态，不要求 {S}）
                if (r.status() == RuleStatus.KEEP || r.status() == RuleStatus.CONDITIONAL) {
                    t.check(r.template().contains("{S}"), "runtime time asset keeps {S}: " + r.id());
                }
            }
        }
        t.check(timeAssets.size() >= 20, "time rule assets retained for Phase2: " + timeAssets.size());
        // 高资源规则默认禁用
        for (PayloadRule r : all) {
            if (r.meta().family().contains("benchmark") || r.meta().family().contains("spatial")
                    || r.meta().family().contains("rblob")) {
                t.check(r.status() == RuleStatus.DISABLED, "resource-heavy rule disabled: " + r.id());
            }
        }

        // ---------- 4. OOB 隔离（6 条 OOB_PROBES + 1 条 DNS 探针重分类） ----------
        List<PayloadRule> oob = PayloadRegistry.oobRules();
        t.checkEq(7, oob.size(), "7 OOB-classified rules (6 OOB_PROBES + UTL_INADDR DNS)");
        for (PayloadRule r : oob) {
            t.checkEq(RuleStatus.ISOLATED, r.status(), "OOB isolated: " + r.id());
            t.check(PayloadRegistry.phase2TimeRuleFor(r.id()) == null,
                    "OOB unreachable from phase2 targeted lookup: " + r.id());
        }
        // DNS 探针已移出时间检测
        for (PayloadRule r : all) {
            if (r.template().contains("UTL_INADDR")) {
                t.checkEq("oob", r.meta().evidenceType(), "DNS probe reclassified as OOB: " + r.id());
            }
        }

        // ---------- 5. 跨来源去重合并 ----------
        var dup = PayloadRegistry.duplicateSourceCount();
        t.check(!dup.isEmpty(), "cross-source duplicates merged: " + dup);
        boolean xrayMerged = false;
        for (PayloadRule r : all) {
            boolean hasNum = r.sourceRefs().stream().anyMatch(s -> s.contains("XRAY_NUMERIC_PROBES"));
            boolean hasStr = r.sourceRefs().stream().anyMatch(s -> s.contains("XRAY_STRING_PROBES"));
            if (hasNum && hasStr) {
                xrayMerged = true;
            }
        }
        t.check(xrayMerged, "XRAY_NUMERIC/XRAY_STRING duplicates share one ID");
        // QUICK 与 TIME_PROBES 重复模板合并（如 ' AND SLEEP({S})-- -）
        boolean qtTpMerged = false;
        for (PayloadRule r : all) {
            if (r.sourceRefs().stream().anyMatch(s -> s.contains("QUICK_TIME_PROBES"))
                    && r.sourceRefs().stream().anyMatch(s -> s.contains("TIME_PROBES#"))) {
                qtTpMerged = true;
            }
        }
        t.check(qtTpMerged, "QUICK_TIME/TIME_PROBES duplicates share one ID");

        // ---------- 6. 遗产 7 条保留为资产 ----------
        int legacy = 0;
        for (PayloadRule r : all) {
            if (r.id().startsWith("P1-")) {
                legacy++;
                t.checkEq(RuleStatus.DISABLED, r.status(), "legacy rule disabled: " + r.id());
                t.check(r.sourceRefs().get(0).contains("PayloadLibrary.DEFAULT_TIME_PAYLOADS"),
                        "legacy sourceRef kept: " + r.id());
            }
        }
        t.checkEq(7, legacy, "7 legacy payloads retained as auditable assets");

        // ---------- 7. phase2 定向取规则 ----------
        PayloadRule pg = PayloadRegistry.byId("QT-PG-PGSLEEP-01");
        t.check(pg != null && PayloadRegistry.phase2TimeRuleFor("QT-PG-PGSLEEP-01") == pg,
                "phase2 targeted lookup works for hit rule");
        t.check(PayloadRegistry.phase2TimeRuleFor("OOB-PG-COPY-01") == null,
                "OOB rule never returned as time rule");
        t.checkEq(2, PayloadRegistry.phase2BareErrorRules().size(), "bare-error rules = 2");
        t.checkEq(5, PayloadRegistry.phase2OrderRules().size(), "orderby rules = 5");
    }
}
