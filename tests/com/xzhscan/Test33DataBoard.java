package com.xzhscan;

import com.xzhscan.config.XzhScanConfig;
import com.xzhscan.engine.PassiveDetectionEngine;
import com.xzhscan.model.EvidenceStore;
import com.xzhscan.model.Models.DifferentialCandidate;
import com.xzhscan.model.Models.FilterDecision;
import com.xzhscan.model.Models.TrafficRecord;
import com.xzhscan.model.RawHttp.RawRequest;
import com.xzhscan.Support.FakeTransport;
import com.xzhscan.ui.SqlScanUi;

import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.atomic.AtomicInteger;

import static com.xzhscan.MiniTest.TestContext;

/**
 * 测试三十三：数据版（v3.9.2）。
 *  - 参数级聚合档位（红 > 黄 > 绿 > 默认）；
 *  - 动态页重测耗尽仍待定 -> INCONCLUSIVE 候选回流（数据版黄色参数来源），
 *    且 PASS 语义保持不变（Test6 锚：动态页无 PASS 候选）；
 *  - 稳定报错页 PASS 候选 filterDecision=PASS（回归锚，数据版红色参数来源）。
 */
public final class Test33DataBoard {

    static final AtomicInteger seq = new AtomicInteger();

    static String dynamicPage() {
        return "<html><body>"
                + "<input name=\"csrf\" value=\"" + java.util.UUID.randomUUID() + "\">"
                + "<span>generated at " + System.currentTimeMillis() + "</span>"
                + "<span>request-id: req-" + seq.incrementAndGet() + "</span>"
                + "<div>search results: item1 item2 item3</div>"
                + "</body></html>";
    }

    public static void run(TestContext t) {
        // ---------- 1. 参数级聚合档位：红 > 黄 > 绿 > 默认 ----------
        t.checkEq(SqlScanUi.dataBoardTier(new int[]{1, 5, 9}), SqlScanUi.TIER_CHANGED,
                "出现过变化 -> 红（数据版保留）");
        t.checkEq(SqlScanUi.dataBoardTier(new int[]{0, 2, 7}), SqlScanUi.TIER_PENDING,
                "无变化有待定 -> 黄（数据版保留）");
        t.checkEq(SqlScanUi.dataBoardTier(new int[]{0, 0, 4}), SqlScanUi.TIER_REJECTED,
                "纯拒绝 -> 绿（数据版剔除）");
        t.checkEq(SqlScanUi.dataBoardTier(new int[]{0, 0, 0}), SqlScanUi.TIER_DEFAULT,
                "无证据 -> 默认（数据版忽略）");

        // ---------- 2. 动态页：INCONCLUSIVE 候选回流（黄色来源），PASS 语义不变 ----------
        XzhScanConfig config = new XzhScanConfig();
        config.requestIntervalMs = 0;
        config.baselineSamples = 3;
        config.maxStabilityRetests = 2;

        RawRequest original = Support.get("http://t.local/list?kw=hello&page=2");
        FakeTransport dynamic = new FakeTransport();
        dynamic.responder = (r, idx) -> Support.text(200, dynamicPage());

        List<DifferentialCandidate> board = new CopyOnWriteArrayList<>();
        PassiveDetectionEngine engine = new PassiveDetectionEngine(config, dynamic, new EvidenceStore());
        TrafficRecord record = new TrafficRecord();
        record.requestId = "REQ-33";
        List<DifferentialCandidate> passed = engine.process(original, null, record,
                new PassiveDetectionEngine.Callback() {
                    @Override
                    public void onTrafficUpdate(TrafficRecord r) {
                    }

                    @Override
                    public void onCandidate(DifferentialCandidate c) {
                        board.add(c);
                    }

                    @Override
                    public void onRejected(String requestId,
                                           com.xzhscan.model.Models.ParameterIdentity param,
                                           String probeKind, String reason, double score) {
                    }

                    @Override
                    public void onGateView(com.xzhscan.model.Models.GateProbeView view) {
                    }
                });

        t.check(passed.isEmpty(), "动态页无 PASS 候选（Test6 语义保持）");
        t.check(!board.isEmpty(), "INCONCLUSIVE 候选已回流（数据版黄色来源，"
                + board.size() + " 条）");
        for (DifferentialCandidate c : board) {
            t.checkEq(FilterDecision.INCONCLUSIVE, c.filterDecision, "待定候选标记 INCONCLUSIVE");
            t.check(c.originalRequest != null, "待定候选携带原始请求（二阶段安全闸可用）");
            t.check(c.candidateType != null, "待定候选已分型（ERROR/BOOLEAN）");
            t.check(c.parameterPath != null && c.requestId != null, "待定候选带参数与请求标识");
        }

        // ---------- 3. 稳定报错页：PASS 候选回归锚（数据版红色来源） ----------
        RawRequest err = Support.get("http://t.local/search?name=admin&page=1&sort=asc");
        FakeTransport stable = new FakeTransport();
        stable.responder = (r, idx) -> {
            String url = r.url;
            if (url.contains("name=admin'") || url.contains("name=admin%27")) {
                return Support.text(500,
                        "MySQLSyntaxErrorException: You have an error in your SQL syntax near 'admin''");
            }
            return Support.text(200, "{\"rows\":[1,2,3],\"total\":3}");
        };
        List<DifferentialCandidate> board2 = new CopyOnWriteArrayList<>();
        List<DifferentialCandidate> passed2 = new CopyOnWriteArrayList<>();
        PassiveDetectionEngine engine2 = new PassiveDetectionEngine(config, stable, new EvidenceStore());
        TrafficRecord record2 = new TrafficRecord();
        record2.requestId = "REQ-33B";
        engine2.process(err, null, record2, new PassiveDetectionEngine.Callback() {
            @Override
            public void onTrafficUpdate(TrafficRecord r) {
            }

            @Override
            public void onCandidate(DifferentialCandidate c) {
                if (c.filterDecision == FilterDecision.PASS) {
                    passed2.add(c);
                } else {
                    board2.add(c);
                }
            }

            @Override
            public void onRejected(String requestId,
                                   com.xzhscan.model.Models.ParameterIdentity param,
                                   String probeKind, String reason, double score) {
            }

            @Override
            public void onGateView(com.xzhscan.model.Models.GateProbeView view) {
            }
        });
        t.check(!passed2.isEmpty(), "稳定报错页产出 PASS 候选（红色来源回归锚）");
        t.check(board2.isEmpty(), "PASS 场景不产生额外 INCONCLUSIVE 候选（误报面不变）");
        for (DifferentialCandidate c : passed2) {
            t.checkEq(FilterDecision.PASS, c.filterDecision, "PASS 候选标记保持 PASS");
        }
    }

    private Test33DataBoard() {
    }
}
