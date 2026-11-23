package com.xzhscan.model;

import com.xzhscan.model.Models.DifferentialCandidate;
import com.xzhscan.model.Models.InjectionFinding;
import com.xzhscan.model.Models.VerificationResult;
import com.xzhscan.model.RawHttp.RawRequest;
import com.xzhscan.model.RawHttp.RawResponse;

import java.util.ArrayList;
import java.util.List;

/**
 * 漏洞记录 → HTTP 证据四元组（原始请求/测试请求/原始响应/测试响应）的纯解析函数。
 * 独立于 UI：缺失证据显式置 null 并给出 missing 说明，UI 据此显示空状态，
 * 绝不用上一条记录的数据填充（任务书 6.2-8），也不伪造 HTTP 数据（6.4）。
 */
public final class EvidenceBundles {

    public static final class Bundle {
        public final RawRequest originalRequest;
        public final RawRequest probeRequest;
        public final RawResponse originalResponse;
        public final RawResponse probeResponse;
        public final List<String> missing;

        Bundle(RawRequest oReq, RawRequest pReq, RawResponse oResp, RawResponse pResp, List<String> missing) {
            this.originalRequest = oReq;
            this.probeRequest = pReq;
            this.originalResponse = oResp;
            this.probeResponse = pResp;
            this.missing = missing;
        }

        public boolean anyMissing() {
            return !missing.isEmpty();
        }
    }

    /**
     * 解析顺序：
     *  1) 原始请求：candidate.originalRequest；
     *  2) 原始响应：verification.evidenceIds 中首个 verify-baseline 且带响应的证据，
     *     回退到同 URL 的第一阶段 baseline 证据；
     *  3) 测试请求/响应：evidenceIds 中最后一个 verify-probe（判定所用的最末探针往返）。
     */
    public static Bundle resolve(DifferentialCandidate candidate,
                                 VerificationResult verification,
                                 InjectionFinding finding,
                                 EvidenceStore store) {
        List<String> missing = new ArrayList<>();
        RawRequest oReq = candidate == null ? null : candidate.originalRequest;
        if (oReq == null) {
            missing.add("原始请求缺失（候选未携带请求快照）");
        }

        RawResponse oResp = null;
        RawRequest pReq = null;
        RawResponse pResp = null;
        List<String> ids = verification != null && !verification.evidenceIds.isEmpty()
                ? verification.evidenceIds
                : (finding != null ? finding.evidenceIds : List.of());
        if (ids.isEmpty() && candidate != null && candidate.evidenceIds != null) {
            ids = candidate.evidenceIds;
        }

        // verify-baseline（含原始请求+原始响应配对）
        for (String id : ids) {
            EvidenceStore.Evidence ev = store.get(id);
            if (ev != null && "verify-baseline".equals(ev.kind) && ev.response != null) {
                oResp = ev.response;
                if (oReq == null) {
                    oReq = ev.request;
                }
                break;
            }
        }
        // 回退：第一阶段 baseline 证据（同 URL）
        if (oResp == null && candidate != null && candidate.targetUrl != null) {
            for (EvidenceStore.Evidence ev : store.all()) {
                if ("baseline".equals(ev.kind) && ev.response != null && ev.request != null
                        && sameBase(ev.request.url, candidate.targetUrl)) {
                    oResp = ev.response;
                    break;
                }
            }
        }
        if (oResp == null) {
            missing.add("原始响应缺失（证据未保存或已被容量上限淘汰）");
        }

        // 最后一个 verify-probe = 判定所用往返
        for (String id : ids) {
            EvidenceStore.Evidence ev = store.get(id);
            if (ev != null && "verify-probe".equals(ev.kind)) {
                pReq = ev.request;
                pResp = ev.response;
            }
        }
        if (pReq == null) {
            missing.add("测试请求缺失（结论未经过主动探针，或证据已淘汰）");
        }
        if (pResp == null) {
            missing.add("测试响应缺失");
        }
        return new Bundle(oReq, pReq, oResp, pResp, missing);
    }

    private static boolean sameBase(String a, String b) {
        int qa = a.indexOf('?');
        int qb = b.indexOf('?');
        return (qa >= 0 ? a.substring(0, qa) : a).equals(qb >= 0 ? b.substring(0, qb) : b);
    }
}
