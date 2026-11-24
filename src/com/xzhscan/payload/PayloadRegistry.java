package com.xzhscan.payload;

import com.xzhscan.payload.PayloadLibrary.PayloadSpec;
import com.xzhscan.vendor.sql.SqlPayloadLibrary;
import com.xzhscan.vendor.sql.SqlPayloadLibrary.TimeProbe;
import com.xzhscan.vendor.sql.SqlPayloadLibrary.XrayProbe;

import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

/**
 * 统一 Payload 规则库（v2.2 重构核心）：
 *
 *  - 第一阶段 PayloadLibrary.DEFAULT_TIME_PAYLOADS（7 条）与第二阶段
 *    SqlPayloadLibrary（TIME/QUICK/XRAY/ERROR/OOB）不再各自独立调度；
 *    全部规则登记到本 Registry，带唯一 ID、家族、DBMS、上下文、处置状态与风险级；
 *  - 规则库与执行调度分离：引擎只向 Registry 请求"当前参数适用的默认规则集"；
 *  - 相同（dbms+template）的规则跨来源去重合并（QUICK 与 TIME_PROBES 重复项、
 *    XRAY_NUMERIC 与 XRAY_STRING 全部 8 条重复项），保留全部 sourceRef 供审计；
 *  - 旧规则全部保留为可审计资产（KEEP/CONDITIONAL/DISABLED/ISOLATED 四态），
 *    不物理删除；
 *  - OOB（带外/DNS/系统命令）ISOLATED：任何自动扫描路径都不会请求它们。
 *
 *  参数类型 ≠ SQL 上下文：sqlContext 描述 payload 期望的 SQL 引号上下文；
 *  引号闭合型（STRING）规则对"值在引号内"的常见形态自给自足，作为第一阶段默认集；
 *  裸算术型（NUMERIC）规则只在值可能落在引号外时有效，保留为资产/第二阶段 replace 用。
 */
public final class PayloadRegistry {

    /** 规则处置状态（对应 PAYLOAD_KEEP_DISABLE_MATRIX）。 */
    public enum RuleStatus {
        /** 默认集内执行（仍受总开关/上下文/stacked 开关约束）。 */
        KEEP,
        /** 条件执行：需显式配置开启（如 Oracle、多语句）。 */
        CONDITIONAL,
        /** 仅资产保留，不参与自动扫描。 */
        DISABLED,
        /** 与时间盲注彻底隔离（OOB/外部解析），任何自动路径不可达。 */
        ISOLATED
    }

    /**
     * 规则元数据（任务书示意 record 的落地版）。
     *
     * @param id               唯一 ID
     * @param family           家族标识（同族变体共享，如 mysql-sleep）
     * @param dbms             MySQL / MSSQL / PostgreSQL / Oracle / SQLite / GENERIC
     * @param sqlContext       SQL 引号上下文：STRING / NUMERIC / ANY
     * @param parameterContext 参数值形态：STRING / NUMBER
     * @param mutationMode     APPEND / REPLACE / NUMBER_TO_STRING_APPEND
     * @param evidenceType     time / time-orderby / error-bare / oob
     * @param stacked          是否多语句（模板含 ; 串联）
     * @param commentVariant   空格→注释变体（同族变体，默认不连发）
     * @param enabledByDefault 是否进入默认扫描集
     * @param riskLevel        low / medium / high（high=资源消耗或外部副作用）
     */
    public record PayloadMetadata(
            String id, String family, String dbms, String sqlContext, String parameterContext,
            String mutationMode, String evidenceType, boolean stacked, boolean commentVariant,
            boolean enabledByDefault, String riskLevel) {
    }

    /** 一条注册规则：元数据 + 模板原文 + 来源引用 + 处置状态。 */
    public record PayloadRule(PayloadMetadata meta, String template, List<String> sourceRefs, RuleStatus status) {
        public String id() {
            return meta.id();
        }

        public String family() {
            return meta.family();
        }

        public String dbms() {
            return meta.dbms();
        }

        public boolean replace() {
            return "REPLACE".equals(meta.mutationMode());
        }
    }

    private static final List<PayloadRule> RULES = Collections.unmodifiableList(build());
    private static final Map<String, PayloadRule> BY_ID = indexById();

    private PayloadRegistry() {
    }

    public static List<PayloadRule> all() {
        return RULES;
    }

    public static PayloadRule byId(String id) {
        return id == null ? null : BY_ID.get(id);
    }

    /** 同家族判定（调度去重用）。 */
    public static boolean sameFamily(PayloadRule a, PayloadRule b) {
        return a != null && b != null && a.meta.family().equals(b.meta.family());
    }

    // v3.5：phase1TimeRules 双重载已随被动时间探针子系统移除——时间规则资产仍登记
    // 在 RULES（审计/扩展点），运行时仅 Phase2 verifyTimeBased 按 QUICK/XRAY 序列消费。

    /** 第二阶段时间定向复核：按候选携带的规则 ID 取规则（不重新枚举）。 */
    public static PayloadRule phase2TimeRuleFor(String ruleId) {
        PayloadRule r = byId(ruleId);
        return r != null && r.meta.evidenceType().startsWith("time") ? r : null;
    }

    /** ORDER BY 家族规则（phase2；参数名仅是弱提示）。 */
    public static List<PayloadRule> phase2OrderRules() {
        List<PayloadRule> out = new ArrayList<>();
        for (PayloadRule r : RULES) {
            if ("time-orderby".equals(r.meta.evidenceType())) {
                out.add(r);
            }
        }
        return out;
    }

    /** 错误型裸表达式规则（XRAY_BARE_ERROR：md5 回显，phase2 错误模块专用）。 */
    public static List<PayloadRule> phase2BareErrorRules() {
        List<PayloadRule> out = new ArrayList<>();
        for (PayloadRule r : RULES) {
            if ("error-bare".equals(r.meta.evidenceType())) {
                out.add(r);
            }
        }
        return out;
    }

    /** OOB 规则（ISOLATED）：仅供审计与矩阵文档，自动扫描不可达。 */
    public static List<PayloadRule> oobRules() {
        List<PayloadRule> out = new ArrayList<>();
        for (PayloadRule r : RULES) {
            if ("oob".equals(r.meta.evidenceType())) {
                out.add(r);
            }
        }
        return out;
    }

    /** 跨来源模板重复统计（审计用：sourceRef 数 > 1 的规则）。 */
    public static Map<String, Integer> duplicateSourceCount() {
        Map<String, Integer> dup = new LinkedHashMap<>();
        for (PayloadRule r : RULES) {
            if (r.sourceRefs().size() > 1) {
                dup.put(r.id(), r.sourceRefs().size());
            }
        }
        return dup;
    }

    // ------------------------------------------------------------------
    // 登记（程序化分类 + 模板去重；模板原文零改动）
    // ------------------------------------------------------------------

    private static List<PayloadRule> build() {
        List<PayloadRule> out = new ArrayList<>();
        Map<String, PayloadRule> byTemplate = new LinkedHashMap<>();

        // ---- 1. 第一阶段遗产 7 条（v1.3-v2.1 曾全量执行；v2.2 起仅资产保留） ----
        // 家族代表由 TP-MYSQL-XOR-01 等规范模板承担，遗产条目全部 DISABLED。
        List<PayloadSpec> legacy = PayloadLibrary.DEFAULT_TIME_PAYLOADS;
        String[] legacyIds = {"P1-MYSQL-XOR-01", "P1-MSSQL-WAITFOR-01", "P1-MSSQL-WAITFOR-02",
                "P1-PG-PGSLEEP-01", "P1-ORA-PIPE-01", "P1-MSSQL-WAITFOR-03", "P1-PG-PGSLEEP-02"};
        for (int i = 0; i < legacy.size(); i++) {
            PayloadSpec s = legacy.get(i);
            register(out, byTemplate,
                    meta(legacyIds[i], s.dedupGroup(), s.db().name().equals("MSSQL") ? "MSSQL"
                                    : s.db().name().equals("PostgreSQL") ? "PostgreSQL"
                                    : s.db().name().equals("Oracle") ? "Oracle" : s.db().name(),
                            "STRING", "STRING", "NUMBER_TO_STRING_APPEND", "time",
                            s.stacked(), s.commentVariant(), false, s.stacked() ? "high" : "medium"),
                    s.raw(), "PayloadLibrary.DEFAULT_TIME_PAYLOADS#" + i, RuleStatus.DISABLED);
        }

        // ---- 2. QUICK_TIME_PROBES（统一时间候选基础；状态按 §5 逐条判定） ----
        // v3.8.3：SQLite RANDOMBLOB 大计算探针整体删除（用户决策——资源消耗不可控，
        // SQLite 场景改由字典页手动 Repeater；TIME_PROBES 资产表同步删除两条 SQLite）。
        List<TimeProbe> qt = SqlPayloadLibrary.QUICK_TIME_PROBES;
        // v4.0：状态按模板特征动态生成（含 ';' 的堆叠形态=CONDITIONAL，其余 KEEP）。
        // 此前是硬编码 8 元素数组——新增探针即越界，属于典型的"数据与代码耦合"脆点。
        RuleStatus[] qtStatus = new RuleStatus[qt.size()];
        for (int i = 0; i < qt.size(); i++) {
            qtStatus[i] = qt.get(i).template().contains(";")
                    ? RuleStatus.CONDITIONAL : RuleStatus.KEEP;
        }
        for (int i = 0; i < qt.size(); i++) {
            TimeProbe p = qt.get(i);
            String ctx = p.ctx() == SqlPayloadLibrary.Ctx.NUMERIC ? "NUMERIC" : "STRING";
            String mode = "NUMERIC".equals(ctx) ? "APPEND" : "NUMBER_TO_STRING_APPEND";
            register(out, byTemplate,
                    meta(qtId(i), qtFamily(p), p.db(), ctx, "STRING", mode, "time",
                            p.template().contains(";"), false,
                            qtStatus[i] == RuleStatus.KEEP && !p.template().contains(";"),
                            "low"),
                    p.template(), "SqlPayloadLibrary.QUICK_TIME_PROBES#" + i, qtStatus[i]);
        }

        // ---- 3. TIME_PROBES 完整表（家族代表保留，变体 DISABLED，特例单判） ----
        List<TimeProbe> tp = SqlPayloadLibrary.TIME_PROBES;
        for (int i = 0; i < tp.size(); i++) {
            TimeProbe p = tp.get(i);
            String tpl = p.template();
            String db = p.db();
            boolean stacked = tpl.contains(";");
            String ctx = p.ctx() == SqlPayloadLibrary.Ctx.NUMERIC ? "NUMERIC"
                    : p.ctx() == SqlPayloadLibrary.Ctx.ANY ? "ANY" : "STRING";
            String mode = "APPEND".equals(modeFor(ctx)) ? "APPEND" : "NUMBER_TO_STRING_APPEND";
            String family = qtFamily(p);
            String evidenceType = "time";
            RuleStatus status = RuleStatus.DISABLED;
            String risk = "low";
            boolean commentVariant = tpl.contains("/**/") || tpl.contains("/**");

            if ("Oracle".equals(db)) {
                if (tpl.contains("UTL_INADDR")) {
                    // DNS 式探针移出时间检测：外部解析耗时不能证明 SQL 时间盲注
                    family = "oracle-dns";
                    evidenceType = "oob";
                    status = RuleStatus.ISOLATED;
                    risk = "high";
                    commentVariant = false;
                } else {
                    status = RuleStatus.CONDITIONAL;
                    risk = "medium";
                }
            } else if (tpl.contains("BENCHMARK") || tpl.contains("ST_X(")) {
                // 不可控大计算/高资源消耗：默认禁用，禁止自动扫描
                // （v3.8.3：SQLite/RANDOMBLOB 子条件随探针删除——RULES 已无该来源）
                status = RuleStatus.DISABLED;
                risk = "high";
                commentVariant = false;
            } else if ("MySQL".equals(db) && tpl.startsWith("0'XOR(IF(1=1,SLEEP({S}),0))XOR'Z")) {
                // XOR 家族规范代表（带 {S} 占位）→ KEEP
                status = RuleStatus.KEEP;
                ctx = "STRING";
                mode = "NUMBER_TO_STRING_APPEND";
                commentVariant = false;
            } else if ("MySQL".equals(db) && "' AND SLEEP({S})-- -".equals(tpl)) {
                // 字符串上下文规范代表（模板与 QT#0 相同 → 自动合并）
                status = RuleStatus.KEEP;
            } else if ("PostgreSQL".equals(db) && " and pg_sleep({S})".equals(tpl)) {
                // 数值上下文规范代表 → KEEP（phase1 默认集不选用 NUMERIC 上下文，phase2 资产）
                status = RuleStatus.KEEP;
            }
            register(out, byTemplate,
                    meta("TP-" + tpSuffix(db, i), family, db, ctx, "STRING", mode, evidenceType,
                            stacked, commentVariant, status == RuleStatus.KEEP && !stacked, risk),
                    tpl, "SqlPayloadLibrary.TIME_PROBES#" + i, status);
        }

        // ---- 4. XRAY_ORDER_PROBES（ORDER BY 家族，phase2 专用；参数名仅弱提示） ----
        List<XrayProbe> xo = SqlPayloadLibrary.XRAY_ORDER_PROBES;
        String[] xoIds = {"XO-MYSQL-ORDERBY-01", "XO-MYSQL-ORDERBY-02", "XO-PG-ORDERBY-01",
                "XO-MYSQL-ORDERBY-03", "XO-MYSQL-ORDERBY-04"};
        for (int i = 0; i < xo.size(); i++) {
            XrayProbe p = xo.get(i);
            register(out, byTemplate,
                    meta(xoIds[i], p.db().toLowerCase(Locale.ROOT) + "-orderby", p.db(), "ANY",
                            "STRING", p.replace() ? "REPLACE" : "APPEND", "time-orderby",
                            false, false, false, "low"),
                    p.template(), "SqlPayloadLibrary.XRAY_ORDER_PROBES#" + i, RuleStatus.KEEP);
        }

        // ---- 5. XRAY_NUMERIC_PROBES（引号前缀=STRING 上下文；replace 语义保留） ----
        List<XrayProbe> xn = SqlPayloadLibrary.XRAY_NUMERIC_PROBES;
        int[] xrCounter = {0, 0, 0, 0};
        for (int i = 0; i < xn.size(); i++) {
            XrayProbe p = xn.get(i);
            boolean quoted = p.template().startsWith("'") || p.template().startsWith("\"")
                    || p.template().startsWith("`");
            String ctx = quoted ? "STRING" : "NUMERIC";
            int dbIdx = dbIndex(p.db());
            xrCounter[dbIdx]++;
            String dbTag = p.db().toLowerCase(Locale.ROOT).replace("mysql", "MYSQL")
                    .replace("postgresql", "PG").replace("mssql", "MSSQL").replace("oracle", "ORA");
            String ctxTag = quoted ? "STR" : "NUM";
            RuleStatus st = "Oracle".equals(p.db()) ? RuleStatus.CONDITIONAL : RuleStatus.KEEP;
            register(out, byTemplate,
                    meta("XR-" + dbTag + "-" + ctxTag + "-" + String.format("%02d", xrCounter[dbIdx]),
                            p.db().toLowerCase(Locale.ROOT) + "-xr", p.db(), ctx,
                            p.replace() ? "NUMBER" : "STRING",
                            p.replace() ? "REPLACE" : "APPEND", "time",
                            p.template().contains(";"), false, false, "low"),
                    p.template(), "SqlPayloadLibrary.XRAY_NUMERIC_PROBES#" + i, st);
        }
        // ---- 5b. XRAY_STRING_PROBES（与 NUMERIC 组模板完全重复 → 全部合并到既有 ID） ----
        List<XrayProbe> xs = SqlPayloadLibrary.XRAY_STRING_PROBES;
        for (int i = 0; i < xs.size(); i++) {
            XrayProbe p = xs.get(i);
            register(out, byTemplate,
                    meta("XS-STR-" + String.format("%02d", i), p.db().toLowerCase(Locale.ROOT) + "-xr",
                            p.db(), "STRING", "STRING", p.replace() ? "REPLACE" : "APPEND", "time",
                            p.template().contains(";"), false, false, "low"),
                    p.template(), "SqlPayloadLibrary.XRAY_STRING_PROBES#" + i, RuleStatus.KEEP);
        }

        // ---- 6. XRAY_BARE_ERROR_PROBES（错误型模块专用，不计入时间规则数） ----
        List<XrayProbe> be = SqlPayloadLibrary.XRAY_BARE_ERROR_PROBES;
        String[] beIds = {"BE-MYSQL-ERR-01", "BE-MSSQL-ERR-01"};
        for (int i = 0; i < be.size(); i++) {
            register(out, byTemplate,
                    meta(beIds[i], be.get(i).db().toLowerCase(Locale.ROOT) + "-bare-error",
                            be.get(i).db(), "ANY", "STRING", be.get(i).replace() ? "REPLACE" : "APPEND",
                            "error-bare", false, false, false, "low"),
                    be.get(i).template(), "SqlPayloadLibrary.XRAY_BARE_ERROR_PROBES#" + i, RuleStatus.KEEP);
        }

        // ---- 7. OOB_PROBES（ISOLATED：DNS/文件访问/系统命令，任何自动路径不可达） ----
        List<SqlPayloadLibrary.OobProbe> oob = SqlPayloadLibrary.OOB_PROBES;
        String[] oobIds = {"OOB-MYSQL-UNC-01", "OOB-MYSQL-UNC-02", "OOB-MSSQL-DIRTREE-01",
                "OOB-MSSQL-FILEEXIST-01", "OOB-ORA-UTL-01", "OOB-PG-COPY-01"};
        for (int i = 0; i < oob.size(); i++) {
            SqlPayloadLibrary.OobProbe p = oob.get(i);
            register(out, byTemplate,
                    meta(oobIds[i], "oob", p.db(), "ANY",
                            p.ctx() == SqlPayloadLibrary.Ctx.NUMERIC ? "NUMBER" : "STRING",
                            "APPEND", "oob", p.template().contains(";"), false, false, "high"),
                    p.template(), "SqlPayloadLibrary.OOB_PROBES#" + i, RuleStatus.ISOLATED);
        }
        return out;
    }

    private static String modeFor(String ctx) {
        return "NUMERIC".equals(ctx) ? "APPEND" : "NUMBER_TO_STRING_APPEND";
    }

    private static String qtId(int i) {
        return switch (i) {
            case 0 -> "QT-MYSQL-SLEEP-01";
            case 1 -> "QT-MYSQL-SLEEP-02";
            case 2 -> "QT-MSSQL-WAITFOR-01";
            case 3 -> "QT-MSSQL-WAITFOR-02";
            case 4 -> "QT-PG-PGSLEEP-01";
            case 5 -> "QT-PG-PGSLEEP-02";
            case 6 -> "QT-ORA-PIPE-01";
            case 7 -> "QT-ORA-PIPE-02";
            // v4.0：sqlmap query-SLEEP 形态（追加在原 8 条之后，保持旧 ID 不变）
            case 8 -> "QT-MYSQL-QSLEEP-01";
            case 9 -> "QT-MYSQL-QSLEEP-02";
            // 兜底不再复用已删除规则的 ID（此前 default 返回 QT-SQLITE-RBLOB-01，
            // 新增探针即与历史 ID 冲突 → 唯一性断言失败）
            default -> "QT-EXTRA-" + (i + 1);
        };
    }

    private static String qtFamily(TimeProbe p) {
        String t = p.template().toLowerCase(Locale.ROOT);
        if (t.contains("benchmark")) {
            return "mysql-benchmark";
        }
        if (t.contains("st_x(") || t.contains("st_buffer")) {
            return "mysql-spatial";
        }
        if (t.contains("dbms_pipe")) {
            return "oracle-pipe";
        }
        if (t.contains("dbms_lock")) {
            return "oracle-lock";
        }
        if (t.contains("utl_inaddr")) {
            return "oracle-dns";
        }
        if (t.contains("waitfor")) {
            return "mssql-waitfor";
        }
        if (t.contains("pg_sleep")) {
            return "pgsql-pg-sleep";
        }
        if (t.contains("xor")) {
            return "mysql-xor";
        }
        if (t.contains("elt(")) {
            return "mysql-elt";
        }
        if (t.contains("json_keys")) {
            return "mysql-jsonkeys";
        }
        return "mysql-sleep";
    }

    private static String tpSuffix(String db, int i) {
        return db.toLowerCase(Locale.ROOT).replace("postgresql", "pg")
                .replace("mysql", "mysql").replace("mssql", "mssql")
                .replace("sqlite", "sqlite") + "-" + String.format("%02d", i);
    }

    private static int dbIndex(String db) {
        return switch (db) {
            case "MySQL" -> 0;
            case "PostgreSQL" -> 1;
            case "MSSQL" -> 2;
            case "Oracle" -> 3;
            default -> 0;
        };
    }

    /**
     * 登记：同（dbms + 模板原文）跨来源去重合并（合并 sourceRef），新模板才产生新条目。
     * 合并时保留首个条目的元数据/状态（由 KEEP 代表承担），后续来源仅追加引用。
     */
    private static void register(List<PayloadRule> out, Map<String, PayloadRule> byTemplate,
                                 PayloadMetadata meta, String template, String sourceRef, RuleStatus status) {
        String key = meta.dbms() + "|" + template;
        PayloadRule existing = byTemplate.get(key);
        if (existing != null) {
            List<String> refs = new ArrayList<>(existing.sourceRefs());
            refs.add(sourceRef);
            PayloadRule merged = new PayloadRule(existing.meta(), existing.template(),
                    Collections.unmodifiableList(refs), existing.status());
            out.set(out.indexOf(existing), merged);
            byTemplate.put(key, merged);
            return;
        }
        PayloadRule rule = new PayloadRule(meta, template,
                Collections.singletonList(sourceRef), status);
        out.add(rule);
        byTemplate.put(key, rule);
    }

    private static PayloadMetadata meta(String id, String family, String dbms, String sqlContext,
                                        String parameterContext, String mutationMode, String evidenceType,
                                        boolean stacked, boolean commentVariant, boolean enabledByDefault,
                                        String riskLevel) {
        return new PayloadMetadata(id, family, dbms, sqlContext, parameterContext, mutationMode,
                evidenceType, stacked, commentVariant, enabledByDefault, riskLevel);
    }

    private static Map<String, PayloadRule> indexById() {
        Map<String, PayloadRule> m = new LinkedHashMap<>();
        for (PayloadRule r : RULES) {
            m.put(r.id(), r);
        }
        return Collections.unmodifiableMap(m);
    }
}
