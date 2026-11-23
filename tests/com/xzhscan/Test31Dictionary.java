package com.xzhscan;

import com.xzhscan.dictionary.DictEntry;
import com.xzhscan.dictionary.GeneratorAssets;
import com.xzhscan.dictionary.InfoGenerator;
import com.xzhscan.dictionary.SqlDict;
import com.xzhscan.dictionary.SqlmapCmdDict;
import com.xzhscan.dictionary.WeakPasswordGenerator;
import com.xzhscan.dictionary.PathDict;
import com.xzhscan.dictionary.XssDict;
import com.xzhscan.ui.DictionaryUi;

import javax.swing.JTabbedPane;

import static com.xzhscan.MiniTest.TestContext;

/**
 * 测试三十一：Dictionary 页签（v3.6）。
 *  - SQL 库名注入：五类 DBMS 齐备，直查/报错/UNION/布尔差分/枚举五组；
 *    盲注只留布尔差分（成对真/假语句），时间型不入典；
 *  - sqlmap 命令：注入类型 technique/https 专项/代理/出库名链路齐备；
 *  - XSS 字典：分组与条目数下限、关键 payload 原样保留；
 *  - 路径字典资产：Linux/Windows 六组条数与内容抽检；
 *  - DictionaryUi：headless 构造五子页不炸。
 */
public final class Test31Dictionary {

    public static void run(TestContext t) {
        // ---------- 1. SQL 注入字典（v3.8：细分类 DBMS·注入类型 + 字符型/数字型标注） ----------
        // 5 DBMS × 5 注入类型 = 25 细分类（v3.8.1 加 ORDER BY）
        t.checkEq(25, SqlDict.categories().size(), "SQL dict: 25 sub-categories (5 DBMS x 5 types)");
        for (String dbms : new String[]{"MySQL", "MSSQL", "Oracle", "PostgreSQL", "SQLite"}) {
            for (String kind : new String[]{"报错注入", "UNION注入", "布尔盲注差分", "时间盲注", "ORDER BY 注入"}) {
                String cat = dbms + "·" + kind;
                t.check(SqlDict.categories().contains(cat), "sub-category exists: " + cat);
            }
        }
        // ORDER BY 组：布尔差分 + 时间盲注条目齐备（MySQL 另有形态说明）
        for (String dbms : new String[]{"MySQL", "MSSQL", "Oracle", "PostgreSQL", "SQLite"}) {
            java.util.List<DictEntry> ob = SqlDict.byCategory(dbms + "·ORDER BY 注入");
            t.check(ob.size() >= 2, dbms + " ORDER BY group has >=2 entries (" + ob.size() + ")");
            t.check(ob.stream().anyMatch(e -> e.label().contains("布尔差分")),
                    dbms + " ORDER BY boolean-diff entry present");
            t.check(ob.stream().anyMatch(e -> e.label().contains("时间盲注")),
                    dbms + " ORDER BY time-based entry present");
        }
        String orderSql = join(SqlDict.byCategory("MySQL·ORDER BY 注入"))
                + join(SqlDict.byCategory("MSSQL·ORDER BY 注入"))
                + join(SqlDict.byCategory("PostgreSQL·ORDER BY 注入"))
                + join(SqlDict.byCategory("Oracle·ORDER BY 注入"))
                + join(SqlDict.byCategory("SQLite·ORDER BY 注入"));
        t.check(orderSql.contains(",(SELECT (CASE WHEN (1=1) THEN SLEEP(5) ELSE 1 END))"),
                "ORDER BY mysql sleep payload present");
        t.check(orderSql.contains("INFORMATION_SCHEMA.PLUGINS"), "ORDER BY mysql boolean payload present");
        t.check(orderSql.contains("UNION ALL SELECT 2"), "ORDER BY mssql boolean payload present");
        t.check(orderSql.contains("GENERATE_SERIES(1,1"), "ORDER BY pg generate_series variant present");
        t.check(orderSql.contains("RANDOMBLOB(500000000/2)"), "ORDER BY sqlite randomblob payload present");
        // 报错方法数下限（MySQL 5 个方法）
        t.check(SqlDict.byCategory("MySQL·报错注入").size() >= 5,
                "MySQL error-based methods >=5 (" + SqlDict.byCategory("MySQL·报错注入").size() + ")");
        t.check(SqlDict.byCategory("MSSQL·报错注入").size() >= 4, "MSSQL error-based methods >=4");
        t.check(SqlDict.byCategory("Oracle·报错注入").size() >= 3, "Oracle error-based methods >=3");
        t.check(SqlDict.byCategory("PostgreSQL·报错注入").size() >= 3, "PG error-based methods >=3");
        String allSql = join(SqlDict.all());
        // 每条报错/UNION/时间条目标注字符型与数字型两种形态（ORDER BY 位为单一形态，豁免）
        long withBoth = SqlDict.all().stream()
                .filter(e -> !e.label().startsWith("说明"))
                .filter(e -> !e.category().contains("布尔"))
                .filter(e -> !e.category().contains("ORDER BY"))
                .filter(e -> e.body().contains("字符型：") && e.body().contains("数字型："))
                .count();
        long expectBoth = SqlDict.all().stream()
                .filter(e -> !e.label().startsWith("说明"))
                .filter(e -> !e.category().contains("布尔"))
                .filter(e -> !e.category().contains("ORDER BY"))
                .count();
        t.checkEq((int) expectBoth, (int) withBoth, "every non-boolean entry marks char/numeric forms");
        // 布尔差分含四行真/假 × 字符/数字
        for (String dbms : new String[]{"MySQL", "MSSQL", "Oracle", "PostgreSQL", "SQLite"}) {
            String boolBody = SqlDict.byCategory(dbms + "·布尔盲注差分").get(0).body();
            t.check(boolBody.contains("真·数字型") && boolBody.contains("假·数字型")
                            && boolBody.contains("真·字符型") && boolBody.contains("假·字符型"),
                    dbms + " boolean diff covers 1=1/1=2 in both contexts");
        }
        t.check(allSql.contains("' AND 'a'='a") && allSql.contains("' AND 'a'='b"),
                "boolean diff pair present (simple 1=1 style)");
        t.check(!allSql.contains(">64") && !allSql.contains(">122"),
                "no per-char bisect payloads (no ORD/ASCII threshold pairs)");
        // 时间盲注五类 DBMS 各就位
        t.check(allSql.contains("SLEEP(5)"), "MySQL sleep payload present");
        t.check(allSql.contains("WAITFOR DELAY '0:0:5'"), "MSSQL waitfor payload present");
        t.check(allSql.contains("DBMS_PIPE.RECEIVE_MESSAGE('a',5)"), "Oracle pipe payload present");
        t.check(allSql.contains("pg_sleep(5)"), "PostgreSQL pg_sleep payload present");
        t.check(allSql.contains("RANDOMBLOB(500000000/2)"), "SQLite randomblob payload present");
        // 报错/UNION 出库名主力保留
        t.check(allSql.contains("extractvalue") && allSql.contains("updatexml")
                        && allSql.contains("EXP(~"), "MySQL error-based functions present");
        t.check(allSql.contains("CONVERT(int,(SELECT DB_NAME()))") && allSql.contains("HAVING 1=1"),
                "MSSQL CONVERT + HAVING present");
        t.check(allSql.contains("CAST(current_database() AS NUMERIC)") && allSql.contains("::int"),
                "PG CAST + :: present");
        t.check(allSql.contains("sqlite_master"), "SQLite master table (union)");
        // 直查语句整体删除
        t.check(!allSql.contains("SELECT SYS_CONTEXT"), "no Oracle direct-query (v3.7.1)");
        t.check(!allSql.contains("LIMIT 0,1"), "no paging direct-queries (v3.7.1)");

        // ---------- 2. sqlmap 命令 ----------
        t.checkEq(6, SqlmapCmdDict.categories().size(), "sqlmap dict: 6 scene groups");
        String allCmd = join(SqlmapCmdDict.all());
        for (String tech : new String[]{"--technique=B", "--technique=T", "--technique=E",
                "--technique=U", "--technique=S"}) {
            t.check(allCmd.contains(tech), "sqlmap technique present: " + tech);
        }
        t.check(allCmd.contains("--force-ssl"), "sqlmap https: --force-ssl present");
        t.check(allCmd.contains("--proxy="), "sqlmap proxy to burp present");
        t.check(allCmd.contains("--current-db") && allCmd.contains("--dbs"),
                "sqlmap db-enumeration chain present");
        t.check(allCmd.contains("--tamper="), "sqlmap tamper present");
        t.check(allCmd.contains("--data='{\"id\":1}'"), "sqlmap JSON body example present");
        t.check(allCmd.contains("--cert="), "sqlmap mTLS cert present");

        // ---------- 3. XSS 字典 ----------
        t.check(XssDict.categories().size() >= 6, "xss dict groups >=6 (incl harmless)");
        t.check(XssDict.categories().contains("无危害验证 payload"), "xss harmless group present");
        t.check(XssDict.all().size() >= 35, "xss dict entries >=35 (" + XssDict.all().size() + ")");
        String harmless = join(XssDict.byCategory("无危害验证 payload"));
        t.check(harmless.contains("<h1>123</h1>") && harmless.contains("<s>123"),
                "xss harmless payloads kept (h1/s tags)");
        t.check(harmless.contains("</tExtArEa><h1>123</h1>#"), "xss harmless textarea escape kept");
        String allXss = join(XssDict.all());
        t.check(allXss.contains("</tExtArEa>"), "xss: textarea escape kept");
        t.check(allXss.contains("%26Tab;"), "xss: Tab-encoding pseudo-protocol kept");
        t.check(allXss.contains("<sc<script>ript>alert(4)</script>"), "xss: double-write bypass kept");
        t.check(allXss.contains("onmouseover=confirm`x1s2s3`"), "xss: backtick confirm kept");
        t.check(allXss.contains("YWxlcnQoZG9jdW1lbnQuY29va2llKTs="), "xss: atob payload kept");
        t.check(allXss.contains("constructor.constructor('alert(1)')()"), "xss: angular escape kept");
        t.check(allXss.contains("\\u0061\\u006c\\u0065\\u0072\\u0074"), "xss: unicode alert kept");
        t.check(allXss.contains("dETAILS%0Aopen%0AonToGgle"), "xss: %0A details payload kept");
        t.check(allXss.contains("onstart=alert(1)") || allXss.contains("onStArt=alert(1)"),
                "xss: marquee onstart kept");
        // 源码级转义守卫：\\u 不应被编译成真实 unicode（条目必须仍含反斜杠原文）
        t.check(allXss.contains("confir\\u006d"), "xss: confir\\u006d raw text preserved");

        // ---------- 4. 路径字典（v3.7.1：Linux 三组 + Windows 三组） ----------
        t.check(splitCount(PathDict.LINUX_PATH) > 100, "linux paths >100");
        t.check(splitCount(PathDict.LINUX_CONFIG) > 80, "linux configs >80");
        t.check(splitCount(PathDict.LINUX_LOG) > 50, "linux logs >50");
        t.check(splitCount(PathDict.WINDOWS_PATH) > 40, "windows paths >40");
        t.check(splitCount(PathDict.WINDOWS_CONFIG) > 30, "windows configs >30");
        t.check(splitCount(PathDict.WINDOWS_LOG) > 30, "windows logs >30");
        t.check(PathDict.LINUX_PATH.contains("/etc/passwd"), "linux path content sanity");
        t.check(PathDict.WINDOWS_PATH.contains("C:\\Windows\\System32\\config\\SAM"),
                "windows path content sanity (SAM)");
        t.check(PathDict.WINDOWS_CONFIG.contains("web.config"), "windows config content sanity");
        t.check(PathDict.WINDOWS_LOG.contains("winevt"), "windows log content sanity (evtx)");

        // ---------- 5. 生成器资产 ----------
        t.check(GeneratorAssets.ID_AREA_CODES.length > 3000,
                "id area codes >3000 (" + GeneratorAssets.ID_AREA_CODES.length + ")");
        t.check(GeneratorAssets.CREDIT_DEPT.length == GeneratorAssets.CREDIT_ORG_TYPE.length,
                "credit dept/org-type arrays aligned");
        t.check(GeneratorAssets.BANK_BINS.length > 100,
                "bank bins >100 (" + GeneratorAssets.BANK_BINS.length + ")");
        t.check(GeneratorAssets.WEAK_TOP100.length == 100, "weak top100 = 100");

        // ---------- 6. InfoGenerator 校验位正确性 ----------
        for (int i = 0; i < 50; i++) {
            InfoGenerator.Info id = InfoGenerator.randomIdCard();
            if (id.value().length() != 18) {
                t.check(false, "idcard length != 18: " + id.value());
                break;
            }
            String body17 = id.value().substring(0, 17);
            int[] weights = {7, 9, 10, 5, 8, 4, 2, 1, 6, 3, 7, 9, 10, 5, 8, 4, 2};
            char[] map = {'1', '0', 'X', '9', '8', '7', '6', '5', '4', '3', '2'};
            int sum = 0;
            for (int j = 0; j < 17; j++) {
                sum += weights[j] * (body17.charAt(j) - '0');
            }
            if (id.value().charAt(17) != map[sum % 11]) {
                t.check(false, "idcard checksum mismatch: " + id.value());
                break;
            }
            t.check(true, "idcard checksum ok (round " + i + ")");
        }
        for (int i = 0; i < 20; i++) {
            InfoGenerator.Info org = InfoGenerator.randomOrgCode();
            if (org.value().length() != 10 || org.value().charAt(8) != '-') {
                t.check(false, "org code format: " + org.value());
                break;
            }
            if (!org.value().substring(9).equals(InfoGenerator.mod11Check(org.value().substring(0, 8)))) {
                t.check(false, "org checksum mismatch: " + org.value());
                break;
            }
            t.check(true, "org code checksum ok (round " + i + ")");
        }
        InfoGenerator.Info credit = InfoGenerator.randomCreditCode();
        t.check(credit.value().length() == 18, "credit code length 18");
        t.check(credit.value().matches("[0-9A-HJ-NPQRTUWXY]{18}"), "credit code charset (no I/O/S/V/Z)");
        for (int i = 0; i < 30; i++) {
            InfoGenerator.Info bank = InfoGenerator.randomBankCard();
            if (bank.value().length() != 16) {
                t.check(false, "bank card length != 16: " + bank.value());
                break;
            }
            int sum = 0;
            for (int j = 0; j < 16; j++) {
                int d = bank.value().charAt(j) - '0';
                if ((15 - j) % 2 == 1) {
                    d = d * 2 > 9 ? d * 2 - 9 : d * 2;
                }
                sum += d;
            }
            if (sum % 10 != 0) {
                t.check(false, "luhn fail: " + bank.value());
                break;
            }
            t.check(true, "luhn ok (round " + i + ")");
        }
        InfoGenerator.Info phone = InfoGenerator.randomPhone();
        t.check(phone.value().matches("1[3-9]\\d{9}"), "phone format 11 digits");

        // ---------- 7. WeakPasswordGenerator ----------
        java.util.Map<String, String> empty = java.util.Map.of();
        java.util.List<String> base = WeakPasswordGenerator.generate(empty);
        t.checkEq(100, base.size(), "empty input -> top100 only");
        java.util.Map<String, String> filled = java.util.Map.of("名字简称", "xzh", "QQ号", "123456");
        java.util.List<String> dict = WeakPasswordGenerator.generate(filled);
        t.check(dict.size() > 100 + 28, "filled dict expands templates (" + dict.size() + ")");
        boolean hasXzh = false;
        boolean noPlaceholder = true;
        for (String s : dict) {
            if (s.contains("xzh")) {
                hasXzh = true;
            }
            if (s.contains("#名字简称#") || s.contains("#QQ号#")) {
                noPlaceholder = false;
            }
        }
        t.check(hasXzh, "placeholder replaced with user input");
        t.check(noPlaceholder, "no leftover placeholders in output");
        t.check(dict.contains("123456"), "top100 still present");

        // ---------- 8. URL 空格编码（Burp GET 参数防截断） ----------
        String enc = DictionaryUi.urlSpaceEncode("' AND extractvalue(1,concat(0x7e,(SELECT DATABASE()),0x7e))-- -");
        t.check(!enc.contains(" ") && enc.contains("%20AND%20"),
                "urlSpaceEncode replaces all spaces with %20");
        t.checkEq("' AND 'a'='a", DictionaryUi.urlSpaceEncode("' AND 'a'='a").replace("%20", " "),
                "urlSpaceEncode round-trips");

        // ---------- 9. DictionaryUi headless 构造 ----------
        try {
            DictionaryUi ui = new DictionaryUi();
            JTabbedPane tabs = ui.build();
            t.checkEq(6, tabs.getTabCount(), "DictionaryUi: 6 sub-tabs");
            t.checkEq("SQL库名注入", tabs.getTitleAt(0), "DictionaryUi sub-tab 0 title");
            t.checkEq("sqlmap命令", tabs.getTitleAt(1), "DictionaryUi sub-tab 1 title");
            t.checkEq("XSS字典", tabs.getTitleAt(2), "DictionaryUi sub-tab 2 title");
            t.checkEq("路径字典", tabs.getTitleAt(3), "DictionaryUi sub-tab 3 title");
            t.checkEq("信息生成", tabs.getTitleAt(4), "DictionaryUi sub-tab 4 title");
            t.checkEq("字典生成", tabs.getTitleAt(5), "DictionaryUi sub-tab 5 title");
        } catch (Exception e) {
            t.check(false, "DictionaryUi headless build failed: " + e);
        }
    }

    private static String join(java.util.List<DictEntry> list) {
        StringBuilder sb = new StringBuilder();
        for (DictEntry e : list) {
            sb.append(e.category()).append('|').append(e.label()).append('|')
                    .append(e.body()).append('|').append(e.note()).append('\n');
        }
        return sb.toString();
    }

    private static int splitCount(String data) {
        int n = 0;
        for (String s : data.split("#")) {
            if (!s.isEmpty()) {
                n++;
            }
        }
        return n;
    }

    private static String lower(String s) {
        return s.toLowerCase(java.util.Locale.ROOT);
    }
}
