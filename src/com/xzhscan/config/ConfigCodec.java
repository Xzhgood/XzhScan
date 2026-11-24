package com.xzhscan.config;

import java.util.Map;
import java.util.TreeMap;

/**
 * 配置序列化（key=value 行格式，存 Burp extensionData）。
 * 只持久化用户可改项；解析时未知键忽略、缺键保持默认。
 * configVersion：v2.3.0 起写入；无版本标记的历史配置按迁移规则升级
 * （见 {@link #MIGRATIONS_V23}）——改默认值对已保存配置无效，必须走版本迁移。
 */
public final class ConfigCodec {

    private static final String NL = String.valueOf((char) 10);
    private static final String ESC_NL = String.valueOf((char) 92) + 'n';

    /** 当前配置格式版本（与插件 VERSION 同步维护）。 */
    public static final String CONFIG_VERSION = "3.9.7";

    /**
     * 历史迁移记录（说明性质，供加载日志与审计）：
     * <ul>
     *   <li>v2.3.0：stacked/Oracle 时间开关 false→true（当时的默认覆盖面恢复）；</li>
     *   <li>v3.0.0：人工化转向，probeTimePayloads →false；v3.1 autoVerify 整体移除；</li>
     *   <li>v3.5.0：被动时间探针子系统整体移除（probeTimePayloads/timeProbePassRatio/
     *       allowStackedProbes/probeOracleTime 四键读取即忽略）——被动= XiaSQL 纯差分，
     *       时间盲注走右键人工触发的 Phase2 全模块序列（模板覆盖五类 DBMS 且有三级
     *       sleep 阶梯定罪，强于被动路径）；</li>
     *   <li>v3.9.3：AuthScan 默认关闭——旧配置的 authEnabled=true 是旧默认值残留
     *       而非用户显式偏好，迁移强制归位 false（未在 AuthScan 页勾选启用=
     *       完全不干活、零日志）。</li>
     * </ul>
     */
    public static final String MIGRATION_NOTES =
            "v2.3.0: stacked/oracle time ->true; v3.0.0: passive time ->false; "
                    + "v3.1: autoVerify removed; v3.5.0: passive time subsystem removed "
                    + "(probeTimePayloads/timeProbePassRatio/allowStackedProbes/probeOracleTime keys ignored); "
                    + "v3.9.3: AuthScan default off (legacy authEnabled=true reset)";

    public static final int MAX_INTERVAL_MS = 60_000;
    public static final int MIN_TIMEOUT_MS = 1_000;
    public static final int MAX_TIMEOUT_MS = 600_000;

    private ConfigCodec() {
    }

    public static String toProperties(XzhScanConfig c) {
        Map<String, String> m = new TreeMap<>();
        m.put("configVersion", CONFIG_VERSION);
        m.put("phase1Enabled", String.valueOf(c.phase1Enabled));
        m.put("phase2Enabled", String.valueOf(c.phase2Enabled));
        m.put("watchProxy", String.valueOf(c.watchProxy));
        m.put("watchRepeater", String.valueOf(c.watchRepeater));
        m.put("watchScanner", String.valueOf(c.watchScanner));
        m.put("watchIntruder", String.valueOf(c.watchIntruder));
        m.put("jsonStrictValidation", String.valueOf(c.jsonStrictValidation));
        m.put("timingStdCoeff", String.valueOf(c.timingStdCoeff));
        m.put("allowTimeBasedProbe", String.valueOf(c.allowTimeBasedProbe));
        m.put("timeDelaySeconds", String.valueOf(c.timeDelaySeconds));
        m.put("minValidDelayMs", String.valueOf(c.minValidDelayMs));
        m.put("denyWriteLookingEndpoints", String.valueOf(c.denyWriteLookingEndpoints));
        m.put("baselineSamples", String.valueOf(c.baselineSamples));
        m.put("maxConcurrentScans", String.valueOf(c.maxConcurrentScans));
        m.put("weakDeltaThreshold", String.valueOf(c.weakDeltaThreshold));
        m.put("minDifferenceScore", String.valueOf(c.minDifferenceScore));
        m.put("requestIntervalMs", String.valueOf(c.requestIntervalMs));
        m.put("requestTimeoutMs", String.valueOf(c.requestTimeoutMs));
        m.put("dedupWindowMinutes", String.valueOf(c.dedupWindowMinutes));
        m.put("authEnabled", String.valueOf(c.authEnabled));
        m.put("authFilterEnabled", String.valueOf(c.authFilterEnabled));
        m.put("authLowAuthHeaders", c.authLowAuthHeaders.replace(NL, ESC_NL));
        m.put("authNoAuthHeaders", c.authNoAuthHeaders.replace(NL, ESC_NL));
        m.put("authWhitelistDomains", c.authWhitelistDomains.replace(NL, ESC_NL));
        m.put("authExtraExtensions", c.authExtraExtensions == null ? "" : c.authExtraExtensions);
        m.put("fuzzPathBlacklist", c.fuzzPathBlacklist.replace(NL, ESC_NL));
        m.put("fuzzPathStaticExts", c.fuzzPathStaticExts == null ? "" : c.fuzzPathStaticExts);
        m.put("fuzzPathRemoveQuery", String.valueOf(c.fuzzPathRemoveQuery));
        m.put("fuzzPathRemoveFragment", String.valueOf(c.fuzzPathRemoveFragment));
        m.put("domainWhitelist", c.domainWhitelist == null ? "" : c.domainWhitelist);
        m.put("urlBlacklist", c.urlBlacklist == null ? "" : c.urlBlacklist);
        StringBuilder sb = new StringBuilder();
        for (Map.Entry<String, String> e : m.entrySet()) {
            sb.append(e.getKey()).append('=').append(e.getValue().replace("\n", "\\n")).append('\n');
        }
        return sb.toString();
    }

    /**
     * 解析配置。返回是否执行了版本迁移（调用方据此打日志并触发一次持久化）。
     * 返回值变更（void→boolean）对既有"语句式调用"无破坏。
     */
    public static boolean fromProperties(String text, XzhScanConfig c) {
        String ver = null;
        for (String line : text.split("\n")) {
            int eq = line.indexOf('=');
            if (eq <= 0) {
                continue;
            }
            String k = line.substring(0, eq).trim();
            String v = line.substring(eq + 1).replace("\\n", "\n").trim();
            if ("configVersion".equals(k)) {
                ver = v;
                continue;
            }
            switch (k) {
                case "phase1Enabled" -> c.phase1Enabled = Boolean.parseBoolean(v);
                case "phase2Enabled" -> c.phase2Enabled = Boolean.parseBoolean(v);
                // autoVerify（v3.1 移除）：旧键忽略
                case "watchProxy" -> c.watchProxy = Boolean.parseBoolean(v);
                case "watchRepeater" -> c.watchRepeater = Boolean.parseBoolean(v);
                case "watchScanner" -> c.watchScanner = Boolean.parseBoolean(v);
                case "watchIntruder" -> c.watchIntruder = Boolean.parseBoolean(v);
                case "jsonStrictValidation" -> c.jsonStrictValidation = Boolean.parseBoolean(v);
                case "timingStdCoeff" -> c.timingStdCoeff = parseDouble(v, c.timingStdCoeff, 3.0, 7.0);
                case "allowTimeBasedProbe" -> c.allowTimeBasedProbe = Boolean.parseBoolean(v);
                case "timeDelaySeconds" -> c.timeDelaySeconds = parseInt(v, c.timeDelaySeconds, 2, 10);
                case "minValidDelayMs" -> c.minValidDelayMs = (long) parseInt(v, (int) c.minValidDelayMs, 500, 5000);
                case "denyWriteLookingEndpoints" -> c.denyWriteLookingEndpoints = Boolean.parseBoolean(v);
                case "baselineSamples" -> c.baselineSamples = parseInt(v, c.baselineSamples, 2, 20);
                case "maxConcurrentScans" -> c.maxConcurrentScans = parseInt(v, c.maxConcurrentScans, 1, 8);
                case "weakDeltaThreshold" -> c.weakDeltaThreshold = parseInt(v, c.weakDeltaThreshold, 0, 10);
                case "minDifferenceScore" -> c.minDifferenceScore = parseDouble(v, c.minDifferenceScore, 0.05, 1.0);
                case "requestIntervalMs" -> c.requestIntervalMs = parseInt(v, c.requestIntervalMs, 0, MAX_INTERVAL_MS);
                case "requestTimeoutMs" -> c.requestTimeoutMs = parseInt(v, c.requestTimeoutMs, MIN_TIMEOUT_MS, MAX_TIMEOUT_MS);
                case "dedupWindowMinutes" -> c.dedupWindowMinutes = parseInt(v, c.dedupWindowMinutes, 0, 1440);
                case "authEnabled" -> c.authEnabled = Boolean.parseBoolean(v);
                case "authFilterEnabled" -> c.authFilterEnabled = Boolean.parseBoolean(v);
                case "authLowAuthHeaders" -> c.authLowAuthHeaders = v;
                case "authNoAuthHeaders" -> c.authNoAuthHeaders = v;
                case "authWhitelistDomains" -> c.authWhitelistDomains = v;
                case "authExtraExtensions" -> c.authExtraExtensions = v;
                case "fuzzPathBlacklist" -> c.fuzzPathBlacklist = v;
                case "fuzzPathStaticExts" -> c.fuzzPathStaticExts = v;
                case "fuzzPathRemoveQuery" -> c.fuzzPathRemoveQuery = Boolean.parseBoolean(v);
                case "fuzzPathRemoveFragment" -> c.fuzzPathRemoveFragment = Boolean.parseBoolean(v);
                // probeTimePayloads/timeProbePassRatio/allowStackedProbes/probeOracleTime
                // （v3.5 移除）与 dir* 键（v2.1 已删除 DirScan 模块）：读取时忽略，不报错
                case "domainWhitelist" -> c.domainWhitelist = v;
                case "urlBlacklist" -> c.urlBlacklist = v;
                default -> {
                }
            }
        }
        // 版本迁移链：迁移只升级版本标记并执行强制归位；旧配置经此统一落到当前
        // 格式并随 configVersion 立即持久化。
        boolean migrated = ver == null || versionOlderThan(ver, CONFIG_VERSION);
        if (migrated) {
            // v3.9.3：AuthScan 默认关闭。旧持久化里的 authEnabled=true 是旧默认值残留
            //（卸载钩子自动存盘），不是用户显式选择——强制归位，UI 勾选才是真相源。
            c.authEnabled = false;
            // v3.10.0：强制关闭所有自动扫描，改为手动启动（需在 SQLScan 设置中手动开启）
            c.phase1Enabled = false;
            c.phase2Enabled = false;
            c.watchProxy = false;
            c.watchRepeater = false;
            c.watchScanner = false;
            c.watchIntruder = false;
        }
        return migrated;
    }

    /** 简单三段版本比较：a < b（解析失败视为更旧，走迁移）。 */
    public static boolean versionOlderThan(String a, String b) {
        int[] va = parseVer(a);
        int[] vb = parseVer(b);
        for (int i = 0; i < 3; i++) {
            if (va[i] != vb[i]) {
                return va[i] < vb[i];
            }
        }
        return false;
    }

    private static int[] parseVer(String v) {
        int[] out = {0, 0, 0};
        if (v == null) {
            return out;
        }
        String[] parts = v.split("\\.");
        for (int i = 0; i < 3 && i < parts.length; i++) {
            try {
                out[i] = Integer.parseInt(parts[i].trim());
            } catch (NumberFormatException ignored) {
                return new int[]{0, 0, 0};
            }
        }
        return out;
    }

    private static int parseInt(String v, int dft, int min, int max) {
        try {
            return Math.max(min, Math.min(max, Integer.parseInt(v)));
        } catch (NumberFormatException e) {
            return dft;
        }
    }

    private static double parseDouble(String v, double dft, double min, double max) {
        try {
            double value = Double.parseDouble(v);
            return Double.isFinite(value) ? Math.max(min, Math.min(max, value)) : dft;
        } catch (NumberFormatException e) {
            return dft;
        }
    }
}
