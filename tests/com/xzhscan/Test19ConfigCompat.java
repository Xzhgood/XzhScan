package com.xzhscan;

import com.xzhscan.config.ConfigCodec;
import com.xzhscan.config.XzhScanConfig;

import static com.xzhscan.MiniTest.TestContext;

/**
 * 测试十九：配置兼容（v3.5 重写：被动时间探针子系统随架构移除）。
 *  - AuthScan 配置键序列化往返；
 *  - v2.0/v2.1 旧配置（含 dir* 键）解析不炸、缺省保留（dir* 键被忽略）；
 *  - v3.5 已移除键（probeTimePayloads/timeProbePassRatio/allowStackedProbes/
 *    probeOracleTime/autoVerify）读取即忽略，不破坏其余键；
 *  - 版本迁移：无/旧 configVersion 的历史配置报告迁移并随保存升级版本标记；
 *    当前版本标记的配置不重复迁移。
 */
public final class Test19ConfigCompat {

    public static void run(TestContext t) {
        // ---------- 1. AuthScan 往返 ----------
        XzhScanConfig out = new XzhScanConfig();
        out.authEnabled = false;
        out.authFilterEnabled = true;
        out.authLowAuthHeaders = "Cookie: session=low\nAuthorization: Bearer x";
        out.authNoAuthHeaders = "Cookie\nAuthorization";
        out.authWhitelistDomains = "*.corp.com";
        out.authExtraExtensions = "tpl";
        String props = ConfigCodec.toProperties(out);
        XzhScanConfig in = new XzhScanConfig();
        ConfigCodec.fromProperties(props, in);
        t.check(!in.authEnabled && in.authFilterEnabled, "AuthScan 开关往返");
        t.check(in.authLowAuthHeaders.contains("Cookie: session=low")
                && in.authLowAuthHeaders.contains("Authorization: Bearer x"), "低权限头多行往返");
        t.checkEq("Cookie\nAuthorization", in.authNoAuthHeaders, "待删头往返");

        // ---------- 2. 历史配置兼容读取（已移除键忽略 + 版本迁移） ----------
        // v3.5 移除的四个时间键 + autoVerify/dir* 键：读取即忽略，不破坏其余键。
        XzhScanConfig legacy = new XzhScanConfig();
        boolean legacyMigrated = ConfigCodec.fromProperties("probeTimePayloads=true\n"
                + "timeProbePassRatio=0.7\n"
                + "allowStackedProbes=false\n"
                + "probeOracleTime=false\n"
                + "autoVerify=true\n"
                + "dirPassiveEnabled=true\n"
                + "dirWhitelistDomains=*.old.com\n"
                + "dedupWindowMinutes=60\n", legacy);
        t.check(!legacy.authEnabled, "旧配置可读键正常解析（v3.9.3 AuthScan 默认关；已移除键被安全忽略）");
        t.checkEq(60, legacy.dedupWindowMinutes, "未移除键在旧配置中正常生效");
        t.check(legacyMigrated, "无版本标记的历史配置 reports migration");

        // 迁移后的配置保存即带当前版本标记：再次加载不再迁移
        String roundTripped = ConfigCodec.toProperties(legacy);
        t.check(roundTripped.contains("configVersion=" + ConfigCodec.CONFIG_VERSION),
                "migrated config saved with current configVersion");
        XzhScanConfig second = new XzhScanConfig();
        t.check(!ConfigCodec.fromProperties(roundTripped, second),
                "migrated config saved with version -> no re-migration");

        // 当前版本标记的配置：完全不迁移（旧键仍安全忽略）
        XzhScanConfig current = new XzhScanConfig();
        boolean offMigrated = ConfigCodec.fromProperties(
                "configVersion=" + ConfigCodec.CONFIG_VERSION + "\n"
                        + "probeTimePayloads=true\nautoVerify=true\nallowStackedProbes=false\n",
                current);
        t.check(!offMigrated, "current-version config -> no migration");
        t.check(!current.authEnabled, "current-version config parses safely (AuthScan default off)");

        // 未知键整体不炸（无版本标记仍走迁移）
        XzhScanConfig unknown = new XzhScanConfig();
        ConfigCodec.fromProperties("futureKey=whatever\n\nbroken-line-no-eq\n", unknown);
        t.check(!unknown.authEnabled, "未知/损坏行不破坏默认配置（AuthScan 默认关）");

        // ---------- v3.9.3 迁移：旧 authEnabled=true 是旧默认残留，强制归位 ----------
        XzhScanConfig mig = new XzhScanConfig();
        boolean m = ConfigCodec.fromProperties("configVersion=3.8.7" + (char) 10 + "authEnabled=true" + (char) 10, mig);
        t.check(m, "3.8.7 旧配置触发迁移（返回 migrated=true）");
        t.check(!mig.authEnabled, "v3.9.3 迁移：旧 authEnabled=true 强制归位为关");
        XzhScanConfig explicit = new XzhScanConfig();
        boolean m2 = ConfigCodec.fromProperties(
                "configVersion=" + ConfigCodec.CONFIG_VERSION + (char) 10 + "authEnabled=true" + (char) 10, explicit);
        t.check(!m2 && explicit.authEnabled, "当前版本显式 authEnabled=true 不被迁移覆盖（用户偏好保留）");

        // versionOlderThan 语义守护（迁移链基础）
        t.check(ConfigCodec.versionOlderThan("2.3.0", "3.5.0"), "2.3.0 < 3.5.0");
        t.check(ConfigCodec.versionOlderThan(null, "3.5.0"), "null 视为最旧");
        t.check(!ConfigCodec.versionOlderThan("3.5.0", "3.5.0"), "等版本不迁移");
        t.check(!ConfigCodec.versionOlderThan("4.0.0", "3.5.0"), "更新版本不迁移");
    }
}
