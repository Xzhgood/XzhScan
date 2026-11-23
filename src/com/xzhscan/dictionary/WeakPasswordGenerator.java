package com.xzhscan.dictionary;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/**
 * 弱口令字典生成器（Dictionary 页签 · 字典生成子页）。
 *
 * 十个关键字段（名字简称/名字全拼/
 * 英文名/用户名/QQ号/出生日期/特殊数字/邮箱前缀/伴侣简称/伴侣全称）非空时
 * 套用对应模板组做占位符替换，另附通用 top100 弱口令。
 */
public final class WeakPasswordGenerator {

    private WeakPasswordGenerator() {
    }

    /** 输入键（与 UI 十个输入框一一对应，key 为中文名）。 */
    public static final String[] INPUT_KEYS = {
            "名字简称", "名字全拼", "英文名", "用户名", "QQ号",
            "出生日期", "特殊数字", "邮箱前缀", "伴侣简称", "伴侣全称"};

    /** 各输入键对应的模板资产组与占位符（注意"伴侣全程"为原版拼写，保持一致）。 */
    private static final String[][] TEMPLATE_MAP = {
            {"WEAK_NAME_JC", "#名字简称#"},
            {"WEAK_NAME_QC", "#名字全拼#"},
            {"WEAK_NAME_YW", "#英文名#"},
            {"WEAK_NAME_YHM", "#用户名#"},
            {"WEAK_NAME_QQ", "#QQ号#"},
            {"WEAK_NAME_RQ", "#出生日期#"},
            {"WEAK_NAME_SZ", "#特殊数字#"},
            {"WEAK_NAME_YX", "#邮箱前缀#"},
            {"WEAK_NAME_BLJC", "#伴侣简称#"},
            {"WEAK_NAME_BLQC", "#伴侣全程#"},
    };

    /**
     * 生成弱口令字典：top100 恒在；填写了某字段才展开对应模板组。
     *
     * @param inputs key 见 {@link #INPUT_KEYS}，值为用户输入；null/空串视为未填
     */
    public static List<String> generate(Map<String, String> inputs) {
        List<String> out = new ArrayList<>();
        for (String p : GeneratorAssets.WEAK_TOP100) {
            out.add(p);
        }
        for (int i = 0; i < INPUT_KEYS.length; i++) {
            String val = inputs.get(INPUT_KEYS[i]);
            if (val == null || val.isEmpty()) {
                continue;
            }
            String[] templates = assets(TEMPLATE_MAP[i][0]);
            String placeholder = TEMPLATE_MAP[i][1];
            for (String tpl : templates) {
                out.add(tpl.replace(placeholder, val));
            }
        }
        return out;
    }

    private static String[] assets(String field) {
        switch (field) {
            case "WEAK_NAME_JC": return GeneratorAssets.WEAK_NAME_JC;
            case "WEAK_NAME_QC": return GeneratorAssets.WEAK_NAME_QC;
            case "WEAK_NAME_YW": return GeneratorAssets.WEAK_NAME_YW;
            case "WEAK_NAME_YHM": return GeneratorAssets.WEAK_NAME_YHM;
            case "WEAK_NAME_QQ": return GeneratorAssets.WEAK_NAME_QQ;
            case "WEAK_NAME_RQ": return GeneratorAssets.WEAK_NAME_RQ;
            case "WEAK_NAME_SZ": return GeneratorAssets.WEAK_NAME_SZ;
            case "WEAK_NAME_YX": return GeneratorAssets.WEAK_NAME_YX;
            case "WEAK_NAME_BLJC": return GeneratorAssets.WEAK_NAME_BLJC;
            case "WEAK_NAME_BLQC": return GeneratorAssets.WEAK_NAME_BLQC;
            default: return new String[0];
        }
    }
}
