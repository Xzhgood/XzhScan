package com.xzhscan.dictionary;

import java.util.AbstractMap;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Random;

/**
 * 信息生成器（Dictionary 页签 · 信息生成子页）。
 *
 * 随机姓名 / 手机号 /
 * 18 位身份证（GB 11643-1999 MOD 11-2 校验）/ 统一社会信用代码（MOD 31-2）/
 * 组织机构代码（MOD 11-2）/ 银行卡（Luhn）。仅授权测试填写注册资料用途。
 */
public final class InfoGenerator {

    private InfoGenerator() {
    }

    private static final Random RD = new Random();

    /** 常见姓氏表。 */
    private static final String[] SURNAME = {"赵", "钱", "孙", "李", "周", "吴", "郑", "王", "冯", "陈",
            "杨", "朱", "许", "何", "吕", "施", "张", "谢", "邹", "章", "范", "韦", "方", "唐", "贺", "黄",
            "宋", "郭", "徐"};

    /** 常用名字用字（见 SURNAME 同级数组）。 */
    private static final String[] WORD = {
            "华", "明", "伟", "强", "军", "磊", "勇", "杰", "涛", "超", "刚", "峰", "辉", "鹏", "斌",
            "波", "辉", "宇", "浩", "凯", "健", "俊", "帆", "帅", "旭", "鑫", "鹏", "毅", "帅", "晨",
            "芳", "娟", "敏", "静", "丽", "艳", "娜", "琳", "燕", "婷", "玲", "雪", "慧", "倩", "晶",
            "云", "洁", "丹", "萍", "颖", "璐", "佳", "蓉", "薇", "彤", "悦", "楠", "蕾", "莹", "欢"};

    // 中国移动 / 联通 / 电信 号段
    private static final String[] CHINA_MOBILE = {"134", "135", "136", "137", "138", "139", "150",
            "151", "152", "157", "158", "159", "182", "183", "184", "187", "188", "178", "147", "172", "198"};
    private static final String[] CHINA_UNICOM = {"130", "131", "132", "145", "155", "156", "166",
            "171", "175", "176", "185", "186"};
    private static final String[] CHINA_TELECOM = {"133", "149", "153", "173", "177", "180", "181",
            "189", "199"};

    /** 生成一条信息：type=姓名/手机号/身份证/信用代码/组织机构/银行卡，value=值，note=附注。 */
    public record Info(String type, String value, String note) {

        public Map.Entry<String, String> asPair() {
            return new AbstractMap.SimpleEntry<>(type, value);
        }
    }

    /** 随机中文姓名（2-3 位名）。 */
    public static String randomName() {
        String surname = SURNAME[RD.nextInt(SURNAME.length)];
        int len = RD.nextInt(2) + 2;
        StringBuilder sb = new StringBuilder(surname);
        for (int i = 0; i < len; i++) {
            sb.append(WORD[RD.nextInt(WORD.length)]);
        }
        return sb.toString();
    }

    /** 随机手机号（三运营商号段 + 8 位随机）。 */
    public static Info randomPhone() {
        int op = RD.nextInt(3);
        String prefix;
        String carrier;
        switch (op) {
            case 0 -> {
                prefix = CHINA_MOBILE[RD.nextInt(CHINA_MOBILE.length)];
                carrier = "中国移动";
            }
            case 1 -> {
                prefix = CHINA_UNICOM[RD.nextInt(CHINA_UNICOM.length)];
                carrier = "中国联通";
            }
            default -> {
                prefix = CHINA_TELECOM[RD.nextInt(CHINA_TELECOM.length)];
                carrier = "中国电信";
            }
        }
        StringBuilder tail = new StringBuilder();
        for (int i = 0; i < 8; i++) {
            tail.append(RD.nextInt(10));
        }
        return new Info("手机号(" + carrier + ")", prefix + tail, "");
    }

    /** 随机 18 位身份证（GB 11643-1999 校验码），附注含所属地与出生日期。 */
    public static Info randomIdCard() {
        String[] area = GeneratorAssets.ID_AREA_CODES[RD.nextInt(GeneratorAssets.ID_AREA_CODES.length)]
                .split("\\|", 2);
        String areaCode = area[0];
        String areaName = area.length > 1 ? area[1] : "";
        int year = RD.nextInt(40) + 1980;
        int month = RD.nextInt(12) + 1;
        int day = RD.nextInt(28) + 1;
        String birth = String.format("%04d%02d%02d", year, month, day);
        int seq = RD.nextInt(1000);
        String seq3 = String.format("%03d", seq);
        String body17 = areaCode + birth + seq3;
        int[] weights = {7, 9, 10, 5, 8, 4, 2, 1, 6, 3, 7, 9, 10, 5, 8, 4, 2};
        char[] map = {'1', '0', 'X', '9', '8', '7', '6', '5', '4', '3', '2'};
        int sum = 0;
        for (int i = 0; i < 17; i++) {
            sum += weights[i] * (body17.charAt(i) - '0');
        }
        String note = "所属地:" + areaName + " 出生日期:" + birth;
        return new Info("身份证", body17 + map[sum % 11], note);
    }

    /** 随机统一社会信用代码（18 位，MOD 31-2 校验）。 */
    public static Info randomCreditCode() {
        int deptIdx = RD.nextInt(GeneratorAssets.CREDIT_DEPT.length);
        String dept = GeneratorAssets.CREDIT_DEPT[deptIdx].split("\\|", 2)[0];
        String[] orgTypes = GeneratorAssets.CREDIT_ORG_TYPE[deptIdx].split("&");
        String orgType = orgTypes[RD.nextInt(orgTypes.length)].split("\\|", 2)[0];
        String area = GeneratorAssets.CREDIT_AREAS[RD.nextInt(GeneratorAssets.CREDIT_AREAS.length)];
        // 主体标识码：8 位组织机构号 + MOD 11-2 校验
        String num8 = randomOrgNum();
        String subject = num8 + mod11Check(num8);
        String body17 = dept + orgType + area + subject;
        int[] wi = {1, 3, 9, 27, 19, 26, 16, 17, 20, 29, 25, 13, 8, 24, 10, 30, 28};
        // GB 32129 MOD 31-2 字符集（31 位，排除 I/O/S/V/Z）
        String charset = "0123456789ABCDEFGHJKLMNPQRTUWXY";
        int sum = 0;
        for (int i = 0; i < 17; i++) {
            sum += charset.indexOf(body17.charAt(i)) * wi[i];
        }
        int c18 = 31 - (sum % 31);
        if (c18 == 31) {
            c18 = 0;
        }
        String deptName = GeneratorAssets.CREDIT_DEPT[deptIdx].split("\\|", 2).length > 1
                ? GeneratorAssets.CREDIT_DEPT[deptIdx].split("\\|", 2)[1] : "";
        return new Info("统一社会信用代码", body17 + charset.charAt(c18), "部门:" + deptName);
    }

    /** 随机组织机构代码（8 位数字 + MOD 11-2 校验位）。 */
    public static Info randomOrgCode() {
        String num8 = randomOrgNum();
        return new Info("组织机构代码", num8 + "-" + mod11Check(num8), "");
    }

    /** 随机银行卡号（BIN 前 6 位 + 9 位随机 + Luhn 校验位），附注银行与卡种。 */
    public static Info randomBankCard() {
        String[] bin = GeneratorAssets.BANK_BINS[RD.nextInt(GeneratorAssets.BANK_BINS.length)]
                .split("\\|", 2);
        String bank = bin[0];
        String binCode = bin.length > 1 ? bin[1] : "622202";
        StringBuilder body15 = new StringBuilder(binCode);
        while (body15.length() < 15) {
            body15.append(RD.nextInt(10));
        }
        String body = body15.substring(0, 15);
        // 标准 Luhn：完整 16 位卡号从右起偶数位 ×2 → body（无校验位）为 0-based 偶数位
        // Luhn 奇偶位序（v3.7 校正位序对齐）
        int sum = 0;
        for (int i = 0; i < 15; i += 2) {
            int d = (body.charAt(i) - '0') * 2;
            sum += d > 9 ? d - 9 : d;
        }
        for (int i = 1; i < 15; i += 2) {
            sum += body.charAt(i) - '0';
        }
        int check = (10 - (sum % 10)) % 10;
        return new Info("银行卡(" + bank + ")", body + check, "Luhn 校验通过");
    }

    /** 一键生成全部六类各一条。 */
    public static List<Info> generateAll() {
        List<Info> out = new ArrayList<>();
        out.add(new Info("姓名", randomName(), ""));
        out.add(randomPhone());
        out.add(randomIdCard());
        out.add(randomCreditCode());
        out.add(randomOrgCode());
        out.add(randomBankCard());
        return out;
    }

    /** 8 位主体号（首位 1-8，其余 0-8）。 */
    private static String randomOrgNum() {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < 8; i++) {
            sb.append(i == 0 ? RD.nextInt(8) + 1 : RD.nextInt(9));
        }
        return sb.toString();
    }

    /** GB 11643 组织机构校验位：11-(加权和 mod 11)；10→X，11→0。 */
    public static String mod11Check(String num8) {
        int[] ws = {3, 7, 9, 10, 5, 8, 4, 2};
        int sum = 0;
        for (int i = 0; i < 8; i++) {
            sum += (num8.charAt(i) - '0') * ws[i];
        }
        int c9 = 11 - (sum % 11);
        if (c9 == 11) {
            return "0";
        }
        if (c9 == 10) {
            return "X";
        }
        return String.valueOf(c9);
    }
}
