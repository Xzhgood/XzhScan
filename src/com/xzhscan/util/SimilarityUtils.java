package com.xzhscan.util;

import java.util.*;

/**
 * 相似度计算工具，整合 DetSql v3.3.0 的快速失败优化。
 * <p>
 * 核心优化：
 * 1. 长度差快速判断（≥100 直接返回 0）- 避免大文本全量计算
 * 2. 完全相同快速返回（equals 检查）
 * 3. 包含关系快速判断（一个是另一个的前缀/后缀）
 * 4. 前 N 字符预检（粗略判断差异）
 */
public final class SimilarityUtils {

    private SimilarityUtils() {
    }

    /**
     * Jaccard 相似度（带快速失败优化）- XzhScan 现有算法的增强版
     *
     * @param a 字符串 A
     * @param b 字符串 B
     * @return 相似度 (0.0-1.0)
     */
    public static double jaccardSimilarity(String a, String b) {
        // 快速检查1：null 处理
        if (a == null || b == null) {
            return 0.0;
        }

        // 快速检查2：完全相同
        if (a.equals(b)) {
            return 1.0;
        }

        // 快速检查3：长度差过大（≥100 直接返回 0）
        int lenDiff = Math.abs(a.length() - b.length());
        if (lenDiff >= 100) {
            return 0.0;
        }

        // 快速检查4：一个为空
        if (a.isEmpty() || b.isEmpty()) {
            return 0.0;
        }

        // 快速检查5：包含关系（前缀/后缀）
        if (a.length() < b.length()) {
            if (b.startsWith(a) || b.endsWith(a)) {
                return 0.0;  // 长度不同但完全包含，视为不相似
            }
        } else if (b.length() < a.length()) {
            if (a.startsWith(b) || a.endsWith(b)) {
                return 0.0;
            }
        }

        // 快速检查6：前 100 字符预检（如果都很长）
        if (a.length() > 100 && b.length() > 100) {
            String prefixA = a.substring(0, 100);
            String prefixB = b.substring(0, 100);
            if (!prefixA.equals(prefixB)) {
                // 前缀差异较大，粗略估算
                int commonPrefix = 0;
                for (int i = 0; i < 100; i++) {
                    if (prefixA.charAt(i) == prefixB.charAt(i)) {
                        commonPrefix++;
                    }
                }
                if (commonPrefix < 50) {  // 前 100 字符只有不到 50% 相同
                    return 0.0;
                }
            }
        }

        // 执行完整 Jaccard 计算（token-based）
        Set<String> tokensA = tokenize(a);
        Set<String> tokensB = tokenize(b);

        if (tokensA.isEmpty() && tokensB.isEmpty()) {
            return 1.0;
        }
        if (tokensA.isEmpty() || tokensB.isEmpty()) {
            return 0.0;
        }

        Set<String> union = new HashSet<>(tokensA);
        union.addAll(tokensB);

        Set<String> intersection = new HashSet<>(tokensA);
        intersection.retainAll(tokensB);

        return (double) intersection.size() / union.size();
    }

    /**
     * 字符串 token 化（提取 2+ 字符的字母数字序列）
     */
    private static Set<String> tokenize(String text) {
        Set<String> tokens = new HashSet<>();
        if (text == null || text.isEmpty()) {
            return tokens;
        }

        String normalized = text.toLowerCase(Locale.ROOT);
        StringBuilder token = new StringBuilder();

        for (int i = 0; i < normalized.length(); i++) {
            char c = normalized.charAt(i);
            if (Character.isLetterOrDigit(c) || c == '#') {
                token.append(c);
            } else {
                if (token.length() >= 2) {
                    tokens.add(token.toString());
                }
                token.setLength(0);
            }
        }

        // 最后一个 token
        if (token.length() >= 2) {
            tokens.add(token.toString());
        }

        return tokens;
    }

    /**
     * Levenshtein 编辑距离相似度（带阈值快速失败）- 移植自 DetSql
     *
     * @param str1 字符串1
     * @param str2 字符串2
     * @param threshold 相似度阈值（0.0-1.0），低于此值可提前返回
     * @return 相似度 (0.0-1.0)
     */
    public static double levenshteinSimilarity(String str1, String str2, double threshold) {
        if (str1 == null || str2 == null) {
            return 0.0;
        }

        // 快速检查1：完全相同
        if (str1.equals(str2)) {
            return 1.0;
        }

        // 快速检查2：长度差异过大，直接返回
        int lenDiff = Math.abs(str1.length() - str2.length());
        int maxLen = Math.max(str1.length(), str2.length());
        if (maxLen > 0 && lenDiff > maxLen * (1 - threshold)) {
            return 0.0; // 不可能达到阈值
        }

        // 快速检查3：前 100 字符差异过大
        if (str1.length() > 100 && str2.length() > 100) {
            String prefix1 = str1.substring(0, 100);
            String prefix2 = str2.substring(0, 100);
            if (!prefix1.equals(prefix2)) {
                int prefixDist = levenshteinDistance(prefix1, prefix2);
                if (prefixDist > 50) {
                    return 0.0; // 前缀差异太大
                }
            }
        }

        // 执行完整计算
        int distance = levenshteinDistance(str1, str2);
        return 1 - (double) distance / maxLen;
    }

    /**
     * Levenshtein 编辑距离相似度（不带阈值）
     */
    public static double levenshteinSimilarity(String str1, String str2) {
        return levenshteinSimilarity(str1, str2, 0.0);
    }

    /**
     * 计算 Levenshtein 编辑距离
     */
    private static int levenshteinDistance(String s1, String s2) {
        int len1 = s1.length();
        int len2 = s2.length();

        // 优化：长度为 0 的情况
        if (len1 == 0) return len2;
        if (len2 == 0) return len1;

        // 动态规划
        int[] prev = new int[len2 + 1];
        int[] curr = new int[len2 + 1];

        for (int j = 0; j <= len2; j++) {
            prev[j] = j;
        }

        for (int i = 1; i <= len1; i++) {
            curr[0] = i;
            for (int j = 1; j <= len2; j++) {
                int cost = (s1.charAt(i - 1) == s2.charAt(j - 1)) ? 0 : 1;
                curr[j] = Math.min(
                        Math.min(prev[j] + 1, curr[j - 1] + 1),
                        prev[j - 1] + cost
                );
            }
            // 交换数组
            int[] temp = prev;
            prev = curr;
            curr = temp;
        }

        return prev[len2];
    }

    /**
     * 长度归一化相似度（快速粗略判断）
     *
     * @param len1 长度1
     * @param len2 长度2
     * @return 长度相似度 (0.0-1.0)
     */
    public static double lengthSimilarity(int len1, int len2) {
        if (len1 == 0 && len2 == 0) {
            return 1.0;
        }
        if (len1 == 0 || len2 == 0) {
            return 0.0;
        }
        int maxLen = Math.max(len1, len2);
        int minLen = Math.min(len1, len2);
        return (double) minLen / maxLen;
    }
}
