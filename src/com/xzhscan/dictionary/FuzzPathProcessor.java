package com.xzhscan.dictionary;

import java.util.Arrays;
import java.util.HashSet;
import java.util.Locale;
import java.util.Set;
import java.util.regex.Pattern;

/**
 * Fuzz 路径清洗处理器（纯文本处理，零 HTTP 请求）。
 *
 * 按顺序执行：
 * 1. 去除首尾空格、BOM、空行、引号
 * 2. 过滤绝对 URL、协议相对 URL
 * 3. 过滤 MIME 类型
 * 4. 过滤版本号、纯数字、无效文本
 * 5. 清理相对路径前缀
 * 6. 合并重复分隔符
 * 7. 统一补充 / 前缀
 * 8. 可选移除 Query 和 Fragment
 * 9. 拒绝路径穿越
 * 10. 过滤静态资源
 * 11. 黑名单过滤
 * 12. 去重（自动）
 */
public final class FuzzPathProcessor {

    // ============ 默认配置 ============

    /** 默认静态资源后缀（不区分大小写）。 */
    public static final String DEFAULT_STATIC_EXTS =
            "js,mjs,css,map,png,jpg,jpeg,gif,svg,ico,webp,bmp," +
            "woff,woff2,ttf,eot,otf,mp3,mp4,webm,avi";

    // ============ 正则模式 ============

    /** 绝对 URL：http:// 或 https:// 或 ftp:// 等。 */
    private static final Pattern ABSOLUTE_URL = Pattern.compile("^[a-z][a-z0-9+.-]*://", Pattern.CASE_INSENSITIVE);

    /** 协议相对 URL：//example.com/path。 */
    private static final Pattern PROTOCOL_RELATIVE_URL = Pattern.compile("^//[^/]");

    /** MIME 类型：text/javascript、application/json 等。 */
    private static final Pattern MIME_TYPE = Pattern.compile("^[a-z]+/[a-z0-9+.-]+$", Pattern.CASE_INSENSITIVE);

    /** 版本号：1.0、2.3.4、v1.2 等。 */
    private static final Pattern VERSION_NUMBER = Pattern.compile("^v?\\d+(\\.\\d+)*$", Pattern.CASE_INSENSITIVE);

    /** 纯数字。 */
    private static final Pattern PURE_NUMBER = Pattern.compile("^\\d+$");

    /** 路径穿越段（危险）。 */
    private static final Pattern PATH_TRAVERSAL = Pattern.compile("\\.\\.|%2e%2e|%252e|%c0%ae", Pattern.CASE_INSENSITIVE);

    /** 多个连续斜杠。 */
    private static final Pattern MULTIPLE_SLASHES = Pattern.compile("/+");

    // ============ 配置项 ============

    private final Set<String> staticExts;
    private final Set<String> blacklist;
    private final boolean removeQuery;
    private final boolean removeFragment;

    /**
     * 构造函数。
     *
     * @param staticExts    静态资源后缀（逗号分隔，不区分大小写）
     * @param blacklist     黑名单关键词（一行一个，不区分大小写）
     * @param removeQuery   是否移除 Query 参数
     * @param removeFragment 是否移除 Fragment
     */
    public FuzzPathProcessor(String staticExts, String blacklist, boolean removeQuery, boolean removeFragment) {
        this.staticExts = parseExtensions(staticExts);
        this.blacklist = parseBlacklist(blacklist);
        this.removeQuery = removeQuery;
        this.removeFragment = removeFragment;
    }

    /**
     * 处理批量路径。
     *
     * @param input 原始输入（多行）
     * @return 处理结果
     */
    public FuzzPathResult process(String input) {
        FuzzPathResult result = new FuzzPathResult();

        if (input == null || input.isEmpty()) {
            return result;
        }

        // 移除 BOM
        if (input.startsWith("﻿")) {
            input = input.substring(1);
        }

        String[] lines = input.split("\\r?\\n");
        result.originalCount = lines.length;

        for (String line : lines) {
            processLine(line, result);
        }

        return result;
    }

    /**
     * 处理单行路径。
     */
    private void processLine(String line, FuzzPathResult result) {
        // 1. 去除首尾空格
        line = line.trim();

        // 空行跳过
        if (line.isEmpty()) {
            return;
        }

        // 去除成对引号
        line = removeQuotes(line);

        // 2. 过滤绝对 URL
        if (ABSOLUTE_URL.matcher(line).find()) {
            result.addFilteredPath(line, "绝对URL");
            result.otherInvalidCount++;
            return;
        }

        // 过滤协议相对 URL
        if (PROTOCOL_RELATIVE_URL.matcher(line).find()) {
            result.addFilteredPath(line, "协议相对URL");
            result.otherInvalidCount++;
            return;
        }

        // 3. 过滤 MIME 类型
        if (MIME_TYPE.matcher(line).matches()) {
            result.addFilteredPath(line, "MIME类型");
            result.otherInvalidCount++;
            return;
        }

        // 4. 过滤版本号
        if (VERSION_NUMBER.matcher(line).matches()) {
            result.addFilteredPath(line, "版本号");
            result.otherInvalidCount++;
            return;
        }

        // 过滤纯数字
        if (PURE_NUMBER.matcher(line).matches()) {
            result.addFilteredPath(line, "纯数字");
            result.otherInvalidCount++;
            return;
        }

        // 过滤明显无效文本（长度过短或过长）
        if (line.length() < 2 || line.length() > 500) {
            result.addFilteredPath(line, "长度无效");
            result.otherInvalidCount++;
            return;
        }

        // 5. 清理相对路径前缀（./ 或 ././）
        while (line.startsWith("./")) {
            line = line.substring(2);
        }

        // 6. 合并重复分隔符
        line = MULTIPLE_SLASHES.matcher(line).replaceAll("/");

        // 7. 统一补充 / 前缀
        if (!line.startsWith("/")) {
            line = "/" + line;
        }

        // 8. 可选移除 Query 和 Fragment
        if (removeQuery) {
            int queryIndex = line.indexOf('?');
            if (queryIndex != -1) {
                line = line.substring(0, queryIndex);
            }
        }

        if (removeFragment) {
            int fragmentIndex = line.indexOf('#');
            if (fragmentIndex != -1) {
                line = line.substring(0, fragmentIndex);
            }
        }

        // 再次去除尾部空格（Query/Fragment 移除后可能产生）
        line = line.trim();

        // 空路径跳过
        if (line.isEmpty() || line.equals("/")) {
            return;
        }

        // 9. 拒绝路径穿越
        if (PATH_TRAVERSAL.matcher(line).find()) {
            result.addFilteredPath(line, "路径穿越");
            result.otherInvalidCount++;
            return;
        }

        // 10. 过滤静态资源
        if (isStaticResource(line)) {
            result.addFilteredPath(line, "静态资源");
            result.staticResourceFilteredCount++;
            return;
        }

        // 11. 黑名单过滤
        if (matchesBlacklist(line)) {
            result.addFilteredPath(line, "黑名单");
            result.blacklistFilteredCount++;
            return;
        }

        // 12. 添加有效路径（自动去重）
        result.addValidPath(line);
    }

    /**
     * 移除成对引号。
     */
    private static String removeQuotes(String s) {
        if (s.length() >= 2) {
            char first = s.charAt(0);
            char last = s.charAt(s.length() - 1);
            if ((first == '"' && last == '"') || (first == '\'' && last == '\'')) {
                return s.substring(1, s.length() - 1);
            }
        }
        return s;
    }

    /**
     * 判断是否为静态资源。
     */
    private boolean isStaticResource(String path) {
        int lastSlash = path.lastIndexOf('/');
        int lastDot = path.lastIndexOf('.');

        // 有后缀且后缀在最后一个斜杠之后
        if (lastDot > lastSlash && lastDot < path.length() - 1) {
            String ext = path.substring(lastDot + 1).toLowerCase(Locale.ROOT);
            return staticExts.contains(ext);
        }

        return false;
    }

    /**
     * 判断是否匹配黑名单。
     */
    private boolean matchesBlacklist(String path) {
        String lowerPath = path.toLowerCase(Locale.ROOT);
        for (String keyword : blacklist) {
            if (lowerPath.contains(keyword)) {
                return true;
            }
        }
        return false;
    }

    /**
     * 解析静态资源后缀。
     */
    private static Set<String> parseExtensions(String exts) {
        Set<String> set = new HashSet<>();
        if (exts == null || exts.isEmpty()) {
            return set;
        }

        for (String ext : exts.split(",")) {
            ext = ext.trim().toLowerCase(Locale.ROOT);
            if (!ext.isEmpty()) {
                set.add(ext);
            }
        }
        return set;
    }

    /**
     * 解析黑名单。
     */
    private static Set<String> parseBlacklist(String blacklist) {
        Set<String> set = new HashSet<>();
        if (blacklist == null || blacklist.isEmpty()) {
            return set;
        }

        for (String line : blacklist.split("\\r?\\n")) {
            line = line.trim().toLowerCase(Locale.ROOT);
            if (!line.isEmpty()) {
                set.add(line);
            }
        }
        return set;
    }
}
