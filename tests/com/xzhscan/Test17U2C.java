package com.xzhscan;

import com.xzhscan.codec.UnicodeCodec;

import static com.xzhscan.MiniTest.TestContext;

/**
 * 测试十七：Chinese 中文解码（v2.2 起 DirScan 已整体移除，本套件仅保留全局 Chinese 能力回归）。
 */
public final class Test17U2C {

    public static void run(TestContext t) {
        t.check(UnicodeCodec.containsUnicodeEscape("{\"name\":\"\\u4e2d\\u6587\"}"), "识别 Unicode 转义");
        String un = UnicodeCodec.unescapeRepeatedly("{\"name\":\"\\\\u4e2d\\\\u6587\"}", 3);
        t.checkEq("{\"name\":\"中文\"}", un, "Unicode 还原为中文");
        String pretty = UnicodeCodec.prettyJson("{\"a\":1,\"b\":[1,2]}");
        t.check(pretty.contains("\n") && pretty.contains("  "), "JSON 美化含缩进换行");
        t.checkEq("UTF-8", UnicodeCodec.detectCharset("hello".getBytes(), null), "ASCII 探测 UTF-8");
        t.check(UnicodeCodec.detectCharset("中文".getBytes(java.nio.charset.StandardCharsets.UTF_8), null).equals("UTF-8"),
                "UTF-8 中文严格校验通过");
        byte[] gbk = "中文".getBytes(java.nio.charset.Charset.forName("GBK"));
        t.checkEq("GBK", UnicodeCodec.detectCharset(gbk, null), "GBK 探测");
        String bs = String.valueOf((char) 92);
        String uniMsg = "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{\"msg\":\""
                + bs + "u6210" + bs + "u529f\"}";
        UnicodeCodec.DisplayResult d = UnicodeCodec.buildDisplayContent(uniMsg.getBytes(), true, "UTF-8");
        t.check(d.json() && d.content().contains("成功"), "响应 JSON Unicode 还原 + 美化");
    }
}
