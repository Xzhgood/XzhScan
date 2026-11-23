package com.xzhscan.codec;

import java.nio.charset.Charset;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Chinese 编解码纯逻辑（迁移自 gatherBurp CodecUtils，去除 fastjson/juniversalchardet/
 * Burp helpers 依赖）：
 *  - Unicode 'u'XXXX 多层转义还原；
 *  - JSON 识别 + 美化（改用自研 MiniJson.prettyPrint，替代 fastjson）；
 *  - 字符集探测降级为启发式（Content-Type charset -> UTF-8 严格校验 -> GBK），
 *    支持候选列表轮换（原版 FALLBACK_CHARSETS 语义保留）。
 * 保留 gatherBurp MIT 许可来源声明（见 vendor/NOTICE-GATHERBURP.md）。
 */
public final class UnicodeCodec {

    private UnicodeCodec() {
    }

    private static final Pattern UNICODE_ESCAPE = Pattern.compile("\\\\u([0-9a-fA-F]{4})|(\\\\\\\\)");

    /** 候选字符集（与原版一致）。 */
    public static final List<String> FALLBACK_CHARSETS =
            List.of("UTF-8", "GBK", "GB2312", "GB18030", "Big5", "UTF-16");

    private static final String BACKSLASH_U = String.valueOf((char) 92) + "u";

    public static boolean containsUnicodeEscape(String s) {
        return s != null && s.indexOf(BACKSLASH_U) >= 0;
    }

    /** 单轮 Unicode 转义还原（双反斜杠还原为单反斜杠），quoteReplacement 防特殊字符。 */
    public static String unescapeUnicode(String input) {
        if (input == null) {
            return null;
        }
        Matcher m = UNICODE_ESCAPE.matcher(input);
        StringBuilder sb = new StringBuilder(input.length());
        while (m.find()) {
            String hex = m.group(1);
            if (hex != null) {
                m.appendReplacement(sb, Matcher.quoteReplacement(String.valueOf((char) Integer.parseInt(hex, 16))));
            } else {
                m.appendReplacement(sb, Matcher.quoteReplacement("\\"));
            }
        }
        m.appendTail(sb);
        return sb.toString();
    }

    /** 多层转义还原（默认 3 轮，与原版一致）。 */
    public static String unescapeRepeatedly(String input, int maxRounds) {
        String cur = input;
        for (int i = 0; i < maxRounds && containsUnicodeEscape(cur); i++) {
            String next = unescapeUnicode(cur);
            if (next.equals(cur)) {
                break;
            }
            cur = next;
        }
        return cur;
    }

    /** 启发式字符集探测：显式 charset 优先 -> UTF-8 严格可解码 -> GBK。 */
    public static String detectCharset(byte[] bytes, String headerCharset) {
        if (headerCharset != null && !headerCharset.isBlank()) {
            String cs = headerCharset.trim();
            if (Charset.isSupported(cs)) {
                return cs;
            }
        }
        if (decodesCleanly(bytes, StandardCharsets.UTF_8)) {
            return "UTF-8";
        }
        return containsHighBytes(bytes) ? "GBK" : "UTF-8";
    }

    /** 探测候选序列：探测结果在前，其余候选去重追加（UI 轮换用）。 */
    public static List<String> charsetCandidates(byte[] bytes, String headerCharset) {
        List<String> out = new ArrayList<>();
        out.add(detectCharset(bytes, headerCharset));
        for (String cs : FALLBACK_CHARSETS) {
            if (!out.contains(cs)) {
                out.add(cs);
            }
        }
        return out;
    }

    private static boolean decodesCleanly(byte[] bytes, Charset cs) {
        try {
            java.nio.ByteBuffer bb = java.nio.ByteBuffer.wrap(bytes);
            cs.newDecoder()
                    .onMalformedInput(CodingErrorAction.REPORT)
                    .onUnmappableCharacter(CodingErrorAction.REPORT)
                    .decode(bb);
            return true;
        } catch (Exception e) {
            return false;
        }
    }

    private static boolean containsHighBytes(byte[] bytes) {
        for (byte b : bytes) {
            if ((b & 0x80) != 0) {
                return true;
            }
        }
        return false;
    }

    /** 跨编码转码。 */
    public static byte[] convertCharset(byte[] bytes, String from, String to) {
        try {
            return new String(bytes, from).getBytes(to);
        } catch (Exception e) {
            return bytes;
        }
    }

    /**
     * 构造展示内容：解码 -> 含 Unicode 转义则逐层还原；JSON 文本则美化。
     *
     * @param isResponse true=响应（HTTP/1.1 开头），false=请求
     */
    public static DisplayResult buildDisplayContent(byte[] raw, boolean isResponse, String charset) {
        String text = new String(raw, charset(charset));
        String headerCharset = extractCharsetParam(headerBlock(text), isResponse);
        if (!headerCharset.isEmpty() && charset.equals("UTF-8") && Charset.isSupported(headerCharset)) {
            text = new String(raw, Charset.forName(headerCharset));
        }
        boolean json = looksLikeJson(bodyPart(text, isResponse));
        String body = bodyPart(text, isResponse);
        String head = text.substring(0, text.length() - body.length());
        String shown;
        if (json) {
            shown = head + prettyJson(body);
        } else if (containsUnicodeEscape(text)) {
            shown = head + unescapeRepeatedly(body, 3);
        } else {
            return new DisplayResult(text, false, false);
        }
        return new DisplayResult(shown, true, json);
    }

    /** 展示结果：内容 + 是否发生转换 + 是否 JSON。 */
    public record DisplayResult(String content, boolean transformed, boolean json) {
    }

    /** JSON 美化（自研 AST，替代 fastjson prettyJson；解析失败原样返回）。 */
    public static String prettyJson(String body) {
        try {
            return com.xzhscan.parameter.MiniJson.prettyPrint(com.xzhscan.parameter.MiniJson.parse(body));
        } catch (RuntimeException e) {
            return body;
        }
    }

    static String headerBlock(String text) {
        int sep = text.indexOf("\r\n\r\n");
        return sep >= 0 ? text.substring(0, sep) : text;
    }

    static String bodyPart(String text, boolean isResponse) {
        int sep = text.indexOf("\r\n\r\n");
        return sep >= 0 ? text.substring(sep + 4) : (isResponse ? "" : text);
    }

    static boolean looksLikeJson(String body) {
        String t = body == null ? "" : body.trim();
        return t.startsWith("{") || t.startsWith("[");
    }

    /** 从 Content-Type 头取 charset= 参数（大小写不敏感）。 */
    static String extractCharsetParam(String headerBlock, boolean isResponse) {
        for (String line : headerBlock.split("\r\n")) {
            String low = line.toLowerCase();
            if (low.startsWith("content-type:")) {
                int i = low.indexOf("charset=");
                if (i >= 0) {
                    String v = line.substring(i + 8).trim();
                    int end = v.indexOf(';');
                    if (end > 0) {
                        v = v.substring(0, end);
                    }
                    return v.replace("\"", "").replace("'", "");
                }
            }
        }
        return "";
    }

    private static Charset charset(String name) {
        try {
            return Charset.forName(name);
        } catch (Exception e) {
            return StandardCharsets.UTF_8;
        }
    }
}
