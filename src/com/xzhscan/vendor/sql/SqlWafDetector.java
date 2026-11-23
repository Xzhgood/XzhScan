package com.xzhscan.vendor.sql;

import com.xzhscan.vendor.http.SimpleHttpResponse;
import java.util.Locale;

public final class SqlWafDetector {
   private static final String[] BODY_SIGNATURES = new String[]{
      "aliyunwaf",
      "yunaq",
      "safedog",
      "sangfor",
      "wzws-waf",
      "wangzhan.qiniu",
      "yunjiasu",
      "cloudflare-nginx",
      "attention required",
      "access denied",
      "request blocked",
      "blocked by waf",
      "web application firewall",
      "your request has been blocked",
      "just a moment",
      "checking your browser",
      "incapsula",
      "sucuri",
      "akamai reference",
      "radware",
      "barracuda",
      "f5 big-ip",
      "traffic filtered",
      "malicious request",
      "illegal request",
      "forbidden by rule",
      "防火墙",
      "拦截",
      "非法请求",
      "恶意请求",
      "访问被拒绝",
      "禁止访问",
      "安全验证",
      "请完成安全验证",
      "存在风险",
      "安全威胁",
      "已被网站管理员",
      "云锁",
      "安全狗",
      "创宇盾",
      "知道创宇",
      "加速乐",
      "百炼",
      "玄武盾",
      "腾讯云waf",
      "阿里云waf"
   };

   private SqlWafDetector() {
   }

   public static String blocked(SimpleHttpResponse var0) {
      if (var0 == null) {
         return null;
      } else {
         int var1 = var0.getStatusCode();
         boolean var2 = var1 == 403 || var1 == 406 || var1 == 412 || var1 == 493 || var1 == 501;
         String var3 = var0.getBodyAsString();
         if (var3 != null && !var3.isEmpty()) {
            String var4 = var3.toLowerCase(Locale.ROOT);

            for (String var8 : BODY_SIGNATURES) {
               if (var4.contains(var8)) {
                  boolean var9 = var8.contains("waf")
                     || var8.contains("防火墙")
                     || var8.contains("拦截")
                     || var8.contains("safedog")
                     || var8.contains("aliyunwaf")
                     || var8.contains("yunaq")
                     || var8.contains("incapsula")
                     || var8.contains("cloudflare")
                     || var8.contains("akamai")
                     || var8.contains("sucuri")
                     || var8.contains("云锁")
                     || var8.contains("安全狗")
                     || var8.contains("创宇盾")
                     || var8.contains("加速乐")
                     || var8.contains("玄武盾");
                  if (var9 || var2) {
                     return (var2 ? "status:" + var1 + " " : "") + "signature:" + var8;
                  }
               }
            }

            return var2 ? "status:" + var1 : null;
         } else {
            return var2 ? "status:" + var1 + " (empty body)" : null;
         }
      }
   }

   public static String blockedVsBaseline(SimpleHttpResponse var0, SimpleHttpResponse var1) {
      String var2 = blocked(var0);
      if (var2 == null) {
         return null;
      } else {
         return var1 != null && blocked(var1) != null ? null : var2;
      }
   }

   public static boolean droppedVsBaseline(SimpleHttpResponse var0, boolean var1) {
      return var0 == null && var1;
   }
}
