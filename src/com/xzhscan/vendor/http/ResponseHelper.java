package com.xzhscan.vendor.http;

import java.util.Map;

public class ResponseHelper {
   public static String body(SimpleHttpResponse var0) {
      return var0 == null ? "" : var0.getBodyAsString();
   }

   public static boolean isSuccess(SimpleHttpResponse var0) {
      int var1;
      return var0 != null && (var1 = var0.getStatusCode()) >= 200 && var1 < 300;
   }

   public static boolean contains(SimpleHttpResponse var0, String... var1) {
      if (var0 != null && var1 != null && var1.length != 0) {
         String var2 = body(var0);

         for (String var6 : var1) {
            if (var6 != null && var2.contains(var6)) {
               return true;
            }
         }

         return false;
      } else {
         return false;
      }
   }

   public static boolean containsAll(SimpleHttpResponse var0, String... var1) {
      if (var0 != null && var1 != null && var1.length != 0) {
         String var2 = body(var0);

         for (String var6 : var1) {
            if (var6 == null || !var2.contains(var6)) {
               return false;
            }
         }

         return true;
      } else {
         return false;
      }
   }

   public static boolean headerContains(SimpleHttpResponse var0, String var1, String var2) {
      if (var0 != null && var0.getHeaders() != null) {
         Map var3 = var0.getHeaders();
         String var4 = (String)var3.get(var1);
         return var4 != null && var4.contains(var2);
      } else {
         return false;
      }
   }

   public static String getHeader(SimpleHttpResponse var0, String var1) {
      return var0 != null && var0.getHeaders() != null ? var0.getHeaders().get(var1) : null;
   }

   public static boolean hasStatusCode(SimpleHttpResponse var0, int var1) {
      return var0 != null && var0.getStatusCode() == var1;
   }

   public static boolean hasStatusCodeInRange(SimpleHttpResponse var0, int var1, int var2) {
      int var3;
      return var0 != null && (var3 = var0.getStatusCode()) >= var1 && var3 <= var2;
   }

   public static boolean isRedirect(SimpleHttpResponse var0) {
      int var1;
      return var0 != null && (var1 = var0.getStatusCode()) >= 300 && var1 < 400;
   }

   public static boolean isClientError(SimpleHttpResponse var0) {
      int var1;
      return var0 != null && (var1 = var0.getStatusCode()) >= 400 && var1 < 500;
   }

   public static boolean isServerError(SimpleHttpResponse var0) {
      int var1;
      return var0 != null && (var1 = var0.getStatusCode()) >= 500 && var1 < 600;
   }

   public static String truncateBody(SimpleHttpResponse var0, int var1) {
      String var2 = body(var0);
      return var2.length() <= var1 ? var2 : var2.substring(0, var1) + "...";
   }
}
