package com.xzhscan.vendor.http;

import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.util.Map;
import java.util.Map.Entry;

public class SimpleHttpResponse {
   private final int statusCode;
   private final Map<String, String> headers;
   private final byte[] body;
   private final long responseTime;
   private volatile String cachedBodyText;

   private SimpleHttpResponse(SimpleHttpResponse.Builder var1) {
      this.statusCode = var1.statusCode;
      this.headers = var1.headers;
      this.body = var1.body;
      this.responseTime = var1.responseTime;
   }

   public static SimpleHttpResponse.Builder builder() {
      return new SimpleHttpResponse.Builder();
   }

   public int getStatusCode() {
      return this.statusCode;
   }

   public Map<String, String> getHeaders() {
      return this.headers;
   }

   public byte[] getBody() {
      return this.body;
   }

   public long getResponseTime() {
      return this.responseTime;
   }

   public String getBodyAsString() {
      String var1 = this.cachedBodyText;
      if (var1 != null) {
         return var1;
      } else if (this.body == null) {
         return "";
      } else {
         String var2 = this.decodeBody();
         this.cachedBodyText = var2;
         return var2;
      }
   }

   private String decodeBody() {
      Charset var1 = StandardCharsets.UTF_8;
      String var2 = this.declaredCharset();
      if (var2 != null) {
         try {
            var1 = Charset.forName(var2);
         } catch (Throwable var5) {
         }
      }

      String var3 = new String(this.body, var1);
      if (var2 == null && var3.indexOf(65533) >= 0) {
         String var4 = new String(this.body, Charset.forName("GBK"));
         if (var4.indexOf(65533) < 0) {
            return var4;
         }
      }

      return var3;
   }

   private String declaredCharset() {
      if (this.headers == null) {
         return null;
      } else {
         for (Entry var2 : this.headers.entrySet()) {
            if (var2.getKey() != null && ((String)var2.getKey()).equalsIgnoreCase("Content-Type") && var2.getValue() != null) {
               String var3 = (String)var2.getValue();
               int var4 = var3.toLowerCase().indexOf("charset=");
               if (var4 < 0) {
                  return null;
               }

               String var5 = var3.substring(var4 + 8).trim();
               int var6 = var5.indexOf(59);
               if (var6 >= 0) {
                  var5 = var5.substring(0, var6).trim();
               }

               if (var5.startsWith("\"") && var5.endsWith("\"") && var5.length() >= 2) {
                  var5 = var5.substring(1, var5.length() - 1);
               }

               return var5.isEmpty() ? null : var5;
            }
         }

         return null;
      }
   }

   public boolean isSuccess() {
      return this.statusCode >= 200 && this.statusCode < 300;
   }

   public boolean isRedirect() {
      return this.statusCode >= 300 && this.statusCode < 400;
   }

   public boolean isClientError() {
      return this.statusCode >= 400 && this.statusCode < 500;
   }

   public boolean isServerError() {
      return this.statusCode >= 500 && this.statusCode < 600;
   }

   public boolean contains(String var1) {
      return this.body != null && this.getBodyAsString().contains(var1);
   }

   public static class Builder {
      private int statusCode;
      private Map<String, String> headers;
      private byte[] body;
      private long responseTime;

      public SimpleHttpResponse.Builder statusCode(int var1) {
         this.statusCode = var1;
         return this;
      }

      public SimpleHttpResponse.Builder headers(Map<String, String> var1) {
         this.headers = var1;
         return this;
      }

      public SimpleHttpResponse.Builder body(byte[] var1) {
         this.body = var1;
         return this;
      }

      public SimpleHttpResponse.Builder responseTime(long var1) {
         this.responseTime = var1;
         return this;
      }

      public SimpleHttpResponse build() {
         return new SimpleHttpResponse(this);
      }
   }
}
