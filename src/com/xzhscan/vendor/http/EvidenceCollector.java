package com.xzhscan.vendor.http;

public class EvidenceCollector {
   private static final int DEFAULT_CAPACITY = 256;
   private static final String LINE_BREAK = "\n";
   private final StringBuilder builder = new StringBuilder(256);

   public EvidenceCollector add(String var1, Object var2) {
      this.builder.append(var1).append(": ").append(var2).append("\n");
      return this;
   }

   public EvidenceCollector addRequest(String var1, int var2) {
      return this.add("Path", var1).add("Status Code", var2);
   }

   public EvidenceCollector addLegacyPathStatus(String var1, int var2) {
      return this.add("Path", var1).add("Status", String.valueOf(var2));
   }

   public EvidenceCollector addRequest(String var1, String var2) {
      return this.add("Method", var1).add("Path", var2);
   }

   public EvidenceCollector addFullRequest(String var1, String var2, int var3) {
      return this.add("Method", var1).add("Path", var2).add("Status Code", var3);
   }

   public EvidenceCollector addResponse(String var1, int var2) {
      if (var1 != null && !var1.isEmpty()) {
         int var4 = Math.max(var2, 0);
         String var3;
         if (var1.length() > var4) {
            var3 = var1.substring(0, var4) + "...";
         } else {
            var3 = var1;
         }

         return this.add("Response Preview", var3);
      } else {
         return this.add("Response Preview", "");
      }
   }

   public EvidenceCollector addResponse(SimpleHttpResponse var1, int var2) {
      return this.addResponse(ResponseHelper.body(var1), var2);
   }

   public EvidenceCollector addVulnerability(String var1) {
      return this.add("Vulnerability", var1);
   }

   public EvidenceCollector addDetectionHeader(String var1, String var2) {
      return this.addTitle(var1).addVulnerability(var2);
   }

   public EvidenceCollector addPayload(String var1) {
      return this.add("Payload", var1);
   }

   public EvidenceCollector addLegacyAlias(String var1) {
      return this.add("Legacy Alias", var1);
   }

   public EvidenceCollector addLegacyEvidence(String var1) {
      return this.add("Evidence", var1);
   }

   public EvidenceCollector addMatchedFeature(String var1) {
      return this.add("Matched Feature", var1);
   }

   public EvidenceCollector addLegacyRequestMatch(String var1, String var2, int var3, String var4) {
      return this.addFullRequest(var1, var2, var3).addMatchedFeature(var4);
   }

   public EvidenceCollector addLegacyRequestMatchWithText(String var1, String var2, int var3, String var4, String var5) {
      return this.addLegacyRequestMatch(var1, var2, var3, var4).addText(var5);
   }

   public EvidenceCollector addLegacyRequestMatchWithResponse(String var1, String var2, int var3, String var4, SimpleHttpResponse var5, int var6) {
      return this.addLegacyRequestMatch(var1, var2, var3, var4).addResponse(var5, var6);
   }

   public EvidenceCollector addLegacyPathStatusText(String var1, int var2, String var3) {
      return this.addRequest(var1, var2).addText(var3);
   }

   public EvidenceCollector addSeparator() {
      this.builder.append("---").append("\n");
      return this;
   }

   public EvidenceCollector addNewLine() {
      this.builder.append("\n");
      return this;
   }

   public EvidenceCollector addTitle(String var1) {
      this.builder.append("===== ").append(var1).append(" =====").append("\n");
      return this;
   }

   public EvidenceCollector addText(String var1) {
      this.builder.append(var1).append("\n");
      return this;
   }

   public String build() {
      return this.builder.toString();
   }

   @Override
   public String toString() {
      return this.build();
   }
}
