package com.xzhscan.filescan;

/**
 * 文件读取扫描结果
 */
public class FileScanResult {
    public String requestId;
    public String url;
    public String method;
    public String parameterName;
    public String parameterLocation;
    public String payload;
    public String hitType;  // "Linux /etc/passwd" / "Java WEB-INF/web.xml" / "Windows win.ini"
    public String evidence;  // 响应片段（前 500 字符）
    public long timestamp;

    public FileScanResult(String requestId, String url, String method,
                         String paramName, String paramLocation,
                         String payload, String hitType, String evidence) {
        this.requestId = requestId;
        this.url = url;
        this.method = method;
        this.parameterName = paramName;
        this.parameterLocation = paramLocation;
        this.payload = payload;
        this.hitType = hitType;
        this.evidence = evidence == null ? "" : (evidence.length() > 500 ? evidence.substring(0, 500) : evidence);
        this.timestamp = System.currentTimeMillis();
    }
}
