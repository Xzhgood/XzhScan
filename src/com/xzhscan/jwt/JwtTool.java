package com.xzhscan.jwt;

import java.io.BufferedReader;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Locale;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

/**
 * JWT 密钥爆破工具（移植自 mingdong-pro）
 * 支持 HS256/HS384/HS512 算法的弱密钥爆破
 */
public final class JwtTool {
    private static volatile List<String> dictionary;

    private JwtTool() {
    }

    public static Result crack(String jwt, AtomicBoolean stopFlag) {
        // 1. 分割 JWT（header.payload.signature）
        String[] parts = jwt.trim().split("\\.");
        if (parts.length != 3) {
            return new Result(false, null, "", 0);
        }

        // 2. 解码 header 并提取算法
        String header = decode(parts[0]);
        String algorithm = extractAlgorithm(header);

        if (algorithm == null || !algorithm.startsWith("HS") || parts[2].isEmpty()) {
            return new Result(false, null, algorithm == null ? "" : algorithm, 0);
        }

        // 3. 解码原始签名
        byte[] originalSignature;
        try {
            originalSignature = Base64.getUrlDecoder().decode(padBase64(parts[2]));
        } catch (IllegalArgumentException e) {
            return new Result(false, null, algorithm, 0);
        }

        // 4. 爆破：尝试字典中的每个密钥
        String data = parts[0] + "." + parts[1];
        int tried = 0;

        for (String secret : loadDictionary()) {
            if (stopFlag != null && stopFlag.get()) {
                break;  // 中断爆破
            }
            tried++;

            byte[] testSignature = calculateHmac(data, algorithm, secret);
            if (testSignature != null && MessageDigest.isEqual(originalSignature, testSignature)) {
                return new Result(true, secret, algorithm, tried);
            }
        }

        return new Result(false, null, algorithm, tried);
    }

    /** 加载密钥字典（从 jwt.txt 或内置列表） */
    private static List<String> loadDictionary() {
        if (dictionary != null) {
            return dictionary;
        }

        synchronized (JwtTool.class) {
            if (dictionary != null) {
                return dictionary;
            }

            List<String> dict = new ArrayList<>();

            // 尝试从 resources 加载 jwt.txt
            try (InputStream is = JwtTool.class.getResourceAsStream("/jwt.txt")) {
                if (is != null) {
                    try (BufferedReader br = new BufferedReader(new InputStreamReader(is, StandardCharsets.UTF_8))) {
                        String line;
                        while ((line = br.readLine()) != null) {
                            if (!line.isEmpty() && line.length() <= 512) {
                                dict.add(line);
                            }
                        }
                    }
                }
            } catch (Throwable ignored) {
            }

            // 如果加载失败，使用内置的常见弱密钥
            if (dict.isEmpty()) {
                dict.addAll(List.of(
                    "secret", "123456", "password", "admin", "root", "test",
                    "qwerty", "12345678", "admin123", "password123",
                    "secret123", "jwt_secret", "your-secret-key", "your-256-bit-secret",
                    "", "null", "undefined"
                ));
            }

            dictionary = dict;
            return dict;
        }
    }

    /** 计算 HMAC 签名 */
    private static byte[] calculateHmac(String data, String algorithm, String secret) {
        try {
            String hmacAlgo = "HmacSHA256";
            String alg = algorithm.toUpperCase(Locale.ROOT);

            if (alg.equals("HS384")) {
                hmacAlgo = "HmacSHA384";
            } else if (alg.equals("HS512")) {
                hmacAlgo = "HmacSHA512";
            }

            Mac mac = Mac.getInstance(hmacAlgo);
            mac.init(new SecretKeySpec(secret.getBytes(StandardCharsets.UTF_8), hmacAlgo));
            return mac.doFinal(data.getBytes(StandardCharsets.UTF_8));
        } catch (Throwable e) {
            return null;
        }
    }

    /** 从 header JSON 中提取 alg 字段 */
    private static String extractAlgorithm(String header) {
        Matcher m = Pattern.compile("\"alg\"\\s*:\\s*\"([^\"]+)\"", Pattern.CASE_INSENSITIVE).matcher(header == null ? "" : header);
        return m.find() ? m.group(1) : null;
    }

    /** Base64 URL 解码 */
    private static String decode(String base64) {
        try {
            return new String(Base64.getUrlDecoder().decode(padBase64(base64)), StandardCharsets.UTF_8);
        } catch (IllegalArgumentException e) {
            return "";
        }
    }

    /** Base64 填充（JWT 的 Base64 可能没有 = 填充） */
    private static String padBase64(String base64) {
        int mod = base64.length() % 4;
        if (mod == 2) {
            return base64 + "==";
        } else if (mod == 3) {
            return base64 + "=";
        }
        return base64;
    }

    /** 爆破结果 */
    public static final class Result {
        public final boolean found;      // 是否找到密钥
        public final String secret;      // 密钥（找到时非 null）
        public final String algorithm;   // 算法（如 HS256）
        public final int tried;          // 尝试的密钥数量

        Result(boolean found, String secret, String algorithm, int tried) {
            this.found = found;
            this.secret = secret;
            this.algorithm = algorithm;
            this.tried = tried;
        }
    }
}
