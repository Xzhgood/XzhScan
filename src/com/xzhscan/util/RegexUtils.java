package com.xzhscan.util;

import java.util.concurrent.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * 安全的正则表达式工具，提供超时保护防止 ReDoS（正则表达式拒绝服务）攻击。
 * <p>
 * 移植自 DetSql v3.3.0 安全加固：当恶意响应体（极长字符串 + 复杂正则）时，
 * 避免 CPU 100% 卡死。200ms 超时后自动取消匹配。
 */
public final class RegexUtils {

    private RegexUtils() {
    }

    /** 默认超时时间（毫秒）*/
    private static final long DEFAULT_TIMEOUT_MS = 200;

    /**
     * 安全的正则匹配（带超时保护）
     *
     * @param input 输入字符串
     * @param pattern 预编译的 Pattern
     * @return 是否匹配成功，超时返回 false
     */
    public static boolean matches(String input, Pattern pattern) {
        return matches(input, pattern, DEFAULT_TIMEOUT_MS);
    }

    /**
     * 安全的正则匹配（带超时保护）
     *
     * @param input 输入字符串
     * @param pattern 预编译的 Pattern
     * @param timeoutMs 超时时间（毫秒）
     * @return 是否匹配成功，超时返回 false
     */
    public static boolean matches(String input, Pattern pattern, long timeoutMs) {
        if (input == null || pattern == null) {
            return false;
        }

        // 快速检查：空字符串
        if (input.isEmpty()) {
            return false;
        }

        ExecutorService executor = Executors.newSingleThreadExecutor(r -> {
            Thread t = new Thread(r);
            t.setDaemon(true);  // 守护线程，JVM 退出时自动结束
            return t;
        });

        Future<Boolean> future = executor.submit(() -> {
            try {
                return pattern.matcher(input).find();
            } catch (Exception e) {
                return false;
            }
        });

        try {
            return future.get(timeoutMs, TimeUnit.MILLISECONDS);
        } catch (TimeoutException e) {
            // 超时：取消任务并返回 false
            future.cancel(true);
            return false;
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            return false;
        } catch (ExecutionException e) {
            return false;
        } finally {
            executor.shutdownNow();
        }
    }

    /**
     * 安全的 Matcher 查找（带超时保护）
     *
     * @param input 输入字符串
     * @param pattern 预编译的 Pattern
     * @return Matcher 对象，超时或失败返回 null
     */
    public static Matcher safeMatcher(String input, Pattern pattern) {
        return safeMatcher(input, pattern, DEFAULT_TIMEOUT_MS);
    }

    /**
     * 安全的 Matcher 查找（带超时保护）
     *
     * @param input 输入字符串
     * @param pattern 预编译的 Pattern
     * @param timeoutMs 超时时间（毫秒）
     * @return Matcher 对象，超时或失败返回 null
     */
    public static Matcher safeMatcher(String input, Pattern pattern, long timeoutMs) {
        if (input == null || pattern == null) {
            return null;
        }

        ExecutorService executor = Executors.newSingleThreadExecutor(r -> {
            Thread t = new Thread(r);
            t.setDaemon(true);
            return t;
        });

        Future<Matcher> future = executor.submit(() -> {
            try {
                Matcher m = pattern.matcher(input);
                if (m.find()) {
                    m.reset();  // 重置到字符串开头
                    return m;
                }
                return null;
            } catch (Exception e) {
                return null;
            }
        });

        try {
            return future.get(timeoutMs, TimeUnit.MILLISECONDS);
        } catch (TimeoutException e) {
            future.cancel(true);
            return null;
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            return null;
        } catch (ExecutionException e) {
            return null;
        } finally {
            executor.shutdownNow();
        }
    }

    /**
     * 安全的 replaceAll（带超时保护）
     *
     * @param input 输入字符串
     * @param pattern 预编译的 Pattern
     * @param replacement 替换字符串
     * @return 替换后的字符串，超时返回原字符串
     */
    public static String safeReplaceAll(String input, Pattern pattern, String replacement) {
        return safeReplaceAll(input, pattern, replacement, DEFAULT_TIMEOUT_MS);
    }

    /**
     * 安全的 replaceAll（带超时保护）
     *
     * @param input 输入字符串
     * @param pattern 预编译的 Pattern
     * @param replacement 替换字符串
     * @param timeoutMs 超时时间（毫秒）
     * @return 替换后的字符串，超时返回原字符串
     */
    public static String safeReplaceAll(String input, Pattern pattern, String replacement, long timeoutMs) {
        if (input == null || pattern == null) {
            return input;
        }

        ExecutorService executor = Executors.newSingleThreadExecutor(r -> {
            Thread t = new Thread(r);
            t.setDaemon(true);
            return t;
        });

        Future<String> future = executor.submit(() -> {
            try {
                return pattern.matcher(input).replaceAll(replacement);
            } catch (Exception e) {
                return input;
            }
        });

        try {
            return future.get(timeoutMs, TimeUnit.MILLISECONDS);
        } catch (TimeoutException e) {
            future.cancel(true);
            return input;  // 超时返回原字符串
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            return input;
        } catch (ExecutionException e) {
            return input;
        } finally {
            executor.shutdownNow();
        }
    }
}
