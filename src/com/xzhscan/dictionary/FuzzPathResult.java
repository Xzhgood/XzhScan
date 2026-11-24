package com.xzhscan.dictionary;

import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

/**
 * Fuzz 路径处理结果及统计。
 */
public final class FuzzPathResult {

    /** 有效路径（去重后，保持顺序）。 */
    public final List<String> validPaths = new ArrayList<>();

    /** 原始输入总数。 */
    public int originalCount = 0;

    /** 有效路径数量（去重后）。 */
    public int validCount = 0;

    /** 重复数量（被去重的）。 */
    public int duplicateCount = 0;

    /** 黑名单过滤数量。 */
    public int blacklistFilteredCount = 0;

    /** 静态资源过滤数量。 */
    public int staticResourceFilteredCount = 0;

    /** 其他无效数量（URL、MIME、版本号等）。 */
    public int otherInvalidCount = 0;

    /** 被过滤的路径详情（用于调试）。 */
    public final List<FilteredPath> filteredPaths = new ArrayList<>();

    /**
     * 过滤路径详情。
     */
    public static final class FilteredPath {
        public final String path;
        public final String reason;

        public FilteredPath(String path, String reason) {
            this.path = path;
            this.reason = reason;
        }

        @Override
        public String toString() {
            return path + " → " + reason;
        }
    }

    /** 添加有效路径（内部自动去重）。 */
    private final Set<String> deduplicationSet = new LinkedHashSet<>();

    public void addValidPath(String path) {
        if (deduplicationSet.add(path)) {
            validPaths.add(path);
            validCount++;
        } else {
            duplicateCount++;
        }
    }

    /** 添加被过滤的路径。 */
    public void addFilteredPath(String path, String reason) {
        filteredPaths.add(new FilteredPath(path, reason));
    }

    /** 生成统计摘要。 */
    public String getSummary() {
        return String.format(
                "原始: %d | 有效: %d | 重复: %d | 黑名单: %d | 静态资源: %d | 其他无效: %d",
                originalCount, validCount, duplicateCount,
                blacklistFilteredCount, staticResourceFilteredCount, otherInvalidCount
        );
    }
}
