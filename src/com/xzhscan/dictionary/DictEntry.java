package com.xzhscan.dictionary;

/**
 * 字典条目通用模型（Dictionary 页签五子页共用）。
 *
 * @param category 分类（DBMS 名 / 场景组 / payload 组）
 * @param label    条目短标签（列表显示）
 * @param body     条目正文（语句/命令/payload 原文，复制按钮复制此内容）
 * @param note     备注（用法/差分对照/厂商绕过提示；可为空串）
 */
public record DictEntry(String category, String label, String body, String note) {

    public DictEntry {
        if (category == null) {
            category = "";
        }
        if (label == null) {
            label = "";
        }
        if (body == null) {
            body = "";
        }
        if (note == null) {
            note = "";
        }
    }
}
