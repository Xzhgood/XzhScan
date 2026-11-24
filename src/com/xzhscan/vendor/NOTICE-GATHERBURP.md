# Third-party Notice — gatherBurp (MIT License)

XzhScan 的 PermAccess、DirScan、U2C 三个模块的检测逻辑迁移自开源项目 **gatherBurp**
（原项目路径 `Desktop/gatherBurp-master`，原作者 kN6jq，MIT License，见其 README/LICENSE）。

迁移方式：只读参考源码后，在 `com.xzhscan` 包内以 Montoya API 重新实现/适配；
未复制其 Swing UI、SQLite DAO 与旧 Extender API 绑定，未修改原始项目任何文件。

## 迁移来源逐项对照

| XzhScan 类 | gatherBurp 来源 | 迁移内容 |
|---|---|---|
| `perm.AuthScanEngine` | `burp/ui/PermUI.java:364-479`（Check） | 三态重放判定（原始/低权限/无权限）、头同名替换/删除语义、状态码+响应体字节数相等判定 |
| `perm.AuthScanEngine.domainMatches` | `burp/utils/Utils.java:364-414` | 域名从右往左通配匹配 |
| `perm.AuthScanRequestFilter` | `burp/utils/Utils.java:142-151,345-356`（后缀黑名单） | 扩展为九大类 + MIME/Disposition/Method 多信号 + ALLOW/REJECT/UNKNOWN 三态 |
| `dirscan.RouteRuleBook` | `burp/dao/RouteDao.java:107-159`（DEFAULT_RULES） | 34 条默认敏感路径规则逐字平移 |
| `dirscan.PathExpression` | `burp/utils/ExpressionUtils.java` | code/title/body/headers + = != && \|\| 括号递归下降 |
| `dirscan.DirScanEngine` | `burp/ui/RouteUI.java`（Check）、`RoutePathUtils`、`RouteSoft404` | soft404 基线比对、路径前缀生成（深度 4）、GET 空 body 探针、请求预算与主机限速 |
| `codec.UnicodeCodec` | `burp/utils/CodecUtils.java` | Unicode 多层转义还原、charset 候选/探测、JSON 美化（改自研 MiniJson 替代 fastjson） |
| `codec.U2cEditorTab` | `burp/ui/codec/U2CTab.java`、`U2CTabFactory.java` | 请求/响应编辑器附属页签（Montoya 编辑器扩展点重写） |

## 许可证

gatherBurp 以 MIT License 发布；本插件对上述迁移部分的再分发保留此声明。

## v2.2 变更（2026-11-20）

**DirScan（目录扫描，迁移自 gatherBurp Route 模块）已整体移除**：
`dirscan.DirScanModule / DirScanEngine / PathExpression / RouteRuleBook` 及 `ui.DirScanUi`
全部删除，相关配置键（dirPassiveEnabled/dirWhitelistDomains/dirHostIntervalMs）废弃。
其来源对照（RouteDao/RoutePathUtils/RouteUI）仅为历史记录，不再对应任何现存代码。
保留的 gatherBurp 衍生模块：AuthScan（Perm）与 U2C。
