#!/usr/bin/env bash
# XzhScan 构建脚本（Git Bash）
# 产物：build/XzhScan.jar（可由 Burp Suite 直接加载的独立扩展）
# 顺序：编译主源码 -> 打包 jar -> 编译测试 -> 运行全部自动化测试（测试七会校验 jar）
set -e
cd "$(dirname "$0")"

# JDK 解析顺序：环境变量 JDK > 本机 Adoptium 默认路径 > PATH 中的 JDK。
# 缺一不可 JDK 17+：--release 17 锁定产物字节码为 major 61（Burp Java 17 运行时可加载）。
DEFAULT_JDK="/c/Program Files/Eclipse Adoptium/jdk-17.0.19.10-hotspot"
if [ -z "$JDK" ] && [ ! -x "$DEFAULT_JDK/bin/javac.exe" ]; then
    JAVAC_IN_PATH="$(command -v javac 2>/dev/null || true)"
    if [ -n "$JAVAC_IN_PATH" ]; then
        JDK="$(dirname "$(dirname "$JAVAC_IN_PATH")")"
        echo "   note: default JDK not found, using JDK from PATH: $JDK"
    fi
fi
JDK="${JDK:-$DEFAULT_JDK}"
JAVAC="$JDK/bin/javac"
JAR="$JDK/bin/jar"
JAVA="$JDK/bin/java"

echo "[1/5] compile main"
rm -rf build/classes build/test-classes build/jar-meta
mkdir -p build/classes build/test-classes build/jar-meta/META-INF/services
"$JAVAC" --release 17 -encoding UTF-8 -cp lib/montoya-api.jar -d build/classes $(find src/com/xzhscan -name '*.java')

echo "[2/5] package XzhScan.jar"
mkdir -p build/classes/META-INF/services
# v2.2 修复：服务声明必须与现存入口类一致（历史上更名后此处仍写旧类名，
# 导致发布 jar 在 Burp 中无法加载——发布阻断级缺陷）
echo "com.xzhscan.burp.XzhScanExtension" > build/classes/META-INF/services/burp.api.montoya.BurpExtension
printf 'Manifest-Version: 1.0\nImplementation-Title: XzhScan\nImplementation-Version: 4.2.0\n' > build/jar-meta/MANIFEST.MF
rm -f build/XzhScan.jar
"$JAR" cfm build/XzhScan.jar build/jar-meta/MANIFEST.MF -C build/classes .
"$JAR" tf build/XzhScan.jar | grep -c 'class$' | xargs echo "   classes in jar:"

echo "[3/5] compile tests"
"$JAVAC" --release 17 -encoding UTF-8 -cp "build/classes;lib/montoya-api.jar" -d build/test-classes $(find tests/com/xzhscan -name '*.java')

echo "[4/5] run automated tests"
"$JAVA" -cp "build/classes;build/test-classes;lib/montoya-api.jar" com.xzhscan.TestRunner

echo "[5/5] done -> build/XzhScan.jar"
