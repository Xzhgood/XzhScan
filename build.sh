#!/bin/bash
# XzhScan 构建脚本

set -e

# 设置 Java 路径
export JAVA_HOME="/c/Program Files/Eclipse Adoptium/jdk-17.0.19.10-hotspot"
export PATH="$JAVA_HOME/bin:$PATH"

echo "[1/5] compile main"
mkdir -p build/classes
javac -encoding UTF-8 -cp "lib/*" -d build/classes $(find src -name "*.java")

echo "[2/5] package XzhScan.jar"
mkdir -p build/jar-meta/META-INF/services
echo "com.xzhscan.burp.XzhScanExtension" > build/jar-meta/META-INF/services/burp.api.montoya.BurpExtension
jar cf build/XzhScan.jar -C build/classes . -C build/jar-meta .
echo "   classes in jar: $(unzip -l build/XzhScan.jar | grep -c "\.class$")"

echo "[3/5] done"
ls -lh build/XzhScan.jar
