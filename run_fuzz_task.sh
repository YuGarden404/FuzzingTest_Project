#!/bin/bash
mkdir -p ./out

echo "=== 开始 10 目标自动化 Fuzzing 任务 ==="

for i in {1..10}
do
    TARGET_SRC="./targets/target$i.c"
    TARGET_BIN="./targets/target$i"

    echo "[+] 正在处理目标 $i: $TARGET_SRC"

    # 编译
    afl-cc $TARGET_SRC -o $TARGET_BIN

    # 运行 Fuzzer (每个目标跑 30 秒)
    python3 fuzzer/main.py $TARGET_BIN
done

# 生成汇总报告
echo "=== 任务结束，正在生成可视化图表 ==="
python3 fuzzer/analyze.py