#!/bin/bash
mkdir -p ./out

echo "=== 开始 10 目标自动化 Fuzzing 任务 ==="

for i in {1..10}
do
    TARGET_BIN="./targets/target$i"

    # 1. 检查文件是否存在且可执行
    if [ ! -x "$TARGET_BIN" ]; then
        echo "[-] 错误: 目标 $TARGET_BIN 不存在或不可执行，跳过..."
        continue
    fi

    echo "[+] 正在 Fuzzing 目标 $i: $TARGET_BIN"

    # 2. 运行 Fuzzer
    # 注意：这里传入了 30，对应 main.py 的 argv[2]，表示只跑 30 秒
    # 如果你想跑久一点，把 30 改成 60 或者 300
    python3 fuzzer/main.py $TARGET_BIN 5

    echo "[+] 目标 $i 测试完成"
    echo "--------------------------------"
done

# 生成汇总报告
echo "=== 任务结束，正在生成可视化图表 ==="
python3 fuzzer/analyze.py