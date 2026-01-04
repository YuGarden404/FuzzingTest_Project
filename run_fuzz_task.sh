#!/bin/bash

# 设置输出目录
mkdir -p ./out

echo "=== 开始 10 目标【并行】自动化 Fuzzing 任务 ==="

# 设定测试时长 (例如 86400 秒 = 24 小时)
# 调试时可以设短一点，比如 60
DURATION=5

# 循环遍历 target1 到 target10
for i in {1..10}
do
    TARGET_BIN="./targets/target$i"

    # 检查文件是否存在
    if [ ! -f "$TARGET_BIN" ]; then
        echo "[-] 错误: 目标 $TARGET_BIN 不存在，跳过..."
        continue
    fi

    # 确保有执行权限
    chmod +x "$TARGET_BIN"

    echo "[+] 启动 Fuzzer (后台运行): 目标 $i ($TARGET_BIN)"

    # === 运行 Fuzzer (并行关键点) ===
    # 1. 在命令末尾加 & 让它在后台运行
    # 2. 输出日志重定向，避免 10 个程序的日志在屏幕上打架
    LOG_FILE="./out/fuzz_log_target$i.txt"
    python3 fuzzer/main.py "$TARGET_BIN" $DURATION > "$LOG_FILE" 2>&1 &

    # 记录后台进程 PID (可选，方便调试)
    echo "    -> PID: $!"
done

echo "------------------------------------------------"
echo "[*] 所有 Fuzzer 已启动，正在并行运行中..."
echo "[*] 请勿关闭此终端，等待 $DURATION 秒..."
echo "[*] 你可以使用 'tail -f out/fuzz_log_target1.txt' 查看某个目标的实时日志"

# === 等待所有后台任务结束 ===
wait

echo "================================================"
echo "所有任务已结束！正在生成可视化报告..."
python3 fuzzer/analyze.py
echo "[+] 报告已生成: out/experiment_report.md"