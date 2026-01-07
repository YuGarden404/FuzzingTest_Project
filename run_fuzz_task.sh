#!/bin/bash

# 设置输出目录
mkdir -p ./out

echo "=== 开始 10 目标【并行】自动化 Fuzzing 任务 ==="

# 设定测试时长 (建议设为 86400 秒 = 24 小时)
# ⚠️ 注意：如果要看到每 100s 的输出，DURATION 至少要大于 100
DURATION=10

# 定义计时监控函数
monitor_time() {
    START_TIME=$(date +%s)
    while true; do
        sleep 100
        CURRENT_TIME=$(date +%s)
        ELAPSED=$((CURRENT_TIME - START_TIME))
        # 转换成更易读的格式 (小时:分钟:秒)
        H=$((ELAPSED/3600))
        M=$(( (ELAPSED%3600)/60 ))
        S=$((ELAPSED%60))
        echo ">>> [系统监控] 当前任务已持续运行: ${ELAPSED} 秒 (${H}h ${M}m ${S}s)"
    done
}

# 初始化 PID 列表
FUZZER_PIDS=""

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

    echo "[+] 启动 Fuzzer (后台运行): 目标 $i"

    # === 运行 Fuzzer ===
    LOG_FILE="./out/fuzz_log_target$i.txt"

    # 以后台模式启动 &
    python3 -u fuzzer/main.py "$TARGET_BIN" $DURATION > "$LOG_FILE" 2>&1 &

    # 记录当前 Fuzzer 的 PID
    FUZZER_PIDS="$FUZZER_PIDS $!"
done

echo "------------------------------------------------"
echo "[*] 所有 Fuzzer 已启动，正在并行运行中..."
echo "[*] 测试总时长设定为: $DURATION 秒"
echo "[*] 你可以使用 'tail -f out/fuzz_log_target1.txt' 查看某个目标的实时日志"

# === 启动时间监控 (后台运行) ===
monitor_time &
MONITOR_PID=$!  # 记录监控进程的 PID，以便最后杀掉它

# === 等待所有 Fuzzer 结束 ===
# 注意：这里指定等待 FUZZER_PIDS，这样就不会被 monitor_time 的死循环卡住
wait $FUZZER_PIDS

# === 清理工作 ===
# 当所有 Fuzzer 结束后，杀掉监控进程
kill $MONITOR_PID 2>/dev/null

echo "================================================"
echo "所有任务已结束！正在生成可视化报告..."
python3 fuzzer/analyze.py
echo "[+] 报告已生成: out/experiment_report.md"