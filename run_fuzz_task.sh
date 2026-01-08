#!/bin/bash

# 设置输出目录
mkdir -p ./out

echo "=== 开始 10 目标【并行】自动化 Fuzzing 任务 ==="

# 设定测试时长 (建议设为 86400 秒 = 24 小时)
# ⚠️ 注意：如果要看到每 100s 的输出，DURATION 至少要大于 100
DURATION=100

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

    # 根据目标不同配置不同的参数
    # target1 (cxxfilt): 使用 stdin
    # target2 (readelf): -a @@ (ELF)
    # target3 (nm): @@ (ELF)
    # target4 (objdump): -d @@ (ELF)
    # target5 (djpeg): @@ (JPEG)
    # target6 (readpng): 使用 stdin
    # target7 (xmllint): @@ (XML)
    # target8 (lua/xml): @@ (XML/LUA)
    # target9 (mjs): -f @@ (JSON/JS)
    # target10 (tcpdump): -nr @@ (PCAP)
    
    ARGS=""
    DICT_OPT=""
    STDIN_OPT=""

    case $i in
        1) STDIN_OPT="-s"; ARGS="" ;;  # cxxfilt: Fuzzer开启stdin模式
        2) ARGS="-a @@"; DICT_OPT="-x dicts/elf.dict" ;;
        3) ARGS="@@"; DICT_OPT="-x dicts/elf.dict" ;;
        4) ARGS="-d @@"; DICT_OPT="-x dicts/elf.dict" ;;
        5) ARGS="@@" ;;
        6) STDIN_OPT="-s"; ARGS="" ;;  # readpng: Fuzzer开启stdin模式
        7) ARGS="@@"; DICT_OPT="-x dicts/xml.dict" ;;
        8) ARGS="@@"; DICT_OPT="-x dicts/xml.dict" ;;
        9) ARGS="-f @@"; DICT_OPT="-x dicts/json.dict" ;;
        10) ARGS="-nr @@" ;;
        *) ARGS="@@" ;; # 默认
    esac

    # 计算 CPU 核心绑定 (绑定到核心 0-9)
    # 如果机器核心数少于10，taskset 可能会报错，所以加个简单的保护或者直接尝试
    # CORE_ID=$((i-1))
    
    # 种子目录配置
    SEED_OPT=""
    if [ "$i" -eq 1 ]; then
        # Target 1 (cxxfilt) 使用内置默认种子 (_Z1fv)
        SEED_OPT=""
    else
        # 其他 Target 使用对应的 seeds/targetX 目录
        SEED_DIR="seeds/target$i"
        # 只有当目录存在且不为空时才添加 -i 参数
        if [ -d "$SEED_DIR" ] && [ "$(ls -A $SEED_DIR)" ]; then
             SEED_OPT="-i $SEED_DIR"
        fi
    fi

    # 构建最终参数部分
    # 只有当 ARGS 非空时，才添加 -- 分隔符
    # 否则 argparse 可能会报错 unrecognized arguments: --
    FINAL_ARGS=""
    if [ -n "$ARGS" ]; then
        FINAL_ARGS="-- $ARGS"
    fi

    # 以后台模式启动 &
    # python3 -u fuzzer/main.py <target> [options] [ -- target_args ]
    python3 -u fuzzer/main.py "$TARGET_BIN" $DICT_OPT $SEED_OPT $STDIN_OPT -t $DURATION $FINAL_ARGS > "$LOG_FILE" 2>&1 &

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