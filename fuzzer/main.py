import os, subprocess, sysv_ipc, random, time, sys

# --- 配置区 ---
MAP_SIZE = 65536
# --- 在类定义之外或作为类的常量 ---
# 8位感兴趣值 (例如: -128, -1, 0, 1, 16, 32...)
INTERESTING_8 = [
    -128, -1, 0, 1, 16, 32, 64, 100, 127
]
# 16位感兴趣值 (例如: -32768, -1, 0, MAX_UINT16...)
INTERESTING_16 = [
    -32768, -129, 128, 255, 256, 512, 1000, 1024, 4096, 32767, 65535
]
# 32位感兴趣值
INTERESTING_32 = [
    -2147483648, -100663046, -32769, 32768, 65536, 100000, 2147483647
]

class GreyBoxFuzzer:
    def __init__(self, target_path):
        self.target_path = target_path

        # === 1. 路径修复：动态计算项目根目录 ===
        # 获取当前脚本 (main.py) 所在的目录 (即 fuzzer/)
        current_dir = os.path.dirname(os.path.abspath(__file__))
        # 获取项目根目录 (即 fuzzer/ 的上一级)
        project_root = os.path.dirname(current_dir)
        # 拼接 out 目录路径
        out_dir = os.path.join(project_root, "out")

        # 确保 out 目录存在，如果不存在则创建
        if not os.path.exists(out_dir):
            os.makedirs(out_dir)

        # 监控组件 & 插装对接
        self.shm = sysv_ipc.SharedMemory(None, flags=sysv_ipc.IPC_CREAT | sysv_ipc.IPC_EXCL, mode=0o600, size=MAP_SIZE)
        self.env = os.environ.copy()
        self.env["__AFL_SHM_ID"] = str(self.shm.id)

        self.global_visited_indices = set()
        self.corpus = [b"init"]  # 初始种子
        self.exec_count = 0
        self.start_time = time.time()

        # 使用动态计算出的绝对路径，避免相对路径报错
        self.stats_file = os.path.join(out_dir, f"stats_{os.path.basename(target_path)}.csv")

    # 2. 变异组件
    # 在 GreyBoxFuzzer 类中添加 splice 方法
    def splice(self, data):
        # 如果语料库太少，没法拼接，直接返回原数据
        if len(self.corpus) < 2:
            return data

        # 随机找另一个种子
        other = random.choice(self.corpus)

        # 随机找个切割点
        cut_at = random.randint(0, min(len(data), len(other)))

        # 拼接：前半段用自己的，后半段用别人的
        return data[:cut_at] + other[cut_at:]

        # === 变异算子实现 ===

    def _bitflip(self, data):
        """Bitflip: 翻转 1 个 bit"""
        res = bytearray(data)
        if not res: return res
        idx = random.randint(0, len(res) - 1)
        bit_idx = random.randint(0, 7)
        res[idx] ^= (1 << bit_idx)  # 异或操作实现翻转
        return bytes(res)

    def _byteflip(self, data):
        """Byteflip: 翻转整个 byte (按位取反)"""
        res = bytearray(data)
        if not res: return res
        idx = random.randint(0, len(res) - 1)
        res[idx] ^= 0xFF
        return bytes(res)

    def _arith(self, data):
        """Arith: 算术加减运算 (例如 +1, -1, +10...)"""
        res = bytearray(data)
        if not res: return res
        idx = random.randint(0, len(res) - 1)
        # 随机加或减一个小整数
        val = random.randint(-35, 35)
        # 确保结果在 0-255 之间 (模拟 8bit 溢出)
        res[idx] = (res[idx] + val) & 0xFF
        return bytes(res)

    def _interest(self, data):
        """Interest: 替换为感兴趣的整数 (边界值)"""
        res = bytearray(data)
        if not res: return res

        # 随机选择替换 1个字节(8bit)、2个字节(16bit) 还是 4个字节(32bit)
        kind = random.choice([8, 16, 32])

        if kind == 8:
            val = random.choice(INTERESTING_8)
            idx = random.randint(0, len(res) - 1)
            res[idx] = val & 0xFF

        elif kind == 16 and len(res) >= 2:
            val = random.choice(INTERESTING_16)
            idx = random.randint(0, len(res) - 2)
            # 大端序或小端序随机
            import struct
            order = random.choice(['<', '>'])
            # 将整数打包成 bytes 并替换
            try:
                chunk = struct.pack(f'{order}h', val)
                res[idx:idx + 2] = chunk
            except:
                pass  # 忽略打包错误

        elif kind == 32 and len(res) >= 4:
            val = random.choice(INTERESTING_32)
            idx = random.randint(0, len(res) - 4)
            import struct
            order = random.choice(['<', '>'])
            try:
                chunk = struct.pack(f'{order}i', val)
                res[idx:idx + 4] = chunk
            except:
                pass

            return bytes(res)

    def _havoc(self, data):
        """Havoc: 大破坏模式 (多次叠加各种变异)"""
        res = data
        # 随机进行 2 到 8 次变异叠加
        for _ in range(random.randint(2, 8)):
            # 随机挑选一个变异算子执行
            operator = random.choice([
                self._bitflip,
                self._byteflip,
                self._arith,
                self._interest,
                # 还可以加入块删除、块插入等
            ])
            res = operator(res)
        return res

        # === 主变异调度函数 ===
    def mutate(self, data):
        """
        调度器: 随机选择一种变异策略
        """
        if not data: return b"a"  # 防止空数据

        # 按照一定概率选择变异策略
        # Havoc 应该是概率最大的，因为它能产生更多样化的输入
        rand = random.random()
        if rand < 0.1:
            return self._bitflip(data)
        elif rand < 0.2:
            return self._byteflip(data)
        elif rand < 0.4:
            return self._arith(data)
        elif rand < 0.6:
            return self._interest(data)
        else:
            return self._havoc(data)  # 40% 的概率进入 Havoc 模式

    # 3. 能量调度组件 (Power Schedule)
    def calculate_energy(self, seed_coverage_len):
        # 覆盖越多，能量越高
        return min(max(5, seed_coverage_len * 2), 50)

    def start(self, timeout=60):  # 默认每个目标跑 60 秒
        print(f"[*] 正在测试目标: {self.target_path}")
        with open(self.stats_file, "w") as f:
            f.write("time,cov\n")

        # === 新增：上一次记录的时间 ===
        last_log_time = time.time()

        while time.time() - self.start_time < timeout:
            # ... (种子选择和变异逻辑保持不变) ...
            self.corpus.sort(key=len)
            top_k = max(1, int(len(self.corpus) * 0.2))
            seed_data = random.choice(self.corpus[:top_k])
            energy = self.calculate_energy(len(self.global_visited_indices))

            for _ in range(energy):
                # ... (变异和拼接逻辑保持不变) ...
                current_seed = seed_data
                if random.random() < 0.1:
                    current_seed = self.splice(current_seed)
                candidate = self.mutate(current_seed)

                # 执行组件
                self.shm.write(b'\x00' * MAP_SIZE)
                proc = subprocess.Popen([self.target_path], stdin=subprocess.PIPE, stderr=subprocess.PIPE, env=self.env)
                try:
                    proc.communicate(input=candidate, timeout=0.1)
                except:
                    proc.kill()
                    proc.wait()

                # 评估组件
                bitmap = self.shm.read(MAP_SIZE)
                current_indices = set(i for i, v in enumerate(bitmap) if v > 0)

                # 发现新路径：立即记录
                if current_indices and not current_indices.issubset(self.global_visited_indices):
                    self.global_visited_indices.update(current_indices)
                    self.corpus.append(candidate)
                    with open(self.stats_file, "a") as f:
                        f.write(f"{time.time() - self.start_time:.2f},{len(self.global_visited_indices)}\n")
                    last_log_time = time.time()  # 更新记录时间

                # === 关键修改：每隔 1 秒强制记录一次状态 (心跳包) ===
                # 这样即使没有新发现，图表上也会有一条横线，证明 Fuzzer 活着
                if time.time() - last_log_time > 1.0:
                    with open(self.stats_file, "a") as f:
                        f.write(f"{time.time() - self.start_time:.2f},{len(self.global_visited_indices)}\n")
                    last_log_time = time.time()

                if proc.returncode == 66 or (proc.returncode is not None and proc.returncode < 0):
                    # print(f"[!] 发现崩溃: {self.target_path}") # 注释掉，避免刷屏
                    pass
        return False


if __name__ == "__main__":
    target = sys.argv[1] if len(sys.argv) > 1 else "./target/target_instrumented"
    # 如果没传参数且默认路径不存在，尝试智能寻找（可选增强）
    if not os.path.exists(target) and target == "./target/target_instrumented":
        # 尝试去上级目录找
        potential_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "target",
                                      "target_instrumented")
        if os.path.exists(potential_path):
            target = potential_path

    f = GreyBoxFuzzer(target)
    try:
        f.start(timeout=30)  # 每个目标跑 30 秒进行快速演示
    finally:
        f.shm.remove()