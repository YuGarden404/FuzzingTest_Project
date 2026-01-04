import os, subprocess, sysv_ipc, random, time, sys

# --- 配置区 ---
MAP_SIZE = 65536


class GreyBoxFuzzer:
    def __init__(self, target_path):
        self.target_path = target_path
        # 1. 监控组件 & 插装对接
        self.shm = sysv_ipc.SharedMemory(None, flags=sysv_ipc.IPC_CREAT | sysv_ipc.IPC_EXCL, mode=0o600, size=MAP_SIZE)
        self.env = os.environ.copy()
        self.env["__AFL_SHM_ID"] = str(self.shm.id)

        self.global_visited_indices = set()
        self.corpus = [b"init"]  # 初始种子
        self.exec_count = 0
        self.start_time = time.time()
        self.stats_file = f"/app/out/stats_{os.path.basename(target_path)}.csv"

    # 2. 变异组件
    def mutate(self, data):
        res = bytearray(data)
        if not res: return b"a"
        for _ in range(random.randint(1, 2)):
            idx = random.randint(0, len(res) - 1)
            res[idx] = (res[idx] + random.randint(1, 255)) % 256
        return bytes(res)

    # 3. 能量调度组件 (Power Schedule)
    def calculate_energy(self, seed_coverage_len):
        # 覆盖越多，能量越高
        return min(max(5, seed_coverage_len * 2), 50)

    def start(self, timeout=60):  # 默认每个目标跑 60 秒
        print(f"[*] 正在测试目标: {self.target_path}")
        with open(self.stats_file, "w") as f:
            f.write("time,cov\n")

        while time.time() - self.start_time < timeout:
            # 4. 种子排序/选择组件 (简单队列)
            seed_data = random.choice(self.corpus)
            energy = self.calculate_energy(len(self.global_visited_indices))

            for _ in range(energy):
                candidate = self.mutate(seed_data)

                # 5. 执行组件
                self.shm.write(b'\x00' * MAP_SIZE)
                proc = subprocess.Popen([self.target_path], stdin=subprocess.PIPE, stderr=subprocess.PIPE, env=self.env)
                try:
                    proc.communicate(input=candidate, timeout=0.1)
                except:
                    proc.kill()
                    proc.wait()

                # 6. 评估组件
                bitmap = self.shm.read(MAP_SIZE)
                current_indices = set(i for i, v in enumerate(bitmap) if v > 0)

                if current_indices and not current_indices.issubset(self.global_visited_indices):
                    self.global_visited_indices.update(current_indices)
                    self.corpus.append(candidate)
                    # 记录实时覆盖率
                    with open(self.stats_file, "a") as f:
                        f.write(f"{time.time() - self.start_time:.2f},{len(self.global_visited_indices)}\n")

                if proc.returncode == 66 or (proc.returncode is not None and proc.returncode < 0):
                    print(f"[!] 发现崩溃: {self.target_path}")
                    return True
        return False


if __name__ == "__main__":
    target = sys.argv[1] if len(sys.argv) > 1 else "/app/target/target_instrumented"
    f = GreyBoxFuzzer(target)
    try:
        f.start(timeout=30)  # 每个目标跑 30 秒进行快速演示
    finally:
        f.shm.remove()