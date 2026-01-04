import os
import subprocess
import sysv_ipc
import random
import time
import sys
import struct

# --- 配置区 ---
MAP_SIZE = 65536

# --- 感兴趣值 (Magic Numbers) ---
INTERESTING_8 = [-128, -1, 0, 1, 16, 32, 64, 100, 127]
INTERESTING_16 = [-32768, -129, 128, 255, 256, 512, 1000, 1024, 4096, 32767, 65535]
INTERESTING_32 = [-2147483648, -100663046, -32769, 32768, 65536, 100000, 2147483647]


class GreyBoxFuzzer:
    def __init__(self, target_path):
        self.target_path = target_path
        self.target_name = os.path.basename(target_path)

        # === 路径修复：动态计算项目根目录 ===
        current_dir = os.path.dirname(os.path.abspath(__file__))
        self.project_root = os.path.dirname(current_dir)
        self.out_dir = os.path.join(self.project_root, "out")

        if not os.path.exists(self.out_dir):
            os.makedirs(self.out_dir)

        # 监控组件 & 插装对接
        try:
            self.shm = sysv_ipc.SharedMemory(None, flags=sysv_ipc.IPC_CREAT | sysv_ipc.IPC_EXCL, mode=0o600,
                                             size=MAP_SIZE)
        except sysv_ipc.ExistentialError:
            # 如果共享内存没清理干净，尝试新建一个
            self.shm = sysv_ipc.SharedMemory(None, flags=sysv_ipc.IPC_CREAT, mode=0o600, size=MAP_SIZE)

        self.env = os.environ.copy()
        self.env["__AFL_SHM_ID"] = str(self.shm.id)

        self.global_visited_indices = set()
        self.total_execs = 0  # 新增：总执行次数用于计算速度
        self.start_time = time.time()

        # === 修复：更智能的种子加载 ===
        self.corpus = []
        # 1. 优先尝试 seeds/targetX (针对性种子)
        specific_seed_dir = os.path.join(self.project_root, "seeds", self.target_name)
        # 2. 其次尝试 seeds/ (通用种子)
        general_seed_dir = os.path.join(self.project_root, "seeds")

        loaded_dir = None
        if os.path.exists(specific_seed_dir) and os.listdir(specific_seed_dir):
            loaded_dir = specific_seed_dir
        elif os.path.exists(general_seed_dir) and os.listdir(general_seed_dir):
            loaded_dir = general_seed_dir

        if loaded_dir:
            print(f"[*] Loading seeds from: {loaded_dir}")
            for f in os.listdir(loaded_dir):
                f_path = os.path.join(loaded_dir, f)
                if os.path.isfile(f_path):
                    try:
                        with open(f_path, "rb") as seed_f:
                            self.corpus.append(seed_f.read())
                    except:
                        pass

        if not self.corpus:
            self.corpus = [b"init"]
            print("[!] Warning: No seeds found, using default b'init'")

        self.stats_file = os.path.join(self.out_dir, f"stats_{self.target_name}.csv")

    # === 变异算子 (保持原有逻辑) ===
    def splice(self, data):
        if len(self.corpus) < 2: return data
        other = random.choice(self.corpus)
        if not data or not other: return data
        cut_at = random.randint(0, min(len(data), len(other)))
        return data[:cut_at] + other[cut_at:]

    def _bitflip(self, data):
        if not data: return data
        res = bytearray(data)
        idx = random.randint(0, len(res) - 1)
        res[idx] ^= (1 << random.randint(0, 7))
        return bytes(res)

    def _byteflip(self, data):
        if not data: return data
        res = bytearray(data)
        idx = random.randint(0, len(res) - 1)
        res[idx] ^= 0xFF
        return bytes(res)

    def _arith(self, data):
        if not data: return data
        res = bytearray(data)
        idx = random.randint(0, len(res) - 1)
        res[idx] = (res[idx] + random.randint(-35, 35)) & 0xFF
        return bytes(res)

    def _interest(self, data):
        if not data: return data
        res = bytearray(data)
        kind = random.choice([8, 16, 32])
        try:
            if kind == 8:
                res[random.randint(0, len(res) - 1)] = random.choice(INTERESTING_8) & 0xFF
            elif kind == 16 and len(res) >= 2:
                idx = random.randint(0, len(res) - 2)
                res[idx:idx + 2] = struct.pack(random.choice(['<', '>']) + 'h', random.choice(INTERESTING_16))
            elif kind == 32 and len(res) >= 4:
                idx = random.randint(0, len(res) - 4)
                res[idx:idx + 4] = struct.pack(random.choice(['<', '>']) + 'i', random.choice(INTERESTING_32))
        except:
            pass
        return bytes(res)

    def _havoc(self, data):
        res = data
        for _ in range(random.randint(2, 8)):
            operator = random.choice([self._bitflip, self._byteflip, self._arith, self._interest])
            res = operator(res)
        return res

    def mutate(self, data):
        if not data: return b"a" * 10
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
            return self._havoc(data)

    # === 优化：能量调度 (Power Schedule) ===
    def calculate_energy(self, seed_data, coverage_len):
        # 基础能量
        energy = min(max(5, coverage_len * 2), 50)
        # 策略1：短种子优先 (执行快)
        if len(seed_data) < 256:
            energy += 10
        # 策略2：如果发现了很多新路径，多给点能量
        if coverage_len > 100:
            energy += 20
        return energy

    def save_crash(self, data, reason):
        """保存崩溃样本"""
        crash_dir = os.path.join(self.out_dir, "crashes", self.target_name)
        if not os.path.exists(crash_dir):
            os.makedirs(crash_dir)

        timestamp = int(time.time())
        filename = f"id_{self.total_execs}_{reason}_{timestamp}"
        filepath = os.path.join(crash_dir, filename)

        with open(filepath, "wb") as f:
            f.write(data)
        print(f"\n[!] 🚨 Found Crash! Saved to {filename}")

    # === 核心运行逻辑 ===
    def start(self, timeout=86400):
        print(f"[*] Fuzzing target: {self.target_name} | Timeout: {timeout}s")

        # 修复：增加 total_execs 列
        with open(self.stats_file, "w") as f:
            f.write("time,cov,total_execs\n")

        temp_input_file = os.path.join(os.path.dirname(self.target_path), f".cur_input_{self.target_name}")
        last_log_time = time.time()

        while time.time() - self.start_time < timeout:
            if not self.corpus: self.corpus = [b"init"]  # 防止为空

            # 1. 调度
            self.corpus.sort(key=len)
            top_k = max(1, int(len(self.corpus) * 0.2))
            seed_data = random.choice(self.corpus[:top_k])
            energy = self.calculate_energy(seed_data, len(self.global_visited_indices))

            for _ in range(energy):
                if time.time() - self.start_time >= timeout: break

                # 2. 变异
                current_seed = seed_data
                if random.random() < 0.1:
                    current_seed = self.splice(current_seed)
                candidate = self.mutate(current_seed)

                # 3. 构造命令
                cmd_args = [self.target_path]
                use_stdin = False

                # 针对不同目标的参数适配
                if "target1" in self.target_name:
                    use_stdin = True  # cxxfilt
                elif "target2" in self.target_name:
                    cmd_args.extend(["-a", temp_input_file])  # readelf
                elif "target3" in self.target_name:
                    cmd_args.append(temp_input_file)  # nm
                elif "target4" in self.target_name:
                    cmd_args.extend(["-d", temp_input_file])  # objdump
                elif "target5" in self.target_name:
                    cmd_args.append(temp_input_file)  # djpeg
                elif "target6" in self.target_name:
                    use_stdin = True  # readpng
                elif "target7" in self.target_name:
                    cmd_args.append(temp_input_file)  # xmllint
                elif "target8" in self.target_name:
                    cmd_args.append(temp_input_file)  # lua/xml
                elif "target9" in self.target_name:
                    cmd_args.extend(["-f", temp_input_file])  # mjs
                elif "target10" in self.target_name:
                    cmd_args.extend(["-nr", temp_input_file])  # tcpdump
                else:
                    cmd_args.append(temp_input_file)

                # 4. 执行
                self.shm.write(b'\x00' * MAP_SIZE)

                if not use_stdin:
                    with open(temp_input_file, "wb") as f:
                        f.write(candidate)
                    stdin_mode = subprocess.DEVNULL
                else:
                    stdin_mode = subprocess.PIPE

                try:
                    # 修复：stdout=subprocess.DEVNULL 屏蔽乱码
                    proc = subprocess.Popen(cmd_args, stdin=stdin_mode,
                                            stdout=subprocess.DEVNULL,
                                            stderr=subprocess.PIPE,
                                            env=self.env)

                    if use_stdin:
                        proc.communicate(input=candidate, timeout=0.1)
                    else:
                        proc.communicate(timeout=0.1)

                    self.total_execs += 1

                    # 修复：检查 Crash (returncode < 0 代表被信号杀死)
                    if proc.returncode < 0:
                        self.save_crash(candidate, f"sig{-proc.returncode}")

                except subprocess.TimeoutExpired:
                    proc.kill()
                    self.save_crash(candidate, "timeout")  # 保存超时用例
                except Exception as e:
                    pass

                # 5. 覆盖率反馈
                bitmap = self.shm.read(MAP_SIZE)
                current_indices = set(i for i, v in enumerate(bitmap) if v > 0)

                if current_indices and not current_indices.issubset(self.global_visited_indices):
                    self.global_visited_indices.update(current_indices)
                    self.corpus.append(candidate)
                    print(f"[+] New Path! Cov: {len(self.global_visited_indices)} | Execs: {self.total_execs}")
                    # 立即写入
                    with open(self.stats_file, "a") as f:
                        f.write(
                            f"{time.time() - self.start_time:.2f},{len(self.global_visited_indices)},{self.total_execs}\n")
                    last_log_time = time.time()

                # 心跳日志
                if time.time() - last_log_time > 1.0:
                    with open(self.stats_file, "a") as f:
                        f.write(
                            f"{time.time() - self.start_time:.2f},{len(self.global_visited_indices)},{self.total_execs}\n")
                    last_log_time = time.time()

        # 清理
        if os.path.exists(temp_input_file):
            try:
                os.remove(temp_input_file)
            except:
                pass


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 main.py <target_binary> [timeout_seconds]")
        sys.exit(1)

    target = sys.argv[1]
    run_time = int(sys.argv[2]) if len(sys.argv) > 2 else 86400

    f = GreyBoxFuzzer(target)
    try:
        f.start(timeout=run_time)
    finally:
        f.shm.remove()