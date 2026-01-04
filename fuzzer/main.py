import os, subprocess, sysv_ipc, random, time, sys

# --- 配置区 ---
MAP_SIZE = 65536

# --- 感兴趣值 (Magic Numbers) ---
# 8位感兴趣值 (例如: -128, -1, 0, 1, 16, 32...)
INTERESTING_8 = [-128, -1, 0, 1, 16, 32, 64, 100, 127]
# 16位感兴趣值 (例如: -32768, -1, 0, MAX_UINT16...)
INTERESTING_16 = [-32768, -129, 128, 255, 256, 512, 1000, 1024, 4096, 32767, 65535]
# 32位感兴趣值
INTERESTING_32 = [-2147483648, -100663046, -32769, 32768, 65536, 100000, 2147483647]


class GreyBoxFuzzer:
    def __init__(self, target_path):
        self.target_path = target_path
        self.target_name = os.path.basename(target_path)  # 获取文件名 (如 target1)

        # === 路径修复：动态计算项目根目录 ===
        current_dir = os.path.dirname(os.path.abspath(__file__))
        project_root = os.path.dirname(current_dir)
        out_dir = os.path.join(project_root, "out")

        if not os.path.exists(out_dir):
            os.makedirs(out_dir)

        # 监控组件 & 插装对接
        self.shm = sysv_ipc.SharedMemory(None, flags=sysv_ipc.IPC_CREAT | sysv_ipc.IPC_EXCL, mode=0o600, size=MAP_SIZE)
        self.env = os.environ.copy()
        self.env["__AFL_SHM_ID"] = str(self.shm.id)

        self.global_visited_indices = set()



        # === 修改为：尝试加载外部种子 ===
        self.corpus = []
        seed_dir = os.path.join(project_root, "seeds")

        # 如果 seeds 目录存在，尝试读取里面的文件
        if os.path.exists(seed_dir):
            for f in os.listdir(seed_dir):
                f_path = os.path.join(seed_dir, f)
                if os.path.isfile(f_path):
                    with open(f_path, "rb") as seed_f:
                        self.corpus.append(seed_f.read())
        # 如果没读到任何种子，才使用默认值
        if not self.corpus:
            self.corpus = [b"init"]
            print("[!] Warning: No external seeds found, using default b'init'")
        else:
            print(f"[*] Loaded {len(self.corpus)} seeds from {seed_dir}")


        self.exec_count = 0
        self.start_time = time.time()

        self.stats_file = os.path.join(out_dir, f"stats_{self.target_name}.csv")

    # === 变异算子实现 ===
    def splice(self, data):
        if len(self.corpus) < 2: return data
        other = random.choice(self.corpus)
        cut_at = random.randint(0, min(len(data), len(other)))
        return data[:cut_at] + other[cut_at:]

    def _bitflip(self, data):
        res = bytearray(data)
        if not res: return res
        idx = random.randint(0, len(res) - 1)
        res[idx] ^= (1 << random.randint(0, 7))
        return bytes(res)

    def _byteflip(self, data):
        res = bytearray(data)
        if not res: return res
        idx = random.randint(0, len(res) - 1)
        res[idx] ^= 0xFF
        return bytes(res)

    def _arith(self, data):
        res = bytearray(data)
        if not res: return res
        idx = random.randint(0, len(res) - 1)
        res[idx] = (res[idx] + random.randint(-35, 35)) & 0xFF
        return bytes(res)

    def _interest(self, data):
        res = bytearray(data)
        if not res: return res
        kind = random.choice([8, 16, 32])
        import struct
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
        if not data: return b"a"
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

    def calculate_energy(self, seed_coverage_len):
        return min(max(5, seed_coverage_len * 2), 50)

    # === 核心运行逻辑 ===
    def start(self, timeout=86400):
        print(f"[*] 正在测试目标: {self.target_name} ({self.target_path})")
        with open(self.stats_file, "w") as f:
            f.write("time,cov\n")

        last_log_time = time.time()

        # 准备临时输入文件路径 (用于文件输入的 targets)
        temp_input_file = os.path.join(os.path.dirname(self.target_path), f".cur_input_{self.target_name}")

        while time.time() - self.start_time < timeout:
            # 1. 种子调度
            self.corpus.sort(key=len)
            top_k = max(1, int(len(self.corpus) * 0.2))
            seed_data = random.choice(self.corpus[:top_k])
            energy = self.calculate_energy(len(self.global_visited_indices))

            for _ in range(energy):
                # 2. 变异
                current_seed = seed_data
                if random.random() < 0.1:
                    current_seed = self.splice(current_seed)
                candidate = self.mutate(current_seed)

                # 3. 构造运行命令 (适配 Target 1-10)
                cmd_args = [self.target_path]
                use_stdin = False

                # 根据作业文档的 AFL-CMD 进行适配
                if "target1" in self.target_name:  # cxxfilt
                    use_stdin = True
                elif "target2" in self.target_name:  # readelf -a @@
                    cmd_args.extend(["-a", temp_input_file])
                elif "target3" in self.target_name:  # nm-new @@
                    cmd_args.append(temp_input_file)
                elif "target4" in self.target_name:  # objdump -d @@
                    cmd_args.extend(["-d", temp_input_file])
                elif "target5" in self.target_name:  # djpeg @@
                    cmd_args.append(temp_input_file)
                elif "target6" in self.target_name:  # readpng (文档显示直接运行，通常读 stdin)
                    use_stdin = True
                elif "target7" in self.target_name:  # xmllint @@
                    cmd_args.append(temp_input_file)
                elif "target8" in self.target_name:  # lua @@
                    cmd_args.append(temp_input_file)
                elif "target9" in self.target_name:  # mjs -f @@
                    cmd_args.extend(["-f", temp_input_file])
                elif "target10" in self.target_name:  # tcpdump -nr @@
                    cmd_args.extend(["-nr", temp_input_file])
                else:
                    # 默认策略：假设是文件输入
                    cmd_args.append(temp_input_file)

                # 4. 执行目标
                self.shm.write(b'\x00' * MAP_SIZE)

                # 如果需要文件输入，先写入临时文件
                if not use_stdin:
                    with open(temp_input_file, "wb") as f:
                        f.write(candidate)
                    stdin_mode = subprocess.DEVNULL
                else:
                    stdin_mode = subprocess.PIPE

                try:
                    # 添加 stdout=subprocess.DEVNULL
                    proc = subprocess.Popen(cmd_args, stdin=stdin_mode, stdout=subprocess.DEVNULL,
                                            stderr=subprocess.PIPE, env=self.env)
                    if use_stdin:
                        proc.communicate(input=candidate, timeout=0.1)
                    else:
                        proc.communicate(timeout=0.1)
                except subprocess.TimeoutExpired:
                    proc.kill()
                    proc.wait()
                except Exception as e:
                    # print(f"Error: {e}")
                    if proc.poll() is None:
                        proc.kill()
                        proc.wait()

                # 5. 收集反馈
                bitmap = self.shm.read(MAP_SIZE)
                current_indices = set(i for i, v in enumerate(bitmap) if v > 0)

                # 发现新路径
                if current_indices and not current_indices.issubset(self.global_visited_indices):
                    self.global_visited_indices.update(current_indices)
                    self.corpus.append(candidate)
                    with open(self.stats_file, "a") as f:
                        f.write(f"{time.time() - self.start_time:.2f},{len(self.global_visited_indices)}\n")
                    last_log_time = time.time()

                # 心跳记录 (每 1 秒强制记录一次)
                if time.time() - last_log_time > 1.0:
                    with open(self.stats_file, "a") as f:
                        f.write(f"{time.time() - self.start_time:.2f},{len(self.global_visited_indices)}\n")
                    last_log_time = time.time()

        # 清理临时文件
        if os.path.exists(temp_input_file):
            try:
                os.remove(temp_input_file)
            except:
                pass

        return False


if __name__ == "__main__":
    target = sys.argv[1] if len(sys.argv) > 1 else "./target/target_instrumented"

    # 支持从命令行传入运行时间 (秒)
    run_time = 86400  # 默认 24 小时
    if len(sys.argv) > 2:
        try:
            run_time = int(sys.argv[2])
        except:
            pass

    # 智能查找路径
    if not os.path.exists(target):
        potential = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "target",
                                 "target_instrumented")
        if os.path.exists(potential): target = potential

    f = GreyBoxFuzzer(target)
    try:
        f.start(timeout=run_time)
    finally:
        f.shm.remove()