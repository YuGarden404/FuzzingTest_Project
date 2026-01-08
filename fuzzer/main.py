import os
import subprocess
import random
import time
import sys
import struct
import hashlib
import platform
import argparse

# --- 兼容性检查 ---
try:
    import sysv_ipc
except ImportError:
    if platform.system() == "Windows":
        print("[-] 错误: 在 Windows 环境下检测到缺少 'sysv_ipc' 模块。")
        print("    此 Fuzzer 依赖 Linux System V 共享内存机制 (AFL 模式)。")
        print("    请使用 WSL2 (Windows Subsystem for Linux) 或 Docker 运行此项目。")
        # 为了不让IDE报错，我们可以定义一个假的 sysv_ipc
        class MockShm:
            ExistentialError = Exception
            IPC_CREAT = 512
            IPC_EXCL = 1024
            class SharedMemory:
                def __init__(self, *args, **kwargs): self.id = 123
                def remove(self): pass
                def write(self, data): pass
                def read(self, size): return b'\x00' * size
        sysv_ipc = MockShm()
    else:
        print("[-] 错误: 缺少 'sysv_ipc' 模块。请运行: pip install sysv_ipc")
        sys.exit(1)

# --- 配置区 ---
MAP_SIZE = 65536

# --- 感兴趣值 (Magic Numbers) ---
INTERESTING_8 = [-128, -1, 0, 1, 16, 32, 64, 100, 127]
INTERESTING_16 = [-32768, -129, 128, 255, 256, 512, 1000, 1024, 4096, 32767, 65535]
INTERESTING_32 = [-2147483648, -100663046, -32769, 32768, 65536, 100000, 2147483647]


class GreyBoxFuzzer:
    def __init__(self, target_path, dict_path=None):
        self.target_path = target_path
        self.target_name = os.path.basename(target_path)

        # === 路径修复：动态计算项目根目录 ===
        current_dir = os.path.dirname(os.path.abspath(__file__))
        self.project_root = os.path.dirname(current_dir)
        self.out_dir = os.path.join(self.project_root, "out")

        # 优化：优先使用内存盘 /dev/shm 减少 IO 开销
        if os.path.exists("/dev/shm"):
             self.temp_file_path = os.path.join("/dev/shm", f".cur_input_{self.target_name}_{os.getpid()}")
        else:
             self.temp_file_path = os.path.join(os.path.dirname(self.target_path), f".cur_input_{self.target_name}")

        # 加载字典
        self.dictionary = []
        if dict_path and os.path.exists(dict_path):
            print(f"[*] Loading dictionary from: {dict_path}")
            try:
                with open(dict_path, "r", encoding="utf-8", errors="ignore") as f:
                    for line in f:
                        line = line.strip()
                        if not line or line.startswith("#"): continue
                        # 处理转义字符如 \x7f
                        if line.startswith('"') and line.endswith('"'):
                            token = line[1:-1]
                            try:
                                # 尝试解析转义
                                self.dictionary.append(token.encode('utf-8').decode('unicode_escape').encode('latin1'))
                            except:
                                self.dictionary.append(token.encode())
                        else:
                            self.dictionary.append(line.encode())
            except Exception as e:
                print(f"[!] Error loading dictionary: {e}")
            print(f"[*] Loaded {len(self.dictionary)} dictionary tokens.")

        # === 新增：AFL风格目录结构 ===
        self.target_out_dir = os.path.join(self.out_dir, self.target_name)
        self.queue_dir = os.path.join(self.target_out_dir, "queue")
        self.crashes_dir = os.path.join(self.target_out_dir, "crashes")
        self.hangs_dir = os.path.join(self.target_out_dir, "hangs")
        
        for d in [self.queue_dir, self.crashes_dir, self.hangs_dir]:
            if not os.path.exists(d):
                os.makedirs(d)

        # 保存 cmdline
        with open(os.path.join(self.target_out_dir, "cmdline"), "w") as f:
            f.write(f"{sys.argv[0]} {target_path}")

        # 初始化 plot_data
        self.plot_data_file = os.path.join(self.target_out_dir, "plot_data")
        with open(self.plot_data_file, "w") as f:
            f.write("# unix_time, cycles_done, cur_path, paths_total, pending_total, pending_favs, map_size, unique_crashes, unique_hangs, max_depth, execs_per_sec\n")

        # 初始化 fuzzer_stats
        self.fuzzer_stats_file = os.path.join(self.target_out_dir, "fuzzer_stats")

        if not os.path.exists(self.out_dir):
            os.makedirs(self.out_dir)

        # 监控组件 & 插装对接
        try:
            self.shm = sysv_ipc.SharedMemory(None, flags=sysv_ipc.IPC_CREAT | sysv_ipc.IPC_EXCL, mode=0o600,
                                             size=MAP_SIZE)
        except sysv_ipc.ExistentialError:
            # 如果共享内存没清理干净，尝试新建一个
            self.shm = sysv_ipc.SharedMemory(None, flags=sysv_ipc.IPC_CREAT, mode=0o600, size=MAP_SIZE)
        except Exception:
            # Fallback for Windows/Mock
             self.shm = sysv_ipc.SharedMemory(None, flags=sysv_ipc.IPC_CREAT, mode=0o600, size=MAP_SIZE)

        self.env = os.environ.copy()
        if hasattr(self.shm, 'id'):
            self.env["__AFL_SHM_ID"] = str(self.shm.id)
        
        self.unique_crashes = set()  # 新增：用于Crash去重
        self.global_visited_indices = set()
        self.total_execs = 0  # 新增：总执行次数用于计算速度
        self.start_time = time.time()
        
        # === 种子优选 (Favored) ===
        # top_rated[edge_idx] = { 'factor': len*time, 'id': index_in_corpus }
        self.top_rated = {} 
        self.corpus_meta = [] # 存储种子的元数据：{'data': bytes, 'len': int, 'exec_us': int, 'favored': bool}

        # === 种子管理 ===
        self.corpus = []
        self.stats_file = os.path.join(self.out_dir, f"stats_{self.target_name}.csv")

    def load_seeds_from_dir(self, seed_dir):
        """从指定目录加载种子"""
        if not os.path.exists(seed_dir):
            print(f"[!] Warning: Seed directory {seed_dir} does not exist.")
            return

        print(f"[*] Loading seeds from: {seed_dir}")
        count = 0
        for f in os.listdir(seed_dir):
            f_path = os.path.join(seed_dir, f)
            if os.path.isfile(f_path):
                try:
                    with open(f_path, "rb") as seed_f:
                        data = seed_f.read()
                        if data: # 忽略空文件
                            self.corpus.append(data)
                            self.corpus_meta.append({'data': data, 'len': len(data), 'exec_us': 1000, 'favored': True})
                            count += 1
                except:
                    pass
        print(f"[*] Loaded {count} seeds.")

    # === 变异算子 ===
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
        # 扩展兴趣值：增加常见边界
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

    def _block_ops(self, data):
        """块操作：删除、复制、插入"""
        if not data: return data
        res = bytearray(data)
        op = random.choice(['del', 'clone', 'memset'])
        
        if op == 'del':
            if len(res) <= 1: return data
            # 随机删除一段
            start = random.randint(0, len(res) - 1)
            length = random.randint(1, min(len(res) - start, 128))
            del res[start:start+length]
            
        elif op == 'clone':
            # 随机复制一段插入到另一处
            start = random.randint(0, len(res) - 1)
            length = random.randint(1, min(len(res) - start, 128))
            block = res[start:start+length]
            
            insert_pos = random.randint(0, len(res))
            res[insert_pos:insert_pos] = block
            
        elif op == 'memset':
            # 随机覆盖一段为相同字节
            start = random.randint(0, len(res) - 1)
            length = random.randint(1, min(len(res) - start, 128))
            byte_val = random.randint(0, 255)
            res[start:start+length] = bytearray([byte_val]) * length
            
        return bytes(res)

    def _dict_mutation(self, data):
        """字典变异：插入或覆盖关键字"""
        if not self.dictionary or not data: return data
        token = random.choice(self.dictionary)
        res = bytearray(data)
        
        # 策略A: 插入
        if random.random() < 0.5:
            pos = random.randint(0, len(res))
            res[pos:pos] = token
        # 策略B: 覆盖
        else:
            if len(res) < len(token): return data # 太短，不覆盖
            pos = random.randint(0, len(res) - len(token))
            res[pos:pos+len(token)] = token
            
        return bytes(res)

    def _havoc(self, data):
        res = data
        # 增强 Havoc：增加堆叠次数 (4-16)
        for _ in range(random.randint(4, 16)):
            # 动态调整算子选择概率，如果有字典，增加字典变异概率
            ops = [self._bitflip, self._byteflip, self._arith, self._interest, self._block_ops]
            if self.dictionary:
                ops.append(self._dict_mutation)
            # 偶尔允许在 havoc 中拼接
            if len(self.corpus) > 1:
                ops.append(self.splice)
            
            operator = random.choice(ops)
            # splice 需要特殊处理参数，其他只接受 data
            if operator == self.splice:
                 res = operator(res)
            else:
                 res = operator(res)
        return res

    def mutate(self, data):
        if not data: return b"a" * 10
        rand = random.random()
        
        # 调整调度概率
        if rand < 0.05:
            return self._bitflip(data)
        elif rand < 0.1:
            return self._byteflip(data)
        elif rand < 0.2: 
            return self._arith(data)
        elif rand < 0.3:
            return self._interest(data)
        elif rand < 0.4:
            return self._block_ops(data) # 新增块操作阶段
        elif rand < 0.55 and self.dictionary: 
            return self._dict_mutation(data)
        elif rand < 0.65:
            # 显式拼接阶段 (10% 概率)
            return self.splice(data)
        else:
            return self._havoc(data)

    # === 优化：能量调度 (Power Schedule) ===
    def calculate_energy(self, seed_data):
        # 改进：基于种子长度的动态能量
        # 种子越短，能量越高（优先测试短路径，速度快）
        # 长度 10 -> energy ~ 50
        # 长度 1000 -> energy ~ 5
        energy = int(500 / max(10, len(seed_data)))
        return min(max(5, energy), 100)

    # === 种子优选逻辑 (参考 AFL update_bitmap_score) ===
    def update_bitmap_score(self, candidate_data, bitmap, exec_us):
        """
        检查当前种子是否比现有的更'优秀'（更短、更快）。
        如果是，更新 top_rated 并标记该种子为 favored。
        """
        # 1. 解析 Bitmap 覆盖的边
        current_indices = [i for i, v in enumerate(bitmap) if v > 0]
        if not current_indices: return

        # 2. 将种子加入元数据列表
        seed_idx = len(self.corpus) - 1 # 假设已经 append 到 corpus
        # 如果还没加 meta (因为是刚跑完还没存)，这里补上
        if len(self.corpus_meta) <= seed_idx:
             self.corpus_meta.append({'data': candidate_data, 'len': len(candidate_data), 'exec_us': exec_us, 'favored': False})
        
        # 3. 遍历每条覆盖的边，竞争最佳位置
        fav_factor = len(candidate_data) * exec_us
        
        for idx in current_indices:
            update_best = False
            if idx not in self.top_rated:
                update_best = True
            else:
                # 竞争：谁的 (长度 * 执行时间) 更小，谁就赢
                prev_best = self.top_rated[idx]
                if fav_factor < prev_best['factor']:
                    update_best = True
                    # 取消前任的 favored 标记 (稍微简化，AFL是定期cull，这里实时更新可能太频繁，暂时只标记新的)
            
            if update_best:
                self.top_rated[idx] = {
                    'factor': fav_factor,
                    'id': seed_idx
                }
                self.corpus_meta[seed_idx]['favored'] = True

    def save_crash(self, data, reason, bitmap_hash=None):
        """保存崩溃样本"""
        # === 去重逻辑 ===
        if bitmap_hash:
            if bitmap_hash in self.unique_crashes:
                return
            self.unique_crashes.add(bitmap_hash)

        # 兼容旧逻辑：同时保存到 out/crashes/targetX (如果需要)
        # 但主要保存到 out/targetX/crashes
        
        timestamp = int(time.time())
        filename = f"id:{self.total_execs:06d},sig:{reason},src:000000,op:havoc,rep:1"
        if bitmap_hash:
             filename += f",hash:{bitmap_hash[:8]}"

        filepath = os.path.join(self.crashes_dir, filename)

        with open(filepath, "wb") as f:
            f.write(data)
        print(f"\n[!] 🚨 Found New Crash! Saved to {filename}")

    def save_seed(self, data):
        """保存感兴趣的种子到 queue"""
        filename = f"id:{len(self.corpus):06d},src:000000,op:havoc,rep:1"
        filepath = os.path.join(self.queue_dir, filename)
        with open(filepath, "wb") as f:
            f.write(data)
            
    def update_monitor(self, current_time, last_update_time):
        """更新监控状态文件"""
        elapsed = current_time - self.start_time
        execs_per_sec = self.total_execs / elapsed if elapsed > 0 else 0
        
        # 1. 更新 fuzzer_stats
        with open(self.fuzzer_stats_file, "w") as f:
            f.write(f"start_time        : {int(self.start_time)}\n")
            f.write(f"last_update       : {int(current_time)}\n")
            f.write(f"fuzzer_pid        : {os.getpid()}\n")
            f.write(f"cycles_done       : 0\n")
            f.write(f"execs_done        : {self.total_execs}\n")
            f.write(f"execs_per_sec     : {execs_per_sec:.2f}\n")
            f.write(f"paths_total       : {len(self.corpus)}\n")
            f.write(f"paths_favored     : {len(self.corpus)}\n")
            f.write(f"paths_found       : {len(self.corpus)}\n")
            f.write(f"paths_imported    : 0\n")
            f.write(f"max_depth         : 0\n")
            f.write(f"cur_path          : 0\n")
            f.write(f"pending_favs      : 0\n")
            f.write(f"pending_total     : 0\n")
            f.write(f"variable_paths    : 0\n")
            f.write(f"stability         : 100.00%\n")
            f.write(f"bitmap_cvg        : 0.00%\n")
            f.write(f"unique_crashes    : {len(self.unique_crashes)}\n")
            f.write(f"unique_hangs      : 0\n")
            f.write(f"last_path         : {int(last_update_time)}\n")
            f.write(f"last_crash        : 0\n")
            f.write(f"last_hang         : 0\n")
            f.write(f"execs_since_crash : {self.total_execs}\n")
            f.write(f"exec_timeout      : 0\n")
            f.write(f"afl_banner        : {self.target_name}\n")
            f.write(f"afl_version       : 4.07c\n")
            f.write(f"target_mode       : default\n")
            f.write(f"command_line      : {sys.argv[0]} {self.target_path}\n")

        # 2. 追加 plot_data
        # unix_time, cycles_done, cur_path, paths_total, pending_total, pending_favs, map_size, unique_crashes, unique_hangs, max_depth, execs_per_sec
        with open(self.plot_data_file, "a") as f:
            f.write(f"{int(current_time)}, 0, 0, {len(self.corpus)}, 0, 0, {len(self.global_visited_indices)}, {len(self.unique_crashes)}, 0, 0, {execs_per_sec:.2f}\n")

        # 3. 打印控制台状态行
        print(f"[*] Fuzzing test case #{self.total_execs} (stats: map={len(self.global_visited_indices)}, speed={execs_per_sec:.0f}/s, crashes={len(self.unique_crashes)}, paths={len(self.corpus)})")

    # === 核心运行逻辑 ===
    def start(self, args_list, use_stdin=False, timeout=86400):
        print(f"[*] Fuzzing target: {self.target_name} | Timeout: {timeout}s")
        print(f"[*] Strategy: {'STDIN' if use_stdin else 'FILE (@@)'}")

        # 修复：增加 total_execs 列
        with open(self.stats_file, "w") as f:
            f.write("time,cov,total_execs\n")

        last_log_time = time.time()

        while time.time() - self.start_time < timeout:
            if not self.corpus: 
                # 默认种子：_Z1fv (针对 cxxfilt 优化，但也作为通用兜底)
                self.corpus = [b"_Z1fv"]
                self.corpus_meta = [{'data': b"_Z1fv", 'len': 5, 'exec_us': 1000, 'favored': True}]
                print("[!] Warning: No seeds found, using default b'_Z1fv'")

            # 1. 调度优化：基于 Favored 的加权选择
            # 优先选择被标记为 favored 的种子 (覆盖新路径且效率高)
            favored_indices = [i for i, meta in enumerate(self.corpus_meta) if meta.get('favored')]
            
            if favored_indices and random.random() < 0.9:
                # 90% 概率从优选池中挑
                idx = random.choice(favored_indices)
                seed_data = self.corpus[idx]
            else:
                # 10% 概率随机探索 (防止陷入局部最优)
                if len(self.corpus) > 5:
                    candidates = [random.choice(self.corpus) for _ in range(5)]
                    seed_data = min(candidates, key=len)
                else:
                    seed_data = random.choice(self.corpus)

            energy = self.calculate_energy(seed_data)

            for _ in range(energy):
                if time.time() - self.start_time >= timeout: break

                # 2. 变异
                current_seed = seed_data
                if random.random() < 0.1:
                    current_seed = self.splice(current_seed)
                candidate = self.mutate(current_seed)

                # 3. 构造命令 (通用化)
                # 如果 args_list 中包含 @@，则替换为临时文件名
                run_args = []
                for arg in args_list:
                    if "@@" in arg:
                        run_args.append(arg.replace("@@", self.temp_file_path))
                    else:
                        run_args.append(arg)
                
                # 如果没有 @@ 且不使用 stdin，通常默认追加文件名在末尾 (兼容旧行为)
                if not use_stdin and "@@" not in str(args_list):
                     run_args.append(self.temp_file_path)

                # 4. 执行
                if hasattr(self.shm, 'write'):
                    self.shm.write(b'\x00' * MAP_SIZE)

                start_exec = time.time() # 计时开始
                exec_us = 0 # 初始化，防止异常时未定义

                if not use_stdin:
                    with open(self.temp_file_path, "wb") as f:
                        f.write(candidate)
                    stdin_mode = subprocess.DEVNULL
                else:
                    stdin_mode = subprocess.PIPE
                
                bitmap = None # 初始化
                try:
                    # 修复：stdout=subprocess.DEVNULL 屏蔽乱码
                    proc = subprocess.Popen(run_args, stdin=stdin_mode,
                                            stdout=subprocess.DEVNULL,
                                            stderr=subprocess.PIPE,
                                            env=self.env)

                    if use_stdin:
                        proc.communicate(input=candidate, timeout=0.1)
                    else:
                        proc.communicate(timeout=0.1)

                    exec_us = int((time.time() - start_exec) * 1000000) # 计算微秒
                    self.total_execs += 1
                    
                    # 立即读取 bitmap 计算 hash (用于去重)
                    if hasattr(self.shm, 'read'):
                        bitmap = self.shm.read(MAP_SIZE)
                        bitmap_hash = hashlib.md5(bitmap).hexdigest()

                    # 修复：检查 Crash (returncode < 0 代表被信号杀死)
                    if proc.returncode < 0:
                        self.save_crash(candidate, f"sig{-proc.returncode}", bitmap_hash)

                except subprocess.TimeoutExpired:
                    proc.kill()
                    # 超时也尝试读取 bitmap
                    if bitmap is None and hasattr(self.shm, 'read'):
                        bitmap = self.shm.read(MAP_SIZE)
                    
                    # 对于超时，也计算 hash 尝试去重
                    if bitmap:
                        bitmap_hash = hashlib.md5(bitmap).hexdigest()
                        self.save_crash(candidate, "timeout", bitmap_hash)  # 保存超时用例
                except Exception as e:
                    pass

                # 5. 覆盖率反馈
                if bitmap is None and hasattr(self.shm, 'read'):
                     bitmap = self.shm.read(MAP_SIZE)
                
                if bitmap:
                    current_indices = set(i for i, v in enumerate(bitmap) if v > 0)

                    if current_indices and not current_indices.issubset(self.global_visited_indices):
                        self.global_visited_indices.update(current_indices)
                        self.corpus.append(candidate)
                        
                        # 调用优选评分
                        self.update_bitmap_score(candidate, bitmap, exec_us)
                        
                        self.save_seed(candidate)  # 新增：保存种子到 queue
                        
                        elapsed = time.time() - self.start_time
                        speed = self.total_execs / elapsed if elapsed > 0 else 0
                        print(f"[+] New Path! Cov: {len(self.global_visited_indices)} | Execs: {self.total_execs} | Speed: {speed:.2f} execs/s")
                        # 立即写入
                        with open(self.stats_file, "a") as f:
                            f.write(
                                f"{time.time() - self.start_time:.2f},{len(self.global_visited_indices)},{self.total_execs}\n")
                        
                        self.update_monitor(time.time(), time.time()) # 更新详细监控
                        last_log_time = time.time()

                # 心跳日志
                if time.time() - last_log_time > 1.0:
                    with open(self.stats_file, "a") as f:
                        f.write(
                            f"{time.time() - self.start_time:.2f},{len(self.global_visited_indices)},{self.total_execs}\n")
                    
                    self.update_monitor(time.time(), last_log_time) # 更新详细监控
                    last_log_time = time.time()

        # 清理
        if os.path.exists(self.temp_file_path):
            try:
                os.remove(self.temp_file_path)
            except:
                pass


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="GreyBox Fuzzer")
    parser.add_argument("target", help="Target binary path")
    parser.add_argument("args", nargs="*", help="Arguments for the target. Use '@@' for input file position.")
    parser.add_argument("-t", "--timeout", type=int, default=86400, help="Fuzzing timeout in seconds")
    parser.add_argument("-s", "--stdin", action="store_true", help="Use STDIN instead of file input")
    parser.add_argument("-x", "--dict", help="Path to dictionary file")
    parser.add_argument("-i", "--input", help="Path to input seed directory")
    
    # 使用 parse_known_args 以避免 argparse 对 -- 后面的参数（如 -a）报错
    args, unknown = parser.parse_known_args()

    # 处理 unknown 参数：过滤掉单纯的 '--'，剩下的就是传给 target 的参数
    target_args = [u for u in unknown if u != '--']

    # 这里的 args.args 是 argparse 解析到的位置参数（如果在 -- 之前有的话）
    # 但通常我们将 target_args 视为真正的参数
    
    # 构造运行参数
    run_args = [args.target]
    
    # 如果有通过 argparse 捕获的 args (很少见，除非没用 --)
    if args.args:
        run_args.extend(args.args)
        
    # 追加 unknown 中的参数
    run_args.extend(target_args)

    f = GreyBoxFuzzer(args.target, dict_path=args.dict)
    
    # 手动指定种子目录
    if args.input:
        f.load_seeds_from_dir(args.input)
        
    try:
        f.start(args_list=run_args, use_stdin=args.stdin, timeout=args.timeout)
    finally:
        if hasattr(f, 'shm') and hasattr(f.shm, 'remove'):
            f.shm.remove()
