import os, subprocess, sysv_ipc


def run_and_get_raw_shm(input_bytes):
    MAP_SIZE = 65536
    shm = sysv_ipc.SharedMemory(None, flags=sysv_ipc.IPC_CREAT | sysv_ipc.IPC_EXCL, mode=0o600, size=MAP_SIZE)
    shm.write(b'\x00' * MAP_SIZE)

    env = os.environ.copy()
    env["__AFL_SHM_ID"] = str(shm.id)

    proc = subprocess.Popen(["./target/target_instrumented"],
                            stdin=subprocess.PIPE, stderr=subprocess.PIPE, env=env)
    _, stderr = proc.communicate(input=input_bytes)

    # 获取所有非零字节的索引
    bitmap = shm.read(MAP_SIZE)
    active_indices = [i for i, v in enumerate(bitmap) if v > 0]

    shm.detach()
    shm.remove()
    return active_indices, stderr.decode()


# --- 测试开始 ---
idx_a, log_a = run_and_get_raw_shm(b"a")
idx_c, log_c = run_and_get_raw_shm(b"crash")

print(f"--- 输入 'a' ---\n日志: {log_a.strip()}\n活跃索引: {idx_a}")
print(f"\n--- 输入 'crash' ---\n日志: {log_c.strip()}\n活跃索引: {idx_c}")

if idx_a == idx_c:
    print("\n[!] 结论：位图完全一致。探头没能区分路径。")
else:
    print(f"\n[OK] 结论：发现差异！新路径索引: {set(idx_c) - set(idx_a)}")