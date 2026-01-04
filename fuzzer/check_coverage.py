import os
import subprocess
import sysv_ipc

TARGET_PATH = "./target/target_instrumented"
MAP_SIZE = 65536


def test_input(input_str):
    shm = sysv_ipc.SharedMemory(None, flags=sysv_ipc.IPC_CREAT | sysv_ipc.IPC_EXCL, mode=0o600, size=MAP_SIZE)

    shm.write(b'\x00' * MAP_SIZE)

    test_env = os.environ.copy()
    test_env["__AFL_SHM_ID"] = str(shm.id)

    data = input_str.encode()
    proc = subprocess.Popen(
        [TARGET_PATH],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=test_env
    )
    proc.communicate(input=data)

    bitmap = shm.read(MAP_SIZE)

    covered_edges = sum(1 for byte in bitmap if byte > 0)

    shm.detach()
    shm.remove()

    return covered_edges


if __name__ == "__main__":
    cov1 = test_input("a")
    cov2 = test_input("crash")

    print(f"输入 'a' 的覆盖率数字: {cov1}")
    print(f"输入 'crash' 的覆盖率数字: {cov2}")

    if cov2 > cov1:
        print("成功！'crash' 触发了更多的代码分支。")
    else:
        print("覆盖率没有变化，请检查 target.c 是否有足够的 if 分支。")