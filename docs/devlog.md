#### 2026-01-02: 开始构建 Docker 镜像。
* 遇到的情况：执行 `apt-get install` 步骤较慢，约持续了数分钟。
* 反思：因为安装了 LLVM/Clang 等大型编译工具，这是正常耗时。

#### 2026-01-02: 尝试使用国外网站后依然存在波动，改用南京大学镜像站 (mirrors.nju.edu.cn)。
* 结果：网络连接显著改善，下载速度提升。
* 状态：正在完成 Docker 镜像的最后构建。

#### 2026-01-02: 
* 克服了 LLVM/Clang 庞大的下载量，成功构建 fuzzer-env 镜像。
* 手动在容器内完成了 AFL++ 的编译与安装 (make distrib)。
* 成功生成了插装版二进制文件 `target_instrumented`。