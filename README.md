测试方法：
* 在app# 输入 ./run_fuzz_task.sh 后回车

进入Ubuntu系统：
* docker ps -a
* docker start nju_fuzzer(或者在上一步完成之后的ID里选择一个复制)
* docker exec -it nju_fuzzer(同上) /bin/bash

fuzzer文件夹负责模糊测试代码<br>
out存放数据的输出和图片<br>
seeds存放测试的种子<br>
target存放测试用的C语言程序<br>

结构：<br>
```
FuzzingTest
|-docker
|   |-Dockerfile
|-docs
|   |-devlog.md #工作日志
|-fuzzer
|   |-analyze.py #数据转图片
|   |-其余测试文件可以随意删除替换
|-out
|-seeds
|-target
|   |-C语言程序
|-.gitignore
|-README.md
|-run_fuzz_task.sh #自动化测试脚本
```

