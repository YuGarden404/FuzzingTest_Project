FROM ubuntu:22.04

FROM ubuntu:22.04

# 1. 基础配置与换源 (保持你原有的南京大学源)
RUN sed -i 's/archive.ubuntu.com/mirrors.nju.edu.cn/g' /etc/apt/sources.list && \
    sed -i 's/security.ubuntu.com/mirrors.nju.edu.cn/g' /etc/apt/sources.list

ENV DEBIAN_FRONTEND=noninteractive

# 2. 安装系统依赖
# [修复点] 新增 python3-pip (装库用) 和 vim (调试用)
RUN apt-get update && apt-get install -y \
    build-essential \
    python3-dev \
    python3-pip \
    automake \
    cmake \
    git \
    flex \
    dos2unix \
    bison \
    libglib2.0-dev \
    libpixman-1-dev \
    clang \
    llvm-dev \
    libtool-bin \
    wget \
    vim \
    && rm -rf /var/lib/apt/lists/*

# 3. 安装 AFL++ (AFLplusplus)
# [修复点] 确保命令在一行，或者使用 \ 正确换行
RUN git clone --depth 1 https://github.com/AFLplusplus/AFLplusplus.git /opt/aflplusplus && \
    cd /opt/aflplusplus && \
    make distrib && \
    make install

WORKDIR /app

# 4. [修复点] 安装 Python 项目依赖
# 这一步非常关键！没有它你的 fuzzer 跑不起来
COPY requirements.txt /app/requirements.txt
RUN pip3 install --no-cache-dir -r requirements.txt -i https://pypi.tuna.tsinghua.edu.cn/simple

# 5. 设置环境变量 (防止中文乱码)
ENV LANG C.UTF-8