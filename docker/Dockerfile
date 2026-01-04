FROM ubuntu:22.04

RUN sed -i 's/archive.ubuntu.com/mirrors.nju.edu.cn/g' /etc/apt/sources.list && \
    sed -i 's/security.ubuntu.com/mirrors.nju.edu.cn/g' /etc/apt/sources.list

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y \
    build-essential \
    python3-dev \
    automake \
    cmake \
    git \
    flex \
    bison \
    libglib2.0-dev \
    libpixman-1-dev \
    clang \
    llvm-dev \
    libtool-bin \
    wget \
    && rm -rf /var/lib/apt/lists/*

RUN git clone --depth 1 https://github.com/AFLplusplus/AFLplusplus.git /opt/aflplusplus && \
    cd /opt/aflplusplus && \
    make distrib && \
    make install

WORKDIR /app