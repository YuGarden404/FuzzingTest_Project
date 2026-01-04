#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>

int main() {
    char buf[100];
    memset(buf, 0, 100);
    if (read(0, buf, 100) <= 0) return 1;

    if (buf[0] == 'c') {
        if (buf[1] == 'r') {
            if (buf[2] == 'a') {
                if (buf[3] == 's') {
                    if (buf[4] == 'h') {
                        // 改进点 1：打印明确的成功信息
                        fprintf(stderr, "\n[!!!] CRASH CONDITION TRIGGERED! [!!!]\n");
                        // 改进点 2：使用自定义错误码退出，确保 AFL 刷写位图
                        exit(66);
                    }
                }
            }
        }
    }
    return 0;
}