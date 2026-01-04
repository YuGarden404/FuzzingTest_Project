#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
int main(){ char buf[100]; memset(buf,0,100); int len=read(0,buf,100); int n=buf[0]; if(n>100 && n<110) *(int*)0=0; return 0; }