#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
int main(){ char buf[100]; memset(buf,0,100); int len=read(0,buf,100); if(buf[0]==0xff && buf[1]==0x00) abort(); return 0; }