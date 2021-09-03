/*
Title: win32/xp pro sp3 MessageBox shellcode 11 bytes
Author: d3c0der - d3c0der[at]hotmail[dot]com
Tested on: WinXP Pro SP3 (EN)  # ( run MessageBox that show an error message )
website : Www.AttackerZ.ir
spt : All firends ;)
*/
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

char code[] =   "\x33\xd2\x52\x52\x52\x52\xe8\xbe\xe9\x44\x7d";

int main(int argc, char **argv)
{
    ((void (*)())code)();

    return 0;
}