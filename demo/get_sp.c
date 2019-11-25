#include <stdio.h>

unsigned long get_sp(void) 
{
	__asm__("movl %esp, %eax");
}

int main() 
{
        unsigned long sp = get_sp();
        unsigned long target = sp - 768; // 0x300 is 768 in decimal
	printf("Stack pointer (ESP): 0x%x\n", sp);
        printf("Stack pointer - 0x300: 0x%x\n", target);
}

