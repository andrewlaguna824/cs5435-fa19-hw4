#include <stdio.h>
#include <string.h>


void greeting( char* temp1 )
{
  char name[400];
  memset(name, 0, 400);
  strcpy(name, temp1);
  printf( "Hi %s \n", temp1);
}


int main(int argc, char* argv[] ) 
{
  greeting( argv[1]);
  printf( "Bye %s \n", argv[1]);
  
  
  /*
  int i= 0;
  for (i = 0; i < 5; i++) {
    printf("number %d\n", i);
  }
  */
}
