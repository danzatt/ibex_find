/*
 *  Copyright 2015, danzatt <twitter.com/danzatt>
 *  All rights reserved.
 *
 *  This program is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 */


#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>

#include <sys/mman.h>
#include <fcntl.h>

#include "plib.h"
#include "link.c"

#include "functions.c"

#define handle_error(msg) \
           do { perror(msg); exit(EXIT_FAILURE); } while (0)

#define print_find_x(x) printf(#x " = 0x%x\n", (unsigned int) x)

int main(int argc, char const *argv[]) {

  char *addr;
  int fd;
  struct stat sb;

  int ida = 0;

  if (argc == 3){
    if (strcmp(argv[2], "-ida") == 0){
//      printf("ida\n");
      ida = 1;
    }
  }

  fd = open(argv[1], O_RDONLY);
  if (fd == -1)
    handle_error("open");

  if (fstat(fd, &sb) == -1)           /* To obtain file size */
    handle_error("fstat");


  addr = mmap((void *) TARGET_BASEADDR, sb.st_size, PROT_READ, MAP_PRIVATE, fd, 0);

  if (addr != TARGET_BASEADDR) {
    printf("cannot map properly to 0x%x\n", TARGET_BASEADDR);
    return 0;
  }


  if (addr == MAP_FAILED)
    handle_error("mmap");

  IBOOT_LEN = sb.st_size;

  if (ida){
    printf("setcmt;symbol found by ibex\n");

    printf("printf;%x\n", find_printf());
    printf("snprintf;%x\n", find_snprintf());
    printf("malloc;%x\n", find_malloc());
    printf("free;%x\n", find_free());
    printf("memmove;%x\n", find_memmove());
    printf("jumpto;%x\n", find_jumpto());
    printf("aes_crypto_cmd;%x\n", find_aes_crypto_cmd());
    printf("enter_critical_section;%x\n", find_enter_critical_section());
    printf("exit_critical_section;%x\n", find_exit_critical_section());
    printf("h2fmi_select;%x\n", find_h2fmi_select());
    printf("create_envvar;%x\n", find_create_envvar());
    printf("fs_mount;%x\n", find_fs_mount());
    printf("fs_loadfile;%x\n", find_fs_loadfile());
    printf("panic;%x\n", find_panic());
    printf("main;%x\n", find_easy("main", sizeof("main") - 1));
    printf("task_create;%x\n", find_task_create());

    printf("bdev_stack;%x\n", find_bdev_stack());
    printf("image_list;%x\n", find_image_list());
  } else {

    printf("TARGET_BASEADDR 0x%x\n", TARGET_BASEADDR);
    printf("IBOOT_LEN 0x%x\n", IBOOT_LEN);
    printf("end 0x%x\n", IBOOT_LEN + TARGET_BASEADDR);
    printf("\n===========ibex===========\n");
    printf("printf = 0x%x\n", find_printf());
    printf("snprintf = 0x%x\n", find_snprintf());
    printf("malloc = 0x%x\n", find_malloc());
    printf("free = 0x%x\n", find_free());
    printf("memmove = 0x%x\n", find_memmove());
    printf("jumpto = 0x%x\n", find_jumpto());
    printf("aes_crypto_cmd = 0x%x\n", find_aes_crypto_cmd());
    printf("enter_critical_section = 0x%x\n", find_enter_critical_section());
    printf("exit_critical_section = 0x%x\n", find_exit_critical_section());
    printf("h2fmi_select = 0x%x\n", find_h2fmi_select());
    printf("create_envvar = 0x%x\n", find_create_envvar());
    printf("fs_mount = 0x%x\n", find_fs_mount());
    printf("fs_loadfile = 0x%x\n", find_fs_loadfile());
    printf("panic = 0x%x\n", find_panic());
    printf("main = 0x%x\n", find_easy("main", sizeof("main") - 1));
    printf("task_create = 0x%x\n", find_task_create());

    printf("bdev_stack = 0x%x\n", find_bdev_stack());
    printf("image_list = 0x%x\n", find_image_list());
  }

#ifdef USE_CYANIDE
  if (ida){
    printf("setcmt;symbol found by cyanide\n");

    for (int i = 0; i < (sizeof(functions)/sizeof(functions[0]) - 1); i++) {
      unsigned int
          x = find_function(functions[i][0], (unsigned char *) TARGET_BASEADDR, (unsigned char *) TARGET_BASEADDR);
      printf("%s;%x\n", functions[i][0], x);
    }

  } else {
    printf("\n==========cyanide=========\n");

    for (int i = 0; i < (sizeof(functions)/sizeof(functions[0]) - 1); i++) {
      unsigned int
          x = find_function(functions[i][0], (unsigned char *) TARGET_BASEADDR, (unsigned char *) TARGET_BASEADDR);
      printf("%s = 0x%x\n", functions[i][0], x);
    }
  }
#endif
  return 0;
}
