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
#include <strings.h>
#include <sys/stat.h>

#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "plib.h"
#include "link.c"

#define handle_error(msg) \
           do { perror(msg); exit(EXIT_FAILURE); } while (0)

#define print_find_x(x) printf(#x " = 0x%x\n", (unsigned int) x);

int main(int argc, char const *argv[]) {
  char *addr;
  int fd;
  struct stat sb;
  off_t offset, pa_offset;
  size_t length;
  ssize_t s;


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

  printf("TARGET_BASEADDR 0x%x\n", TARGET_BASEADDR);
  printf("IBOOT_LEN 0x%x\n", IBOOT_LEN);
  printf("end 0x%x\n", IBOOT_LEN + TARGET_BASEADDR);

  print_find_x(find_printf());
  print_find_x(find_snprintf());
  print_find_x(find_malloc());
  print_find_x(find_free());
  print_find_x(find_memmove());
  print_find_x(find_jumpto());
  print_find_x(find_aes_crypto_cmd());
  print_find_x(find_enter_critical_section());
  print_find_x(find_exit_critical_section());
  print_find_x(find_h2fmi_select());
  print_find_x(find_create_envvar());
  print_find_x(find_fs_mount());
  print_find_x(find_fs_loadfile());

  print_find_x(find_bdev_stack());
  print_find_x(find_image_list());

  return 0;
}
