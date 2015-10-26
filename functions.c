/**
  * GreenPois0n Cynanide - functions.c
  * Copyright (C) 2010 Chronic-Dev Team
  * Copyright (C) 2010 Joshua Hill
  *
  * This program is free software: you can redistribute it and/or modify
  * it under the terms of the GNU General Public License as published by
  * the Free Software Foundation, either version 3 of the License, or
  * (at your option) any later version.
  *
  * This program is distributed in the hope that it will be useful,
  * but WITHOUT ANY WARRANTY; without even the implied warranty of
  * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  * GNU General Public License for more details.
  *
  * You should have received a copy of the GNU General Public License
  * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 **/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/*#include "task.h"
#include "lock.h"
#include "common.h"
#include "commands.h"*/

static unsigned char push = 0xB5;
static unsigned char push_r7_lr[] = { 0x80, 0xB5 };
static unsigned char push_r4_r7_lr[] = { 0x90, 0xB5 };
static unsigned char push_r4_to_r7_lr[] = { 0xF0, 0xB5 };
static unsigned char push_r4_r5_r7_lr[] = { 0xB0, 0xB5 };

static unsigned char* functions[][3] = {
		{ "aes_crypto_cmd", "aes_crypto_cmd", push_r4_r7_lr },
		{ "free", "heap_panic",  push_r4_to_r7_lr },
		{ "fs_mount", "fs_mount", push_r4_to_r7_lr },
		{ "cmd_ramdisk", "Ramdisk too large", push_r4_r5_r7_lr },
		{ "cmd_go", "jumping into image", push_r7_lr },
		{ "image_load", "image validation failed but untrusted images are permitted", push_r4_to_r7_lr },
		{ "fsboot", "root filesystem mount failed", push_r4_to_r7_lr },
		{ "kernel_load", "rd=md0", push_r4_to_r7_lr },
		{ "task_yield", "task_yield", push_r4_r5_r7_lr },
		{ "default_block_write", "no reasonable default block write routine", push_r7_lr },
		{ "populate_images", "image %p: bdev %p type %c%c%c%c offset 0x", push_r4_r5_r7_lr },
		{ "uart_read", "uart_read", push_r4_to_r7_lr },
		{ "uart_write", "uart_write", push_r4_to_r7_lr },
		{ "task_create", "task_create", push_r4_to_r7_lr },
		{ "task_exit", "task_exit", push_r4_to_r7_lr },
		{ "fs_open", "fs_open", push_r4_to_r7_lr },
		{ "dma_set_aes", "dma_set_aes", push_r4_to_r7_lr },
		{ "dma_generate_segments", "dma_generate_segments", push_r4_to_r7_lr },
		{ "dma_generate_aes_segments", "dma_generate_aes_segments", push_r4_to_r7_lr },
		{ "dma_cancel", "dma_cancel", push_r4_to_r7_lr },
		{ "dma_continue_async", "dma_continue_async", push_r4_to_r7_lr },
		{ "dma_int_handler", "dma_int_handler", push_r4_to_r7_lr },
		{ "cdma_init", "cdma_init", push_r4_to_r7_lr },
		{ "aes_hw_crypto_cmd", "aes_hw_crypto_cmd", push_r4_to_r7_lr },
		{ "displaypipe_init", "displaypipe_init", push_r4_to_r7_lr },
		{ "h2fmi_wait_dma_task_pending", "h2fmi_wait_dma_task_pending", push_r4_to_r7_lr },
		{ "h2fmi_pio_read_sector", "h2fmi_pio_read_sector", push_r4_to_r7_lr },
		{ "h2fmi_pio_write_sector", "h2fmi_pio_write_sector", push_r4_to_r7_lr },
		{ "h2fmi_wait_done", "h2fmi_wait_done", push_r4_to_r7_lr },
		{ "_memalign", "_memalign", push_r4_to_r7_lr },
		{ "_malloc", "_malloc", push_r4_to_r7_lr },
		{ "exit_critical_section", "exit_critical_section", push_r4_to_r7_lr },
		{ "enter_critical_section", "enter_critical_section", push_r4_to_r7_lr },
		{ "sha1_calculate", "sha1_calculate", push_r4_to_r7_lr },
		{ "nand_read_block_hook", "nand_read_block_hook", push_r4_to_r7_lr },
		{ "uart_set_mode", "uart_set_mode", push_r4_to_r7_lr },
		{ "uart_set_flow_control", "uart_set_flow_control", push_r4_to_r7_lr },
		{ "uart_set_baud_rate", "uart_set_baud_rate", push_r4_to_r7_lr },
		{ "hfs_init", "HFSInitPartition", push_r4_to_r7_lr },
		{ "h2fmiReadBootpage", "h2fmiReadBootpage", push_r4_to_r7_lr },
		{ "h2fmiWriteBootpage", "h2fmiWriteBootpage", push_r4_to_r7_lr },
		{ NULL, NULL, NULL }
};

unsigned int find_reference(unsigned char* data, unsigned int base, unsigned int size, char* signature) {
	unsigned int i = 0;

	// First find the string
	unsigned int address = 0;
	for(i = 0; i < size; i++) {
		if(!memcmp(&data[i], signature, strlen(signature))) {
			address = base | i;
			break;
		}
	}
	if(address == 0) return NULL;

	// Next find where that string is referenced
	unsigned int reference = 0;
	for(i = 0; i < size; i++) {
		if(!memcmp(&data[i], &address, 4)) {
			reference = base | i;
			break;
		}
	}
	if(reference == 0) return NULL;
	reference -= 8;

	unsigned int reference2 = 0;
	for(i = 0; i < size; i++) {
		if(!memcmp(&data[i], &reference, 4)) {
			reference2 = base | i;
			break;
		}
	}
	if(reference2 == 0) return NULL;
	return reference2;
}

unsigned int find_top(unsigned char* data, unsigned int base, unsigned int size, unsigned int address) {
	// Find the top of that function
	int i = 0;
	unsigned int function = 0;
	while(i > 0) {
		i--;
		if(data[i] == push) {
			function = base | i;
			break;
		}
	}
	if(function == 0) return NULL;
}

unsigned int find_offset(unsigned char* data, unsigned int base, unsigned int size, unsigned char** what) {
	unsigned int i = 0;
	unsigned char* top = what[2];
	unsigned char* name = what[0];
	unsigned char* signature = what[1];
	unsigned int dbase = (unsigned int) data;

	// First find the string
	unsigned int address = 0;
	for(i = 0; i < size; i++) {
		if(!memcmp(&data[i], signature, strlen(signature))) {
			address = base | i;
			break;
		}
	}
	if(address == 0) return NULL;

	// Next find where that string is referenced
	unsigned int reference = 0;
	for(i = 0; i < size; i++) {
		if(!memcmp(&data[i], &address, 4)) {
			reference = base | i;
			break;
		}
	}
	if(reference == 0) return NULL;

	// Finally find the top of that function
	unsigned int function = 0;
	while(i > 0) {
		i--;
		if(data[i] == push) {
			function = dbase | i;
			break;
		}
	}
	if(function == 0) return NULL;

	return function;
}

unsigned int find_string(unsigned char* data, unsigned int base, unsigned int size, const char* name) {
	// First find the string
	int i = 0;
	unsigned int address = 0;
	for(i = 0; i < size; i++) {
		if(!memcmp(&data[i], name, strlen(name))) {
			address = &data[i];
			break;
		}
	}
	return address;
}

void* find_function(const char* name, unsigned char* target, unsigned char* base) {
	int i = 0;
	unsigned int found = 0;
	for(i = 0; i < sizeof(functions); i++) {
		if(!strcmp(functions[i][0], name)) {
			found = find_offset(target, base, 0x40000, functions[i]);
			if(found < 0) {
				return NULL;
			}
			break;
		}
	}

	return (void*) found;
}
