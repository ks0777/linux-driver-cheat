#include "utils.h"

void hexdump(const void* data, size_t size) {
    	char ascii[17];
	size_t i, j;
	ascii[16] = '\0';
	for (i = 0; i < size; ++i) {
		printk(KERN_CONT "%02X ", ((unsigned char*)data)[i]);
		if (((unsigned char*)data)[i] >= ' ' && ((unsigned char*)data)[i] <= '~') {
			ascii[i % 16] = ((unsigned char*)data)[i];
		} else {
			ascii[i % 16] = '.';
		}
		if ((i+1) % 8 == 0 || i+1 == size) {
			printk(KERN_CONT " ");
			if ((i+1) % 16 == 0) {
				printk(KERN_CONT "|  %s \n", ascii);
			} else if (i+1 == size) {
				ascii[(i+1) % 16] = '\0';
				if ((i+1) % 16 <= 8) {
					printk(KERN_CONT " ");
				}
				for (j = (i+1) % 16; j < 16; ++j) {
					printk(KERN_CONT "   ");
				}
				printk(KERN_CONT "|  %s \n", ascii);
			}
		}
	}
}
