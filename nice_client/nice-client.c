#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <time.h>
#include <math.h>

#include "ioctl-defs.h"

#define timing(a) clock_t start=clock(), diff; a; diff = clock() - start; unsigned int nsec = diff * 1000000 / CLOCKS_PER_SEC; printf("%dns\n",nsec);
#define timing(a) a

struct Vec3 {
    float x,y,z;
};

int pid;
int proc_fd;

int mem_read(unsigned long address, void* buf, unsigned int buflen) {
    struct nd_rw_req req = { .pid = pid, .addr = address, .buf = buf, .buflen = buflen };

    timing(int ret = ioctl(proc_fd, ND_READ, &req);)
    if (ret < 0) {
	printf("Error in kernel module: %d\n", errno);
    } else if (ret != buflen) {
	//printf("Error reading %u bytes from %p\n", buflen, (void*)address);
    }

    return ret;
}

unsigned long ptr_read(unsigned long address) {
    unsigned long ptr;
    mem_read(address, &ptr, sizeof(unsigned long)); 
    return ptr;
}

unsigned long int_read(unsigned long address) {
    int ptr;
    mem_read(address, &ptr, sizeof(int)); 
    return ptr;
}


int mem_write(unsigned long address, void* buf, unsigned int buflen) {
    struct nd_rw_req req = { .pid = pid, .addr = address, .buf = buf, .buflen = buflen };

    timing(int ret = ioctl(proc_fd, ND_WRITE, &req);)
    if (ret < 0) {
	printf("Error in kernel module: %d\n", errno);
    } else if (ret != buflen) {
	printf("Error writing %u bytes to %p\n", buflen, (void*)address);
    }

    return ret;
}

unsigned long get_base(char* filename) {
    unsigned long base_address = 0;
    struct nd_vma_base_req req = { .pid = pid, .filename = filename, .filename_len = strlen(filename), .base_address = &base_address};

    printf("Sending IOCTL\n");
    timing(int ret = ioctl(proc_fd, ND_VMA_BASE, &req);)
    printf("Done!\n");
    if (ret < 0) {
	printf("Error in kernel module: %d\n", errno);
    } else if (base_address == 0) {
	printf("Unable to find base address of %s in process with pid %u\n", filename, pid);
    }

    return base_address;
}

#define sqr(x) x*x

float dist_fast(struct Vec3 v1, struct Vec3 v2) {
    return sqr(fabsf(v1.x - v2.x)) + sqr(fabsf(v1.y - v2.y)) + sqr(fabsf(v1.z - v2.z)); 
}
void clearScreen()
{
  const char *CLEAR_SCREEN_ANSI = "\e[1;1H\e[2J";
  write(STDOUT_FILENO, CLEAR_SCREEN_ANSI, 12);
}

int main(int argc,char** argv) {
    if (argc != 2) {
	printf("Usage: %s pid\n", argv[0]);
	return 0;
    }

    pid = atoi(argv[1]);
    proc_fd = open("/proc/nice_driver", O_RDWR);

    unsigned long base = get_base("DayZ_BE.exe");

    unsigned long world = ptr_read(base + 0x4089990);
    printf("WORLD 0x%lx\n", world);

    unsigned long local_player = ptr_read(ptr_read(world + 0x28B8) + 0x8) - 0xA8;
    printf("LOCAL_PLAYER 0x%lx\n", local_player);

    unsigned long visual_state = ptr_read(local_player + 0x198);
    printf("VISUAL_STATE 0x%lx\n", visual_state);
    unsigned long item_table = ptr_read(world + 0x1FB8);
    int item_table_size = ptr_read(world + 0x1FB8 + 0x8);

    printf("0x%lx %u\n", item_table, item_table_size);


    while (1) {
	struct Vec3 player_pos;
	mem_read(visual_state + 0x2C, &player_pos, sizeof(struct Vec3));
	//printf("%f %f %f\n", player_pos.x, player_pos.y, player_pos.z); 

	for (int i=0; i<item_table_size;i+=2) {
	    unsigned long item = ptr_read(item_table + 0x8*i);
	    if (item < 10) continue;
	    struct Vec3 item_pos;
	    mem_read(ptr_read(item + 0x198) + 0x2C, &item_pos, sizeof(struct Vec3));
	    float distance = dist_fast (player_pos, item_pos);

	    if (distance > 10000) continue;
	    //printf("%f %f %f\n", item_pos.x, item_pos.y, item_pos.z); 
	    char str[32];
	    unsigned long arma_str = ptr_read(ptr_read(item+0x148) + 0x4E0);
	    mem_read(arma_str + 0x10, str, 32);

	    printf("Type Name %32s Distance: %f\n", str, distance);
	}
	sleep(1);
	clearScreen();
    }

    close(proc_fd);

    return EXIT_SUCCESS;
}
