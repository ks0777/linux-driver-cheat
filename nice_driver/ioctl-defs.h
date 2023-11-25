#ifndef IOCTL_DEFS_H
#define IOCTL_DEFS_H

#include <asm-generic/ioctl.h>

struct nd_rw_req {
    unsigned int pid;
    unsigned long addr;
    unsigned char *buf;
    unsigned int buflen;
};

struct nd_vma_base_req {
    unsigned int pid;
    char *filename;
    unsigned short filename_len;
    unsigned long *base_address;
};

#define ND_READ _IOWR(0x69, 0x01, struct nd_rw_req)
#define ND_WRITE _IOW(0x69, 0x02, struct nd_rw_req)
#define ND_VMA_BASE _IOWR(0x69, 0x03, struct nd_vma_base_req)

#endif
