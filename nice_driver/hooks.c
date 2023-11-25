#include "hooks.h"

atomic_t recvmsg_count = ATOMIC_INIT(0);
atomic_t ioctl_count = ATOMIC_INIT(0);

inline void mywrite_cr0(unsigned long cr0) {
  //asm volatile("mov %0,%%cr0" : "+r"(cr0), "+m"(__force_order));
  asm volatile("mov %0,%%cr0" : "+r"(cr0) : : "memory");
}

void protect_memory(void) {
  unsigned long cr0 = read_cr0();
  set_bit(16, &cr0);
  mywrite_cr0(cr0);
}

void unprotect_memory(void) {
  unsigned long cr0 = read_cr0();
  clear_bit(16, &cr0);
  mywrite_cr0(cr0);
}


#define debug
#ifndef debug
#define printk(...)
#endif

void **syscall_table;

int handle_sg_io(void* user_arg) {
    if (!user_arg) return -EINVAL;

    void* xferp = 0;
    unsigned char cmd = 0;

    struct sg_io_v4 sg_io_req;
    unsigned long ret = copy_from_user(&sg_io_req, user_arg, sizeof(struct sg_io_v4));

    if (!ret && sg_io_req.protocol == BSG_PROTOCOL_SCSI && sg_io_req.subprotocol == BSG_SUB_PROTOCOL_SCSI_CMD && sg_io_req.request_len >= 9) {
	xferp = (void*)sg_io_req.din_xferp;
	if (copy_from_user(&cmd, ((unsigned char*)sg_io_req.request)+9, 1)) return -EIO;
    }

    struct sg_io_hdr sg_io_v3;
    ret = copy_from_user(&sg_io_v3, user_arg, sizeof(struct sg_io_hdr));
    if (!ret && sg_io_v3.interface_id == 'S' && sg_io_v3.cmd_len >= 9) {
	xferp = sg_io_v3.cmdp;
	if (copy_from_user(&cmd, ((unsigned char*)sg_io_v3.cmdp)+9, 1)) return -EIO;
    }

    if (xferp && cmd == 0xEC) {
	unsigned char serial[20];
	get_random_bytes(serial, 20);
	int i =0;
	for (; i<20; i++) {
	    serial[i] = serial[i] % 25 + 65;
	}

	if (copy_to_user((unsigned char*)xferp + 20, serial, 20)) return -EIO;
    }

    return 0;
}

int handle_hdio_get_identity(void* user_arg) {
    if (!user_arg) return -EINVAL;

    printk("[RK] HDIO_GET_IDENTITY ioctl called\n");
    struct hd_driveid driveid;

    if (copy_from_user(&driveid, user_arg, sizeof(struct hd_driveid))) return -EIO;
    printk("Serial: %20s\n", driveid.serial_no);

    get_random_bytes(driveid.serial_no, 20);
    int i =0;
    for (; i<20; i++) {
	driveid.serial_no[i] = driveid.serial_no[i] % 25 + 65;
    }
    if (copy_to_user(user_arg, &driveid, sizeof(struct hd_driveid))) return -EIO;

    printk("New Serial: %20s\n", driveid.serial_no);

    return 0;
}

int handle_siocgifhwaddr(void* user_arg) {
    if (!user_arg) return -EINVAL;

    printk("[RK] SIOCGIFHWADDR");

    struct ifreq ifr;
    if (copy_from_user(&ifr, user_arg, sizeof(struct ifreq))) return -EIO;

    get_random_bytes(ifr.ifr_ifru.ifru_hwaddr.sa_data, 6);
    ifr.ifr_ifru.ifru_hwaddr.sa_data[0] = 0x70; 
    ifr.ifr_ifru.ifru_hwaddr.sa_data[1] = 0x85; 
    ifr.ifr_ifru.ifru_hwaddr.sa_data[2] = 0xC2; 

    if (copy_to_user(user_arg, &ifr, sizeof(struct ifreq))) return -EIO;

    return 0;
}

int handle_siocethtool(void* user_arg) {
    if (!user_arg) return -EINVAL;

    printk("[RK] SIOCETHTOOL");

    struct ifreq ifr;
    struct ethtool_perm_addr* epa = kmalloc(sizeof(struct ethtool_perm_addr) + IFHWADDRLEN, GFP_KERNEL);
    if (!epa || copy_from_user(&ifr, user_arg, sizeof(struct ifreq)) ||
	copy_from_user(epa, ifr.ifr_ifru.ifru_data, sizeof(struct ethtool_perm_addr) + IFHWADDRLEN)) {
	kfree(epa);
	return -EIO;
    }

    if (epa->cmd == ETHTOOL_GPERMADDR) {
	get_random_bytes(epa->data, 6);
	epa->data[0] = 0x70; 
	epa->data[1] = 0x85; 
	epa->data[2] = 0xC2; 
	if (copy_to_user(ifr.ifr_ifru.ifru_data, epa, sizeof(struct ethtool_perm_addr) + IFHWADDRLEN)) {
	    kfree(epa);
	    return -EIO;
	}
    }

    kfree (epa);

    return 0;
}

asmlinkage long (*orig_sys_ioctl)(const struct pt_regs *pt_regs);

long hook_sys_ioctl (const struct pt_regs *pt_regs) {
    atomic_inc(&ioctl_count);
    long ret = orig_sys_ioctl(pt_regs);
    atomic_dec(&ioctl_count);

    if (ret)
	return ret;

    switch (pt_regs->si) {
    // disk serials
    case SG_IO:
	handle_sg_io((void*)pt_regs->dx);
	break;
    case HDIO_GET_IDENTITY:
	handle_hdio_get_identity((void*)pt_regs->dx);
	break;
    // network interfaces addresses
    case SIOCGIFHWADDR:
	// assignable mac
	handle_siocgifhwaddr((void*)pt_regs->dx);
	break;
    case SIOCETHTOOL:
	// permanent mac
	handle_siocethtool((void*)pt_regs->dx);
	break;
    }
    
    return ret;
}

asmlinkage long (*orig_sys_recvmsg)(const struct pt_regs *pt_regs);

long hook_sys_recvmsg (const struct pt_regs *pt_regs) {
    atomic_inc(&recvmsg_count);
    long orig_len = orig_sys_recvmsg(pt_regs);
    atomic_dec(&recvmsg_count);
    
    if (orig_len <= 0) return orig_len;
    
    struct user_msghdr *msg = (struct user_msghdr*)pt_regs->si;

    char *hdr_kbuf = kmalloc(sizeof(struct user_msghdr), GFP_KERNEL);
    if (copy_from_user(hdr_kbuf, msg, sizeof(struct user_msghdr))) {
        kfree(hdr_kbuf);
        return orig_len;
    }

    char *iov_kbuf = kmalloc(sizeof(struct iovec), GFP_KERNEL);
    if (copy_from_user(iov_kbuf, ((struct user_msghdr*) hdr_kbuf)->msg_iov, sizeof(struct iovec))) {
        kfree(hdr_kbuf);
        kfree(iov_kbuf);
        return orig_len;
    }
    struct iovec* iov =((struct iovec*) iov_kbuf);

    kfree(hdr_kbuf);

    if (!iov->iov_base){
        kfree(iov_kbuf);
        return orig_len;
    } 

    char *kbuf = kmalloc(iov->iov_len, GFP_KERNEL);
    if (copy_from_user(kbuf, iov->iov_base, iov->iov_len)) {
        kfree(iov_kbuf);
        kfree(kbuf);
        return orig_len;
    }
    struct nlmsghdr* nh = (struct nlmsghdr *) kbuf;

    long len = orig_len;
    while (NLMSG_OK (nh, len)) {
        if (nh->nlmsg_type != RTM_NEWLINK) {
            break;            
        }
        
        struct nlattr* attr = nlmsg_find_attr(nh, sizeof(struct ifinfomsg), IFLA_ADDRESS);
        if (attr) {    
            unsigned char* address = (unsigned char*)(attr+1);
	    unsigned char loopback_addr[6] = {0,0,0,0,0,0};
	    if (memcmp(address,loopback_addr, 6) != 0) { 
		get_random_bytes(address, 6);
		address[0] = 0x70; 
		address[1] = 0x85; 
		address[2] = 0xC2; 
	    }
        }

        nh = NLMSG_NEXT (nh, len);
    }
    copy_to_user(iov->iov_base, kbuf, iov->iov_len);
    kfree(iov_kbuf);
    kfree(kbuf);
    return orig_len;
}

void *hook_syscall(void *hook_fn, int table_offset) {
    void *orig_fn = syscall_table[table_offset];
    unprotect_memory();
    syscall_table[table_offset] = hook_fn;
    protect_memory();

    return orig_fn;
}

void unhook_syscall(void *orig_fn, int table_offset, atomic_t *counter) {
    unprotect_memory();
    syscall_table[table_offset] = orig_fn;
    protect_memory();
    while (counter && atomic_read(counter)) {}
}

void install_hooks() {
    syscall_table = (void **)kallsyms_lookup_name("sys_call_table");

    if (!syscall_table)
    {
        printk("[RK] Unable to find syscall_table\n");
        return;
    }

    
    orig_sys_recvmsg = hook_syscall(hook_sys_recvmsg, 47);
    orig_sys_ioctl = hook_syscall(hook_sys_ioctl, 16);
}

void uninstall_hooks()
{ 
    unhook_syscall(orig_sys_recvmsg, 47, &recvmsg_count);
    unhook_syscall(orig_sys_ioctl, 16, &ioctl_count);
}
