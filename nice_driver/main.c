#include "main.h"

long nd_ioctl(struct file * file, unsigned int cmd, unsigned long arg) {
    if (cmd == ND_READ) {
	if (!arg) return -1;
	struct nd_rw_req req;
	if (copy_from_user(&req, (void*)arg, sizeof(struct nd_rw_req))) return -1;
	return handle_nd_rw(req, 0);
    } else if (cmd == ND_WRITE) {
	if (!arg) return -1;
	struct nd_rw_req req;
	if (copy_from_user(&req, (void*)arg, sizeof(struct nd_rw_req))) return -1;
	return handle_nd_rw(req, 1);
    } else if (cmd == ND_VMA_BASE) {
	if (!arg) return -1;
	struct nd_vma_base_req req;
	if (copy_from_user(&req, (void*)arg, sizeof(struct nd_vma_base_req))) return -1;
	return handle_nd_vma_base(req);
    } else {
	printk("Unkown IOCTL command: %u\n", cmd);
    }

    return -1;
}

int procfs_open (struct inode *ip, struct file *file) {
    try_module_get(THIS_MODULE);
    return 0;
}

int procfs_close (struct inode *ip, struct file *file) {
    module_put(THIS_MODULE);
    return 0;
}

const struct file_operations file_ops = {
    .owner          = THIS_MODULE,
    .unlocked_ioctl = nd_ioctl,
    .open           = procfs_open,
    .release        = procfs_close,
};

static int __init nd_init(void) {
    printk(KERN_ALERT "RK_INIT\n");
    proc_create_data("nice_driver", 0777, NULL, &file_ops, NULL);
    install_hooks();
    return 0;
}

static void __exit nd_exit(void) {
    printk(KERN_ALERT "RK_EXIT\n");
    remove_proc_entry("nice_driver", NULL);
    uninstall_hooks();
}

MODULE_LICENSE("GPL");

module_init(nd_init);
module_exit(nd_exit);
