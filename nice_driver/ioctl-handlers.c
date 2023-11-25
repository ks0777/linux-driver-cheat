#include "ioctl-handlers.h"

struct task_struct* get_task(int pid) {
    struct task_struct *task; 
    for_each_process(task) {
	if (task->pid == pid) break;
    }

    if (task == &init_task) {
	printk("Process with PID %hu not found!\n", pid);
	return NULL;
    }

    return task;
}

int handle_nd_rw(struct nd_rw_req req, int write) {
    int gup_flags = write ? FOLL_WRITE : 0;

    struct task_struct *task = get_task(req.pid);
    if (!task) return -1;

    unsigned char *buf = kmalloc(req.buflen, GFP_KERNEL);
    if (!buf) return -1;

    if (write) {
	if(copy_from_user(buf, req.buf, req.buflen)) return -1;
    } else {
	memset(buf, 0, req.buflen);
    }

    int bytes = access_process_vm(task, req.addr, buf, req.buflen, gup_flags); 

    if (!write)
	bytes -= copy_to_user(req.buf, buf, bytes);

    kfree(buf);
    
    return bytes;
}

int handle_nd_vma_base(struct nd_vma_base_req req) {
    char *filename = kmalloc(req.filename_len, GFP_KERNEL);
    if (!filename) return -1;
    if (copy_from_user(filename, req.filename, req.filename_len)) return -1;

    struct task_struct *task = get_task(req.pid);
    if (!task) return -1;

    struct vm_area_struct *vma = task->mm->mmap;

    while (vma != NULL) {
	//printk("[%lx-%lx]: %s\n", vma->vm_start, vma->vm_end, vma->vm_file ? vma->vm_file->f_path.dentry->d_name.name : NULL);
	if (vma->vm_file && strcmp(vma->vm_file->f_path.dentry->d_name.name, filename) == 0) {
	    if (copy_to_user((void*)req.base_address, &vma->vm_start, sizeof(unsigned long))) return -1;
	    return 0;
	}
	vma = vma->vm_next;
    }

    return 0;
}
