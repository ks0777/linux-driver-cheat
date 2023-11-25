#ifndef IOCTL_HANDLERS_H
#define IOCTL_HANDLERS_H

#include <linux/mm.h>
#include <linux/sched.h>
#include <linux/sched/signal.h>
#include <linux/sched/task.h>
#include <linux/uaccess.h>
#include <linux/slab.h>
#include <linux/mm_types.h>

#include "ioctl-defs.h"
#include "utils.h"

int handle_nd_rw(struct nd_rw_req req, int write);
int handle_nd_vma_base(struct nd_vma_base_req req);

#endif
