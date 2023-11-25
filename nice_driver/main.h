#include <linux/init.h>
#include <linux/module.h>
#include <linux/proc_fs.h>
#include <uapi/asm-generic/ioctl.h>

#include "hooks.h"
#include "ioctl-handlers.h"
#include "ioctl-defs.h"
#include "utils.h"
