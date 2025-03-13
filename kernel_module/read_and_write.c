#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/syscalls.h>
#include <linux/version.h>
#include <linux/namei.h>
#include <linux/slab.h>   // Для kmalloc и kfree
#include <linux/sched.h>  // Для current и task_struct
#include <linux/mm.h>     // Для mm_struct
#include <linux/string.h>

#include "ftrace_helper.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("alexevgmart");
MODULE_DESCRIPTION("read and write syscall hook");
MODULE_VERSION("0.01");

static char *target_file = NULL; // Имя файла для поиска
module_param(target_file, charp, 0);
MODULE_PARM_DESC(target_file, "The name of the file to search for");

static asmlinkage long (*orig_read)(const struct pt_regs *);
static asmlinkage long (*orig_write)(const struct pt_regs *);

asmlinkage int hook_read(const struct pt_regs *regs)
{
    unsigned int fd = regs->di;
    char __user *buf = (char __user *)regs->si;
    size_t count = regs->dx;

    long ret_val = -1;

    struct task_struct *task = current;

    char *binary_path = NULL;
    if (task->mm && task->mm->exe_file) {
        binary_path = kmalloc(PATH_MAX, GFP_KERNEL);
        if (binary_path) {
            char* path = d_path(&task->mm->exe_file->f_path, binary_path, PATH_MAX);
            if (!IS_ERR(path)) {
                if (fd == 0) {
                    strncpy(binary_path, path, PATH_MAX);
                    goto next_check_read;
                }
                goto exit_read;
            }
            else {
exit_read:
                kfree(binary_path);
                binary_path = NULL;
                return orig_read(regs);
            }
        }
    }

next_check_read:
    if (fd == 0 && binary_path && target_file && strstr(binary_path, target_file)) {
        ret_val = orig_read(regs);
        
        char *data = kmalloc(count, GFP_ATOMIC);
        if (data) {
            if (copy_from_user(data, buf, count)) {
                pr_err("Failed to copy from user space\n");
            }

            for (int i = 0; i < ret_val; i++) {
                if ((data[i] < 0x20 && (data[i] < 0x07 || data[i] > 0x0d)) || data[i] > 0x7e) {
                    data[i] = 0;
                }
            }

            if (copy_to_user(buf, data, count)) {
                pr_err("Failed to copy to user space\n");
            }

            kfree(data);
        }
    }
    else {
        ret_val = orig_read(regs);
    }

    if (binary_path)
        kfree(binary_path);

    return ret_val;
}

asmlinkage int hook_write(const struct pt_regs *regs) {
    unsigned int fd = regs->di;
    char __user *buf = (char __user *)regs->si;
    size_t count = regs->dx;

    long ret_val = -1;

    struct task_struct *task = current;

    char *binary_path = NULL;
    if (task->mm && task->mm->exe_file) {
        binary_path = kmalloc(PATH_MAX, GFP_KERNEL);
        if (binary_path) {
            char* path = d_path(&task->mm->exe_file->f_path, binary_path, PATH_MAX);
            if (!IS_ERR(path)) {
                if (fd == 1 || fd == 2) {
                    strncpy(binary_path, path, PATH_MAX);
                    goto next_check_write;
                }
                goto exit_write;
            }
            else {
exit_write:
                kfree(binary_path);
                binary_path = NULL;
                return orig_write(regs);
            }
        }
    }

next_check_write:
    if ((fd == 1 || fd == 2) && binary_path && target_file && strstr(binary_path, target_file)) {
        char *data = kmalloc(count, GFP_ATOMIC);
        if (data) {
            if (copy_from_user(data, buf, count)) {
                pr_err("Failed to copy from user space\n");
            }

            pr_info("buf before: %s\n", data);

            for (int i = 0; i < count; i++) {
                if ((data[i] < 0x20 && (data[i] < 0x07 || data[i] > 0x0d)) || data[i] > 0x7e) {
                    data[i] = 0;
                }
            }

            pr_info("buf after: %s\n", data);

            if (copy_to_user(buf, data, count)) {
                pr_err("Failed to copy to user space\n");
            }

            kfree(data);
            ret_val = orig_write(regs);
        }
    }
    else {
        ret_val = orig_write(regs);
    }

    if (binary_path)
        kfree(binary_path);

    return ret_val;
}

static struct ftrace_hook hooks[] = {
    HOOK("__x64_sys_read", hook_read, &orig_read),
    HOOK("__x64_sys_write", hook_write, &orig_write),
};

static int __init interception_init(void)
{
    int err;
    err = fh_install_hooks(hooks, ARRAY_SIZE(hooks));
    if(err)
        return err;

    printk(KERN_INFO "hook interception: loaded\n");
    return 0;
}

static void __exit interception_exit(void)
{
    fh_remove_hooks(hooks, ARRAY_SIZE(hooks));
    printk(KERN_INFO "hook interception: unloaded\n");
}

module_init(interception_init);
module_exit(interception_exit);