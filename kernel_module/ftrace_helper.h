// ftrace_helper.h
#ifndef FTRACE_HELPER_H
#define FTRACE_HELPER_H

#include <linux/ftrace.h>
#include <linux/kallsyms.h>
#include <linux/kernel.h>
#include <linux/linkage.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/version.h>
#include <linux/kprobes.h>

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 11, 0)
#define FTRACE_OPS_FL_RECURSION_SAFE FTRACE_OPS_FL_RECURSION
#endif

static unsigned long lookup_name(const char *name) {
    struct kprobe kp = { .symbol_name = name };
    unsigned long addr = 0;
    
    if (register_kprobe(&kp) < 0)
        return 0;
    
    addr = (unsigned long)kp.addr;
    unregister_kprobe(&kp);
    return addr;
}

struct ftrace_hook {
    const char *name;
    void *function;
    void *original;

    unsigned long address;
    struct ftrace_ops ops;
};

#define HOOK(_name, _hook, _orig) \
{ \
    .name = (_name), \
    .function = (_hook), \
    .original = (_orig), \
}

// Прототипы функций
int fh_install_hook(struct ftrace_hook *hook);
void fh_remove_hook(struct ftrace_hook *hook);
int fh_install_hooks(struct ftrace_hook *hooks, size_t count);
void fh_remove_hooks(struct ftrace_hook *hooks, size_t count);

static void fh_ftrace_thunk(unsigned long ip, unsigned long parent_ip,
                            struct ftrace_ops *ops, struct ftrace_regs *regs)
{
    struct ftrace_hook *hook = container_of(ops, struct ftrace_hook, ops);

    if (!within_module(parent_ip, THIS_MODULE))
        regs->regs.ip = (unsigned long)hook->function;
}

int fh_install_hook(struct ftrace_hook *hook)
{
    int err;

    hook->address = lookup_name(hook->name);
    if (!hook->address) {
        pr_err("rootkit: unresolved symbol: %s\n", hook->name);
        return -ENOENT;
    }

    *((unsigned long *)hook->original) = hook->address;

    hook->ops.func = fh_ftrace_thunk;
    hook->ops.flags = FTRACE_OPS_FL_SAVE_REGS
                    | FTRACE_OPS_FL_RECURSION_SAFE
                    | FTRACE_OPS_FL_IPMODIFY;

    err = ftrace_set_filter_ip(&hook->ops, hook->address, 0, 0);
    if (err) {
        pr_err("rootkit: ftrace_set_filter_ip() failed: %d\n", err);
        return err;
    }

    err = register_ftrace_function(&hook->ops);
    if (err) {
        pr_err("rootkit: register_ftrace_function() failed: %d\n", err);
        return err;
    }

    return 0;
}

void fh_remove_hook(struct ftrace_hook *hook)
{
    unregister_ftrace_function(&hook->ops);
    ftrace_set_filter_ip(&hook->ops, hook->address, 1, 0);
}

int fh_install_hooks(struct ftrace_hook *hooks, size_t count)
{
    int err;
    size_t i;

    for (i = 0; i < count; i++) {
        err = fh_install_hook(&hooks[i]);
        if (err)
            goto error;
    }

    return 0;

error:
    while (i--)
        fh_remove_hook(&hooks[i]);

    return err;
}

void fh_remove_hooks(struct ftrace_hook *hooks, size_t count)
{
    size_t i;

    for (i = 0; i < count; i++)
        fh_remove_hook(&hooks[i]);
}

#endif // FTRACE_HELPER_H
