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

#include <net/sock.h>
#include <linux/module.h>
#include <linux/netlink.h>
#include <linux/skbuff.h>
#include <linux/notifier.h>
#include <linux/signal.h>

#include "ftrace_helper.h"


typedef struct proto_msg {
    pid_t pid;
    bool std; // 0 - stdin; 1 - stdout/stderr
    uint64_t counter;
    bool exited;
    uint64_t msg_len;
    char msg[0x2000];
} proto_msg;

typedef struct current_process {
    pid_t pid;
    uint64_t counter; // минимальное значение 1 (у каждого процесса должен быть минимум 1 ввод/вывод)
    struct current_process* next;
    struct current_process* prev;
} current_process;

current_process* processes = NULL;

struct sock *nl_sock = NULL;

static char *target_file = NULL;
module_param(target_file, charp, 0);
MODULE_PARM_DESC(target_file, "The name of the file to search for");

static char *server_monitor = NULL;
module_param(server_monitor, charp, 0);
MODULE_PARM_DESC(server_monitor, "The name of the server monitor file");

static asmlinkage long (*orig_read)(const struct pt_regs *);
static asmlinkage long (*orig_write)(const struct pt_regs *);
static asmlinkage long (*orig_do_exit)(long code);
static asmlinkage long (*orig_send_signal)(int sig, struct kernel_siginfo *info, struct task_struct *task, enum pid_type type);



// Получение counter процесса
uint64_t get_process_counter(pid_t pid) {
    uint64_t ret = -1;

    current_process* tmp = processes;
    while (tmp) {
        if (tmp->pid == pid) {
            ret = tmp->counter;
            break;
        }
        tmp = tmp->next;
    }

    return ret;
}

// Добавление процесса / увеличение counter
void inc_process(pid_t pid) {
    if (get_process_counter(pid) == -1) {
        current_process* new_process = kzalloc(sizeof(current_process), GFP_KERNEL);
        if (!new_process) {
            pr_info("Error: Failed to allocate memory for new process");
            return;
        }

        new_process->pid = pid;
        new_process->counter = 1;
        new_process->next = processes;
        new_process->prev = NULL;

        if (processes)
            processes->prev = new_process;

        processes = new_process;
    }
    else {
        current_process* tmp = processes;
        while (tmp) {
            if (tmp->pid == pid) {
                tmp->counter++;
                break;
            }
            tmp = tmp->next;
        }
    }
}

// Удаление процесса
void remove_process(pid_t pid) {
    current_process* tmp = processes;
    while (tmp) {
        if (tmp->pid == pid) {
            if (tmp->prev) {
                tmp->prev->next = tmp->next;
            } else {
                // Если удаляемый элемент — голова списка
                processes = tmp->next;
            }

            if (tmp->next) {
                tmp->next->prev = tmp->prev;
            }

            kfree(tmp);
            return;
        }
        tmp = tmp->next;
    }
}

// Функция для поиска PID по имени процесса
pid_t get_pid_by_name(const char *name) {
    struct task_struct *task;
    pid_t pid = -1;

    rcu_read_lock(); // Захватываем RCU read lock для безопасного доступа к списку процессов

    for_each_process(task) {
        if (strncmp(task->comm, name, TASK_COMM_LEN) == 0) {
            pid = task->pid;
            break;
        }
    }

    rcu_read_unlock(); // Освобождаем RCU read lock

    return pid;
}

// Функция для отправки сообщения в пользовательское пространство
static void netlink_send_msg(const char *data, uint64_t data_size, bool std, bool exited) {
    if (data_size == 0) {
        pr_info("Nothing to send");
        return;
    }

    struct sk_buff *skb_out;
    struct nlmsghdr *nlh;
    int res;

    proto_msg* msg = kzalloc(sizeof(proto_msg), GFP_KERNEL);
    msg->pid = current->pid;
    msg->std = std;
    msg->counter = get_process_counter(current->pid);
    msg->exited = exited;
    msg->msg_len = data_size;

    inc_process(current->pid);

    memcpy(msg->msg, data, data_size);

    skb_out = nlmsg_new(sizeof(proto_msg), 0);
    if (!skb_out) {
        printk(KERN_ERR "netlink: Failed to allocate new skb\n");
        return;
    }

    nlh = nlmsg_put(skb_out, 0, 0, NLMSG_DONE, sizeof(proto_msg), 0);
    memcpy(nlmsg_data(nlh), msg, sizeof(proto_msg));

    pid_t server_monitor_pid = -1;
    server_monitor_pid = get_pid_by_name(server_monitor);
    if (server_monitor_pid == -1) {
        printk(KERN_INFO "server monitor not found\n");
        return;
    }
    else {
        res = nlmsg_unicast(nl_sock, skb_out, server_monitor_pid);
        if (res < 0) {
            printk(KERN_INFO "netlink: Error while sending skb to user\n");
        }
    }
}

// Функция для обработки входящих сообщений
static void netlink_test_recv_msg(struct sk_buff *skb) {
    struct nlmsghdr *nlh;
    char *msg;
    int msg_size;

    nlh = (struct nlmsghdr *)skb->data;
    msg = (char *)nlmsg_data(nlh);
    msg_size = strlen(msg);

    printk(KERN_INFO "netlink: Received message: %s\n", msg);

    // Отправляем ответ всем подписанным процессам
    netlink_send_msg(msg, msg_size, false, false);
}

asmlinkage int hook_read(const struct pt_regs *regs) {
    unsigned int fd = regs->di;
    char __user *buf = (char __user *)regs->si;
    size_t count = regs->dx;

    long ret_val = -1;

    struct task_struct *task = current;

    char *binary_path = NULL;
    if (task->mm && task->mm->exe_file) {
        binary_path = kzalloc(PATH_MAX, GFP_KERNEL);
        if (binary_path) {
            char* path = d_path(&task->mm->exe_file->f_path, binary_path, PATH_MAX);
            if (!IS_ERR(path)) {
                if (fd == 0) {
                    memcpy(binary_path, path, PATH_MAX);
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
    ret_val = orig_read(regs);
    if (fd == 0 && binary_path && target_file && strstr(binary_path, target_file)) {
        if (ret_val <= 0) {
            netlink_send_msg(binary_path, strlen(binary_path), false, true);
            remove_process(current->pid);

            if (send_sig(SIGKILL, current, 0))
                pr_err("Failed to kill process\n");

            kfree(binary_path);
            return ret_val;
        }

        char *data = kzalloc(count, GFP_KERNEL);
        if (data) {
            memset(data, 0, count);

            if (copy_from_user(data, buf, count)) {
                pr_err("Failed to copy from user space\n");
                kfree(data);
                return ret_val;
            }

            netlink_send_msg(data, count, false, false);

            for (int i = 0; i < count; i++) {
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
        binary_path = kzalloc(PATH_MAX, GFP_KERNEL);
        if (binary_path) {
            char* path = d_path(&task->mm->exe_file->f_path, binary_path, PATH_MAX);
            if (!IS_ERR(path)) {
                if (fd == 1 || fd == 2) {
                    memcpy(binary_path, path, PATH_MAX);
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
        char *data = kzalloc(count, GFP_KERNEL);
        if (data) {
            memset(data, 0, count);

            if (copy_from_user(data, buf, count)) {
                pr_err("Failed to copy from user space\n");
            }
            
            netlink_send_msg(data, count, true, false);
            // pr_info("sending: %s", data);

            for (int i = 0; i < count; i++) {
                if ((data[i] < 0x20 && (data[i] < 0x07 || data[i] > 0x0d)) || data[i] > 0x7e) {
                    data[i] = 0;
                }
            }

            if (copy_to_user(buf, data, count)) {
                pr_err("Failed to copy to user space or data in .rodata\n");
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

static asmlinkage long hook_do_exit(long code) {
    struct task_struct *task = current;

    char *binary_path = NULL;
    if (task->mm && task->mm->exe_file) {
        binary_path = kzalloc(PATH_MAX, GFP_KERNEL);
        if (binary_path) {
            char* path = d_path(&task->mm->exe_file->f_path, binary_path, PATH_MAX);
            if (!IS_ERR(path)) {
                memcpy(binary_path, path, PATH_MAX);
            }
            else {
                kfree(binary_path);
                binary_path = NULL;
                return orig_do_exit(code);
            }
        }
    }

    if (target_file && binary_path && strstr(binary_path, target_file)) {
        netlink_send_msg(binary_path, strlen(binary_path), false, true);
        remove_process(current->pid);

        if (send_sig(SIGKILL, current, 0))
            pr_err("Failed to kill process\n");
    }

    kfree(binary_path);
    binary_path = NULL;
    return orig_do_exit(code);
}

asmlinkage int hook_send_signal(int sig, struct kernel_siginfo *info, struct task_struct *task, enum pid_type type) {
    char *binary_path = NULL;
    if (task->mm && task->mm->exe_file) {
        binary_path = kzalloc(PATH_MAX, GFP_KERNEL);
        if (binary_path) {
            char* path = d_path(&task->mm->exe_file->f_path, binary_path, PATH_MAX);
            if (!IS_ERR(path)) {
                strncpy(binary_path, path, PATH_MAX);
            }
            else {
                kfree(binary_path);
                binary_path = NULL;
                return orig_send_signal(sig, info, task, type);
            }
        }
    }

    if ((sig == 15 || sig == 23 || sig == 14 || sig == 2) && target_file && binary_path && strstr(binary_path, target_file)) {
        pr_info("Received signal: %d (PID: %d)\n", sig, current->pid);
        pr_info("process stopped");
        netlink_send_msg(binary_path, strlen(binary_path), false, true);
        remove_process(current->pid);

        if (send_sig(SIGKILL, current, 0))
            pr_err("Failed to kill process\n");
    }

    kfree(binary_path);
    binary_path = NULL;
    return orig_send_signal(sig, info, task, type);
}

static struct ftrace_hook hooks[] = {
    HOOK("__x64_sys_read", hook_read, &orig_read),
    HOOK("__x64_sys_write", hook_write, &orig_write),
    HOOK("do_exit", hook_do_exit, &orig_do_exit),
    // HOOK("send_signal_locked", hook_send_signal, &orig_send_signal),
};

static int __init interception_init(void) {
    int err;
    err = fh_install_hooks(hooks, ARRAY_SIZE(hooks));
    if(err)
        return err;

    struct netlink_kernel_cfg cfg = {
        .input = netlink_test_recv_msg,
    };

    nl_sock = netlink_kernel_create(&init_net, NETLINK_USERSOCK, &cfg);
    if (!nl_sock) {
        printk(KERN_ALERT "netlink: Error creating socket.\n");
        return -10;
    }

    printk(KERN_INFO "hook interception: loaded\n");
    return 0;
}

static void __exit interception_exit(void) {
    fh_remove_hooks(hooks, ARRAY_SIZE(hooks));
    netlink_kernel_release(nl_sock);
    printk(KERN_INFO "hook interception: unloaded\n");
}

module_init(interception_init);
module_exit(interception_exit);


MODULE_LICENSE("GPL");
MODULE_AUTHOR("Sanechka");
MODULE_DESCRIPTION("read and write syscall hook");
MODULE_VERSION("0.01");