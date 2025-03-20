#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/socket.h>
#include <linux/netlink.h>

#include <sys/types.h>
#include <signal.h>
#include <errno.h>
#include <stdint.h>
#include <stdbool.h>

#define MYGRP 18

typedef struct proto_msg {
    pid_t pid;
    bool std; // 0 - stdin; 1 - stdout/stderr
    uint64_t counter;
    bool exited;
    uint64_t msg_len;
    char msg[0x2000];
} proto_msg;

typedef struct data_struct {
    bool std; // 0 - stdin; 1 - stdout/stderr
    uint64_t data_len;
    char* data;
    struct data_struct* next;
    struct data_struct* prev;
} data_struct;

typedef struct process {
    pid_t pid;
    data_struct* messages;
    data_struct* last;
    struct process* next;
    struct process* prev;
} process;

process* processes = NULL;


// Добавление нового сообщения определенному процессу
void add_msg(process* current_process, proto_msg* msg) {
    if (!current_process->messages) {
        current_process->messages = malloc(sizeof(data_struct));
        current_process->messages->std = msg->std;
        current_process->messages->data_len = msg->msg_len;
        current_process->messages->data = malloc(msg->msg_len);
        memcpy(current_process->messages->data, msg->msg, msg->msg_len);
        current_process->messages->next = NULL;
        current_process->messages->prev = NULL;
        current_process->last = current_process->messages;
    }
    else {
        if (current_process->last->std == msg->std) {
            current_process->last->data_len = current_process->last->data_len + msg->msg_len + 1;
            char* tmp = calloc(current_process->last->data_len, 1);
            memcpy(tmp, current_process->last->data, current_process->last->data_len);
            strncat(tmp, msg->msg, msg->msg_len);
            current_process->last->data = realloc(current_process->last->data, current_process->last->data_len);
            memcpy(current_process->last->data, tmp, current_process->last->data_len);
            free(tmp);
        }
        else {
            data_struct* new_msg = malloc(sizeof(data_struct));
            new_msg->std = msg->std;
            new_msg->data_len = msg->msg_len;
            new_msg->data = calloc(msg->msg_len, 1);
            memcpy(new_msg->data, msg->msg, msg->msg_len);
            new_msg->prev = current_process->last;
            new_msg->next = NULL;
            current_process->last->next = new_msg;
            current_process->last = new_msg;
        }
    }
}

// вывод всей информации которая была во время взаимодействия
void print_process(process* current_process) {
    data_struct* tmp = current_process->messages;
    while (tmp) {
        if (tmp->std)
            puts("write:");
        else
            puts("read:");

        puts(tmp->data);
        tmp = tmp->next;
    }
}

// остановка отслеживания процесса
void remove_process(process* current_process) {
    if (!current_process) return;

    // Удаляем процесс из списка
    if (current_process->prev) {
        current_process->prev->next = current_process->next;
    } else {
        processes = current_process->next;
    }

    if (current_process->next) {
        current_process->next->prev = current_process->prev;
    }

    // Освобождаем память для сообщений
    data_struct* tmp_msg = current_process->messages;
    while (tmp_msg) {
        data_struct* next_msg = tmp_msg->next;
        if (tmp_msg->data) {
            free(tmp_msg->data);
        }
        free(tmp_msg);
        tmp_msg = next_msg;
    }

    // Освобождаем память для самого процесса
    free(current_process);
}

// добавление нового процесса/сообщения
void add_msg_or_process(proto_msg* msg) {
    process* tmp = processes;
    bool new = true;

    while (tmp) {
        if (tmp->pid == msg->pid) {
            if (msg->exited) {
                print_process(tmp);
                remove_process(tmp);
                return;
            }
            new = false;
            add_msg(tmp, msg);
            break;
        }

        tmp = tmp->next;
    }

    if (new) {
        process* new_process = malloc(sizeof(process));
        if (!new_process) {
            perror("malloc");
            return;
        }

        new_process->pid = msg->pid;
        new_process->next = processes;
        new_process->prev = NULL;

        if (processes)
            processes->prev = new_process;

        processes = new_process;

        add_msg(new_process, msg);
    }
}

// Функция для чтения сообщения от ядра
void read_message(int sock)
{
    struct sockaddr_nl nladdr;
    struct msghdr msg;
    struct iovec iov;
    char buffer[sizeof(proto_msg)];
    int ret;

    memset(buffer, 0, sizeof(buffer));

    iov.iov_base = (void *)buffer;
    iov.iov_len = sizeof(buffer);
    msg.msg_name = (void *)&nladdr;
    msg.msg_namelen = sizeof(nladdr);
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;

    // printf("\nWaiting for message from kernel...\n");
    ret = recvmsg(sock, &msg, 0);
    if (ret < 0) {
        perror("recvmsg");
        return;
    }

    proto_msg* data = NLMSG_DATA((struct nlmsghdr *)&buffer);
    // if (strlen(data->msg) > 0)
    add_msg_or_process(data);
    // printf("%s", data->msg);
    // printf("%s(pid: %d, counter: %ld)", data->msg, data->pid, data->counter);
    // printf("\n\npid: %d\nmsg_len: %ld\nstd: %1d\ncounter: %ld\nexited: %1d\n%s", data->pid, data->msg_len, data->std, data->counter, data->exited, data->msg);
}

int main(int argc, char **argv)
{
    setvbuf(stdin, 0LL, 2, 0LL);
	setvbuf(stdout, 0LL, 2, 0LL);
	setvbuf(stderr, 0LL, 2, 0LL);

    struct sockaddr_nl src_addr;
    int sock_fd;
    int group = MYGRP;

    // Создаем сокет
    sock_fd = socket(PF_NETLINK, SOCK_RAW, NETLINK_USERSOCK);
    if (sock_fd < 0) {
        perror("socket");
        return 1;
    }

    // Заполняем адрес источника
    memset(&src_addr, 0, sizeof(src_addr));
    src_addr.nl_family = AF_NETLINK;
    src_addr.nl_pid = getpid();  // PID текущего процесса
    bind(sock_fd, (struct sockaddr *)&src_addr, sizeof(src_addr));

    int buf_size = 1024 * 1024 * 1024;
    if (setsockopt(sock_fd, SOL_SOCKET, SO_RCVBUF, &buf_size, sizeof(buf_size)) < 0) {
        perror("setsockopt");
        close(sock_fd);
        return 1;
    }

    // Читаем сообщения от ядра
    while (1) {
        read_message(sock_fd);
    }

    close(sock_fd);
    return 0;
}
