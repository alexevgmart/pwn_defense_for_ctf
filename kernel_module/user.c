#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/socket.h>
#include <linux/netlink.h>
#include <regex.h>

#include <sys/types.h>
#include <signal.h>
#include <errno.h>
#include <stdint.h>
#include <stdbool.h>
#include <arpa/inet.h>

#define NETLINK_MY_GROUP 18

typedef struct proto_msg {
    pid_t pid;
    uint8_t std; // 0 - stdin; 1 - stdout/stderr
    uint64_t counter;
    bool exited;
    uint64_t msg_len;
    char msg[0x2000];
} proto_msg;

typedef struct data_struct {
    uint8_t std; // 0 - stdin; 1 - stdout/stderr
    bool exited;
    uint64_t data_len; // добавить сюда exited, чтобы отправлять название файла который вышел
    char* data;        // нужно сделать несколько имен в target_file
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

typedef struct banned {
    uint8_t std;
    uint8_t pattern_len;
    char* pattern;
} banned;

char* server_ip;
int server_port;
int module_sock_fd;

process* processes = NULL;
banned* banned_patterns = NULL;
uint8_t number_of_banned_patterns = 0;


// Добавление нового сообщения определенному процессу
void add_msg(process* current_process, proto_msg* msg) {
    if (!current_process->messages) {
        current_process->messages = malloc(sizeof(data_struct));
        if (!current_process->messages) {
            perror("malloc");
            return;
        }
        current_process->messages->std = msg->std;
        current_process->messages->exited = msg->exited;
        current_process->messages->data_len = msg->msg_len;
        current_process->messages->data = malloc(msg->msg_len);
        if (!current_process->messages->data) {
            perror("malloc");
            return;
        }
        memcpy(current_process->messages->data, msg->msg, msg->msg_len);
        current_process->messages->next = NULL;
        current_process->messages->prev = NULL;
        current_process->last = current_process->messages;
    }
    else {
        if (current_process->last->std == msg->std && !msg->exited) {
            size_t new_data_len = current_process->last->data_len + msg->msg_len;
            char* tmp = calloc(new_data_len + 1, 1);
            if (!tmp) {
                perror("calloc");
                return;
            }
        
            // Копируем старые данные в временный буфер
            memcpy(tmp, current_process->last->data, current_process->last->data_len);
        
            // Добавляем новые данные
            memcpy(tmp + current_process->last->data_len, msg->msg, msg->msg_len);
            free(current_process->last->data);
            
            current_process->last->data = tmp;
            current_process->last->data_len = new_data_len;
        }
        else {
            data_struct* new_msg = malloc(sizeof(data_struct));
            if (!new_msg) {
                perror("malloc");
                return;
            }
            new_msg->std = msg->std;
            new_msg->exited = new_msg->exited;
            new_msg->data_len = msg->msg_len;
            new_msg->data = calloc(msg->msg_len, 1);
            if (!new_msg->data) {
                perror("calloc");
                return;
            }
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
        // for (int i = 0; i < tmp->data_len; i++) {
        //     printf("%02x ", tmp->data[i]);
        // }
        // printf("\n");
        tmp = tmp->next;
    }
}

// отправляем один байт в модуль ядра (банить non printable или нет)
int send_byte_to_kernel(bool banned) {
    struct sockaddr_nl src_addr, dest_addr;
    struct nlmsghdr *nlh = NULL;
    struct iovec iov;
    struct msghdr msg;
    int ret = -1;

    memset(&dest_addr, 0, sizeof(dest_addr));
    dest_addr.nl_family = AF_NETLINK;
    dest_addr.nl_pid = 0;
    dest_addr.nl_groups = 0;

    nlh = (struct nlmsghdr *)malloc(NLMSG_SPACE(1));
    if (!nlh) {
        perror("malloc");
        goto cleanup;
    }
    memset(nlh, 0, NLMSG_SPACE(1));

    nlh->nlmsg_len = NLMSG_SPACE(1);
    nlh->nlmsg_pid = getpid();
    nlh->nlmsg_flags = 0;

    if (banned)
        *((unsigned char *)NLMSG_DATA(nlh)) = 0xff;
    else 
        *((unsigned char *)NLMSG_DATA(nlh)) = 0x7f;

    iov.iov_base = (void *)nlh;
    iov.iov_len = nlh->nlmsg_len;
    memset(&msg, 0, sizeof(msg));
    msg.msg_name = (void *)&dest_addr;
    msg.msg_namelen = sizeof(dest_addr);
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;

    if (sendmsg(module_sock_fd, &msg, 0) < 0) {
        perror("sendmsg");
        goto cleanup;
    }

    ret = 0;

cleanup:
    if (nlh) free(nlh);
    return ret;
}

// отправление данных на python сервер
void send_to_python(process* current_process) {
    int sock;
    struct sockaddr_in server_addr;
    char message[1024];

    // Создаем TCP-сокет
    sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        perror("socket");
        return;
    }

    // Настраиваем адрес сервера
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(server_port);
    inet_pton(AF_INET, server_ip, &server_addr.sin_addr);
    // inet_pton(AF_INET, "127.0.0.1", &server_addr.sin_addr);

    // Подключаемся к серверу
    if (connect(sock, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        perror("connect");
        close(sock);
        return;
    }

    data_struct* tmp = current_process->messages;
    while (tmp) {
        if (send(sock, &tmp->std, 1, 0) < 0) {
            perror("send");
        }

        if (send(sock, &tmp->data_len, sizeof(uint64_t), 0) < 0) {
            perror("send");
        }
        if (send(sock, tmp->data, tmp->data_len, 0) < 0) {
            perror("send");
        }

        tmp = tmp->next;
    }

    // uint8_t no_more_data = 0xff;
    // if (send(sock, &no_more_data, 1, 0) < 0) {
    //     perror("send");
    //     return;
    // }

    number_of_banned_patterns;
    if (recv(sock, &number_of_banned_patterns, 1, 0) < 0) {
        perror("recv");
        close(sock);
        return;
    }

    if (number_of_banned_patterns == 0) {
        close(sock);
        return;
    }

    if (!banned_patterns) {
        banned_patterns = calloc(number_of_banned_patterns * sizeof(banned), 1);
    }
    else {
        banned_patterns = realloc(banned_patterns, number_of_banned_patterns * sizeof(banned));
    }
    for (int i = 0; i < number_of_banned_patterns; i++) {
        recv(sock, &banned_patterns[i].std, 1, 0);
        recv(sock, &banned_patterns[i].pattern_len, 1, 0);
        banned_patterns[i].pattern = calloc(banned_patterns[i].pattern_len, 1);
        recv(sock, banned_patterns[i].pattern, banned_patterns[i].pattern_len, 0);
        // puts(banned_patterns[i].pattern);
    }

    close(sock);
}

// остановка отслеживания процесса
void remove_process(process* current_process) {
    if (!current_process)
        return;

    if (current_process->prev) {
        current_process->prev->next = current_process->next;
    } else {
        processes = current_process->next;
    }

    if (current_process->next) {
        current_process->next->prev = current_process->prev;
    }

    data_struct* tmp = current_process->messages;
    while (tmp) {
        data_struct* next_msg = tmp->next;
        if (tmp->data) {
            free(tmp->data);
        }
        free(tmp);
        tmp = next_msg;
    }

    free(current_process);
}

// добавление нового процесса/сообщения
void add_msg_or_process(proto_msg* msg) {
    process* tmp = processes;
    bool new = true;

    while (tmp) {
        if (tmp->pid == msg->pid) {
            new = false;
            add_msg(tmp, msg);
            if (msg->exited) {
                // print_process(tmp);
                send_to_python(tmp);
                remove_process(tmp);
                return;
            }
            // new = false;
            // add_msg(tmp, msg);
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
        new_process->messages = NULL;
        new_process->last = NULL;
        new_process->next = processes;
        new_process->prev = NULL;

        if (processes)
            processes->prev = new_process;

        processes = new_process;

        add_msg(new_process, msg);
    }
}

// kill процесс если там есть забаненный паттерн
void check_ban(char* data, pid_t pid, uint8_t std) {
    bool ban_non_printable = false;

    if (!banned_patterns) {
        send_byte_to_kernel(ban_non_printable);
        return;
    }

    for (int i = 0; i < number_of_banned_patterns; i++) {
        if (banned_patterns[i].std != 2 && std != banned_patterns[i].std)
            continue;

        if (strstr(banned_patterns[i].pattern, "non_printable_bytes_block")) {
            ban_non_printable = true;
            continue;
        }

        regex_t regex;
        regmatch_t matches[1];
        int ret;

        ret = regcomp(&regex, banned_patterns[i].pattern, REG_EXTENDED);
        if (ret != 0) {
            printf("Could not compile regex\n");
            return;
        }

        ret = regexec(&regex, data, 1, matches, 0);
        if (ret == 0) {
            if (kill(pid, SIGKILL) == -1) {
                perror("Ошибка при отправке SIGKILL");
                return;
            }
        }

        regfree(&regex);
    }
    send_byte_to_kernel(ban_non_printable);
}

// Функция для чтения сообщения от ядра
void read_message(int sock)
{
    struct sockaddr_nl nladdr;
    struct msghdr msg;
    struct iovec iov;
    char buffer[sizeof(proto_msg) + NLMSG_SPACE(0)];
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

    proto_msg* data = (proto_msg*)NLMSG_DATA((struct nlmsghdr *)&buffer);
    // if (strlen(data->msg) > 0)
    
    // printf("%s(pid: %d, counter: %ld, std: %02x)", data->msg, data->pid, data->counter, data->std);
    check_ban(data->msg, data->pid, data->std);
    add_msg_or_process(data);
    // printf("std: %d, data: ", data->std);
    // for (int i = 0; i < data->msg_len; i++)
    //     printf("%02x ", data->msg[i]);
    // printf("\n");
    // printf("%s(pid: %d, counter: %ld)", data->msg, data->pid, data->counter);
    // printf("\n\npid: %d\nmsg_len: %ld\nstd: %1d\ncounter: %ld\nexited: %1d\n%s", data->pid, data->msg_len, data->std, data->counter, data->exited, data->msg);
}

int main(int argc, char *argv[])
{
    setvbuf(stdin, 0LL, 2, 0LL);
	setvbuf(stdout, 0LL, 2, 0LL);
	setvbuf(stderr, 0LL, 2, 0LL);

    if (argc < 3) {
        printf("Usage: %s <server_ip> <server_port>\n", argv[0]);
        exit(1);
    }

    server_ip = argv[1];
    server_port = atoi(argv[2]);

    struct sockaddr_nl src_addr;
    int sock_fd;
    int group = NETLINK_MY_GROUP;

    // Создаем сокет
    sock_fd = socket(PF_NETLINK, SOCK_RAW, NETLINK_USERSOCK);
    if (sock_fd < 0) {
        perror("socket");
        return 1;
    }
    module_sock_fd = sock_fd;

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

    // if (setsockopt(sock_fd, SOL_NETLINK, NETLINK_ADD_MEMBERSHIP, &group, sizeof(group)) < 0) {
    //     perror("setsockopt NETLINK_ADD_MEMBERSHIP");
    //     close(sock_fd);
    //     return -1;
    // }


    // Читаем сообщения от ядра
    while (1) {
        read_message(sock_fd);
    }

    close(sock_fd);
    return 0;
}
