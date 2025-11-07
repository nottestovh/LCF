#define _GNU_SOURCE
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>

#include "config.h"


int lcf_server_conn(void)
{
    int lcf_fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if ( lcf_fd < 0 ) {
        perror("lcf_server_conn: socket creat error");
        _exit(EXIT_FAILURE);
    }

    struct sockaddr_un addr;
    memset(&addr, 0x0, sizeof(struct sockaddr_un));
    addr.sun_family = AF_UNIX;
    addr.sun_path[0] = '\0';
    strcpy(addr.sun_path + 1, SNAME);

    socklen_t len = sizeof(addr.sun_family) + 1 + strlen(SNAME);
    if ( connect(lcf_fd, (struct sockaddr*)&addr, len) < 0 ) {
        perror("lcf_server_conn: connection failed");
        close(lcf_fd);
        _exit(EXIT_FAILURE);
    }

    return lcf_fd;
}


int main(int argc, char **argv)
{
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <program> <argv>\n", argv[0]);
        return EXIT_FAILURE;
    }

    int lcf_fd = lcf_server_conn();

    pid_t pid = fork();
    if ( pid < 0 ) {
        perror("main: fork error");
        return -1;
    } else if ( pid == 0 ) {
        dup2(lcf_fd, STDOUT_FILENO);
        close(lcf_fd);
        execl(argv[1], (char*)&argv[1], (char*)NULL);
        _exit(EXIT_FAILURE);
    } else {
        wait(NULL);
        close(lcf_fd);
    }

    return 0;
}
