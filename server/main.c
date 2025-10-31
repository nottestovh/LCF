#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <sys/un.h>
#include <sys/epoll.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
//#include <netinet/ip.h>
#include <netinet/tcp.h>

#include "rr.h"
#include "config.h"


// fd of the server checking the flags
int rs_fd = -1;
uint32_t succ_flags = 0;
uint32_t fail_flags = 0;


void set_nonblocking(int fd) {
    int flags = fcntl(fd, F_GETFL, 0);
    if ( flags < 0 ) {
        perror("set_nonblocking: error switching to non-blocking mode");
        close(fd);
        _exit(EXIT_FAILURE);
    }
    fcntl(fd, F_SETFL, flags | O_NONBLOCK);
}


int remote_server_connect(void)
{
    int remote_fd = socket(AF_INET, SOCK_STREAM, 0);
    if ( remote_fd < 0 ) {
        perror("remote_server_connect: socket creat error");
        return -1;
    }
    
    int opt = 1;
    if ( setsockopt(remote_fd, IPPROTO_TCP, TCP_NODELAY, &opt, sizeof(int)) < 0 ) {
        perror("remote_server_connect: setsockopt error (TCP_NODELAY)");
        close(remote_fd);
        return -1;
    }
    
    struct sockaddr_in addr;
    memset(&addr, 0x0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(RPORT);
    if ( inet_pton(AF_INET, RHOST, &addr.sin_addr) <= 0 ) {
        perror("remote_server_connect: inet_pton");
        close(remote_fd);
        return -1;
    }

    if ( connect(remote_fd, (struct sockaddr*)&addr, sizeof(addr)) < 0 ) {
        perror("remote_server_connect: connection failed");
        close(remote_fd);
        return -1;
    }
    
    // set_nonblocking(remote_fd);
    return remote_fd;
}


int create_unix_socket(void)
{
    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if ( fd < 0 ) {
        perror("create_unix_socket: socket creating error");
        return -1;
    }
    
    return fd;
}


ssize_t sendall(int fd, const void* buf, size_t len)
{
    const char *p = buf;
    size_t total = 0;

    while ( total < len ) {
        ssize_t n = write(fd, p + total, len - total);
#ifdef DEBUG
        printf("[DBG] sendall: %zu\n", n);
#endif
        if ( n > 0 ) total += n;
        else if ( n < 0 && (errno == EINTR) ) continue;
        else if ( n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK) ) break;
        else return -1;
    }
    
    return total;
}


ssize_t recvall(int fd, void *buf, size_t len)
{
    ssize_t n = read(fd, buf, len);
#ifdef DEBUG
    printf("[DBG] recvall: %zu\n", n);
#endif
    if ( n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK) ) return 0;
    
    return n;
}


void event_handler(int epoll_fd, struct epoll_event *ev)
{
    int fd = ev->data.fd;
    uint32_t event = ev->events;
    
    // Client has disconnected
    if ( event & (EPOLLHUP | EPOLLERR) ) {
        epoll_ctl(epoll_fd, EPOLL_CTL_DEL, fd, ev);
        close(fd);
        printf("Flags accepted: %hu | Flags rejected: %hu (close)\n", succ_flags, fail_flags);
        return;
    }

    // If there is data to read
    if ( event & EPOLLIN ) {
        ssize_t r = 0;
        char buff[BUFFSIZE];

        while ( (r = recvall(fd, buff, sizeof(buff)-1)) > 0 ) {
            buff[r] = '\0';

            if ( rs_fd < 0 ) {
                rs_fd = remote_server_connect();
                if ( rs_fd < 0 ) {
                    perror("event_handler: remote_fd < 0");
                    _exit(EXIT_FAILURE);
                }
            }

            if ( sendall(rs_fd, buff, r) < 0 ) {
                perror("event_handler: send_all");
                close(rs_fd);
                rs_fd = -1;
                continue;
            }

            
            char reply[BUFFSIZE];
            ssize_t n = recvall(rs_fd, reply, sizeof(reply) - 1);
#ifdef DEBUG
            printf("[DBG][RECVALL] %s\n", reply);
#endif 
            if (n < 0) {
                perror("event_handler: remote read");
                close(rs_fd);
                rs_fd = -1;
                continue;
            } else {
                reply[n] = '\0';

                if ( !strncmp(reply, TFLAG, strlen(TFLAG)) ) succ_flags++;
                else fail_flags++;
            }

        } // while
        
        if ( r < 0 && !(errno == EAGAIN || errno == EWOULDBLOCK) ) {
            perror("event_handler: read client failed");
            epoll_ctl(epoll_fd, EPOLL_CTL_DEL, fd, NULL);
            close(fd);
            printf("Flags accepted: %hu | Flags rejected: %hu\n", succ_flags, fail_flags);
        }
    }

}


int lcf_run(int main_fd)
{
    if ( main_fd < 0 ) {
        perror("lcf_run: main_fd < 0");
        return -1;
    }

    int epoll_fd;
    struct epoll_event ev, events[MAX_CLIENTS];

    memset(&ev, 0x0, sizeof(ev));
    memset(&events, 0x0, sizeof(events));

    epoll_fd = epoll_create1(0);
    if ( epoll_fd < 0 ) {
        perror("lcf_run: epoll_create1 error");
        _exit(EXIT_FAILURE);
    }

    ev.data.fd = main_fd;
    ev.events = EPOLLIN;
    if ( epoll_ctl(epoll_fd, EPOLL_CTL_ADD, main_fd, &ev) < 0 ) {
        perror("lcf_run: epoll_ctl (listen_fd)");
        _exit(EXIT_FAILURE);
    }
    
    if ( rs_fd < 0 ) {
        perror("lcf_run: rs_fd < 0");
        _exit(EXIT_FAILURE);
    }

    ev.data.fd = rs_fd;
    ev.events = EPOLLIN | EPOLLOUT;
    if ( epoll_ctl(epoll_fd, EPOLL_CTL_ADD, rs_fd, &ev) < 0 ) {
        perror("lcf_run: epoll_ctl (listen_fd)");
        _exit(EXIT_FAILURE);
    }

    while (1) {
        int n = epoll_wait(epoll_fd, events, MAX_CLIENTS, -1);

        for ( int i = 0; i < n; i++ ) {
            int fd = events[i].data.fd;
            uint32_t ep_ev = events[i].events;
            
            if ( fd == main_fd ) {
                struct sockaddr_in client_addr;
                socklen_t len = sizeof(client_addr);

                int client_fd = accept(main_fd, (struct sockaddr*)&client_addr, &len);
                if ( client_fd < 0 ) {
                    fprintf(stderr, "lcf_run: acceptance error | fd: %d\n", client_fd);
                    continue;
                }

                set_nonblocking(client_fd);
                ev.data.fd = client_fd;
                ev.events  = EPOLLIN | EPOLLHUP | EPOLLERR | EPOLLET;
            
                if ( epoll_ctl(epoll_fd, EPOLL_CTL_ADD, client_fd, &ev) < 0 ) {
                    fprintf(stderr, "lcf_run: epoll_ctl error (client_fd: %d)\n", client_fd);
                    close(client_fd);
                    continue;
                }
            } else {
                event_handler(epoll_fd, &events[i]);
            }

        } // for
    } // while
    
    close(epoll_fd);
    return 0;
}


int lcf_init(void)
{
    int listen_fd = create_unix_socket();
    if ( listen_fd < 0 ) {
        perror("lcf_init: listen_fd creating error");
        return -1;
    }
    set_nonblocking(listen_fd);
    
    struct sockaddr_un addr;
    memset(&addr, 0x0, sizeof(struct sockaddr_un));
    addr.sun_family = AF_UNIX;
    addr.sun_path[0] = 0x0;
    strcpy(addr.sun_path + 1, SNAME);
    
    socklen_t len = sizeof(addr.sun_family) + 1 + strlen(SNAME);
    if ( bind(listen_fd, (struct sockaddr*)&addr, len) < 0 ) {
        perror("lcf_init: socket binding error");
        close(listen_fd);
        return -1;
    }

    if ( listen(listen_fd, MAX_CLIENTS) < 0 ) {
        perror("lcf_init: listening error");
        close(listen_fd);
        return -1;
    }

    return listen_fd;
}


int main(void)
{
    rs_fd = remote_server_connect();
    if ( rs_fd < 0 ) return -1;
    puts("[+] Connection to the remote server is established");

    int main_fd = lcf_init();
    if ( main_fd < 0 ) {
        close(rs_fd);
        return -1;
    }
    puts("[+] LCF INIT");

    return lcf_run(main_fd);
}
