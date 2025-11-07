#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <sys/un.h>
#include <sys/time.h>
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
volatile sig_atomic_t sq_reset_flag = 0;

size_t sq_ind = 0;
RRing *SQ = NULL;

void set_nonblocking(int fd);
int remote_server_connect(void);
int create_unix_socket(void);
ssize_t sendall(int fd, const void *buf, size_t len);
ssize_t recvall(int fd, void *buf, size_t len);
int read_in_sq(int fd);
void event_handler(int epoll_fd, struct epoll_event *ev);
int lcf_run(int main_fd);
int lcf_init(void);
static int sq_reset();
static void sq_del(RRing *rr);
static int sq_init(void);


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
    
//    set_nonblocking(remote_fd);
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


int read_in_sq(int fd)
{
    if ( fd < 0 ) return -1;
    if ( SQ == NULL && (sq_init() < 0) ) return -1;
#ifdef DEBUG
    printf("[DBG] sq_ind: %d | SQ->size: %d\n", sq_ind, SQ->size);
#endif
    if ( sq_ind == SQ->size ) {
        if ( sq_reset() < 0) {
            perror("read_in_sq: sq_reset error");
            return -1;
        }
    }
    
    RRNode *slot = SQ->cur;
    char *buff = slot->data.buf.ptr;
    if ( !buff ) return -1;

    ssize_t r = recvall(fd, buff, BUFFSIZE-1);
    if ( r < 0 && !(errno == EAGAIN || errno == EWOULDBLOCK) ) {
        return -1;
    }

    buff[r] = '\0';
    slot->data.buf.size = (size_t)r;
    
    if ( sq_ind < SQ->size ) sq_ind++;
    SQ->cur = SQ->cur->next;

    if (sq_ind >= SQ->size) {
        if (sq_reset() < 0) {
            perror("read_in_sq: sq_reset failed");
            return -1;
        }
    }

    return 0;
}


void event_handler(int epoll_fd, struct epoll_event *ev)
{
    int fd = ev->data.fd;
    uint32_t event = ev->events;
    
    // Client has disconnected
    if ( event & (EPOLLHUP | EPOLLERR) ) {
        epoll_ctl(epoll_fd, EPOLL_CTL_DEL, fd, ev);
        close(fd);
#ifdef DEBUG
        printf("Flags accepted: %hu | Flags rejected: %hu (close)\n", succ_flags, fail_flags);
#endif
        return;
    }

    // If there is data to read
    if ( event & EPOLLIN ) {
        if ( read_in_sq(fd) < 0 ) {
            perror("event_handler: read client failed");
            epoll_ctl(epoll_fd, EPOLL_CTL_DEL, fd, NULL);
            close(fd);
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
    ev.events = EPOLLIN | EPOLLHUP | EPOLLERR;
    if ( epoll_ctl(epoll_fd, EPOLL_CTL_ADD, rs_fd, &ev) < 0 ) {
        perror("lcf_run: epoll_ctl (listen_fd)");
        _exit(EXIT_FAILURE);
    }

    while (1) {
        if ( sq_reset_flag ) {
#ifdef DEBUG
            puts("[DBG] Timer: SIGALRM");
#endif
            if ( sq_reset() < 0 ) {
                perror("lcf_run: sq_reset error (timer)");
            }
            sq_reset_flag = 0;
        }

        int n = epoll_wait(epoll_fd, events, MAX_CLIENTS, -1);

        for ( int i = 0; i < n; i++ ) {
            int fd = events[i].data.fd;
            uint32_t ep_ev = events[i].events;
            
            if ( fd == main_fd ) {
                if ( ep_ev & (EPOLLHUP | EPOLLERR) ) {
                    fprintf(stderr, "lcf_run: main_fd error\n");
                    close(main_fd);
                    close(rs_fd);
                    return -1;
                }

                struct sockaddr_un client_addr;
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
            } else if ( fd == rs_fd ) {
                if ( ep_ev & (EPOLLHUP | EPOLLERR) ) {
                    fprintf(stderr, "lcf_run: rs_fd closed or errored - exiting\n");
                    close(rs_fd);
                    return -1;
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


static int sq_reset(void)
{
    if ( rs_fd < 0 ) {
        rs_fd = remote_server_connect();
        if ( rs_fd < 0 ) {
            perror("sq_reset: error connecting to a remote server");
            sq_del(SQ);
            _exit(EXIT_FAILURE);
        }
    }
    
    RRNode *cur = SQ->head;
    int err_count = 0;
    char reply[BUFFSIZE];

    for ( size_t i = 0; i < SQ->size && i < sq_ind; i++ ) {
        void *buf = cur->data.buf.ptr;
        size_t size = cur->data.buf.size;

        if ( !buf || size == 0 ) {
            cur = cur->next;
            continue;
        }


        if ( sendall(rs_fd, buf, size) < 0 ) {
            perror("sq_reset: sendall");
            if ( ++err_count >= 3 ) {
                perror("sq_reset: Too many send errors");
                close(rs_fd);
                rs_fd = -1;
                return -1;
            }
            continue;
        }

        ssize_t n = recvall(rs_fd, reply, sizeof(reply) - 1);
#ifdef DEBUG
        printf("[DBG][RECVALL] %s (reply)\n", reply);
#endif
        if ( n <= 0 ) {
            perror("sq_reset: rs_fd read");
            if ( ++err_count >= 3 ) {
                perror("sq_reset: Too many recv errors");
                close(rs_fd);
                rs_fd = -1;
                return -1;
            }
            continue;
        }

        reply[n] = '\0';
        if ( !strncmp(reply, TFLAG, strlen(TFLAG)) ) succ_flags++;
        else fail_flags++;

        memset(buf, 0x0, size);
        cur->data.buf.size = 0;
        cur = cur->next;
    } // for

    SQ->cur = SQ->head;
    sq_ind = 0;

    printf("Flags accepted: %hu | Flags rejected: %hu\n", succ_flags, fail_flags);

    return 0;
}


static void sq_del(RRing *rr)
{
    if ( !rr || !rr->head || !rr->tail ) return;


    RRNode *cur = rr->head;
    RRNode *next = NULL;

    if ( rr->head == rr->tail ) {
        if ( rr->head->data.buf.ptr != NULL ) free(rr->head->data.buf.ptr); 

        free(rr->tail);
        rr->head = rr->tail = NULL;
    } else {
        do {
            next = cur->next;
            if ( cur->data.buf.ptr != NULL ) free(cur->data.buf.ptr);
            free(cur);
            cur = next;
        } while ( cur && cur != rr->head );
    }

    rr->head = rr->tail = NULL;
    rr->size = 0;

    free(rr);
}


static int sq_init(void)
{
    if ( SQ != NULL ) return 0;

    RRing *tmp = rr_create();
    if ( !tmp ) {
        perror("sq_init: rr_create error");
        return -1;
    }
    
    RRData init_data;
    memset(&init_data, 0x0, sizeof(init_data));

    for ( int i = 0; i < SQSIZE; i++ ) {
        init_data.buf.ptr = malloc(BUFFSIZE);
        if ( !init_data.buf.ptr ) {
            perror("sq_init: malloc error");
            sq_del(tmp);
            SQ = NULL;
            return -1;
        }

        RRNode *t = rr_add(tmp, init_data);
        if ( !t ) {
            perror("sq_init: rr_add error");
            free(init_data.buf.ptr);
            sq_del(tmp);
            SQ = NULL;
            return -1;
        }
    }
    
    tmp->cur = tmp->head;
    SQ = tmp;
    return 0;
}


void sigalrm_handler(int sig) {
    (void)sig;
    sq_reset_flag = 1;
}


int timer_init(void)
{
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = sigalrm_handler;
    sigemptyset(&sa.sa_mask);
    if (sigaction(SIGALRM, &sa, NULL) < 0) {
        perror("sigaction");
        return 1;
    }

    if ( (FLAGTTL - 5) < 20 ) {
        perror("timer_init: FLAGTTL < 25");
        return -1;
    }

    struct itimerval it = {0};
    it.it_interval.tv_sec = FLAGTTL-5;
    it.it_value.tv_sec = FLAGTTL-5;
    if (setitimer(ITIMER_REAL, &it, NULL) < 0) {
        perror("setitimer");
        return 1;
    }

    return 0;
}


int main(void)
{
    if ( timer_init() < 0 ) {
        perror("main: timer_init error");
        return -1;
    }

    if ( sq_init() < 0 ) {
        perror("main: sq_init error");
        return -1;
    }

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
