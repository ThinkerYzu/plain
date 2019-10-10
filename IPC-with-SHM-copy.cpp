/* -*- Mode: c++; c-basic-offset: 4; indent-tabs-mode: nil; tab-width: 8 -*- */
#include <stdio.h>
#include <sys/types.h>
#include <unistd.h>
#include <sys/mman.h>
#include <linux/memfd.h>
#include <string.h>
#include <stdlib.h>

#include <linux/futex.h>
#include <sys/time.h>

#include <sys/syscall.h>

struct RingBufferHeader {
    volatile unsigned int read_head;
    volatile unsigned int write_head;
    unsigned int alloc;
    void* data_off;
};

struct RingBuffer {
    RingBufferHeader header;
    char data[16 * 1024 - sizeof(RingBufferHeader)];
};

struct FuncCall {
    int cmd;
    int size;
    char *msg;
};

enum {
    CMD_NONE,
    CMD_SKIP_TAIL,
    CMD_HELLO
};

void
futex(int* v, int op, unsigned int arg) {
    syscall(__NR_futex, v, op, arg);
}

FuncCall*
peek_call(RingBuffer *rbuf) {
    return (FuncCall*)(rbuf->data + rbuf->header.read_head);
}

void
relocate_call(RingBuffer *rbuf, FuncCall *call, char *base) {
    call->msg = base + (call->msg - (char*)rbuf->header.data_off);
}

FuncCall*
fetch_call(RingBuffer *rbuf) {
    FuncCall* call = peek_call(rbuf);
    __sync_synchronize();
    relocate_call(rbuf, call, rbuf->data);
    return call;
}

void
finish_call(RingBuffer *rbuf) {
    FuncCall* call = peek_call(rbuf);
    __sync_synchronize();
    rbuf->header.read_head = (rbuf->header.read_head + call->size) % sizeof(rbuf->data);
    futex((int*)&rbuf->header.read_head, FUTEX_WAKE, 1);
}

int wait_count = 0;

bool
have_call(RingBuffer *rbuf) {
    bool r = rbuf->header.read_head != rbuf->header.write_head;
    if (r && peek_call(rbuf)->cmd == CMD_SKIP_TAIL) {
        rbuf->header.read_head = 0;
        r = rbuf->header.read_head != rbuf->header.write_head;
    }
    return r;
}

void
wait_call(RingBuffer *rbuf) {
    while (true) {
        while (rbuf->header.read_head == rbuf->header.write_head) {
            wait_count++;
            __sync_synchronize();
            unsigned int write_head = rbuf->header.write_head;
            if (write_head == rbuf->header.read_head) {
                futex((int*)&rbuf->header.write_head, FUTEX_WAIT, write_head);
            }
        }
        FuncCall *call = peek_call(rbuf);
        __sync_synchronize();
        if (call->cmd != CMD_SKIP_TAIL) {
            break;
        }
        rbuf->header.read_head = 0;
    }
}

FuncCall*
get_new_call(RingBuffer *rbuf) {
    return (FuncCall*)(rbuf->data + rbuf->header.write_head);
}

void
add_skip_tail(RingBuffer *rbuf) {
    FuncCall *call = get_new_call(rbuf);
    call->cmd = CMD_SKIP_TAIL;
    __sync_synchronize();
    rbuf->header.write_head = 0;
}

void
add_skip_tail_commit(RingBuffer *rbuf) {
    add_skip_tail(rbuf);
    rbuf->header.alloc = 0;
}

unsigned int
try_allocate(RingBuffer *rbuf, int size) {
    int alloc = rbuf->header.alloc;
    int alloc_end = alloc + size;
    int read_head = rbuf->header.read_head;
    while (true) {
        bool run_over_read_head = alloc < read_head && alloc_end >= read_head;
        if (run_over_read_head) {
            return sizeof(rbuf->data);
        }

        bool overflow_buf = alloc_end > sizeof(rbuf->data);
        if (overflow_buf) {
            alloc = 0;
            alloc_end = size;
            continue;
        }
        break;
    }

    return alloc;
}

char*
allocate(RingBuffer *rbuf, int size) {
    size = (size + 0x3) & ~0x3;
    unsigned int start = try_allocate(rbuf, size);
    bool nospace = start >= sizeof(rbuf->data);
    if (nospace) {
        return NULL;
    }

    char *r = rbuf->data + start;
    rbuf->header.alloc = (start + size) % sizeof(rbuf->data);
    return r;
}

void
wait_new_call(RingBuffer *rbuf) {
    unsigned int read_head = rbuf->header.read_head;
    while (try_allocate(rbuf, sizeof(FuncCall)) == sizeof(rbuf->data)) {
        __sync_synchronize();
        futex((int*)&rbuf->header.read_head, FUTEX_WAIT, read_head);
        read_head = rbuf->header.read_head;
    }
}

FuncCall*
start_new_call(RingBuffer *rbuf) {
    FuncCall *r = (FuncCall*)allocate(rbuf, sizeof(FuncCall));
    if (r == NULL) {
        return r;
    }
    bool round_to_head = rbuf->header.alloc == sizeof(FuncCall);
    if (round_to_head) {
        add_skip_tail(rbuf);
    }
    __sync_synchronize();
    return r;
}

void
commit_new_call(RingBuffer *rbuf) {
    int size = (int)rbuf->header.alloc - (int)rbuf->header.write_head;
    if (size < 0) {
        size += sizeof(rbuf->data);
    }
    get_new_call(rbuf)->size = (unsigned int)size;
    __sync_synchronize();
    rbuf->header.write_head = rbuf->header.alloc;
    futex((int*)&rbuf->header.write_head, FUTEX_WAKE, 1);
}

void
rollback_call(RingBuffer *rbuf) {
    rbuf->header.alloc = rbuf->header.write_head;
}

bool
round_to_head(RingBuffer *rbuf) {
    return rbuf->header.alloc > 0 && rbuf->header.alloc < rbuf->header.write_head;
}

void
show_ringbuffers(RingBuffer *rbuf) {
#if 0
    printf("S: %d %d %d\n", rbuf->header.read_head,
           rbuf->header.write_head,
           rbuf->header.alloc);
#endif
}

void
show_ringbufferc(RingBuffer *rbuf) {
#if 0
    printf("C: %d %d %d\n", rbuf->header.read_head,
           rbuf->header.write_head,
           rbuf->header.alloc);
#endif
}

void
make_shadow(RingBuffer *rbuf, RingBuffer *shadow) {
    memcpy(&shadow->header, &rbuf->header, sizeof(rbuf->header));
    __sync_synchronize();
    if (shadow->header.write_head < shadow->header.read_head) {
        memcpy(shadow->data, rbuf->data, shadow->header.write_head);
        memcpy(shadow->data + shadow->header.read_head,
               rbuf->data + shadow->header.read_head,
               sizeof(rbuf->data) - shadow->header.read_head);
    } else {
        memcpy(shadow->data + shadow->header.read_head,
               rbuf->data + shadow->header.read_head,
               shadow->header.write_head - shadow->header.read_head);
    }
    rbuf->header.read_head = shadow->header.write_head;
    futex((int*)&rbuf->header.read_head, FUTEX_WAKE, 1);
}

void
do_server(int fd) {
    RingBuffer *rbuf = (RingBuffer*)mmap(NULL, sizeof(RingBuffer),
                                         PROT_WRITE | PROT_READ,
                                         MAP_SHARED,
                                         fd, 0);
    RingBuffer *shadow = (RingBuffer*)malloc(sizeof(RingBuffer));

    int i = 0;
    while (true) {
        wait_call(rbuf);
        make_shadow(rbuf, shadow);
        while (have_call(shadow)) {
            RingBuffer *rbuf = shadow;

            FuncCall* call = fetch_call(rbuf);
            switch (call->cmd) {
            case CMD_HELLO:
                if (++i == 1000000) {
                    printf("MSG: %s %d\n", call->msg, wait_count);
                    i = 0;
                }
                break;
            default:
                abort();
            }
            finish_call(rbuf);
            show_ringbuffers(rbuf);
        }
    }
}

void
do_client(int fd) {
    RingBuffer *rbuf_ = (RingBuffer*)mmap(NULL, sizeof(RingBuffer),
                                          PROT_WRITE | PROT_READ,
                                          MAP_SHARED,
                                          fd, 0);
    RingBuffer *rbuf = (RingBuffer*)mmap(NULL, sizeof(RingBuffer),
                                         PROT_WRITE | PROT_READ,
                                         MAP_SHARED,
                                         fd, 0);
    rbuf->header.data_off = rbuf->data;
    munmap(rbuf_, sizeof(RingBuffer));

    int seq = 0;
    while (true) {
        char buf[256];
        seq++;
        snprintf(buf, 256, "Hello World %d", seq);

        while (true) {
            wait_new_call(rbuf);
            FuncCall *call = start_new_call(rbuf);
            call->cmd = CMD_HELLO;
            int sz = strlen(buf);
            char *msg = NULL;
            while ((msg = allocate(rbuf, sz + 1)) == NULL) {
            }
#if 0
            if (round_to_head(rbuf)) {
                rollback_call(rbuf);
                add_skip_tail_commit(rbuf);
                continue;
            }
#endif
            strcpy(msg, buf);
            call->msg = msg;
            commit_new_call(rbuf);
            show_ringbufferc(rbuf);
            break;
        }
    }
}

int
main() {
    int fd = memfd_create("comm", 0);
    for (int i = 0; i < sizeof(RingBuffer); i++) {
        write(fd, " ", 1);
    }
    RingBuffer *rbuf = (RingBuffer*)mmap(NULL, sizeof(RingBuffer),
                                         PROT_WRITE | PROT_READ,
                                         MAP_SHARED,
                                         fd, 0);
    rbuf->header.read_head = rbuf->header.write_head = rbuf->header.alloc = 0;
    munmap(rbuf, sizeof(RingBuffer));

    int pid = fork();
    if (pid < 0) {
        perror("fork");
        return 255;
    }
    if (pid == 0) {
        do_client(fd);
    } else {
        do_server(fd);
    }
    return 0;
}
