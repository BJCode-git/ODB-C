#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <sys/mman.h>
#include <signal.h>
#include <errno.h>

#define PAGE_SIZE sysconf(_SC_PAGESIZE)

typedef struct {
    size_t n_tests;
    size_t allocated_size;
    int out_fd;
} Options;

volatile int report_measure = 0;

void write_header(Options *o) {
    if (o) {
        dprintf(o->out_fd, "type,allocated_size,user_time_usec,system_time_usec,total_time_usec\n");
    }
}

// Retourne le temps en microsecondes à partir d’un timeval
long long timeval_to_usec(struct timeval *tv) {
    return (long long)tv->tv_sec * 1000000LL + tv->tv_usec;
}

typedef enum measure_type {
    vanilla=0,
    protection=1,
    unprotection=2
} measure_type;

const char *measure_types[] = {"vanilla", "protection", "unprotection"};

void log_result(measure_type t, struct rusage *delta, Options *o) {
    if (!delta || !o) return;

    long long utime = timeval_to_usec(&delta->ru_utime);
    long long stime = timeval_to_usec(&delta->ru_stime);
    long long total = utime + stime;

    const char *type = measure_types[t];
    dprintf(o->out_fd, "%s,%zu,%lld,%lld,%lld\n", type, o->allocated_size, utime, stime, total);
}

int parse_options(int argc, char **argv, Options *o) {
    if (argc < 2 || !o){
        fprintf(stderr, "Usage: %s [-n <n>] [-f <file>]\n", argv[0]);
        return -1;
    }

    o->n_tests = 1;
    o->out_fd = STDOUT_FILENO;

    int opt;
    while ((opt = getopt(argc, argv, "n:f:")) != -1) {
        switch (opt) {
            case 'n':
                o->n_tests = atoi(optarg);
                break;

            case 'f':
                o->out_fd = open(optarg, O_WRONLY | O_CREAT | O_TRUNC, 0644);
                if (o->out_fd == -1) return -1;
                write_header(o);
                break;

            default:
                return -1;
        }
    }
    // help message
    if (optind < argc) {
        fprintf(stderr, "Usage: %s [-n <n>] [-f <file>]\n", argv[0]);
        return -1;
    }

    return 0;
}

int compute_delta(struct rusage *start, struct rusage *end, struct rusage *delta) {
    if (!start || !end || !delta) return -1;

    timersub(&end->ru_utime, &start->ru_utime, &delta->ru_utime);
    timersub(&end->ru_stime, &start->ru_stime, &delta->ru_stime);
    return 0;
}

void sigsev_handler(int sig, siginfo_t *info, void *context) {
    (void)context;
    if (sig != SIGSEGV || info == NULL) return;

    uintptr_t addrToUnprotect = (uintptr_t)info->si_addr & ~(PAGE_SIZE - 1);
    report_measure = mprotect((void *)addrToUnprotect, PAGE_SIZE, PROT_READ | PROT_WRITE);
}

int main(int argc, char **argv) {
    struct rusage ru_start, ru_end, delta;
    Options o;
    memset(&o, 0, sizeof(o));

    if (parse_options(argc, argv, &o) == -1) {
        fprintf(stderr, "Error parsing options\n");
        return 1;
    }

    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_sigaction = sigsev_handler;
    sa.sa_flags = SA_SIGINFO;
    sigemptyset(&sa.sa_mask);
    sigaction(SIGSEGV, &sa, NULL);

    size_t total = o.n_tests * 60;
    size_t done = 1;

    for (int nb_page = 1; nb_page <= 60; nb_page++) {
        char *buf = NULL;
        size_t alloc_size = nb_page * PAGE_SIZE;

        if ( posix_memalign((void**) &buf, PAGE_SIZE, alloc_size) != 0 || !buf ) {
            perror("Error allocating buffer\n");
            close(o.out_fd);
            return 1;
        }

        o.allocated_size = alloc_size;
        for (size_t i = 0; i < o.n_tests; i++) {
            done++;
            printf("\rTest %zu / %zu (%.1f%%)", done, total, (100.0 * done) / total);
            fflush(stdout);

            // test vanilla
            getrusage(RUSAGE_SELF, &ru_start);
                buf[0] = 0;
            getrusage(RUSAGE_SELF, &ru_end);
            compute_delta(&ru_start, &ru_end, &delta);
            log_result(vanilla, &delta, &o);

            // test protection
            getrusage(RUSAGE_SELF, &ru_start);
            int res = mprotect(buf, alloc_size, PROT_NONE);
            getrusage(RUSAGE_SELF, &ru_end);

            if (res >= 0) {
                compute_delta(&ru_start, &ru_end, &delta);
                log_result(protection, &delta, &o);
            }

            // déclencher le SIGSEGV
            getrusage(RUSAGE_SELF, &ru_start);
                buf[0] = 0;
            getrusage(RUSAGE_SELF, &ru_end);

            if (report_measure == 0){
                compute_delta(&ru_start, &ru_end, &delta);
                log_result(unprotection, &delta, &o);
            }
        }

        if (buf) free(buf);
    }

    printf("\n");
    close(o.out_fd);
    return 0;
}
