#pragma once

#include <stdlib.h>
#include <stdio.h>
#include <stdbool.h>
#include <string.h>
#include <stdarg.h>
#include <errno.h>
#include <time.h>
#include <math.h>

#include <unistd.h>
#include <signal.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <sys/time.h>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/ip_icmp.h>
#include <netdb.h>

typedef struct {
    char *dest_hostname_arg;

    int socket_fd;
    int icmp_socket_fd;
    struct sockaddr_in dest_addr;
    char dest_addr_str[INET_ADDRSTRLEN];
    char dest_hostname[1024];

    struct timeval *send_times;

    int first_ttl; // -f --first
    int max_ttl; // -m --max-hops
    int num_simultaneous_queries; // -N --sim-queries
    int num_queries_per_hop; // -q --queries
    int port; // -p --port
    float max_wait_in_seconds; // -w --wait
    float here_wait_in_seconds; // -w --wait
    float near_wait_in_seconds; // -w --wait
} Context;

void FatalError(const char *message, ...);
void FatalErrorErrno(const char *message, int err);
void FatalErrorEAI(const char *message, int err);

int SendICMPEchoPacket(Context *ctx, int ttl);
int ReceiveICMPPacket(Context *ctx, void *buff, int size);
void PrintICMPPacket(Context *ctx, void *data, int size, double elapsed_ms);

void TraceRoute(Context *ctx);
