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
#include <netinet/udp.h>
#include <netdb.h>

typedef struct {
    bool received;
    double send_time;
    double recv_time;
} HopInfo;

typedef struct {
    char *dest_hostname_arg;

    int socket_fd;
    int icmp_socket_fd;
    struct sockaddr_in dest_addr;
    char dest_addr_str[INET_ADDRSTRLEN];
    char dest_hostname[1024];

    HopInfo *hop_infos;
    int final_dest_hop;

    int first_query_this_loop;
    int total_queries_sent;
    int queries_sent_this_loop;
    int last_printed_query;

    int ttl_num_digits;
    int first_ttl; // -f --first
    int max_ttl; // -m --max-hops
    int num_simultaneous_queries; // -N --sim-queries
    int num_queries_per_hop; // -q --queries
    int port; // -p --port
    float max_wait_in_seconds; // -w --wait
    float here_wait_in_seconds; // -w --wait
    float near_wait_in_seconds; // -w --wait
} Context;

struct timeval SecondsDoubleToTimeval(double seconds);
double GetTime();

void FatalError(const char *message, ...);
void FatalErrorErrno(const char *message, int err);
void FatalErrorEAI(const char *message, int err);

int SendICMPEchoPacket(Context *ctx, int ttl);
int ReceiveICMPPacket(Context *ctx, void *buff, int size);
void PrintICMPPacket(Context *ctx, void *data, int size, double elapsed_ms);

void SendProbe(Context *ctx);
void ReceivePacket(Context *ctx, int hop);
void PrintPacket(Context *ctx, int query_index, HopInfo *hop_info);
bool ReachedFinalDestForHop(Context *ctx, int hop);

void TraceRoute(Context *ctx);
