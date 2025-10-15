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
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <netdb.h>

// #define Dbg(...) dprintf(STDOUT_FILENO, __VA_ARGS__)
#define Dbg(...)

typedef struct {
    bool received;
    uint8_t icmp_type;
    struct sockaddr_in recv_addr;
    double send_time;
    double recv_time;
} ProbeInfo;

typedef struct {
    char *dest_hostname_arg;

    int socket_fd;
    int icmp_socket_fd;
    struct sockaddr_in dest_addr;
    char dest_addr_str[INET_ADDRSTRLEN];
    char dest_hostname[1024];

    ProbeInfo *probe_infos;

    int first_query_this_loop;
    int total_queries_sent;
    int queries_sent_this_loop;
    int final_dest_hop;
    int last_printed_query;
    struct in_addr last_printed_addr;
    uint16_t source_port;
    double receive_start_time;

    int ttl_num_digits;
    int first_ttl; // -f --first
    int max_ttl; // -m --max-hops
    int num_simultaneous_queries; // -N --sim-queries
    int num_queries_per_hop; // -q --queries
    uint16_t port; // -p --port
    float max_wait_in_seconds; // -w --wait
} Context;

#define Packet_Size 60

struct timeval SecondsDoubleToTimeval(double seconds);
double TimevalToSecondsDouble(struct timeval time);
double GetTime();

void FatalError(const char *message, ...);
void FatalErrorErrno(const char *message, int err);
void FatalErrorEAI(const char *message, int err);

void SendProbe(Context *ctx);
void ReceivePacket(Context *ctx);
bool ReachedFinalDestForHop(Context *ctx, int hop);

void TraceRoute(Context *ctx);
